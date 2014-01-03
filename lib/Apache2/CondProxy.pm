package Apache2::CondProxy;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Apache2::RequestRec  ();
use Apache2::RequestUtil ();
use Apache2::ServerRec   ();
use Apache2::SubRequest  ();
use Apache2::Response    ();
use Apache2::Filter      ();
use Apache2::Connection  ();
use Apache2::Log         ();
use Apache2::ModSSL      ();

use APR::Table           ();
use APR::Bucket          ();
use APR::Brigade         ();

use Apache2::Const -compile => qw(OK DECLINED SERVER_ERROR PROXYREQ_REVERSE);
use APR::Const     -compile => qw(:common ENOTIMPL OVERLAP_TABLES_SET);

use Path::Class ();
use File::Spec  ();
use File::Temp  ();
use URI         ();
use URI::Escape ();

# constants for pnotes
use constant BRIGADE => __PACKAGE__ . '::BRIGADE';
use constant INPUT   => __PACKAGE__ . '::INPUT';
use constant CACHE   => __PACKAGE__ . '::CACHE';

BEGIN {
    # stopgap implementation of ap_save_brigade
    unless (Apache2::Filter->can('save_brigade')) {
        *Apache2::Filter::save_brigade = sub {
            my ($f, $saveto, $bb, $pool) = @_;
            # XXX should this be $f->r->pool?
            $pool ||= $f->c->pool;

            my $ret = APR::Const::SUCCESS;

            for (my $b = $bb->first; $b && !$b->is_eos; $b = $bb->next($b)) {
                my $rv = $b->setaside($pool);

                if ($rv == APR::Const::ENOTIMPL) {
                    my $len = $b->read(my $data);
                    # apparently this changes the bucket type?
                    $rv = $b->setaside($pool) if $len;
                }

                # check for some other kind of error
                if ($rv != APR::Const::SUCCESS) {
                    $ret = $rv;
                    return $rv if $rv != APR::Const::ENOTIMPL;
                }
            }

            # now concatenate the brigade to the target
            $saveto->concat($bb);

            return $ret;
        };
    }
}

# if i recall correctly, mod_perl doesn't like 'use base'.
our @ISA = qw(Apache2::RequestRec);

=head1 NAME

Apache2::CondProxy - Intelligent reverse proxy for missing resources

=head1 VERSION

Version 0.14

=cut

our $VERSION = '0.14';

=head1 SYNOPSIS

    # httpd.conf
    PerlFixupHandler Apache2::CondProxy
    PerlSetVar ProxyTarget http://another.host/
    PerlSetVar RequestBodyCache /tmp

=head1 DESCRIPTION

This module performs the logic required to achieve what is implied by
the following Apache configuration:

    # httpd.conf
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !-U
    RewriteRule (.*) http://another.host$1 [P,NS]

Which says I<if I can't respond to a given request, try another.host>.
Unfortunately, the architecture of mod_rewrite, as well as the design
of Apache's handler model itself, prohibits this. In the first case,
all C<RewriteCond> directives are evaluated I<after> the associated
C<RewriteRule>. In the second, the response code is initialized to
C<200> and remains that way until it is changed, most likely by a
response handler which never gets run. This confluence of behaviour
makes the above configuration not do what we imagine it would.

This module works by running the request all the way through in a
subrequest. Before doing so, a filter is installed to trap the
subrequest's response. If the response is I<unsuccessful>,
specifically if it is a C<403> or C<404>, the filter disposes of the
error body, and the request is forwarded to the proxy target. The
proxy URI scheme is matched to the original request URI scheme, so
make sure you have C<SSLProxyEngine on>.

If a proxy response contains a C<Location> header, and its host is the
same as the proxy target, that header will be rewritten to point to
the source host.

=cut

# XXX this probably doesn't need to be a method handler
sub new {
    bless {}, __PACKAGE__;
}

sub handler : method {
    my $r = ref $_[0] ? $_[0] : bless { r => $_[1] }, $_[0];

    if ($r->is_initial_req) {
        # make the temp directory
        umask 077;
        my $dir = Path::Class::Dir->new
            ($r->dir_config('RequestBodyCache') || File::Spec->tmpdir);
        eval { $dir->mkpath };
        if ($@) {
            $r->log->crit("Cannot make directory $dir: $@");
            return Apache2::Const::SERVER_ERROR;
        }

        $r->pnotes(CACHE, $dir);

        my $uri = $r->unparsed_uri;
        $r->log->debug("Attempting lookup on $uri");
        my $subr = $r->lookup_method_uri($r->method, $uri);

        # set the content-type and content-length in the subrequest
        my $ct = $r->headers_in->get('Content-Type');
        $subr->headers_in->set('Content-Type', $ct) if $ct;
        my $cl = $r->headers_in->get('Content-Length');
        $subr->headers_in->set('Content-Length', $cl) if $cl;

        # remove Accept-Encoding header for proxy
        my $ae = $r->headers_in->get('Accept-Encoding');
        $r->headers_in->unset('Accept-Encoding');
        $subr->headers_in->unset('Accept-Encoding');

        if ($subr->status == 404) {
            $r->log->debug('Proxying before subrequest is run');
            return _do_proxy($r);
        }

        $r->log->debug(sprintf 'Results inconclusive: %d; running subrequest',
                       $subr->status);
        $subr->add_input_filter(\&_input_filter_tee);
        $subr->add_output_filter(\&_output_filter_hold);
        my $rv = $subr->run;

        # we only care about 404
        my $st = $subr->status;
        if (grep { $rv == $_ || $st == $_ } (403, 404)) {
            $r->log->debug("Proxying $uri after subrequest is run");
            return _do_proxy($r);
        }
        else {
            # override the subrequest status
            $subr->status($rv) if $subr->status != $rv && $rv != 0;
            $r->status($subr->status);

            # replace Accept-Encoding header
            $r->headers_in->set('Accept-Encoding', $ae) if $ae;

            $r->log->debug(
                sprintf 'Subrequest returned %d; serving content for %s',
                $subr->status, $uri);

            # copy headers from subreq
            $r->headers_out->overlap
                ($subr->headers_out, APR::Const::OVERLAP_TABLES_SET);
            $r->err_headers_out->overlap
                ($subr->err_headers_out, APR::Const::OVERLAP_TABLES_SET);

            # apparently content_type has to be done separately
            $r->log->debug($subr->content_type);
            $r->content_type($subr->content_type) if $subr->content_type;
            $r->content_encoding($subr->content_encoding)
                if $subr->content_encoding;
            $r->set_last_modified($subr->mtime) if $subr->mtime;

            $r->SUPER::handler('modperl');
            $r->set_handlers(PerlResponseHandler => \&_response_handler);
            $r->push_handlers(PerlCleanupHandler => \&_cleanup_handler);
            $r->add_output_filter(\&_output_filter_release);
        }
    }

    Apache2::Const::OK;
}

sub _do_proxy {
    my $r = shift;
    my $c = $r->connection;

    my $base = URI->new($r->dir_config('ProxyTarget'));
    # make the scheme match the request
    $c->is_https ? $base->scheme('https') : $base->scheme('http');
    # for some reason this started double-escaping URIs
    #my $uri = URI::Escape::uri_unescape($r->unparsed_uri);
    # XXX this will contain content from Files, LocationMatch, etc.
    #my $loc = $r->location || '/';
    #$loc =~ s!/+$!!;
    #$uri =~ s!^$loc(.*)!$1!;

    # just do this.
    $base->path_query($r->unparsed_uri);
    # AHA: MAGIC.
    $r->notes->set('proxy-nocanon', 1);

    #$r->filename(sprintf 'proxy:%s%s', $base, $uri);
    $r->filename(sprintf 'proxy:%s', $base);
    $r->proxyreq(Apache2::Const::PROXYREQ_REVERSE);
    $r->SUPER::handler('proxy-server');
    $r->add_input_filter(\&_input_filter_replay);
    $r->add_output_filter(\&_output_filter_fix_location);

    return Apache2::Const::OK;
}

sub _output_filter_fix_location {
    my ($f, $bb) = @_;
    my $c = $f->c;
    my $r = $f->r;

    my $mainr = $r->main || $r;
    unless ($f->ctx) {
        my $loc  = $r->headers_out->get('Location');
        if ($loc) {
            # get the hostname of the request
            my $host = $r->headers_in->get('Host')
                || $r->server->server_hostname;
            $host = ($c->is_https ? 'https://' : 'http://') . $host;
            $host = URI->new($host)->canonical;

            # get the proxy base
            my $base = URI->new($r->dir_config('ProxyTarget'));
            $c->is_https ? $base->scheme('https') : $base->scheme('http');

            # fix for malformed Location header
            $loc = URI->new_abs($loc, $base);
            $loc = $loc->canonical;

            $r->log->debug(sprintf 'Location is %s', $loc->authority);

            if ($loc->authority eq $base->authority) {
                $r->log->debug
                    ('Setting Location authority to %s', $host->authority);
                $loc->authority($host->authority);
                $r->headers_out->set(Location => $loc->as_string);
            }
        }
        $f->ctx(1);
    }

    Apache2::Const::DECLINED;
}

sub _response_handler {
    my $r = shift;
    #$r->log->debug('lol response handler');
    Apache2::Const::OK;
}

sub _cleanup_handler {
    my $r = shift;
    if (my $xx = $r->pnotes(INPUT)) {
        $r->log->debug
            ('Unlinking temporary file in case it is still sticking around');
        unlink($xx->[0]);
    }
    Apache2::Const::OK;
}

sub _input_filter_tee {
    my ($f, $bb, $mode, $block, $readbytes) = @_;
    my $c = $f->c;
    my $r = $f->r;

    my $mainr = $r->main || $r;

    $r->log->debug('Pre-emptively storing request input');

    my $in = APR::Brigade->new($c->pool, $c->bucket_alloc);
    my $rv = $f->next->get_brigade($in, $mode, $block, $readbytes);
    return $rv unless $rv == APR::Const::SUCCESS;

    # only open the tempfile if there is something to put in it
    unless ($in->is_empty) {

        # deal with tempfile
        my $fh;
        my $xx = $mainr->pnotes(INPUT);
        if ($xx) {
            $fh = $xx->[1];
        }
        else {
            # unfortunately something does not like the preemptive unlink
            my $dir = $mainr->pnotes(CACHE);
            my $fn;
            eval { ($fh, $fn) = $dir->tempfile(OPEN => 1, UNLINK => 0) };
            if ($@) {
                $r->log->crit("Could not create temporary file in $dir: $@");
                return Apache2::Const::SERVER_ERROR;
            }

            $fh->binmode;
            # also yes I know this is the reverse of what File::Temp returns
            $mainr->pnotes(INPUT, [$fn, $fh]);
        }

        for (my $b = $in->first; $b; $b = $in->next($b)) {
            if ($b->is_eos) {
                # flush the temp file and seek it to zero
                $fh->flush;
                $fh->seek(0, 0);
            }
            elsif (my $len = $b->read(my $data)) {
                $fh->write($data);
            }
            else {
                # noop?
            }
        }
    }

    $bb->concat($in);

    APR::Const::SUCCESS;
}

# it kinda sucks there's no way to make file buckets in mod_perl
# because this would probably be way more efficient to stick the fd in
# a bucket than read the file out in perl.
sub _input_filter_replay {
    my ($f, $bb, $mode, $block, $readbytes) = @_;
    my $c = $f->c;
    my $r = $f->r;

    my $xx = $r->pnotes(INPUT) or return Apache2::Const::DECLINED;
    my ($fn, $fh) = @$xx;

    $r->log->debug('Replaying input into proxy request');

    # XXX do i even have to do this?
    my $in = APR::Brigade->new($c->pool, $c->bucket_alloc);
    my $rv = $f->next->get_brigade($in, $mode, $block, $readbytes);
    return $rv unless $rv == APR::Const::SUCCESS;

    # whatever is in it, empty it
    $in->destroy;

    # get the data out of the file
    my $len = $fh->read(my $data, $readbytes);
    if ($len) {
        $r->log->debug
            ("Replaying $len bytes from $fn (Block size: $readbytes)");
        my $b = APR::Bucket->new($c->bucket_alloc, $data);
        $bb->insert_tail($b);
        # eos if there's nothing left to read, flush otherwise
        if ($fh->eof) {
            $r->log->debug('End of file, appending EOS bucket');
            $bb->insert_tail(APR::Bucket::eos_create($c->bucket_alloc));
            unlink($fn);
        }
        else {
            $bb->insert_tail(APR::Bucket::flush_create($c->bucket_alloc));
        }
    }
    else {
        $r->log->debug('Empty file or end, appending EOS bucket');
        $bb->insert_tail(APR::Bucket::eos_create($c->bucket_alloc));
        unlink($fn);
    }

    APR::Const::SUCCESS;
}

sub _output_filter_hold {
    my ($f, $bb) = @_;
    my $c = $f->c;
    my $r = $f->r;

    my $mainr = $r->main || $r;

    my $saveto = $mainr->pnotes(BRIGADE);
    unless ($saveto) {
        $saveto = APR::Brigade->new($c->pool, $c->bucket_alloc);
        $mainr->pnotes(BRIGADE, $saveto);
    }

    return $f->save_brigade($saveto, $bb, $c->pool);
}

sub _output_filter_release {
    my ($f, $bb) = @_;
    my $r = $f->r;

    $bb = $r->pnotes(BRIGADE) or return Apache2::Const::DECLINED;
    return Apache2::Const::DECLINED unless $bb->length;

    return $f->next->pass_brigade($bb);
}

=head1 AUTHOR

Dorian Taylor, C<< <dorian at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-apache2-filterfun
at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Apache2-CondProxy>.
I will be notified, and then you'll automatically be notified of
progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Apache2::CondProxy


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Apache2-CondProxy>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Apache2-CondProxy>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Apache2-CondProxy>

=item * Search CPAN

L<http://search.cpan.org/dist/Apache2-CondProxy/>

=back

=head1 LICENSE AND COPYRIGHT

Copyright 2013 Dorian Taylor.

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at
L<http://www.apache.org/licenses/LICENSE-2.0> .

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.  See the License for the specific language governing
permissions and limitations under the License.

=cut

1; # End of Apache2::CondProxy
