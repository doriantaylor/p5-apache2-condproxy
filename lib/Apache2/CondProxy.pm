package Apache2::CondProxy;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Apache2::RequestRec  ();
use Apache2::RequestUtil ();
use Apache2::SubRequest  ();
use Apache2::Filter      ();
use Apache2::Connection  ();
use Apache2::Log         ();

use APR::Table           ();
use APR::Bucket          ();
use APR::Brigade         ();

use Apache2::Const -compile => qw(OK DECLINED PROXYREQ_REVERSE);
use APR::Const     -compile => qw(:common);

use File::Spec  ();
use Path::Class ();

# if i recall correctly, mod_perl doesn't like 'use base'.
our @ISA = qw(Apache2::RequestRec);

=head1 NAME

Apache2::CondProxy - Intelligent reverse proxy for missing resources

=head1 VERSION

Version 0.02

=cut

our $VERSION = '0.02';


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
subrequest's response. If the response is I<unsuccessful>, the filter
disposes of the error body, and the request is forwarded to the proxy
target.

=cut

sub handler :method {
    my $r = ref $_[0] ? $_[0] : bless { r => $_[1] }, $_[0];

    if ($r->is_initial_req) {
        # remove Accept-Encoding

        my $hdr = $r->headers_in;
        my @enc = $hdr->get('Accept-Encoding');
        $hdr->unset('Accept-Encoding');

        my $subr = $r->lookup_uri($r->uri);
        # we don't need to run the response handler if the response is
        # already an error

        if ($r->_is_error($subr->status)) {
            #map { $hdr->add('Accept-Encoding', $_) } @enc;
            return $r->do_proxy;
        }

#        return $r->do_proxy if $r->_is_error($subr->status);

#        $r->log->debug(sprintf 'Subrequest status code before handler: %d',
#                       $subr->status);

        # set up filters
        $subr->add_input_filter(\&_trap_input);
        $subr->add_output_filter(\&_trap_output);

        # run the subrequest
        my $return = $subr->run;
        $r->log->debug($return);

        # put the header back on unconditionally
        #map { $hdr->add('Accept-Encoding', $_) } @enc;

        # use the RETURN VALUE from the subreq not its ->status
        return $r->do_proxy if $r->_is_error($return);
    }

    Apache2::Const::DECLINED;
}

sub do_proxy {
    my $r = shift;
    my $base = $r->dir_config('ProxyTarget');
    $r->log->debug("proxying to $base");
    # TODO: deal with potentially missing or malformed target

    # $r->add_input_filter(\&_resurrect_input);

    $r->filename(sprintf 'proxy:%s%s', $base, $r->uri);
    $r->log->debug("Proxying to " . $r->filename);
    $r->proxyreq(Apache2::Const::PROXYREQ_REVERSE);
    # duh, we redefine $r->handler above. I guess this isn't the best
    $r->SUPER::handler('proxy-server');

    # TODO: resurrect request body if one is present

    Apache2::Const::OK;
}

sub _trap_input {
    my ($f, $bb, $mode, $block, $readbytes) = @_;
    my $c = $f->c;
    my $r = $f->r;

    warn $readbytes;

    $r->log->debug('running trap input filter');

    # XXX this is an error unless $dir is writable
    my $dir = Path::Class::Dir->new
        ($r->dir_config('RequestBodyCache') || File::Spec->tmpdir);

    # XXX test this
    $dir->mkpath;

    # create a new brigade
    my $bb_ctx = APR::Brigade->new($c->pool, $c->bucket_alloc);
    my $rv = $f->next->get_brigade($bb_ctx, $mode, $block, $readbytes);
    return $rv unless $rv == APR::Const::SUCCESS;

    # tee all request input into a temporary file

    unless ($bb_ctx->is_empty) {
        # store the tempfile
        my $tmp = $r->pnotes(__PACKAGE__ . '::TMPFILE');
        unless ($tmp) {
            ($tmp, my $fn) = $dir->tempfile(OPEN => 1);
            warn $fn;
            $r->pnotes(__PACKAGE__ . '::TMPFILE', $tmp);
        }

        while (!$bb_ctx->is_empty) {
            my $b = $bb_ctx->first;

            $b->remove;
            if ($b->is_eos) {
                $bb->insert_tail($b);
                last;
            }

            # pull the content out of the bucket and stick it in the
            # tempfile
            my $len = $b->read(my $data);
            $tmp->syswrite($data);

            # pull the bucket out of the current brigade and attach it
            # to the end of the next one
            #$b->remove;
            $bb->insert_tail($b);
        }
    }

    Apache2::Const::OK;
}

# read the cached input back into the input stream

sub _resurrect_input {
    my ($f, $bb, $mode, $block, $readbytes) = @_;
    my $r = $f->r;

    $r->log->debug('running resurrect input filter');

    #my $c = $f->c;
    #my $bb_ctx = APR::Brigade->new($c->pool, $c->bucket_alloc);
    #my $rv = $f->next->get_brigade($bb_ctx, $mode, $block, $readbytes);
    #return $rv unless $rv == APR::Const::SUCCESS;

    # pull the contents out of the file and stick it back in the brigade

    Apache2::Const::OK;
}

sub _trap_output {
    my ($f, $bb) = @_;
    my $r = $f->r;

    $r->log->debug("derp derp " . $r->status);

    $bb->flatten(my $dur);
    #$r->log->debug($dur);

    if (_is_error($r, $r->status)) {
        $r->log->debug
            (__PACKAGE__ . ' output filter: dropping subrequest body');
        # $bb->destroy;
    }

    Apache2::Const::OK;
}

# what our configuration considers an error
sub _is_error {
    my ($r, $code) = @_;
    unless ($code) {
        $r->log->debug(sprintf 'Setting null code to %d', $r->status);
        $code = $r->status;
    }

    my ($pkg, $file, $line) = caller;

    $r->log->debug(
        sprintf('Code %d from request to %s from %s line %d',
                $code, $r->uri, $file, $line));

    return ($code >= 400 && $code < 500);
}

=head1 AUTHOR

Dorian Taylor, C<< <dorian at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-apache2-condproxy
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

Copyright 2012 Dorian Taylor.

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at
L<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.  See the License for the specific language governing
permissions and limitations under the License.


=cut

1; # End of Apache2::CondProxy
