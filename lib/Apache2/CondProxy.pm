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

use APR::Bucket          ();
use APR::Brigade         ();

use Apache2::Const -compile => qw(OK DECLINED PROXYREQ_REVERSE);

# if i recall correctly, mod_perl doesn't like 'use base'.
our @ISA = qw(Apache2::RequestRec);

=head1 NAME

Apache2::CondProxy - Intelligent reverse proxy for missing resources

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

    # httpd.conf
    PerlFixupHandler +Apache2::CondProxy
    PerlSetVar ProxyTarget http://other.host/
    PerlSetVar RequestBodyCache /tmp

=head1 DESCRIPTION

This module performs the logic required to achieve what is implied by
the following Apache configuration:

    # httpd.conf
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !-U
    RewriteRule (.*) http://some.host$1 [P,NS]

Which says I<if I can't respond to a given request, try some.host>.
Unfortunately, the architecture of mod_rewrite, as well as the design
of Apache's handler model itself, prohibits this. In the first case,
all C<RewriteCond> directives are evaluated I<after> the associated
C<RewriteRule>. In the second, the response code is initialized to
C<200> and remains that way until it is changed, most likely by a
response handler. This confluence of behaviour makes the above
configuration not do what we imagine it would.

This module works by running the request all the way through in a
subrequest. Before doing so, a filter is installed to trap the
subrequest's response. If the response is I<unsuccessful>, the filter
disposes of the error body, resets the status code, and the request
is redirected to the proxy target.

=cut

sub new {
    my ($class, $r) = @_;
    bless { r => $r }, $class;
}

sub handler :method {
    my ($self, $r) = @_;

    if ($r->is_initial_req) {
        my $subr = $r->lookup_uri($r->uri);
        # we don't need to run the response handler if the response is
        # already an error
        return $r->do_proxy if _is_error($subr->status);

        # set up filters
        $subr->add_input_filter(\&_trap_input);
        $subr->add_output_filter(\&_trap_output);
        my $status = $subr->run;
        return $r->do_proxy if _is_error($status);
    }

    Apache2::Const::DECLINED;
}

sub do_proxy {
    my $r = shift;
    my $base = $r->dir_config('ProxyTarget');
    # TODO: deal with potentially missing or malformed target

    $r->filename(sprintf 'proxy:%s%s', $base, $r->uri);
    $r->proxyreq(Apache2::Const::PROXYREQ_REVERSE);
    $r->handler('proxy-server');

    # TODO: resurrect request body if one is present

    Apache2::Const::OK;
}

sub _trap_input :FilterRequestHandler {
    my ($f, $bb) = @_;
    my $r = $f->r;

    # tee all request input into a temporary file

    Apache2::Const::OK;
}

# read the cached input back into the input stream

sub _resurrect_input :FilterRequestHandler {
    my ($f, $bb) = @_;
    my $r = $f->r;

    Apache2::Const::OK;
}

sub _trap_output :FilterRequestHandler {
    my ($f, $bb) = @_;
    my $r = $f->r;

    if (_is_error($r->status)) {
        $r->log->debug
            (__PACKAGE__ . ' output filter: dropping subrequest body');
        $bb->destroy;
    }

    Apache2::Const::OK;
}

# what our configuration considers an error
sub _is_error {
    my $r = shift;
}

=head1 AUTHOR

Dorian Taylor, C<< <dorian at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-apache2-condproxy at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Apache2-CondProxy>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




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


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 Dorian Taylor.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    L<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


=cut

1; # End of Apache2::CondProxy
