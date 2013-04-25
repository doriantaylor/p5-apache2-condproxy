use inc::Module::Install;

name     'Apache2-CondProxy';
abstract 'This module implements logic for a conditional reverse proxy.';
all_from 'lib/Apache2/CondProxy.pm';
author   q{Dorian Taylor <dorian@cpan.org>};
license  'apache';

requires 'Path::Class';

build_requires 'Test::More';
build_requires 'Apache::Test';

clean_files 't/TEST t/SMOKE';

require Apache::TestMM;
Apache::TestMM->import(qw(test clean));

Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');

auto_install;

WriteAll;

