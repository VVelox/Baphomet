#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

my @modules = (
	'App::Baphomet',
	'App::Baphomet::LogDrek',
	'App::Baphomet::Config',
	'App::Baphomet::Parser',
	'App::Baphomet::Parser::BSDSyslog',
	'App::Baphomet::Parser::IETFSyslog',
	'App::Baphomet::Parser::JSONSyslog',
	'App::Baphomet::Parser::JSON',
	'App::Baphomet::Parser::Syslog',
	'App::Baphomet::Parser::HTTPAccess',
	'App::Baphomet::Parser::ApacheError',
	'App::Baphomet::Parser::NginxError',
	'App::Baphomet::Parser::Raw',
	'App::Baphomet::Rules',
	'App::Baphomet::Rules::Base',
	'App::Baphomet::Rules::Syslog',
	'App::Baphomet::Rules::HTTP',
	'App::Baphomet::Rules::HTTPError',
	'App::Baphomet::Rules::JSON',
	'App::Baphomet::Rules::Raw',
	'App::Baphomet::Galla',
	'App::Baphomet::App',
);

plan tests => scalar(@modules);

foreach my $module (@modules) {
	use_ok($module) || print "Bail out!\n";
}

diag("Testing App::Baphomet $App::Baphomet::VERSION, Perl $], $^X");
