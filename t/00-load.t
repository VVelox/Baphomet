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
	'App::Baphomet::Rule',
	'App::Baphomet::Gate',
	'App::Baphomet::Gate::account',
	'App::Baphomet::Gate::active_time',
	'App::Baphomet::Gate::asn',
	'App::Baphomet::Gate::ban_not_internal',
	'App::Baphomet::Gate::ban_var',
	'App::Baphomet::Gate::capture',
	'App::Baphomet::Gate::capture_regexp',
	'App::Baphomet::Gate::condition',
	'App::Baphomet::Gate::country',
	'App::Baphomet::Gate::daemons',
	'App::Baphomet::Gate::detection_var',
	'App::Baphomet::Gate::dnsbl',
	'App::Baphomet::Gate::gate',
	'App::Baphomet::Gate::ignore',
	'App::Baphomet::Gate::ignore_regexp',
	'App::Baphomet::Gate::key',
	'App::Baphomet::Gate::keywords',
	'App::Baphomet::Gate::level',
	'App::Baphomet::Gate::limit',
	'App::Baphomet::Gate::mark',
	'App::Baphomet::Gate::marked',
	'App::Baphomet::Gate::match',
	'App::Baphomet::Gate::message_json',
	'App::Baphomet::Gate::message_regexp',
	'App::Baphomet::Gate::method',
	'App::Baphomet::Gate::module',
	'App::Baphomet::Gate::mungers',
	'App::Baphomet::Gate::namtar_list',
	'App::Baphomet::Gate::not_marked',
	'App::Baphomet::Gate::not_tracked',
	'App::Baphomet::Gate::reverse_dns',
	'App::Baphomet::Gate::sequence',
	'App::Baphomet::Gate::stages',
	'App::Baphomet::Gate::status',
	'App::Baphomet::Gate::track',
	'App::Baphomet::Gate::tracked',
	'App::Baphomet::Gate::unmark',
	'App::Baphomet::Rules',
	'App::Baphomet::Rules::Gates',
	'App::Baphomet::Rules::Tokens',
	'App::Baphomet::Rules::SelfTest',
	'App::Baphomet::Galla',
	'App::Baphomet::ClayTablet',
	'App::Baphomet::ClayTablet::File',
	'App::Baphomet::ClayTablet::Redis',
	'App::Baphomet::App',
);

plan tests => scalar(@modules);

foreach my $module (@modules) {
	use_ok($module) || print "Bail out!\n";
}

diag("Testing App::Baphomet $App::Baphomet::VERSION, Perl $], $^X");
