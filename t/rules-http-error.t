#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp            qw( tempdir );
use File::Path            qw( make_path );
use App::Baphomet::Config qw( check_kur_def );
use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();

my $rules_dir = tempdir( CLEANUP => 1 );
make_path( $rules_dir . '/http_error' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $rules_dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

sub apache_line {
	my ( $module, $level, $client, $message ) = @_;
	return App::Baphomet::Parser::parse( 'apache_error',
		      '[Thu Jun 27 11:55:44.569531 2013] ['
			. ( defined($module) ? $module . ':' : '' )
			. $level
			. '] [pid 4101] '
			. ( defined($client) ? '[client ' . $client . ':23456] ' : '' )
			. $message );
} ## end sub apache_line

write_rule( 'http_error/probes', <<'EOR' );
---
level:
  - error
  - //^crit//
module:
  - auth_basic
message_regexp:
  - '^user (?<USER>\S*): password mismatch'
  - '^user \S* not found'
ignore_regexp:
  - 'user probemaster:'
test_parser: apache_error
tests:
  positive:
    - message: '[Thu Jun 27 11:55:44.569531 2013] [auth_basic:error] [pid 4101] [client 1.2.3.4:23456] AH01617: user foo: password mismatch'
      found: 1
      data:
        client: "1.2.3.4"
        USER: "foo"
  negative:
    - message: '[Thu Jun 27 11:55:44.569531 2013] [auth_basic:notice] [pid 4101] [client 1.2.3.4:23456] user foo: password mismatch'
      found: 0
      undefed: ["client"]
EOR

my $rules = App::Baphomet::Rules->new( rules_dir => $rules_dir );
my $rule  = $rules->load('http_error/probes');
ok( defined($rule), 'http_error rule loaded' );
is( ( $rule->ban_var )[0], 'client', 'ban_var is client' );

my $found = $rule->check( apache_line( 'auth_basic', 'error', '1.2.3.4', 'user foo: password mismatch' ) );
ok( defined($found), 'match found' );
is( $found->{data}{client}, '1.2.3.4', 'client in data' );
is( $found->{data}{USER},   'foo',     'named capture merged into data' );
is( $found->{regexp},       0,         'first regexp hit' );

$found = $rule->check( apache_line( 'auth_basic', 'error', '1.2.3.4', 'user foo not found: /x' ) );
is( $found->{regexp}, 1, 'second regexp hit' );

ok( !defined( $rule->check( apache_line( 'auth_basic', 'notice', '1.2.3.4', 'user foo: password mismatch' ) ) ),
	'level gate blocks a notice' );
ok( defined( $rule->check( apache_line( 'auth_basic', 'crit3', '1.2.3.4', 'user foo: password mismatch' ) ) ),
	'level gate regexp entry matches' );
ok( !defined( $rule->check( apache_line( 'authz_core', 'error', '1.2.3.4', 'user foo: password mismatch' ) ) ),
	'module gate blocks another module' );
ok( !defined( $rule->check( apache_line( undef, 'error', '1.2.3.4', 'user foo: password mismatch' ) ) ),
	'module gate blocks a moduleless 2.2 line' );
ok( !defined( $rule->check( apache_line( 'auth_basic', 'error', undef, 'user foo: password mismatch' ) ) ),
	'clientless lines are never offenses' );
ok( !defined( $rule->check( apache_line( 'auth_basic', 'error', '1.2.3.4', 'user probemaster: password mismatch' ) ) ),
	'ignore_regexp vetoes' );
ok( !defined( $rule->check( apache_line( 'auth_basic', 'error', '1.2.3.4', 'something else entirely' ) ) ),
	'non-matching message not found' );

# other parser shapes are refused
my $syslog_parsed = App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 vixen42 sshd[1]: foo' );
ok( !defined( $rule->check($syslog_parsed) ), 'syslog shaped lines are refused' );
my $access_parsed = App::Baphomet::Parser::parse( 'http_access',
	'1.2.3.4 - - [12/Jul/2026:08:15:50 -0500] "GET / HTTP/1.1" 200 5' );
ok( !defined( $rule->check($access_parsed) ), 'access log shaped lines are refused' );

# a nginx line through a moduleless rule
write_rule( 'http_error/nginx', <<'EOR' );
---
level:
  - error
message_regexp:
  - '^user "[^"]*":? (?:password mismatch|was not found in)'
test_parser: nginx_error
tests:
  positive:
    - message: '2012/04/09 11:53:36 [error] 2865#0: *66647 user "xyz": password mismatch, client: 192.0.43.10, server: www.myhost.com, request: "GET / HTTP/1.1", host: "www.myhost.com"'
      found: 1
      data:
        client: "192.0.43.10"
EOR

my $nginx_rule = $rules->load('http_error/nginx');
my $nginx_parsed = App::Baphomet::Parser::parse( 'nginx_error',
	'2012/04/09 11:53:36 [error] 2865#0: *66647 user "xyz": password mismatch, client: 192.0.43.10, server: x, request: "GET / HTTP/1.1", host: "x"'
);
$found = $nginx_rule->check($nginx_parsed);
ok( defined($found), 'nginx line found' );
is( $found->{data}{client}, '192.0.43.10', 'nginx client in data' );

# but a module gate makes a rule apache only
ok( !defined( $rule->check($nginx_parsed) ), 'module gate blocks nginx lines' );

#
# invalid defs
#

write_rule( 'http_error/noregexp', "---\nlevel:\n  - error\n" );
ok( !eval { $rules->load('http_error/noregexp'); 1 }, 'missing message_regexp refuses to load' );

write_rule( 'http_error/badregexp', "---\nmessage_regexp:\n  - '((('\n" );
ok( !eval { $rules->load('http_error/badregexp'); 1 }, 'uncompilable regexp refuses to load' );

#
# pairing
#

ok( App::Baphomet::Rules::type_accepts_parser( 'http_error', 'apache_error' ), 'http_error takes apache_error' );
ok( App::Baphomet::Rules::type_accepts_parser( 'http_error', 'nginx_error' ),  'http_error takes nginx_error' );
ok( !App::Baphomet::Rules::type_accepts_parser( 'http_error', 'syslog' ),      'http_error refuses syslog' );

my $good_def = {
	'errorlog' =>
		{ 'log' => '/var/log/httpd-error.log', 'parser' => 'apache_error', 'rule' => 'http_error/apache-auth' } };
ok( eval { check_kur_def( 'www', $good_def ); 1 }, 'http_error rule with apache_error parser checks out' )
	|| diag($@);

my $bad_def = { 'errorlog' => { 'log' => '/var/log/httpd-error.log', 'rule' => 'http_error/apache-auth' } };
ok( !eval { check_kur_def( 'www', $bad_def ); 1 }, 'http_error rule with the default syslog parser refuses' );

done_testing;
