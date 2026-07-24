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
make_path( $rules_dir . '/http' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $rules_dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

sub parsed_line {
	my ( $host, $request, $status, $user_agent ) = @_;
	return App::Baphomet::Parser::parse( 'http_access',
		      $host
			. ' - - [12/Jul/2026:08:15:50 -0500] "'
			. $request . '" '
			. $status
			. ' 196 "-" "'
			. $user_agent
			. '"' );
} ## end sub parsed_line

#
# gates, matches, ignores
#

write_rule( 'http/probes', <<'EOR' );
---
status:
  - 404
  - //^4[0-9][0-9]$//
method:
  - GET
  - POST
match:
  - field: path
    regexp: '^/\.env'
  - field: user_agent
    regexp: '(?i:zgrab)'
ignore:
  - field: user_agent
    regexp: 'FriendlyAuditBot'
tests:
  positive:
    - message: '203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "GET /.env HTTP/1.1" 404 196 "-" "curl/8"'
      found: 1
      data:
        host: "203.0.113.9"
        path: "/.env"
        status: "404"
  negative:
    - message: '198.51.100.7 - - [12/Jul/2026:08:15:51 -0500] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"'
      found: 0
      undefed: ["host"]
EOR

my $rules = App::Baphomet::Rules->new( rules_dir => $rules_dir, shipped => 0 );
my $rule  = $rules->load('http/probes');
ok( defined($rule), 'http rule loaded' );
is( ( $rule->ban_var )[0], 'host', 'ban_var is host' );

my $found = $rule->check( parsed_line( '203.0.113.9', 'GET /.env HTTP/1.1', 404, 'curl/8' ) );
ok( defined($found), 'path match found' );
is( $found->{data}{host}, '203.0.113.9', 'host in data' );
is( $found->{regexp},     0,             'first match entry hit' );

$found = $rule->check( parsed_line( '203.0.113.9', 'GET /robots.txt HTTP/1.1', 404, 'zgrab/0.x' ) );
ok( defined($found), 'user_agent match found' );
is( $found->{regexp}, 1, 'second match entry hit' );

ok( !defined( $rule->check( parsed_line( '203.0.113.9', 'GET /.env HTTP/1.1', 200, 'curl/8' ) ) ),
	'status gate blocks a 200' );
ok( !defined( $rule->check( parsed_line( '203.0.113.9', 'DELETE /.env HTTP/1.1', 404, 'curl/8' ) ) ),
	'method gate blocks a DELETE' );
ok( !defined( $rule->check( parsed_line( '203.0.113.9', 'GET /index.html HTTP/1.1', 404, 'curl/8' ) ) ),
	'no match entry hit means not found' );
ok( !defined( $rule->check( parsed_line( '203.0.113.9', 'GET /.env HTTP/1.1', 404, 'FriendlyAuditBot/1' ) ) ),
	'ignore vetoes a would-be match' );
ok( defined( $rule->check( parsed_line( '203.0.113.9', 'GET /.env HTTP/1.1', 499, 'curl/8' ) ) ),
	'status gate regexp entry matches' );

# a syslog-parsed line is never an offense to a http rule
my $syslog_parsed = App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 vixen42 sshd[1]: foo' );
ok( !defined( $rule->check($syslog_parsed) ), 'syslog shaped lines are refused' );

#
# gates only rule... every 401
#

write_rule( 'http/all401', <<'EOR' );
---
status:
  - 401
tests:
  positive:
    - message: '203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "GET /secret HTTP/1.1" 401 196 "-" "curl/8"'
      found: 1
      data:
        host: "203.0.113.9"
EOR

my $all401 = $rules->load('http/all401');
$found = $all401->check( parsed_line( '203.0.113.9', 'GET /secret HTTP/1.1', 401, 'curl/8' ) );
ok( defined($found), 'gates only rule found' );
ok( !defined( $found->{regexp} ), 'gates only rule has no regexp index' );
ok( !defined( $all401->check( parsed_line( '203.0.113.9', 'GET /secret HTTP/1.1', 200, 'curl/8' ) ) ),
	'gates only rule not found on a 200' );

#
# invalid defs
#

write_rule( 'http/empty', "---\ntests: {}\n" );
ok( !eval { $rules->load('http/empty'); 1 }, 'no gates and no matches refuses to load' );

write_rule( 'http/badfield', <<'EOR' );
---
match:
  - field: lunar_phase
    regexp: 'full'
EOR
ok( !eval { $rules->load('http/badfield'); 1 }, 'unknown field refuses to load' );
like( $@, qr/lunar_phase/, 'unknown field named in the error' );

write_rule( 'http/badregexp', <<'EOR' );
---
match:
  - field: path
    regexp: '((('
EOR
ok( !eval { $rules->load('http/badregexp'); 1 }, 'uncompilable regexp refuses to load' );

#
# rule type / parser pairing
#

ok( App::Baphomet::Rules::type_accepts_parser( 'http',   'http_access' ), 'http takes http_access' );
ok( !App::Baphomet::Rules::type_accepts_parser( 'http',   'syslog' ),     'http refuses syslog' );
ok( App::Baphomet::Rules::type_accepts_parser( 'syslog', 'bsd_syslog' ),  'syslog takes bsd_syslog' );
ok( !App::Baphomet::Rules::type_accepts_parser( 'syslog', 'http_access' ), 'syslog refuses http_access' );

my $good_def = {
	'accesslog' => { 'log' => '/var/log/httpd-access.log', 'parser' => 'http_access', 'rule' => 'http/probes' } };
ok( eval { check_kur_def( 'www', $good_def ); 1 }, 'http rule with http_access parser checks out' ) || diag($@);

my $bad_def = { 'accesslog' => { 'log' => '/var/log/httpd-access.log', 'rule' => 'http/probes' } };
ok( !eval { check_kur_def( 'www', $bad_def ); 1 }, 'http rule with the default syslog parser refuses' );
like( $@, qr/can not consume/, 'pairing error says why' );

done_testing;
