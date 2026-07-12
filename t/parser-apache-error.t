#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Parser ();

# 2.2 shape
my $parsed = App::Baphomet::Parser::parse( 'apache_error',
	'[Wed Oct 11 14:32:52 2000] [error] [client 1.2.3.4] client denied by server configuration: /export/htdocs/test'
);
ok( defined($parsed), '2.2 line parsed' ) || BAIL_OUT('the most basic line did not parse');
is( $parsed->{format},      'apache_error',              'format' );
is( $parsed->{time},        'Wed Oct 11 14:32:52 2000',  'time' );
is( $parsed->{module},      undef,                       '2.2 module undef' );
is( $parsed->{level},       'error',                     'level' );
is( $parsed->{pid},         undef,                       '2.2 pid undef' );
is( $parsed->{client},      '1.2.3.4',                   'client' );
is( $parsed->{client_port}, undef,                       '2.2 client_port undef' );
is( $parsed->{code},        undef,                       '2.2 code undef' );
is( $parsed->{message}, 'client denied by server configuration: /export/htdocs/test', 'message' );

# 2.4 shape
$parsed = App::Baphomet::Parser::parse( 'apache_error',
	'[Thu Jun 27 11:55:44.569531 2013] [auth_basic:error] [pid 4101:tid 2992] [client 1.2.3.4:23456] AH01617: user foo: authentication failure for "/": Password Mismatch'
);
ok( defined($parsed), '2.4 line parsed' );
is( $parsed->{module},      'auth_basic', '2.4 module' );
is( $parsed->{level},       'error',      '2.4 level' );
is( $parsed->{pid},         '4101',       '2.4 pid' );
is( $parsed->{tid},         '2992',       '2.4 tid' );
is( $parsed->{client},      '1.2.3.4',    '2.4 client' );
is( $parsed->{client_port}, '23456',      '2.4 client_port' );
is( $parsed->{code},        'AH01617',    '2.4 code' );
is( $parsed->{message}, 'user foo: authentication failure for "/": Password Mismatch',
	'2.4 message with the code split off' );

# 2.4 pid with out tid
$parsed = App::Baphomet::Parser::parse( 'apache_error',
	'[Sun Sep 14 21:44:43.008606 2014] [authz_core:error] [pid 10691] [client 192.3.9.178:44271] AH01630: client denied by server configuration: /x'
);
ok( defined($parsed), 'pid only line parsed' );
is( $parsed->{pid}, '10691', 'pid with out tid' );
is( $parsed->{tid}, undef,   'tid undef' );

# IPv6 client with a port... the split prefers the port when the left of
# the last colon is still valid IPv6
$parsed = App::Baphomet::Parser::parse( 'apache_error',
	'[Thu Jun 27 11:55:44.569531 2013] [core:error] [pid 1] [client 2001:db8::1:23456] AH00135: foo' );
ok( defined($parsed), 'IPv6 client line parsed' );
is( $parsed->{client},      '2001:db8::1', 'IPv6 client split' );
is( $parsed->{client_port}, '23456',       'IPv6 client_port split' );

# IPv6 client with out a port (2.2 style)
$parsed = App::Baphomet::Parser::parse( 'apache_error',
	'[Thu Jul 11 01:21:44 2013] [error] [client 2606:2800:220:1:248:1893:25c8:1946] user test-ipv6 not found: /' );
ok( defined($parsed), 'portless IPv6 client line parsed' );
is( $parsed->{client}, '2606:2800:220:1:248:1893:25c8:1946', 'portless IPv6 client' );

# the 2.4 prefork empty module form
$parsed = App::Baphomet::Parser::parse( 'apache_error',
	'[Sat May 09 00:35:52.389262 2020] [:error] [pid 22406:tid 139985298601728] [client 192.0.2.2:47762] foo' );
ok( defined($parsed), 'empty module line parsed' );
is( $parsed->{module}, undef,       'empty module comes back undef' );
is( $parsed->{level},  'error',     'empty module level' );
is( $parsed->{client}, '192.0.2.2', 'empty module client' );

# no client at all
$parsed = App::Baphomet::Parser::parse( 'apache_error',
	'[Sat Jun 01 02:17:43 2013] [mpm_prefork:notice] [pid 123] AH00163: Apache/2.4 configured -- resuming normal operations'
);
ok( defined($parsed), 'clientless line parsed' );
is( $parsed->{client}, undef,  'client undef' );
is( $parsed->{level},  'notice', 'clientless level' );

# garbage
is( App::Baphomet::Parser::parse( 'apache_error', 'Jul 12 08:15:50 vixen42 httpd[123]: foo' ),
	undef, 'syslog line returns undef' );
is( App::Baphomet::Parser::parse( 'apache_error', undef ), undef, 'undef returns undef' );

ok( App::Baphomet::Parser::is_known('apache_error'), 'apache_error is a known parser' );

done_testing;
