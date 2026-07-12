#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Parser ();

my $parsed = App::Baphomet::Parser::parse( 'nginx_error',
	'2026/07/12 08:15:50 [error] 12345#0: *67 user "admin" was not found in "/etc/nginx/.htpasswd", client: 1.2.3.4, server: example.com, request: "GET / HTTP/1.1", host: "example.com"'
);
ok( defined($parsed), 'standard line parsed' ) || BAIL_OUT('the most basic line did not parse');
is( $parsed->{format},  'nginx_error',         'format' );
is( $parsed->{time},    '2026/07/12 08:15:50', 'time' );
is( $parsed->{level},   'error',               'level' );
is( $parsed->{pid},     '12345',               'pid' );
is( $parsed->{tid},     '0',                   'tid' );
is( $parsed->{cid},     '67',                  'cid' );
is( $parsed->{client},  '1.2.3.4',             'client peeled' );
is( $parsed->{server},  'example.com',         'server peeled' );
is( $parsed->{request}, 'GET / HTTP/1.1',      'request peeled and unquoted' );
is( $parsed->{host},    'example.com',         'host peeled and unquoted' );
is( $parsed->{message}, 'user "admin" was not found in "/etc/nginx/.htpasswd"', 'message is just the free text' );

# empty server value, host with port, referrer
$parsed = App::Baphomet::Parser::parse( 'nginx_error',
	'2014/04/02 12:37:58 [error] 6563#0: *1861 user "x": password mismatch, client: 10.0.2.2, server: , request: "GET /admin HTTP/1.1", host: "localhost:8443", referrer: "https://scribend.io/admin"'
);
ok( defined($parsed), 'empty server line parsed' );
is( $parsed->{server},   '',                          'empty server peeled as empty' );
is( $parsed->{host},     'localhost:8443',            'host with port' );
is( $parsed->{referrer}, 'https://scribend.io/admin', 'referrer peeled' );

# injected pairs... the rightmost value of a repeated key wins
$parsed = App::Baphomet::Parser::parse( 'nginx_error',
	'2014/04/03 22:20:40 [error] 30708#0: *3 user "test": password mismatch, client: 127.0.0.1, server: test, request: "GET / HTTP/1.1", host: "localhost:8443"": was not found in "/etc/nginx/.htpasswd", client: 192.0.2.2, server: , request: "GET / HTTP/1.1", host: "localhost:8443"'
);
ok( defined($parsed), 'injected line parsed' );
is( $parsed->{client}, '192.0.2.2', 'rightmost client wins over the injected one' );
like( $parsed->{message}, qr/^user "test": password mismatch/, 'message keeps the leading free text' );

# no connection id
$parsed = App::Baphomet::Parser::parse( 'nginx_error', '2026/07/12 08:15:51 [notice] 1#1: using epoll' );
ok( defined($parsed), 'cidless line parsed' );
is( $parsed->{cid},    undef,         'cid undef' );
is( $parsed->{client}, undef,         'client undef' );
is( $parsed->{message}, 'using epoll', 'message' );

# garbage
is( App::Baphomet::Parser::parse( 'nginx_error', '[Wed Oct 11 14:32:52 2000] [error] [client 1.2.3.4] foo' ),
	undef, 'apache line returns undef' );
is( App::Baphomet::Parser::parse( 'nginx_error', undef ), undef, 'undef returns undef' );

ok( App::Baphomet::Parser::is_known('nginx_error'), 'nginx_error is a known parser' );

done_testing;
