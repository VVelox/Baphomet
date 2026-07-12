#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Parser ();

# combined
my $parsed = App::Baphomet::Parser::parse( 'http_access',
	'203.0.113.9 - kitsune [12/Jul/2026:08:15:50 -0500] "GET /.env HTTP/1.1" 404 196 "http://example.com/" "zgrab/0.x"'
);
ok( defined($parsed), 'combined line parsed' ) || BAIL_OUT('the most basic line did not parse');
is( $parsed->{format},     'combined',            'format' );
is( $parsed->{host},       '203.0.113.9',         'host' );
is( $parsed->{ident},      undef,                 'ident undef for -' );
is( $parsed->{user},       'kitsune',             'user' );
is( $parsed->{time},       '12/Jul/2026:08:15:50 -0500', 'time' );
is( $parsed->{request},    'GET /.env HTTP/1.1',  'request' );
is( $parsed->{method},     'GET',                 'method' );
is( $parsed->{path},       '/.env',               'path' );
is( $parsed->{protocol},   'HTTP/1.1',            'protocol' );
is( $parsed->{status},     '404',                 'status' );
is( $parsed->{bytes},      '196',                 'bytes' );
is( $parsed->{referer},    'http://example.com/', 'referer' );
is( $parsed->{user_agent}, 'zgrab/0.x',           'user_agent' );

# common (CLF)
$parsed = App::Baphomet::Parser::parse( 'http_access',
	'198.51.100.7 - - [12/Jul/2026:08:15:51 -0500] "GET /index.html HTTP/1.1" 200 5120' );
ok( defined($parsed), 'CLF line parsed' );
is( $parsed->{format},     'clf', 'CLF format' );
is( $parsed->{referer},    undef, 'CLF referer undef' );
is( $parsed->{user_agent}, undef, 'CLF user_agent undef' );

# - for bytes, referer, and user agent
$parsed = App::Baphomet::Parser::parse( 'http_access',
	'198.51.100.7 - - [12/Jul/2026:08:15:51 -0500] "GET / HTTP/1.1" 304 - "-" "-"' );
ok( defined($parsed), 'dashes line parsed' );
is( $parsed->{bytes},      undef,      'bytes undef for -' );
is( $parsed->{referer},    undef,      'referer undef for -' );
is( $parsed->{user_agent}, undef,      'user_agent undef for -' );
is( $parsed->{format},     'combined', 'still the combined format' );

# escaped quotes inside quoted fields
$parsed = App::Baphomet::Parser::parse( 'http_access',
	'203.0.113.5 - - [12/Jul/2026:08:15:52 -0500] "GET /?q=\" OR 1=1 HTTP/1.1" 400 226 "-" "sneaky \"agent\""' );
ok( defined($parsed), 'escaped quote line parsed' );
is( $parsed->{user_agent}, 'sneaky \"agent\"', 'escaped quotes kept raw in user_agent' );
like( $parsed->{request}, qr/OR 1=1/, 'escaped quote request captured' );

# HTTP/0.9 style request, no protocol
$parsed = App::Baphomet::Parser::parse( 'http_access',
	'203.0.113.6 - - [12/Jul/2026:08:15:53 -0500] "GET /index.html" 200 512' );
ok( defined($parsed), 'HTTP/0.9 line parsed' );
is( $parsed->{method},   'GET',         'HTTP/0.9 method' );
is( $parsed->{path},     '/index.html', 'HTTP/0.9 path' );
is( $parsed->{protocol}, undef,         'HTTP/0.9 protocol undef' );

# junk request... raw kept, split undef
$parsed = App::Baphomet::Parser::parse( 'http_access',
	'203.0.113.7 - - [12/Jul/2026:08:15:54 -0500] "\x16\x03\x01" 400 226' );
ok( defined($parsed), 'junk request line parsed' );
is( $parsed->{method}, undef, 'junk request method undef' );
is( $parsed->{request}, '\x16\x03\x01', 'junk request kept raw' );

# garbage
is( App::Baphomet::Parser::parse( 'http_access', 'Jul 12 08:15:50 vixen42 sshd[123]: foo' ),
	undef, 'syslog line returns undef' );
is( App::Baphomet::Parser::parse( 'http_access', undef ), undef, 'undef returns undef' );

ok( App::Baphomet::Parser::is_known('http_access'), 'http_access is a known parser' );

done_testing;
