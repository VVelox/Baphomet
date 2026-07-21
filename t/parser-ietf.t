#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Parser ();

my $parsed = App::Baphomet::Parser::parse( 'ietf_syslog',
	'<38>1 2026-07-12T08:15:50.313437-05:00 vixen42 sshd-session 66891 - - Invalid user moth3r from 216.137.179.214 port 34640'
);
ok( defined($parsed), 'standard line parsed' ) || BAIL_OUT('the most basic line did not parse');
is( $parsed->{time},     '2026-07-12T08:15:50.313437-05:00', 'time' );
is( $parsed->{hostname}, 'vixen42',                          'hostname' );
is( $parsed->{daemon},   'sshd-session',                     'daemon' );
is( $parsed->{pid},      '66891',                            'pid' );
is( $parsed->{facility}, 4,                                  'facility' );
is( $parsed->{severity}, 6,                                  'severity' );
is( $parsed->{level},    'info',                             'level' );
is( $parsed->{message},  'Invalid user moth3r from 216.137.179.214 port 34640', 'message' );

# nil fields
$parsed = App::Baphomet::Parser::parse( 'ietf_syslog', '<13>1 - - - - - - hello' );
ok( defined($parsed), 'nil field line parsed' );
is( $parsed->{time},     undef,   'nil time undef' );
is( $parsed->{hostname}, undef,   'nil hostname undef' );
is( $parsed->{daemon},   undef,   'nil daemon undef' );
is( $parsed->{pid},      undef,   'nil pid undef' );
is( $parsed->{message},  'hello', 'message' );

# structured data
$parsed = App::Baphomet::Parser::parse( 'ietf_syslog',
	'<165>1 2026-07-12T08:15:50Z host app 123 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] BOMAn application event log entry' );
ok( defined($parsed), 'structured data line parsed' );
is( $parsed->{daemon},  'app', 'daemon with structured data' );
like( $parsed->{message}, qr/^BOMAn application/, 'message with structured data' );

# no message at all
$parsed = App::Baphomet::Parser::parse( 'ietf_syslog', '<165>1 2026-07-12T08:15:50Z host app 123 ID47 -' );
ok( defined($parsed), 'messageless line parsed' );
is( $parsed->{message}, '', 'message empty' );

# structured data with a escaped quote inside a param value, as the RFC
# requires a quote be written
$parsed = App::Baphomet::Parser::parse( 'ietf_syslog',
	'<38>1 2026-07-12T08:15:50Z host app 123 ID47 [id a="b\\"c"] hello world' );
ok( defined($parsed), 'escaped quote in structured data parsed' );
is( $parsed->{message}, 'hello world', 'message past the escaped quote' );

# a PRI past 191 is not syslog
is( App::Baphomet::Parser::parse( 'ietf_syslog', '<999>1 2026-07-12T08:15:50Z host app 123 ID47 - foo' ),
	undef, 'out of range PRI returns undef' );

# garbage
is( App::Baphomet::Parser::parse( 'ietf_syslog', 'Jul 12 08:15:50 vixen42 sshd[123]: foo' ),
	undef, 'bsd line returns undef' );
is( App::Baphomet::Parser::parse( 'ietf_syslog', undef ), undef, 'undef returns undef' );

done_testing;
