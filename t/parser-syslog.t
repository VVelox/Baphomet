#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Parser ();

# a BSD line through the combined parser
my $parsed = App::Baphomet::Parser::parse( 'syslog',
	'Jul 12 08:15:50 vixen42 sshd-session[66891]: Invalid user moth3r from 216.137.179.214 port 34640' );
ok( defined($parsed), 'BSD line parsed' );
is( $parsed->{format}, 'bsd_syslog',   'BSD line format' );
is( $parsed->{daemon}, 'sshd-session', 'BSD line daemon' );

# a IETF line through the combined parser
$parsed = App::Baphomet::Parser::parse( 'syslog',
	'<38>1 2026-07-12T08:15:50.313437-05:00 vixen42 sshd-session 66891 - - Invalid user moth3r from 216.137.179.214 port 34640'
);
ok( defined($parsed), 'IETF line parsed' );
is( $parsed->{format}, 'ietf_syslog',  'IETF line format' );
is( $parsed->{daemon}, 'sshd-session', 'IETF line daemon' );

# a BSD line with a PRI... the sniff sees <PRI> followed by J, not a
# version digit, so BSD goes first and wins
$parsed = App::Baphomet::Parser::parse( 'syslog', '<38>Jul 12 08:15:50 vixen42 sshd[123]: foo' );
ok( defined($parsed), 'BSD line with PRI parsed' );
is( $parsed->{format},   'bsd_syslog', 'BSD line with PRI format' );
is( $parsed->{facility}, 4,            'BSD line with PRI facility' );

# the specific parsers report their format too
$parsed = App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 vixen42 sshd[123]: foo' );
is( $parsed->{format}, 'bsd_syslog', 'bsd_syslog reports format' );
$parsed = App::Baphomet::Parser::parse( 'ietf_syslog', '<13>1 - - - - - - hello' );
is( $parsed->{format}, 'ietf_syslog', 'ietf_syslog reports format' );

# garbage
is( App::Baphomet::Parser::parse( 'syslog', 'this is not a syslog line' ), undef, 'garbage returns undef' );
is( App::Baphomet::Parser::parse( 'syslog', undef ),                       undef, 'undef returns undef' );

ok( App::Baphomet::Parser::is_known('syslog'), 'syslog is a known parser' );

done_testing;
