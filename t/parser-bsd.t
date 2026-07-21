#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Parser ();

# the standard local log file form
my $parsed
	= App::Baphomet::Parser::parse( 'bsd_syslog',
	'Jul 12 08:15:50 vixen42 sshd-session[66891]: Invalid user moth3r from 216.137.179.214 port 34640' );
ok( defined($parsed), 'standard line parsed' ) || BAIL_OUT('the most basic line did not parse');
is( $parsed->{time},     'Jul 12 08:15:50', 'time' );
is( $parsed->{hostname}, 'vixen42',         'hostname' );
is( $parsed->{daemon},   'sshd-session',    'daemon' );
is( $parsed->{pid},      '66891',           'pid' );
is( $parsed->{message},  'Invalid user moth3r from 216.137.179.214 port 34640', 'message' );
is( $parsed->{facility}, undef, 'facility undef with out PRI' );
is( $parsed->{severity}, undef, 'severity undef with out PRI' );
is( $parsed->{level},    undef, 'level undef with out PRI' );

# with a PRI
$parsed = App::Baphomet::Parser::parse( 'bsd_syslog', '<38>Jul 12 08:15:50 vixen42 sshd[123]: foo' );
ok( defined($parsed), 'PRI line parsed' );
is( $parsed->{facility}, 4,      'facility from PRI' );
is( $parsed->{severity}, 6,      'severity from PRI' );
is( $parsed->{level},    'info', 'level from PRI' );
is( $parsed->{daemon},   'sshd', 'daemon with PRI' );

# FreeBSD verbose form
$parsed = App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 <auth.info> vixen42 sshd[123]: foo' );
ok( defined($parsed), 'verbose line parsed' );
is( $parsed->{facility}, 'auth', 'facility from verbose form' );
is( $parsed->{level},    'info', 'level from verbose form' );
is( $parsed->{severity}, 6,      'severity mapped from verbose level' );

# no hostname
$parsed = App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 sshd[123]: foo' );
ok( defined($parsed), 'hostnameless line parsed' );
is( $parsed->{hostname}, undef,  'hostname undef' );
is( $parsed->{daemon},   'sshd', 'daemon with out hostname' );
is( $parsed->{pid},      '123',  'pid with out hostname' );

# no pid
$parsed = App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 vixen42 sshd: foo' );
ok( defined($parsed), 'pidless line parsed' );
is( $parsed->{pid},    undef,  'pid undef' );
is( $parsed->{daemon}, 'sshd', 'daemon with out pid' );

# no hostname and no pid
$parsed = App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 sshd: Server listening on 0.0.0.0 port 22.' );
ok( defined($parsed), 'hostnameless pidless line parsed' );
is( $parsed->{hostname}, undef,  'hostname undef' );
is( $parsed->{daemon},   'sshd', 'daemon' );

# a message containing colons should not confuse the hostname/daemon split
$parsed = App::Baphomet::Parser::parse( 'bsd_syslog',
	'Jul 12 08:25:49 vixen42 sshd-session[36748]: Accepted publickey for kitsune from 127.0.0.1 port 21680 ssh2: ED25519 SHA256:abc' );
ok( defined($parsed), 'colonful message parsed' );
is( $parsed->{daemon}, 'sshd-session', 'daemon with colonful message' );
like( $parsed->{message}, qr/^Accepted publickey/, 'message with colonful message' );

# a relayed IPv6 hostname must not slide into the daemon slot
$parsed = App::Baphomet::Parser::parse( q(bsd_syslog),
	q(Jul 12 08:15:50 2001:db8::1 sshd[66891]: Invalid user moth3r from 216.137.179.214) );
ok( defined($parsed), q(ipv6 hostname line parsed) );
is( $parsed->{hostname}, q(2001:db8::1), q(ipv6 hostname captured) );
is( $parsed->{daemon},   q(sshd),        q(daemon beside a ipv6 hostname) );
like( $parsed->{message}, qr/^Invalid user/, q(message beside a ipv6 hostname) );

# the RFC 3339 form rsyslog chisels by default
$parsed = App::Baphomet::Parser::parse( q(bsd_syslog),
	q(2026-07-12T08:15:50.123456+00:00 vixen42 sshd[66891]: Invalid user moth3r from 216.137.179.214) );
ok( defined($parsed), q(rfc3339 line parsed) );
is( $parsed->{time},   q(2026-07-12T08:15:50.123456+00:00), q(rfc3339 timestamp captured) );
is( $parsed->{daemon}, q(sshd),                             q(daemon on a rfc3339 line) );

# a PRI past 191 is not syslog
is( App::Baphomet::Parser::parse( q(bsd_syslog), q(<999> Jul 12 08:15:50 vixen42 sshd[1]: foo) ),
	undef, q(out of range PRI returns undef) );

# garbage
is( App::Baphomet::Parser::parse( q(bsd_syslog), q(this is not a syslog line) ), undef, q(garbage returns undef) );
is( App::Baphomet::Parser::parse( 'bsd_syslog', undef ),                       undef, 'undef returns undef' );

# dispatch
ok( App::Baphomet::Parser::is_known('bsd_syslog'),   'bsd_syslog known' );
ok( !App::Baphomet::Parser::is_known('cuneiform'),   'cuneiform not known' );
ok( eval { App::Baphomet::Parser::parse( 'cuneiform', 'foo' ); 1 } ? 0 : 1, 'unknown parser dies' );

done_testing;
