#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();

my $sshd_line
	= '{"PROGRAM":"sshd-session","PRIORITY":"info","PID":"66891","MESSAGE":"Invalid user moth3r from 216.137.179.214 port 34640","HOST":"vixen42","FACILITY":"auth","DATE":"Jul 12 08:15:50"}';

my $parsed = App::Baphomet::Parser::parse( 'json_syslog', $sshd_line );
ok( defined($parsed), 'standard line parsed' ) || BAIL_OUT('the most basic line did not parse');
is( $parsed->{format},   'json_syslog',     'format' );
is( $parsed->{daemon},   'sshd-session',    'daemon from PROGRAM' );
is( $parsed->{pid},      '66891',           'pid from PID' );
is( $parsed->{hostname}, 'vixen42',         'hostname from HOST' );
is( $parsed->{time},     'Jul 12 08:15:50', 'time from DATE' );
is( $parsed->{level},    'info',            'level from PRIORITY' );
is( $parsed->{severity}, 6,                 'severity mapped from the PRIORITY name' );
is( $parsed->{facility}, 'auth',            'facility from FACILITY' );
is( $parsed->{message}, 'Invalid user moth3r from 216.137.179.214 port 34640', 'message from MESSAGE' );

# lowercase keys, ISODATE preferred, LEVEL_NUM authoritative for severity
$parsed = App::Baphomet::Parser::parse( 'json_syslog',
	'{"program":"sshd","message":"foo","isodate":"2026-07-12T08:15:50-05:00","date":"Jul 12 08:15:50","level_num":"3","host":"vixen42"}'
);
ok( defined($parsed), 'lowercase key line parsed' );
is( $parsed->{daemon},   'sshd',                      'lowercase daemon' );
is( $parsed->{time},     '2026-07-12T08:15:50-05:00', 'ISODATE preferred over DATE' );
is( $parsed->{severity}, 3,                           'severity from LEVEL_NUM' );
is( $parsed->{level},    'err',                       'level mapped from LEVEL_NUM' );

# PRIORITY wins for the level name, LEVEL_NUM for the number
$parsed = App::Baphomet::Parser::parse( 'json_syslog',
	'{"PROGRAM":"sshd","MESSAGE":"foo","PRIORITY":"error","LEVEL_NUM":"3"}' );
is( $parsed->{level},    'error', 'PRIORITY name kept as the level' );
is( $parsed->{severity}, 3,       'LEVEL_NUM kept as the severity' );

# FACILITY_NUM fallback, empty strings count as absent
$parsed = App::Baphomet::Parser::parse( 'json_syslog',
	'{"PROGRAM":"","MESSAGE":"foo","FACILITY_NUM":"4","PID":""}' );
ok( defined($parsed), 'empty string line parsed' );
is( $parsed->{facility}, '4',   'facility from FACILITY_NUM' );
is( $parsed->{daemon},   undef, 'empty PROGRAM counts as absent' );
is( $parsed->{pid},      undef, 'empty PID counts as absent' );

# unknown keys ignored, nested values skipped
$parsed = App::Baphomet::Parser::parse( 'json_syslog',
	'{"PROGRAM":"sshd","MESSAGE":"foo",".SDATA.meta.sequenceId":"1","custom":{"nested":"x"}}' );
ok( defined($parsed), 'line with extras parsed' );
is( $parsed->{message}, 'foo', 'extras ignored' );

# no MESSAGE means not syslog shaped
is( App::Baphomet::Parser::parse( 'json_syslog', '{"event":"login","user":"kitsune"}' ),
	undef, 'JSON with out a MESSAGE returns undef' );

# a present but empty MESSAGE is still a parsed line, like the text grammars
$parsed = App::Baphomet::Parser::parse( 'json_syslog', '{"PROGRAM":"sshd","MESSAGE":""}' );
ok( defined($parsed), 'empty MESSAGE still parses' );
is( $parsed->{message}, '', 'and carries a empty message' );

# garbage
is( App::Baphomet::Parser::parse( 'json_syslog', '{"PROGRAM":"sshd","MESSAGE":' ), undef,
	'truncated JSON returns undef' );
is( App::Baphomet::Parser::parse( 'json_syslog', 'Jul 12 08:15:50 vixen42 sshd[1]: foo' ),
	undef, 'BSD line returns undef' );
is( App::Baphomet::Parser::parse( 'json_syslog', '[1,2,3]' ), undef, 'non-object JSON returns undef' );
is( App::Baphomet::Parser::parse( 'json_syslog', undef ),     undef, 'undef returns undef' );

ok( App::Baphomet::Parser::is_known('json_syslog'), 'json_syslog is a known parser' );

# the combined syslog parser sniffs the leading brace
$parsed = App::Baphomet::Parser::parse( 'syslog', $sshd_line );
ok( defined($parsed), 'combined parser handles a JSON line' );
is( $parsed->{format}, 'json_syslog',  'combined parser format' );
is( $parsed->{daemon}, 'sshd-session', 'combined parser daemon' );

# and the shipped sshd rule matches a JSON encoded corpus line unchanged
my $rules = App::Baphomet::Rules->new( rules_dir => 'rules' );
SKIP: {
	skip( 'no rules dir found... not running from the dist root?', 2 ) if !-d 'rules';

	my $sshd  = $rules->load('syslog/sshd');
	my $found = $sshd->check($parsed);
	ok( defined($found), 'syslog/sshd matches the JSON encoded line' );
	is( $found->{data}{SRC}, '216.137.179.214', 'and captures the offender' );
}

done_testing;
