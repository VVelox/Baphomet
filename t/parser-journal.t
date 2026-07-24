#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Parser ();

my $line
	= '{"__CURSOR":"s=abc;i=1;b=2;m=3;t=4;x=5","__REALTIME_TIMESTAMP":"1783948550123456","_HOSTNAME":"vixen42","SYSLOG_IDENTIFIER":"sshd-session","_COMM":"sshd-session","_PID":"66891","PRIORITY":"6","SYSLOG_FACILITY":"4","MESSAGE":"Invalid user moth3r from 216.137.179.214 port 34640"}';

my $parsed = App::Baphomet::Parser::parse( 'journal', $line );
ok( defined($parsed), 'journal line parsed' ) || BAIL_OUT('the most basic line did not parse');
is( $parsed->{format},   'journal',            'format' );
is( $parsed->{daemon},   'sshd-session',       'daemon from SYSLOG_IDENTIFIER' );
is( $parsed->{pid},      '66891',              'pid from _PID' );
is( $parsed->{hostname}, 'vixen42',            'hostname' );
is( $parsed->{time},     '1783948550123456',   'time from __REALTIME_TIMESTAMP' );
is( $parsed->{severity}, 6,                    'severity from PRIORITY' );
is( $parsed->{level},    'info',               'level from PRIORITY' );
is( $parsed->{facility}, '4',                  'facility from SYSLOG_FACILITY' );
is( $parsed->{message},  'Invalid user moth3r from 216.137.179.214 port 34640', 'message' );

# _COMM fallback when there is no SYSLOG_IDENTIFIER
$parsed = App::Baphomet::Parser::parse( 'journal', '{"_COMM":"cron","MESSAGE":"foo"}' );
is( $parsed->{daemon}, 'cron', 'daemon falls back to _COMM' );

# a MESSAGE as a byte array (non-UTF-8) is turned back into a string
$parsed = App::Baphomet::Parser::parse( 'journal', '{"SYSLOG_IDENTIFIER":"x","MESSAGE":[104,105]}' );
is( $parsed->{message}, 'hi', 'byte-array MESSAGE reassembled' );

# the shipped sshd rule matches a journal line unchanged
use App::Baphomet::Rules ();
SKIP: {
	skip( 'no rules dir', 2 ) if !-d 'share/rules';
	my $rules     = App::Baphomet::Rules->new( rules_dir => 'share/rules', shipped => 0 );
	my $sshd      = $rules->load('syslog/sshd');
	my $re_parsed = App::Baphomet::Parser::parse( 'journal', $line );
	my $found     = $sshd->check($re_parsed);
	ok( defined($found), 'syslog/sshd matches a journal line' );
	is( $found->{data}{SRC}, '216.137.179.214', 'and captures the offender' );
}

# no MESSAGE means not usable
is( App::Baphomet::Parser::parse( 'journal', '{"SYSLOG_IDENTIFIER":"sshd"}' ), undef, 'no MESSAGE returns undef' );

# a present but empty MESSAGE is still a parsed record, like the text grammars
{
	my $empty = App::Baphomet::Parser::parse( 'journal', '{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":""}' );
	ok( defined($empty), 'empty MESSAGE still parses' );
	is( $empty->{message}, '', 'and carries a empty message' );
}

# garbage
is( App::Baphomet::Parser::parse( 'journal', 'Jul 12 08:15:50 vixen42 sshd[1]: foo' ), undef, 'syslog line undef' );
is( App::Baphomet::Parser::parse( 'journal', '{"truncated":' ), undef, 'truncated JSON undef' );
is( App::Baphomet::Parser::parse( 'journal', undef ),           undef, 'undef undef' );

ok( App::Baphomet::Parser::is_known('journal'), 'journal is a known parser' );

done_testing;
