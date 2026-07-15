#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );

use App::Baphomet::App::Command::stop;

my $wait    = \&App::Baphomet::App::Command::stop::_wait_for_exit;
my $timeout = \&App::Baphomet::App::Command::stop::_config_timeout;

#
# _wait_for_exit... returns true when the PID is gone, false on timeout
#

# a reaped child is gone... returns at once
my $pid = fork();
if ( !defined($pid) ) {
	plan skip_all => 'fork failed';
}
if ( $pid == 0 ) {
	exit(0);
}
waitpid( $pid, 0 );
my $t0 = time;
ok( $wait->( $pid, 5 ),     'a dead PID is seen as gone' );
ok( ( time - $t0 ) < 2,     '...without burning the whole timeout' );

# a live PID (self) times out and returns false, having waited about the window
$t0 = time;
ok( !$wait->( $$, 1 ), 'a live PID times out to false' );
ok( ( time - $t0 ) >= 1, '...after waiting the timeout' );

# a zero timeout does not wait... false for a live PID, true for a dead one
ok( !$wait->( $$, 0 ),  'a zero timeout does not wait on a live PID' );
ok( $wait->( $pid, 0 ), 'a zero timeout still reports a already-dead PID gone' );

#
# _config_timeout... the config's timeout, or 30 when it can not be read
#

is( $timeout->('/nonexistent/baphomet.toml'), 30, 'a unreadable config falls back to 30' );

my $dir = tempdir( CLEANUP => 1 );
open( my $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
timeout = 12

[kur.x.w]
log = "$dir/l"
parser = "syslog"
rule = "syslog/sshd"
EOC
close($fh);
is( $timeout->( $dir . '/config.toml' ), 12, 'a readable config yields its timeout' );

done_testing;
