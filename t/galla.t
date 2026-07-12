#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog' );
make_path( $dir . '/run' );

open( my $fh, '>', $dir . '/rules/syslog/sshd.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
EOR
close($fh);

open( $fh, '>', $dir . '/rules/syslog/other.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - otherd
message_regexp:
  - 'worse thing involving %%%%ADDR%%%%'
  - 'bad thing from %%%%ADDR%%%%'
ban_var:
  - ADDR
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 otherd[1]: worse thing involving 1.2.3.4"
      found: 1
      data:
        ADDR: "1.2.3.4"
EOR
close($fh);

open( $fh, '>', $dir . '/log' ) || die($!);
print $fh '';
close($fh);

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
max_retrys = 3
find_time = 600

[kur.sshd]
ban_time = 300

[kur.sshd.authlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"

[kur.sshd.otherlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"
max_retrys = 7

[kur.sshd.multilog]
log = "$dir/log"
parser = "bsd_syslog"
rule = [ "syslog/sshd", "syslog/other" ]
max_retrys = 2
EOC
close($fh);

#
# new
#

my $galla = App::Baphomet::Galla->new( 'config' => $dir . '/config.toml', 'name' => 'sshd' );
ok( defined($galla), 'new worked' );
is( $galla->socket_path, $dir . '/run/galla/sshd.sock', 'socket_path' );
is( $galla->pid_path,    $dir . '/run/galla/sshd.pid',  'pid_path' );
ok( -d $dir . '/run/galla', 'run galla dir created' );

# settings layering... global max_retrys, kur ban_time, watcher max_retrys
is( $galla->{watchers}{authlog}{settings}{max_retrys},  3,   'watcher inherits global max_retrys' );
is( $galla->{watchers}{authlog}{settings}{ban_time},    300, 'watcher inherits kur ban_time' );
is( $galla->{watchers}{authlog}{settings}{find_time},   600, 'watcher inherits global find_time' );
is( $galla->{watchers}{otherlog}{settings}{max_retrys}, 7,   'watcher override of max_retrys' );

ok( !eval { App::Baphomet::Galla->new( 'config' => $dir . '/config.toml', 'name' => 'nope' ); 1 },
	'new dies on a unknown kur' );

#
# line handling, with _send_ban swapped out for a recorder
#

my @sent;
my $send_error;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub {
		my ( $self, $ip, $ban_time ) = @_;
		if ( defined($send_error) ) {
			die($send_error);
		}
		push( @sent, { 'ip' => $ip, 'ban_time' => $ban_time } );
		return;
	};
}

sub feed {
	my ($message) = @_;
	$galla->_handle_line( 'authlog', 'Jul 12 08:15:50 vixen42 sshd[1]: ' . $message );
	return;
}

feed('bad thing from 1.2.3.4');
feed('bad thing from 1.2.3.4');
is( scalar(@sent),                            0, 'no ban below max_retrys' );
is( scalar( @{ $galla->{counters}{'1.2.3.4'} } ), 2, 'counter counting' );

feed('bad thing from 1.2.3.4');
is( scalar(@sent),          1,         'ban at max_retrys' );
is( $sent[0]{ip},           '1.2.3.4', 'banned the right IP' );
is( $sent[0]{ban_time},     300,       'ban_time forwarded' );
ok( !defined( $galla->{counters}{'1.2.3.4'} ), 'counter reset after the ban' );
is( $galla->{stats}{bans},    1, 'bans stat' );
is( $galla->{stats}{matched}, 3, 'matched stat' );
is( $galla->{stats}{lines},   3, 'lines stat' );

# other IPs counted separately
feed('bad thing from 5.6.7.8');
is( scalar(@sent), 1, 'other IP not banned yet' );
is( scalar( @{ $galla->{counters}{'5.6.7.8'} } ), 1, 'other IP counted separately' );

# non-matching and unparsable lines
feed('nothing of note');
is( $galla->{stats}{matched}, 4, 'non-matching line not matched' );
$galla->_handle_line( 'authlog', 'complete garbage' );
is( $galla->{stats}{unparsed}, 1, 'unparsable line counted' );
is( scalar(@sent),             1, 'neither banned anything' );

# find_time expiry... age the existing hits out and hit again
$galla->{counters}{'5.6.7.8'} = [ time - 700, time - 650 ];
feed('bad thing from 5.6.7.8');
is( scalar( @{ $galla->{counters}{'5.6.7.8'} } ), 1, 'aged out hits no longer count' );
is( scalar(@sent), 1, 'no ban after aging out' );

#
# rule lists... first match wins, per rule daemon gates and ban_var
#

is_deeply( $galla->{watchers}{multilog}{rules}, [ 'syslog/sshd', 'syslog/other' ], 'rule list loaded in order' );

# a otherd line passes through sshd's daemon gate untouched and matches the second rule
$galla->_handle_line( 'multilog', 'Jul 12 08:15:50 vixen42 otherd[9]: worse thing involving 7.7.7.7' );
$galla->_handle_line( 'multilog', 'Jul 12 08:15:50 vixen42 otherd[9]: worse thing involving 7.7.7.7' );
is( $sent[-1]{ip}, '7.7.7.7', 'second rule in the list matched and banned via its own ban_var' );

# a line matching both rules of the sshd rule counts once... matched went up by
# exactly 2 for the 2 lines above
my $matched_before = $galla->{stats}{matched};
$galla->_handle_line( 'multilog', 'Jul 12 08:15:50 vixen42 sshd[9]: bad thing from 8.8.8.8' );
is( $galla->{stats}{matched}, $matched_before + 1, 'a line is counted once across the rule list' );

#
# ban failure and the retry sweep
#

my $sent_before = scalar(@sent);
$send_error = "no answer from below\n";
$galla->{counters}{'9.9.9.9'} = [ time, time ];
feed('bad thing from 9.9.9.9');
is( scalar(@sent),                     $sent_before, 'failed ban not recorded as sent' );
is( $galla->{stats}{ban_errors},       1,            'ban_errors stat' );
is( $galla->{pending_bans}{'9.9.9.9'}, 300,          'failed ban pending retry' );

$send_error = undef;
$galla->_sweep;
is( scalar(@sent), $sent_before + 1, 'sweep retried the pending ban' );
is( $sent[-1]{ip}, '9.9.9.9',        'retried the right IP' );
ok( !defined( $galla->{pending_bans}{'9.9.9.9'} ), 'pending ban cleared' );

#
# status
#

my $status = $galla->_cmd_status;
is( $status->{name}, 'sshd', 'status name' );
is( $status->{stats}{bans}, scalar(@sent), 'status stats' );
is( ref( $status->{watchers}{authlog} ), 'HASH', 'status watchers' );

done_testing;
