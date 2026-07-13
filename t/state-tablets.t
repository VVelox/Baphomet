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
make_path( $dir . '/rules/syslog', $dir . '/run', $dir . '/cache' );

open( my $fh, '>', $dir . '/rules/syslog/sshd.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
  - regexp: '^\[conn(?<KEY>\d+)\] auth failed'
    key: KEY
    defer: 600
capture_regexp:
  - regexp: '^\[conn(?<KEY>\d+)\] end connection %%%%SRC%%%%:\d+'
    key: KEY
    ttl: 600
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

open( $fh, '>', $dir . '/thelog' ) || die($!);
print $fh "existing line one\nexisting line two\n";
close($fh);

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
max_retrys = 5
find_time = 600

[kur.sshd]
ban_time = 300

[kur.sshd.authlog]
log = "$dir/thelog"
parser = "bsd_syslog"
rule = "syslog/sshd"
EOC
close($fh);

#
# populate state on a first galla and checkpoint
#

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );

# counters... a couple of hits, below threshold
$galla->_register_hit( 'authlog', '9.9.9.9' );
$galla->_register_hit( 'authlog', '9.9.9.9' );
$galla->_register_hit( 'authlog', '8.8.8.8' );

# a pending ban
$galla->{pending_bans}{'7.7.7.7'} = 300;

# a deferred correlation... offense parked awaiting its end connection
my $rule = $galla->{watchers}{authlog}{rule_objs}[0];
$rule->check( App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 vixen42 sshd[1]: [conn42] auth failed' ),
	'authlog' );

# a log position... pretend we followed to a byte offset
$galla->{positions}{ $dir . '/thelog' } = { inode => ( stat( $dir . '/thelog' ) )[1], offset => 18 };

# some stats, galla-wide and broken down, to survive the respawn
$galla->_tick( 'lines',   'authlog' );
$galla->_tick( 'lines',   'authlog' );
$galla->_tick( 'matched', 'authlog', 'syslog/sshd' );

$galla->checkpoint;

ok( -f $dir . '/cache/galla.sshd.counters.csv',  'counters tablet written' );
ok( -f $dir . '/cache/galla.sshd.pending.csv',   'pending tablet written' );
ok( -f $dir . '/cache/galla.sshd.positions.csv', 'positions tablet written' );
ok( -f $dir . '/cache/galla.sshd.context.jsonl', 'context tablet written' );
ok( -f $dir . '/cache/galla.sshd.stats.jsonl',   'stats tablet written' );

#
# a fresh galla restores it all
#

my $reborn = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );

is( scalar( @{ $reborn->{counters}{'9.9.9.9'} } ), 2, 'counter for 9.9.9.9 restored with both hits' );
is( scalar( @{ $reborn->{counters}{'8.8.8.8'} } ), 1, 'counter for 8.8.8.8 restored' );
is( $reborn->{pending_bans}{'7.7.7.7'}, 300, 'pending ban restored' );
is( $reborn->{positions}{ $dir . '/thelog' }{offset}, 18, 'log position restored' );
is( $reborn->{stats}{lines}, 2, 'stats totals restored' );
is( $reborn->{stats}{per_watcher}{authlog}{lines},      2, 'per watcher stats restored' );
is( $reborn->{stats}{per_rule}{'syslog/sshd'}{matched}, 1, 'per rule stats restored' );

# the accused command sees the restored counters
my $accused = $reborn->_cmd_accused;
is( $accused->{accused}{'9.9.9.9'}{hits}, 2, 'accused shows the counted hits' );
is( $accused->{accused}{'8.8.8.8'}{hits}, 1, 'accused shows the other defendant' );
ok( defined( $accused->{accused}{'9.9.9.9'}{first} ), 'accused carries the first hit epoch' );

# the restored deferred offense completes when its capture line arrives
my $reborn_rule = $reborn->{watchers}{authlog}{rule_objs}[0];
my $found = $reborn_rule->check(
	App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:51 vixen42 sshd[1]: [conn42] end connection 5.5.5.5:1234' ),
	'authlog'
);
ok( defined($found), 'restored deferred correlation completes' );
is( $found->{data}{SRC}, '5.5.5.5', 'and carries the address from the capture line' );

#
# a restored counter still bans at threshold
#

foreach ( 1 .. 3 ) {
	$reborn->{counters}{'9.9.9.9'} ||= [];
}
# three more hits pushes 9.9.9.9 from 2 to 5
my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}
$reborn->_register_hit( 'authlog', '9.9.9.9' );
$reborn->_register_hit( 'authlog', '9.9.9.9' );
$reborn->_register_hit( 'authlog', '9.9.9.9' );
ok( ( grep { $_ eq '9.9.9.9' } @sent ), 'a restored counter reaches the threshold and bans' );

#
# _seek_for behaviors
#

is( $reborn->_seek_for( $dir . '/thelog' ), 18, 'same inode, grown file... resume at offset' );

# a shrunk file resumes at the top
$reborn->{positions}{ $dir . '/thelog' }{offset} = 99999;
is( $reborn->_seek_for( $dir . '/thelog' ), 0, 'shrunk file... start from the top' );

# a rotated file (inode changed) starts at the top
$reborn->{positions}{ $dir . '/thelog' } = { inode => 999999999, offset => 5 };
is( $reborn->_seek_for( $dir . '/thelog' ), 0, 'changed inode... start from the top' );

# a file with no saved position gets undef
is( $reborn->_seek_for( $dir . '/neverseen' ), undef, 'unknown file... no seek' );

done_testing;
