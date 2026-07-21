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

use App::Baphomet::Galla  ();
use App::Baphomet::Config qw( check_kur_def watcher_join );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/raw' );
make_path( $dir . '/run' );

# the offense and the address land on different physical lines of one
# record... only the joiner gluing them lets the regexp span both
open( my $fh, '>', $dir . '/rules/raw/trace.yaml' ) || die($!);
print $fh <<'EOR';
---
message_regexp:
  - '(?s)^PANIC: auth exploded.*request from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "PANIC: auth exploded\n    at Foo.pm line 1\n    request from 192.0.2.80"
      found: 1
      data:
        SRC: "192.0.2.80"
  negative:
    - message: "PANIC: auth exploded"
      found: 0
EOR
close($fh);

open( $fh, '>', $dir . '/log' ) || die($!);
print $fh '';
close($fh);

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
max_score = 10
find_time = 600

[kur.app]
ban_time = 300

[kur.app.applog]
log = "$dir/log"
parser = "raw"
rule = "raw/trace"

[kur.app.applog.join]
continuation = '^\\s'
max_lines = 5
flush_after = 1
EOC
close($fh);

my $galla = App::Baphomet::Galla->new( 'config' => $dir . '/config.toml', 'name' => 'app' );
ok( defined($galla),   'new worked' );
ok( !$galla->{perror}, 'no perror' ) || diag( $galla->{errorString} );

my $join = $galla->{watchers}{applog}{join};
ok( defined($join), 'the joiner compiled onto the watcher' );
is( $join->{max_lines},   5, 'max_lines carried' );
is( $join->{flush_after}, 1, 'flush_after carried' );

#
# gluing... head plus continuations become one record on the next head
#

$galla->_handle_line( 'applog', 'PANIC: auth exploded',        'src1' );
$galla->_handle_line( 'applog', '    at Foo.pm line 1',        'src1' );
$galla->_handle_line( 'applog', '    request from 192.0.2.80', 'src1' );
ok( !defined( $galla->{counters}{'192.0.2.80'} ), 'the record is still gathering... nothing counted yet' );
is( scalar( @{ $galla->{join_buffers}{applog}{src1}{lines} } ), 3, 'three physical lines buffered' );

$galla->_handle_line( 'applog', 'PANIC: auth exploded', 'src1' );
is( scalar( @{ $galla->{counters}{'192.0.2.80'} } ),            1, 'the next head flushed the record and it counted' );
is( scalar( @{ $galla->{join_buffers}{applog}{src1}{lines} } ), 1, 'the new head is buffering' );
is( $galla->{stats}{joined},                                    1, 'one joined record ticked' );

# the second record has no address, so a forced flush counts nothing
$galla->_flush_stale_join_buffers(1);
ok( !defined( $galla->{join_buffers}{applog}{src1} ), 'forced flush emptied the buffer' );
is( scalar( @{ $galla->{counters}{'192.0.2.80'} } ), 1, 'the addressless record counted nothing' );

#
# max_lines... a record at the cap flushes with out waiting for a head
#

$galla->_handle_line( 'applog', 'PANIC: auth exploded',        'src1' );
$galla->_handle_line( 'applog', '    at Foo.pm line 1',        'src1' );
$galla->_handle_line( 'applog', '    at Bar.pm line 2',        'src1' );
$galla->_handle_line( 'applog', '    at Baz.pm line 3',        'src1' );
$galla->_handle_line( 'applog', '    request from 192.0.2.81', 'src1' );
is( scalar( @{ $galla->{counters}{'192.0.2.81'} } ), 1, 'the record flushed at max_lines and counted' );
ok( !defined( $galla->{join_buffers}{applog}{src1} ), 'nothing left buffered after the cap flush' );

#
# flush_after... a quiet buffer past its age is flushed by the tick, a
# fresh one is left gathering
#

$galla->_handle_line( 'applog', 'PANIC: auth exploded',        'src1' );
$galla->_handle_line( 'applog', '    request from 192.0.2.82', 'src1' );
$galla->_flush_stale_join_buffers;
ok( defined( $galla->{join_buffers}{applog}{src1} ), 'a fresh buffer is left gathering' );
$galla->{join_buffers}{applog}{src1}{last_seen} = time - 2;
$galla->_flush_stale_join_buffers;
ok( !defined( $galla->{join_buffers}{applog}{src1} ), 'a quiet buffer past flush_after flushed' );
is( scalar( @{ $galla->{counters}{'192.0.2.82'} } ), 1, 'and its record counted' );

#
# per source... continuation only means adjacency with in one file
#

$galla->_handle_line( 'applog', 'PANIC: auth exploded',        'src1' );
$galla->_handle_line( 'applog', '    request from 192.0.2.83', 'src2' );
is( scalar( @{ $galla->{join_buffers}{applog}{src1}{lines} } ), 1, 'the head of one source gathered nothing foreign' );
is( scalar( @{ $galla->{join_buffers}{applog}{src2}{lines} } ),
	1, 'a continuation with no head of its own source heads its own record' );
$galla->_flush_stale_join_buffers(1);

#
# config validation
#

my $base_watcher = { 'log' => $dir . '/log', 'parser' => 'raw', 'rule' => 'raw/trace' };

ok( defined( watcher_join( { %{$base_watcher}, 'join' => { 'continuation' => '^\s' } } ) ),
	'a minimal join validates' );
my $defaults = watcher_join( { 'join' => { 'continuation' => '^\s' } } );
is( $defaults->{max_lines},   50, 'max_lines defaults' );
is( $defaults->{flush_after}, 2,  'flush_after defaults' );

ok( !eval { watcher_join( { 'join' => {} } );                        1 }, 'a join with out a continuation refuses' );
ok( !eval { watcher_join( { 'join' => { 'continuation' => '(' } } ); 1 },
	'a continuation that does not compile refuses' );
ok( !eval { watcher_join( { 'join' => { 'continuation' => '^\s', 'derp' => 1 } } ); 1 }, 'a unknown join key refuses' );
ok( !eval { watcher_join( { 'join' => { 'continuation' => '^\s', 'max_lines' => 0 } } ); 1 },
	'a zero max_lines refuses' );

ok(
	!eval {
		check_kur_def( 'app',
			{ 'j' => { 'journal' => 1, 'rule' => 'syslog/sshd', 'join' => { 'continuation' => '^\s' } } } );
		1;
	},
	'a journal watcher with a join refuses'
);

done_testing;
