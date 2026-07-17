#!perl

# Unit tests for the per-tablet restore helpers that _load_state was broken
# into. Each helper is driven directly with a stubbed _read_tablet feeding it
# canned lines, so a single tablet's parsing and pruning is exercised in
# isolation... the full round trip through checkpoint/_load_state lives in
# t/state-tablets.t.

use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp    qw( tempdir );
use File::Path    qw( make_path );
use JSON::MaybeXS qw( encode_json );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla  ();
use App::Baphomet::Parser ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run', $dir . '/cache' );

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

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
max_score = 5
find_time = 600

[kur.sshd]
ban_time = 300

[kur.sshd.authlog]
log = "$dir/thelog"
parser = "bsd_syslog"
rule = "syslog/sshd"
EOC
close($fh);

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );

# every helper reads through _read_tablet($kind)... hand it whatever this test
# wants for the kind under exercise, an empty list for anything else
my %canned;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_read_tablet = sub {
		my ( undef, $kind ) = @_;
		return @{ $canned{$kind} || [] };
	};
}

# a fixed clock so seeded epochs and the value handed to each helper agree
my $now = time;

#
# _load_counters... 4-field and legacy 3-field rows, weight defaulting, the
# stale drop and the malformed skip
#
subtest '_load_counters' => sub {
	$galla->{counters}      = {};
	$galla->{rule_counters} = {};
	%canned                 = (
		counters => [
			'ip,hit,weight,rule',                           # header, skipped
			'9.9.9.9,' . ( $now - 10 ) . ',1,',             # shared bucket, later hit first in the file
			'9.9.9.9,' . ( $now - 30 ) . ',2,',             # shared bucket, weight 2, earlier hit
			'8.8.8.8,' . ( $now - 20 ) . ',syslog/sshd',    # legacy 3-field... rule bucket, weight 1
			'3.3.3.3,' . ( $now - 5 ) . ',bogus,',          # unparsable weight defaults to 1
			'4.4.4.4,' . ( $now - 90000 ) . ',1,',          # stale, pruned away
			'5.5.5.5,notanumber,1,',                        # non-numeric hit, skipped
			'',                                             # blank, skipped
		],
	);

	$galla->_load_counters($now);

	is( scalar( @{ $galla->{counters}{'9.9.9.9'} } ), 2,         'both shared-bucket hits kept' );
	is( $galla->{counters}{'9.9.9.9'}[0][0],          $now - 30, 'entries sorted ascending by epoch' );
	is( $galla->{counters}{'9.9.9.9'}[0][1],          2,         'weight column preserved' );
	is( $galla->{counters}{'3.3.3.3'}[0][1],          1,         'unparsable weight falls back to 1' );
	is( scalar( @{ $galla->{rule_counters}{'syslog/sshd'}{'8.8.8.8'} } ),
		1, 'legacy three-field row lands in its rule bucket' );
	is( $galla->{rule_counters}{'syslog/sshd'}{'8.8.8.8'}[0][1], 1, 'legacy row weighs 1' );
	ok( !exists( $galla->{counters}{'4.4.4.4'} ), 'stale counter pruned' );
	ok( !exists( $galla->{counters}{'5.5.5.5'} ), 'row with non-numeric hit skipped' );
}; ## end '_load_counters' => sub

#
# _prune_counter_buckets... sort, stale drop, and the empty rule bucket sweep,
# driven straight off pre-seeded buckets
#
subtest '_prune_counter_buckets' => sub {
	$galla->{counters} = {
		'keep' => [ [ $now - 50,    1 ], [ $now - 100, 1 ] ],    # recent, out of order
		'drop' => [ [ $now - 90000, 1 ] ],                       # nothing recent
	};
	$galla->{rule_counters} = {
		'r/a' => { 'ip1' => [ [ $now - 10,    1 ] ] },           # survives
		'r/b' => { 'ip2' => [ [ $now - 99999, 1 ] ] },           # its only ip is stale
	};

	$galla->_prune_counter_buckets($now);

	is( $galla->{counters}{'keep'}[0][0], $now - 100, 'surviving bucket sorted ascending' );
	ok( !exists( $galla->{counters}{'drop'} ),           'bucket with nothing recent dropped' );
	ok( exists( $galla->{rule_counters}{'r/a'}{'ip1'} ), 'live per-rule ip kept' );
	ok( !exists( $galla->{rule_counters}{'r/b'} ),       'per-rule bucket left empty is removed' );
}; ## end '_prune_counter_buckets' => sub

#
# _load_distinct... valid restore, stale skip, missing field, bad json
#
subtest '_load_distinct' => sub {
	$galla->{distinct_counters} = {};
	%canned = (
		distinct => [
			encode_json( { rule => 'r', ip => '1.1.1.1', value => 'u1', epoch => $now - 10 } ),
			encode_json( { rule => 'r', ip => '1.1.1.1', value => 'u2', epoch => $now - 90000 } ),    # stale
			encode_json( { rule => 'r', ip => '1.1.1.1', epoch => $now } ),                           # no value
			'not json at all',
			'',
		],
	);

	$galla->_load_distinct($now);

	is( $galla->{distinct_counters}{'r'}{'1.1.1.1'}{'u1'}, $now - 10, 'fresh distinct value restored' );
	ok( !exists( $galla->{distinct_counters}{'r'}{'1.1.1.1'}{'u2'} ), 'stale distinct value skipped' );
}; ## end '_load_distinct' => sub

#
# _load_pending_bans... an ip with a ban_time, one without, header and empty
# ip skipped
#
subtest '_load_pending_bans' => sub {
	$galla->{pending_bans} = {};
	%canned = (
		pending => [
			'ip,ban_time',    # header, skipped
			'7.7.7.7,300',    # owed a specific duration
			'6.6.6.6',        # owed, no duration recorded
			',999',           # empty ip, skipped
			'',
		],
	);

	$galla->_load_pending_bans;

	is( $galla->{pending_bans}{'7.7.7.7'}, 300, 'pending ban with duration restored' );
	ok( exists( $galla->{pending_bans}{'6.6.6.6'} ),   'pending ban without duration recorded' );
	ok( !defined( $galla->{pending_bans}{'6.6.6.6'} ), '...as an undef duration' );
	ok( !exists( $galla->{pending_bans}{''} ),         'empty ip skipped' );
}; ## end '_load_pending_bans' => sub

#
# _load_positions... trailing digit columns parsed, malformed line skipped
#
subtest '_load_positions' => sub {
	$galla->{positions} = {};
	%canned = (
		positions => [
			'file,inode,offset',        # header, skipped
			'/var/log/a,111,222',       # inode 111, offset 222
			'/var/log/b,notdigit,5',    # inode column not digits, skipped
			'garbage',                  # no trailing columns, skipped
			'',
		],
	);

	$galla->_load_positions;

	is( $galla->{positions}{'/var/log/a'}{inode},  111, 'inode column parsed' );
	is( $galla->{positions}{'/var/log/a'}{offset}, 222, 'offset column parsed' );
	ok( !exists( $galla->{positions}{'/var/log/b'} ), 'row with non-numeric inode skipped' );
}; ## end '_load_positions' => sub

#
# _load_cursors... restored only for a watcher that still exists and is still
# a journal one
#
subtest '_load_cursors' => sub {
	$galla->{journal_cursors} = {};
	$galla->{watchers}{'jw'}  = { is_journal => 1 };
	$galla->{watchers}{'fw'}  = { is_journal => 0 };
	%canned                   = (
		cursors => [
			'watcher,cursor',    # header, skipped
			'jw,cursorAAA',      # journal watcher, restored
			'fw,cursorBBB',      # file watcher, skipped
			'gone,cursorCCC',    # unknown watcher, skipped
			'',
		],
	);

	$galla->_load_cursors;

	is( $galla->{journal_cursors}{'jw'}, 'cursorAAA', 'journal watcher cursor restored' );
	ok( !exists( $galla->{journal_cursors}{'fw'} ),   'non-journal watcher cursor skipped' );
	ok( !exists( $galla->{journal_cursors}{'gone'} ), 'cursor for a departed watcher skipped' );
}; ## end '_load_cursors' => sub

#
# _load_stats... numeric totals and hash breakdowns taken, wrong shapes and
# unknown keys ignored
#
subtest '_load_stats' => sub {
	$galla->{stats} = { lines => 0, matched => 0, per_watcher => {}, per_rule => {} };
	%canned = (
		stats => [
			encode_json(
				{
					lines       => 5,                          # numeric total, taken
					matched     => 'notnum',                   # bad scalar, ignored
					per_watcher => { w => { lines => 3 } },    # hash breakdown, taken
					per_rule    => 'notahash',                 # wrong shape, ignored
					unknownkey  => 7,                          # not a known stat, ignored
				}
			),
		],
	);

	$galla->_load_stats;

	is( $galla->{stats}{lines},                 5, 'numeric total restored' );
	is( $galla->{stats}{matched},               0, 'non-numeric total left at default' );
	is( $galla->{stats}{per_watcher}{w}{lines}, 3, 'hash breakdown restored' );
	is_deeply( $galla->{stats}{per_rule}, {}, 'wrong-shape breakdown left at default' );
	ok( !exists( $galla->{stats}{unknownkey} ), 'unknown key not carried over' );
}; ## end '_load_stats' => sub

#
# _load_marks... future marks kept with their optional set/value, expired ones
# dropped
#
subtest '_load_marks' => sub {
	$galla->{marks} = {};
	%canned = (
		marks => [
			encode_json( { name => 'bad', key => 'k1', expires => $now + 100, set => $now - 5, value => 'v' } ),
			encode_json( { name => 'bad', key => 'k2', expires => $now - 1 } ),     # expired
			encode_json( { name => 'bad', key => 'k3', expires => $now + 50 } ),    # no set/value
			'not json',
			'',
		],
	);

	$galla->_load_marks($now);

	is( $galla->{marks}{'bad'}{'k1'}{expires}, $now + 100, 'live mark restored' );
	is( $galla->{marks}{'bad'}{'k1'}{set},     $now - 5,   'optional set carried' );
	is( $galla->{marks}{'bad'}{'k1'}{value},   'v',        'optional value carried' );
	ok( !exists( $galla->{marks}{'bad'}{'k2'} ),      'expired mark dropped' );
	ok( exists( $galla->{marks}{'bad'}{'k3'} ),       'live mark without extras restored' );
	ok( !exists( $galla->{marks}{'bad'}{'k3'}{set} ), '...and carries no set' );
}; ## end '_load_marks' => sub

#
# _load_mark_stream... the cursor is the first non-empty line
#
subtest '_load_mark_stream' => sub {
	$galla->{mark_stream_id} = undef;
	my $synced = 0;
	no warnings 'redefine';
	local *App::Baphomet::Galla::_sync_marks = sub { $synced++; return; };
	%canned = ( mark_stream => [ '', '1234-5', '9999-0' ] );

	$galla->_load_mark_stream;

	is( $galla->{mark_stream_id}, '1234-5', 'stream cursor is the first non-empty line' );
	is( $synced,                  1,        'a first drain follows the cursor restore' );
}; ## end '_load_mark_stream' => sub

#
# _load_context... a line naming a loadable rule hands its state back to the
# rule, a line with no rule is skipped
#
subtest '_load_context' => sub {
	my @restored;
	no warnings 'redefine';
	local *App::Baphomet::Rules::Base::restore_state = sub {
		my ( undef, $state, $ts ) = @_;
		push( @restored, { state => $state, ts => $ts } );
		return;
	};
	%canned = (
		context => [
			encode_json( { rule  => 'syslog/sshd', state => { foo => 1 } } ),
			encode_json( { state => { bar => 2 } } ),    # no rule named, skipped
			'not json',
			'',
		],
	);

	$galla->_load_context($now);

	is( scalar(@restored), 1, 'only the line naming a rule restores state' );
	is_deeply( $restored[0]{state}, { foo => 1 }, 'the stored state is handed back verbatim' );
	is( $restored[0]{ts}, $now, 'restore is told the current time' );
}; ## end '_load_context' => sub

done_testing;
