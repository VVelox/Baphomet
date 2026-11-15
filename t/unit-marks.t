#!perl
# direct unit tests for App::Baphomet::Marks, the mark store's pure core, and
# the three gates that read it, marked, not_marked, and sequence... no galla,
# no store on an object, just the functions and gates over a hashref. pins the
# conservative value-compare rules and the store bound that the galla and
# run_tests both lean on but neither exercises exhaustively
use 5.006;
use strict;
use warnings;
use Test::More;
use List::Util qw( all );

use App::Baphomet::Marks qw( mark_key mark_set apply_marks bound_expiring_store );
use App::Baphomet::Gate  qw( gate_class bind_rule_gates );

my $now = 1_000_000_000;

# whether the mark gates the passed entries make all hold over a store, asked
# as the galla asks them... a hash of gate type to the list of what each gate
# of the type is told, bound and sorted by pass, then the result pass asked
# with a undef $ip and the offender pass with one
sub gates_hold {
	my ( $store, $entries_of, $data, $ip, $now_is ) = @_;

	my @gates;
	foreach my $type ( sort( keys( %{$entries_of} ) ) ) {
		foreach my $args ( @{ $entries_of->{$type} } ) {
			push( @gates, gate_class( $type, 'the test' )->new( 'type' => $type, 'args' => $args, 'where' => 'the gate' ) );
		}
	}
	my $bound = bind_rule_gates( \@gates, { 'marks' => sub { return $store; } }, 'the rule "x"' );

	return ( all { $_->holds( $data, $ip, $now_is ) } @{ $bound->{ defined($ip) ? 'offender' : 'result' } } ) ? 1 : 0;
}

#
# mark_key... the compound join, the single var, the var-less offender
#

is( mark_key( { 'var' => 'user' }, { 'user' => 'bob' }, '1.2.3.4' ), 'bob', 'a var keys by that capture' );
is( mark_key( {}, {}, '1.2.3.4' ), '1.2.3.4', 'a var-less entry keys by the offender' );
is( mark_key( { 'vars' => [ 'ip', 'user' ] }, { 'ip' => '1.2.3.4', 'user' => 'bob' }, undef ),
	"1.2.3.4\x1fbob", 'vars joins the captures on the unit separator' );
is( mark_key( { 'vars' => [ 'ip', 'user' ] }, { 'ip' => '1.2.3.4' }, undef ),
	undef, 'a vars key with any capture missing is undef, never a partial join' );

#
# the marked gate... the two passes, expiry, any-of, value compares
#

my %store = ( 'known' => { '1.2.3.4' => { 'expires' => $now + 100 } } );

ok( gates_hold( \%store, { 'marked' => [ { 'name' => 'known', 'var' => 'ip' } ] }, { 'ip' => '1.2.3.4' },
	undef, $now ), 'a marked gate holds when the branded key is live' );
ok( !gates_hold( \%store, { 'marked' => [ { 'name' => 'known', 'var' => 'ip' } ] }, { 'ip' => '5.6.7.8' },
	undef, $now ), 'and fails on a unbranded key' );
ok(
	gates_hold(
		\%store,
		{ 'marked' => [ { 'name' => 'known', 'var' => 'ip' } ] },
		{ 'ip' => '1.2.3.4' },
		'9.9.9.9', $now
	),
	'a gate naming a var is not of the offender pass, so there is nothing to veto there'
);

# expiry... a brand at or before now is dead
my %expired = ( 'known' => { '1.2.3.4' => { 'expires' => $now } } );
ok(
	!gates_hold(
		\%expired, { 'marked' => [ { 'name' => 'known', 'var' => 'ip' } ] },
		{ 'ip' => '1.2.3.4' }, undef, $now
	),
	'a brand whose expiry is at now is dead'
);

# names, the any-of... any listed live brand satisfies it
my %anyof = ( 'brand_b' => { '1.2.3.4' => { 'expires' => $now + 100 } } );
ok(
	gates_hold(
		\%anyof,
		{ 'marked' => [ { 'names' => [ 'brand_a', 'brand_b' ], 'var' => 'ip' } ] },
		{ 'ip' => '1.2.3.4' },
		undef, $now
	),
	'a names any-of holds when any listed brand is live'
);

# value_is / value_not against the stored value
my %valued = ( 'acct' => { 'bob' => { 'expires' => $now + 100, 'value' => '1.1.1.1' } } );
ok(
	gates_hold(
		\%valued,
		{ 'marked' => [ { 'name' => 'acct', 'var' => 'user', 'value_is' => 'ip' } ] },
		{ 'user' => 'bob', 'ip' => '1.1.1.1' },
		undef, $now
	),
	'value_is holds when the stored value equals the named capture'
);
ok(
	!gates_hold(
		\%valued,
		{ 'marked' => [ { 'name' => 'acct', 'var' => 'user', 'value_is' => 'ip' } ] },
		{ 'user' => 'bob', 'ip' => '2.2.2.2' },
		undef, $now
	),
	'and fails when it differs'
);
ok(
	!gates_hold(
		\%valued,
		{ 'marked' => [ { 'name' => 'acct', 'var' => 'user', 'value_is' => 'ip' } ] },
		{ 'user' => 'bob' },
		undef, $now
	),
	'a marked value compare with the capture missing fails closed'
);

# a names any-of where the live brand must ALSO clear the value compare...
# brand_a is live but its value mismatches, brand_b is live and matches
my %anyval = (
	'brand_a' => { 'bob' => { 'expires' => $now + 100, 'value' => 'wrong' } },
	'brand_b' => { 'bob' => { 'expires' => $now + 100, 'value' => 'right' } },
);
ok(
	gates_hold(
		\%anyval,
		{ 'marked' => [ { 'names' => [ 'brand_a', 'brand_b' ], 'var' => 'user', 'value_is' => 'want' } ] },
		{ 'user' => 'bob', 'want' => 'right' },
		undef, $now
	),
	'a any-of never rides a value it did not prove... the mismatching brand is skipped for the matching one'
);

#
# the not_marked gate... the inverse, and the value-compare spare
#

ok(
	gates_hold(
		\%store, { 'not_marked' => [ { 'name' => 'known', 'var' => 'ip' } ] },
		{ 'ip' => '5.6.7.8' }, undef, $now
	),
	'not_marked holds when the key carries no brand'
);
ok(
	!gates_hold(
		\%store, { 'not_marked' => [ { 'name' => 'known', 'var' => 'ip' } ] },
		{ 'ip' => '1.2.3.4' }, undef, $now
	),
	'and vetoes when it does'
);
ok(
	gates_hold(
		\%valued,
		{ 'not_marked' => [ { 'name' => 'acct', 'var' => 'user', 'value_is' => 'ip' } ] },
		{ 'user' => 'bob', 'ip' => '2.2.2.2' },
		undef, $now
	),
	'not_marked value_is spares a live brand storing a different value... not marked WITH this value'
);
ok(
	!gates_hold(
		\%valued,
		{ 'not_marked' => [ { 'name' => 'acct', 'var' => 'user', 'value_is' => 'ip' } ] },
		{ 'user' => 'bob', 'ip' => '1.1.1.1' },
		undef, $now
	),
	'and vetoes a live brand storing the same value'
);
ok(
	!gates_hold(
		\%valued,
		{ 'not_marked' => [ { 'name' => 'acct', 'var' => 'user', 'value_is' => 'ip' } ] },
		{ 'user' => 'bob' },
		undef, $now
	),
	'a not_marked value compare that can not be evaluated still vetoes'
);

#
# the sequence gate... ordered by first-seen set time
#

my %seq = (
	'stage1' => { 'k' => { 'expires' => $now + 100, 'set' => $now } },
	'stage2' => { 'k' => { 'expires' => $now + 100, 'set' => $now + 50 } },
);
ok(
	gates_hold(
		\%seq,
		{ 'sequence' => [ { 'marks' => [ 'stage1', 'stage2' ], 'var' => 'ip' } ] },
		{ 'ip' => 'k' },
		undef, $now
	),
	'a sequence holds when the set times are non-decreasing in the listed order'
);
my %seqrev = (
	'stage1' => { 'k' => { 'expires' => $now + 100, 'set' => $now + 50 } },
	'stage2' => { 'k' => { 'expires' => $now + 100, 'set' => $now } },
);
ok(
	!gates_hold(
		\%seqrev,
		{ 'sequence' => [ { 'marks' => [ 'stage1', 'stage2' ], 'var' => 'ip' } ] },
		{ 'ip' => 'k' },
		undef, $now
	),
	'and fails when they are out of order'
);
ok(
	!gates_hold(
		\%seq,
		{ 'sequence' => [ { 'marks' => [ 'stage1', 'missing' ], 'var' => 'ip' } ] },
		{ 'ip' => 'k' },
		undef, $now
	),
	'a sequence with a missing stage fails'
);

# a empty gate set passes vacuously
ok( gates_hold( \%store, {}, {}, undef, $now ), 'no gates is a pass' );

#
# mark_set... first-seen set time preserved across a re-brand, on_set fires
#

my %ms;
my @heard;
mark_set( \%ms, 'n', 'k', 'v', 100, $now, sub { push( @heard, [@_] ); return; } );
is( $ms{n}{k}{expires}, $now + 100, 'mark_set sets the expiry from now + ttl' );
is( $ms{n}{k}{set},     $now,       'and the first-seen set time' );
is( $ms{n}{k}{value},   'v',        'and the value' );
is_deeply( $heard[0], [ 'n', 'k', 'v', $now + 100, $now ], 'the on_set callback heard the brand' );

mark_set( \%ms, 'n', 'k', 'v', 100, $now + 30 );
is( $ms{n}{k}{expires}, $now + 130, 're-branding refreshes the expiry' );
is( $ms{n}{k}{set},     $now,       'but keeps the first-seen set time' );

# a re-brand of a DEAD entry starts a fresh set time
$ms{n}{k}{expires} = $now - 1;
mark_set( \%ms, 'n', 'k', 'v', 100, $now + 200 );
is( $ms{n}{k}{set}, $now + 200, 'a re-brand of an expired entry resets the set time' );

#
# apply_marks... var-less, var, vars, value_var, and unmark
#

my %am = ( 'seen' => { '9.9.9.9' => { 'expires' => $now + 10 } } );
my ( $set, $lifted ) = apply_marks(
	\%am,
	[ { 'name' => 'brand', 'ttl' => 100 } ],
	[ { 'name' => 'seen' } ],
	{ 'ip' => '1.2.3.4' },
	['9.9.9.9'],
	$now
);
ok( defined( $am{brand}{'9.9.9.9'} ), 'apply_marks brands the var-less offender' );
ok( !defined( $am{seen} ), 'and the unmark lifted the brand, dropping the emptied name' );
is_deeply( $set,    [ { 'name' => 'brand', 'key' => '9.9.9.9' } ], 'the set list names the brand and key' );
is_deeply( $lifted, [ { 'name' => 'seen',  'key' => '9.9.9.9' } ], 'the lifted list too' );

my %amv;
apply_marks( \%amv, [ { 'name' => 'acct', 'ttl' => 100, 'var' => 'user', 'value_var' => 'ip' } ],
	[], { 'user' => 'bob', 'ip' => '1.1.1.1' }, [], $now );
is( $amv{acct}{bob}{value}, '1.1.1.1', 'a var-keyed mark brands by the capture and stores value_var' );

my %amc;
apply_marks( \%amc, [ { 'name' => 'pair', 'ttl' => 100, 'vars' => [ 'ip', 'user' ] } ],
	[], { 'ip' => '1.2.3.4', 'user' => 'bob' }, [], $now );
ok( defined( $amc{pair}{"1.2.3.4\x1fbob"} ), 'a vars mark brands the compound key' );

# a rule that brands nothing touches nothing
my %amn;
my ( $s2, $l2 ) = apply_marks( \%amn, [], [], {}, ['1.2.3.4'], $now );
is_deeply( [ $s2, $l2 ], [ [], [] ], 'a rule with no marks brands and lifts nothing' );

#
# bound_expiring_store... the 10000 cap, the branch nothing else reaches
#

# a store under the cap is left alone
my %small = ( 'a' => { 'expires' => $now + 1 } );
bound_expiring_store( \%small, 'b', $now );
is( scalar( keys(%small) ), 1, 'under the cap, nothing is evicted' );

# a full store of live entries evicts the soonest-to-expire ahead of a new key
my %full;
foreach my $i ( 1 .. 10000 ) {
	$full{$i} = { 'expires' => $now + 1000 + $i };
}
$full{soonest} = { 'expires' => $now + 1 };
delete( $full{10000} );    # keep exactly 10000 keys with 'soonest' the least
bound_expiring_store( \%full, 'newkey', $now );
ok( !defined( $full{soonest} ), 'a full store evicts the soonest-to-expire before a new key' );
is( scalar( keys(%full) ), 9999, 'leaving room for the insert' );

# expired entries are pruned first, before any live eviction
my %aging;
foreach my $i ( 1 .. 9999 ) {
	$aging{$i} = { 'expires' => $now + 1000 };
}
$aging{dead} = { 'expires' => $now - 1 };
bound_expiring_store( \%aging, 'newkey', $now );
ok( !defined( $aging{dead} ), 'the expired are pruned first' );
ok( defined( $aging{1} ), 'and a live entry survives when pruning made room' );

done_testing;
