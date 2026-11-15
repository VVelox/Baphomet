#!perl
# direct unit tests for App::Baphomet::Marks, the mark store's pure core, the
# three gates that read it, marked, not_marked, and sequence, and the two that
# write it, mark and unmark... no galla, no store on an object, just the
# functions and gates over a hashref. pins the conservative value-compare
# rules and the store bound that the galla and run_tests both lean on but
# neither exercises exhaustively
use 5.006;
use strict;
use warnings;
use Test::More;
use List::Util qw( all );

use App::Baphomet::Marks qw( mark_key mark_set mark_unset bound_expiring_store );
use App::Baphomet::Gate  qw( gate_class compile_rule_gates bind_rule_gates walk_offense );

my $now = 1_000_000_000;

# whether the mark gates the passed entries make all hold over a store... a
# hash of gate type to the list of what each gate of the type is told, bound,
# then those of the result pass asked with a undef $ip and those of the
# offender pass with one
sub gates_hold {
	my ( $store, $entries_of, $data, $ip, $now_is ) = @_;

	my @gates;
	foreach my $type ( sort( keys( %{$entries_of} ) ) ) {
		foreach my $args ( @{ $entries_of->{$type} } ) {
			push( @gates, gate_class( $type, 'the test' )->new( 'type' => $type, 'args' => $args, 'where' => 'the gate' ) );
		}
	}
	my $bound = bind_rule_gates( \@gates, { 'marks' => sub { return $store; } }, 'the rule "x"' );
	my $pass  = defined($ip) ? 'offender' : 'result';

	return ( all { $_->holds( $data, $ip, $now_is ) } grep { $_->pass eq $pass } @{ $bound->{offense} } ) ? 1 : 0;
} ## end sub gates_hold

# takes one offense down a rule_gates list over a store, as the galla does...
# the list compiled as a rule's is, with no rule behind it as the gates here
# ask nothing of one, bound over the store and whatever else of the context
# is passed, and walked at $now.
#
# args:
#   $store      :: the mark store, a hash of mark name to its branded keys
#   $rule_gates :: the list, each entry a hash of one key, the gate type
#   $data       :: the found data of the offense
#   %context    :: the context keys beside marks... brandable, on_set, on_unset
#
# returns the offense, its set and lifted the brands the walk set and lifted,
# each a hash of name and key.
#
#   my $offense = walked( \%store, [ { 'ban_var' => ['ip'] }, { 'mark' => { 'name' => 'seen', 'ttl' => 60 } } ],
#       { 'ip' => '192.0.2.7' } );
sub walked {
	my ( $store, $rule_gates, $data, %context ) = @_;

	my $gates   = compile_rule_gates( $rule_gates, undef, 'json/x' );
	my $bound   = bind_rule_gates( $gates, { 'marks' => sub { return $store; }, %context }, 'the rule "x"' );
	my $offense = { 'data' => $data, 'regexp' => undef, 'now' => $now, 'set' => [], 'lifted' => [] };
	walk_offense( $bound, $offense );

	return $offense;
} ## end sub walked

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
# mark_unset... the lift, the emptied name dropped, on_unset fires
#

my %mu = ( 'n' => { 'k' => { 'expires' => $now + 100 }, 'beside' => { 'expires' => $now + 100 } } );
my @heard_lifts;
my $hear_lift = sub { push( @heard_lifts, [@_] ); return; };
is( mark_unset( \%mu, 'n', 'k', $hear_lift ), 1, 'mark_unset says it lifted a brand' );
ok( !defined( $mu{n}{k} ),     'the brand is gone' );
ok( defined( $mu{n}{beside} ), 'and the one beside it under the name is left' );
is_deeply( \@heard_lifts, [ [ 'n', 'k' ] ], 'the on_unset callback heard the lift' );

is( mark_unset( \%mu, 'n', 'k', $hear_lift ), 0, 'a key with no such brand lifts nothing' );
is( scalar(@heard_lifts), 1, 'which the callback does not hear' );

mark_unset( \%mu, 'n', 'beside' );
ok( !defined( $mu{n} ), 'lifting the last brand under a name drops the name' );

#
# the mark and unmark gates... var-less, var, vars, value_var, and the lift
#

my %am = ( 'seen' => { '9.9.9.9' => { 'expires' => $now + 10 } } );
my ( @heard_set, @heard_unset );
my $branded = walked(
	\%am,
	[
		{ 'ban_var' => ['ip'] },
		{ 'mark'    => { 'name' => 'brand', 'ttl' => 100 } },
		{ 'unmark'  => { 'name' => 'seen' } },
	],
	{ 'ip' => '9.9.9.9' },
	'on_set'   => sub { push( @heard_set,   [@_] ); return; },
	'on_unset' => sub { push( @heard_unset, [@_] ); return; },
);
ok( defined( $am{brand}{'9.9.9.9'} ), 'a mark naming no var brands the offender' );
is( $am{brand}{'9.9.9.9'}{expires}, $now + 100, 'for the ttl it was told' );
ok( !defined( $am{seen} ), 'and the unmark lifted the brand, dropping the emptied name' );
is_deeply( $branded->{set},    [ { 'name' => 'brand', 'key' => '9.9.9.9' } ], 'the set list names the brand and key' );
is_deeply( $branded->{lifted}, [ { 'name' => 'seen',  'key' => '9.9.9.9' } ], 'the lifted list too' );
is_deeply( \@heard_set, [ [ 'brand', '9.9.9.9', undef, $now + 100, $now ] ], 'the on_set callback heard the brand' );
is_deeply( \@heard_unset, [ [ 'seen', '9.9.9.9' ] ], 'and the on_unset callback the lift' );

# a unmark of what is not branded lifts nothing and says nothing of it
my %amu;
my $unlifted
	= walked( \%amu, [ { 'ban_var' => ['ip'] }, { 'unmark' => { 'name' => 'seen' } } ], { 'ip' => '9.9.9.9' } );
is_deeply( $unlifted->{lifted}, [], 'a unmark of a offender with no such brand lifts nothing' );

my %amv;
walked(
	\%amv,
	[ { 'mark' => { 'name' => 'acct', 'ttl' => 100, 'var' => 'user', 'value_var' => 'ip' } } ],
	{ 'user' => 'bob', 'ip' => '1.1.1.1' }
);
is( $amv{acct}{bob}{value}, '1.1.1.1', 'a var-keyed mark brands by the capture and stores value_var' );

my %amc;
walked(
	\%amc,
	[ { 'mark' => { 'name' => 'pair', 'ttl' => 100, 'vars' => [ 'ip', 'user' ] } } ],
	{ 'ip' => '1.2.3.4', 'user' => 'bob' }
);
ok( defined( $amc{pair}{"1.2.3.4\x1fbob"} ), 'a vars mark brands the compound key' );

my %aml = ( 'pair' => { "1.2.3.4\x1fbob" => { 'expires' => $now + 10 }, 'bob' => { 'expires' => $now + 10 } } );
my $pair_lifted = walked(
	\%aml,
	[ { 'unmark' => { 'name' => 'pair', 'vars' => [ 'ip', 'user' ] } } ],
	{ 'ip' => '1.2.3.4', 'user' => 'bob' }
);
ok( !defined( $aml{pair}{"1.2.3.4\x1fbob"} ), 'a vars unmark lifts the compound key' );
ok( defined( $aml{pair}{bob} ),               'and nothing else under the name' );
is_deeply( $pair_lifted->{lifted}, [ { 'name' => 'pair', 'key' => "1.2.3.4\x1fbob" } ], 'which the lifted list names' );

# a rule that brands nothing touches nothing
my %amn;
my $unbranded = walked( \%amn, [ { 'ban_var' => ['ip'] } ], { 'ip' => '1.2.3.4' } );
is_deeply( [ $unbranded->{set}, $unbranded->{lifted} ], [ [], [] ], 'a rule with no marks brands and lifts nothing' );
is_deeply( \%amn, {}, 'and leaves the store as it was' );

# a offender the context says may not be branded is neither branded nor has a
# brand lifted, and one beside it is... only where the key is the offender
my %amb = ( 'seen' => { '127.0.0.1' => { 'expires' => $now + 10 }, '1.2.3.4' => { 'expires' => $now + 10 } } );
my $spared = walked(
	\%amb,
	[
		{ 'ban_var' => [ 'src', 'dest' ] },
		{ 'mark'    => { 'name' => 'brand', 'ttl' => 100 } },
		{ 'mark'    => { 'name' => 'peer',  'ttl' => 100, 'var' => 'dest' } },
		{ 'unmark'  => { 'name' => 'seen' } },
	],
	{ 'src'     => '1.2.3.4', 'dest' => '127.0.0.1' },
	'brandable' => sub { return $_[0] ne '127.0.0.1'; },
);
ok( defined( $amb{brand}{'1.2.3.4'} ),    'a brandable offender is branded' );
ok( !defined( $amb{brand}{'127.0.0.1'} ), 'a unbrandable one is not' );
ok( defined( $amb{peer}{'127.0.0.1'} ),   'though a mark naming a var brands whatever the var holds' );
ok( !defined( $amb{seen}{'1.2.3.4'} ),    'a brandable offender has its brand lifted' );
ok( defined( $amb{seen}{'127.0.0.1'} ),   'a unbrandable one keeps its own' );
is_deeply(
	$spared->{set},
	[ { 'name' => 'brand', 'key' => '1.2.3.4' }, { 'name' => 'peer', 'key' => '127.0.0.1' } ],
	'the set list names only what was branded'
);
is_deeply(
	$spared->{lifted},
	[ { 'name' => 'seen', 'key' => '1.2.3.4' } ],
	'and the lifted list only what was lifted'
);

#
# a mark or unmark naming no var keys on the offender, so one with nothing
# above it in the list to name a offender is refused when the rule loads
#

my %told_no_var = ( 'mark' => { 'name' => 'brand', 'ttl' => 100 }, 'unmark' => { 'name' => 'brand' } );
foreach my $type ( sort( keys(%told_no_var) ) ) {
	ok(
		!eval {
			compile_rule_gates( [ { $type => $told_no_var{$type} }, { 'ban_var' => ['ip'] } ], undef, 'json/x' );
			1;
		},
		'a ' . $type . ' naming no var with no ban_var above it refuses to load'
	);
	is(
		$@ =~ s/ at \S+ line \d+\.\n\z//r,
		'The '
			. $type
			. ' gate of the rule "json/x" (rule_gates entry 0) keys on the offender, and no ban_var above it names one',
		'the die naming the gate and what it lacks'
	);
	ok(
		eval {
			compile_rule_gates( [ { 'detection_var' => ['user'] }, { $type => $told_no_var{$type} } ],
				undef, 'json/x' );
			1;
		},
		'while one below a detection_var loads'
	);
	ok(
		eval {
			compile_rule_gates( [ { $type => { %{ $told_no_var{$type} }, 'var' => 'user' } } ], undef, 'json/x' );
			1;
		},
		'and so does one naming a var with nothing above it'
	);
} ## end foreach my $type ( sort( keys(%told_no_var) ) )

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
