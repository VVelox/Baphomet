#!perl
# direct unit tests for App::Baphomet::Correlation, the correlation store's
# pure core... no rule, just the functions over a store hashref. pins the
# expiry at read, the per key pending cap, and that asking after a key never
# creates it, none of which the rule tests reach but by way of whole lines
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Correlation qw(
	correlation_key context_put context_get pending_park pending_complete
	fold_completions correlation_prune correlation_restore
);

my $now = 1_000_000_000;

#
# correlation_key... a plain key, a compound one, the envelope, and the
# refusals
#

is( correlation_key( ['SESSION'], { 'SESSION' => 'abc' }, undef ),
	'abc', 'a single component resolves to the bare value' );

is( correlation_key( [ 'HOST', 'SESSION' ], { 'HOST' => 'mx1', 'SESSION' => '42' }, undef ),
	"mx1\x0042", 'a compound key joins on a NUL' );

is( correlation_key( [ 'HOST', 'SESSION' ], { 'HOST' => 'mx1' }, undef ),
	undef, 'a missing component gives no key at all rather than a partial join' );

is( correlation_key( [ 'syslog.pid', 'SESSION' ], { 'SESSION' => '42' }, { 'syslog.pid' => 311 } ),
	"311\x0042", 'a syslog. component is read off the envelope' );

is( correlation_key( ['syslog.pid'], { 'syslog.pid' => 999 }, { 'syslog.pid' => 311 } ),
	311, 'and never off the captures, whatever they hold' );

is( correlation_key( ['syslog.pid'], { 'syslog.pid' => 999 }, undef ),
	undef, 'with no envelope a syslog. component is unresolved' );

is( correlation_key( ['syslog.pid'], {}, { 'syslog.host' => 'mx1' } ), undef, 'as is one the envelope does not hold' );

#
# context_put / context_get... the store, the expiry at read, and the scope
# wall
#

my %store = ( 'context' => {}, 'pending' => {} );

is( context_get( \%store, 'maillog', 'abc', $now ), undef, 'a key nothing stored reads back as none' );
is_deeply( \%store, { 'context' => {}, 'pending' => {} }, 'and asking after it leaves the store as it was' );

context_put( \%store, 'maillog', 'abc', { 'SRC' => '192.0.2.7' }, 60, $now );
is_deeply(
	context_get( \%store, 'maillog', 'abc', $now + 59 ),
	{ 'SRC' => '192.0.2.7' },
	'stored context reads back while it lives'
);
is( context_get( \%store, 'maillog', 'abc', $now + 60 ), undef, 'and is gone at its expiry, swept or not' );
is( context_get( \%store, 'authlog', 'abc', $now ),      undef, 'one scope does not see the key of another' );
ok( !defined( $store{context}{authlog} ), 'and the scope asked after was not created' );

context_put( \%store, 'maillog', 'abc', { 'SRC' => '198.51.100.4' }, 60, $now + 10 );
is( context_get( \%store, 'maillog', 'abc', $now + 10 )->{SRC},
	'198.51.100.4', 'a later capture line replaces what the key held' );

# the per scope bound, the shared 10000 cap... a full scope of live keys
# evicts the soonest to expire ahead of a new one
my %full = ( 'context' => { 'maillog' => {} }, 'pending' => {} );
foreach my $key_int ( 1 .. 9999 ) {
	$full{context}{maillog}{$key_int} = { 'data' => {}, 'expires' => $now + 1000 };
}
$full{context}{maillog}{soonest} = { 'data' => {}, 'expires' => $now + 1 };
context_put( \%full, 'maillog', 'newkey', { 'SRC' => '192.0.2.7' }, 60, $now );
ok( !defined( $full{context}{maillog}{soonest} ), 'a full scope evicts its soonest to expire ahead of a new key' );
is( scalar( keys( %{ $full{context}{maillog} } ) ), 10000, 'and holds no more than the cap after the insert' );

#
# pending_park / pending_complete
#

my %parked = ( 'context' => {}, 'pending' => {} );

is_deeply( [ pending_complete( \%parked, 'maillog', 'abc', { 'SRC' => '192.0.2.7' }, $now ) ],
	[], 'a key nothing is parked under completes nothing' );
is_deeply( \%parked, { 'context' => {}, 'pending' => {} }, 'and asking after it leaves the store as it was' );

pending_park( \%parked, 'maillog', 'abc', { 'USER' => 'admin', 'SRC' => 'unknown' }, 0, 60, $now );
pending_park( \%parked, 'maillog', 'abc', { 'USER' => 'root' },                      1, 5,  $now );

is_deeply(
	[
		pending_complete(
			\%parked, 'maillog', 'abc', { 'SRC' => '192.0.2.7', 'HELO' => 'mail.example.com' },
			$now + 10
		)
	],
	[
		{
			'data'   => { 'USER' => 'admin', 'SRC' => 'unknown', 'HELO' => 'mail.example.com' },
			'regexp' => 0,
		}
	],
	'a live pending completes with the context under its own data, and a expired one is dropped'
);
ok( !defined( $parked{pending}{maillog}{abc} ), 'the pendings come off the key whether or not they completed' );
is_deeply( [ pending_complete( \%parked, 'maillog', 'abc', { 'SRC' => '192.0.2.7' }, $now + 10 ) ],
	[], 'so a second capture line completes nothing more' );

pending_park( \%parked, 'maillog', 'def', { 'USER' => 'admin' }, undef, 60, $now );
is_deeply(
	[ pending_complete( \%parked, 'maillog', 'def', {}, $now ) ],
	[ { 'data' => { 'USER' => 'admin' }, 'regexp' => undef } ],
	'a pending parked with no regexp completes with none'
);

# the per key cap of 100, the oldest dropped to make room
foreach my $pending_int ( 1 .. 105 ) {
	pending_park( \%parked, 'maillog', 'flood', { 'N' => $pending_int }, 0, 60, $now );
}
my @flood = pending_complete( \%parked, 'maillog', 'flood', {}, $now );
is( scalar(@flood),      100, 'no more than 100 wait under one key' );
is( $flood[0]{data}{N},  6,   'the oldest being what was dropped' );
is( $flood[-1]{data}{N}, 105, 'and the newest what was kept' );

#
# fold_completions
#

my $own    = { 'data' => { 'SRC' => '192.0.2.7' },    'regexp' => 0 };
my $first  = { 'data' => { 'SRC' => '198.51.100.4' }, 'regexp' => 1 };
my $second = { 'data' => { 'SRC' => '203.0.113.9' },  'regexp' => 1 };

is( fold_completions( undef, [] ), undef, 'no offense and no completions folds to nothing' );

my $alone = fold_completions( $own, [] );
is( $alone, $own, 'a offense with no completions is returned as it is' );
ok( !exists( $alone->{more} ), 'with no more' );

my @completions = ( $first, $second );
my $led         = fold_completions( undef, \@completions );
is( $led, $first, 'with no offense the first completion leads' );
is_deeply( $led->{more}, [$second], 'and the rest ride in its more' );
is( scalar(@completions), 2, 'the passed completions are left untouched' );

delete( $first->{more} );
my $both = fold_completions( $own, [ $first, $second ] );
is( $both, $own, 'a offense leads its completions' );
is_deeply( $both->{more}, [ $first, $second ], 'which all ride in its more' );

#
# correlation_prune... the sweeper's half
#

my %pruning = ( 'context' => {}, 'pending' => {} );
context_put( \%pruning, 'maillog', 'live', {}, 3600, $now );
context_put( \%pruning, 'maillog', 'dead', {}, 10,   $now );
context_put( \%pruning, 'authlog', 'dead', {}, 10,   $now );
pending_park( \%pruning, 'maillog', 'mixed', { 'N' => 1 }, 0, 10,   $now );
pending_park( \%pruning, 'maillog', 'mixed', { 'N' => 2 }, 0, 3600, $now );
pending_park( \%pruning, 'authlog', 'dead',  { 'N' => 3 }, 0, 10,   $now );

correlation_prune( \%pruning, $now + 100 );
ok( defined( $pruning{context}{maillog}{live} ),  'live context survives the prune' );
ok( !defined( $pruning{context}{maillog}{dead} ), 'expired context is dropped' );
ok( !defined( $pruning{context}{authlog} ),       'a context scope left empty is dropped with its last key' );
is_deeply( [ map { $_->{caps}{N} } @{ $pruning{pending}{maillog}{mixed} } ],
	[2], 'a key keeps its live pendings and loses its expired ones' );
ok( !defined( $pruning{pending}{authlog} ), 'a pending scope left empty is dropped with its last key' );

#
# correlation_restore... what came back off the context tablet
#

my %dumped = ( 'context' => {}, 'pending' => {} );
context_put( \%dumped, 'maillog', 'live', { 'SRC' => '192.0.2.7' }, 3600, $now );
context_put( \%dumped, 'maillog', 'dead', { 'SRC' => '192.0.2.8' }, 10,   $now );
pending_park( \%dumped, 'maillog', 'waiting', { 'USER' => 'admin' }, 0, 3600, $now );
pending_park( \%dumped, 'maillog', 'waiting', { 'USER' => 'root' },  0, 10,   $now );

my %restored = ( 'context' => {}, 'pending' => {} );
pending_park( \%restored, 'maillog', 'waiting', { 'USER' => 'guest' }, 0, 3600, $now );
correlation_restore( \%restored, \%dumped, $now + 100 );

is_deeply(
	context_get( \%restored, 'maillog', 'live', $now + 100 ),
	{ 'SRC' => '192.0.2.7' },
	'live context is restored'
);
ok( !defined( $restored{context}{maillog}{dead} ), 'context that expired while down is not' );
is_deeply(
	[ map { $_->{caps}{USER} } @{ $restored{pending}{maillog}{waiting} } ],
	[ 'guest', 'admin' ],
	'live pendings are merged in behind what the key already held, the expired left out'
);

my %untouched = ( 'context' => {}, 'pending' => {} );
foreach my $junk ( undef, 'a string', [ 'a', 'list' ], { 'context' => 'nope', 'pending' => ['nope'] } ) {
	correlation_restore( \%untouched, $junk, $now );
}
is_deeply( \%untouched, { 'context' => {}, 'pending' => {} }, 'a state not shaped like a store restores nothing' );

done_testing;
