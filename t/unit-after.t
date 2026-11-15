#!perl
# direct unit tests for App::Baphomet::Gate::after, the after gate... what
# it takes for a key to have been seen often enough, and how that slides
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::after ();

sub after_gate {
	my ($args) = @_;

	return App::Baphomet::Gate::after->new( 'type' => 'after', 'args' => $args, 'where' => 'the gate' );
}

# asks the gate of a offense of the passed data at the passed time, on the
# watcher "auth" unless a scope is passed
sub holds_at {
	my ( $gate, $data, $now, $scope ) = @_;

	return $gate->ask( { 'data' => $data, 'now' => $now, 'scope' => $scope // 'auth' } );
}

my $compiled = after_gate( { 'by' => 'USER', 'count' => 3, 'seconds' => 60 } );
is_deeply( $compiled->{by}, ['USER'], 'a lone by is a list of one' );
is( $compiled->reads_offenders, 0, 'it does not read the offenders, so it may sit above the ban_var' );
isa_ok( $compiled, 'App::Baphomet::Gate', 'it' );

my %refused = (
	'no count'       => { 'by' => 'USER', 'seconds' => 60 },
	'a count of one' => { 'by' => 'USER', 'seconds' => 60, 'count' => 1 },
	'no seconds'     => { 'by' => 'USER', 'count'   => 3 },
	'no by'          => { 'count' => 3, 'seconds' => 60 },
);
foreach my $description ( sort( keys(%refused) ) ) {
	ok( !eval { after_gate( $refused{$description} ); 1 }, 'a entry with ' . $description . ' is refused' );
}
like( $@, qr/^the gate lacks a seconds/, 'and says what it lacks' );
ok( !eval { after_gate( { 'by' => 'USER', 'seconds' => 60, 'count' => 1 } ); 1 }, 'a count of one again' );
like( $@, qr/^the gate has a count that is not a int of two or more/, 'says a count of one counts nothing' );

#
# the count, and the window sliding
#

my %neti  = ( 'USER' => 'neti' );
my $three = after_gate( { 'by' => 'USER', 'count' => 3, 'seconds' => 60 } );
is_deeply( [ map { holds_at( $three, \%neti, 1000 + $_ ) } 0 .. 4 ],
	[ 0, 0, 1, 1, 1 ], 'the third of a key holds, and so does every one after it' );
is( holds_at( $three, { 'USER' => 'namtar' }, 1004 ), 0, 'another key is counted on its own' );
is( holds_at( $three, \%neti, 1004, 'messages' ),      0, 'and what is seen is kept apart by watcher' );

my $slide = after_gate( { 'by' => 'USER', 'count' => 3, 'seconds' => 60 } );
is( holds_at( $slide, \%neti, 2000 ), 0, 'one' );
is( holds_at( $slide, \%neti, 2050 ), 0, 'two, fifty seconds on' );
is( holds_at( $slide, \%neti, 2059 ), 1, 'the third with in sixty seconds of the first holds' );
is( holds_at( $slide, \%neti, 2100 ), 1, 'a fourth holds on the two before it, the first having slid out' );
is( holds_at( $slide, \%neti, 2160 ), 0, 'a fifth a hundred seconds from the third back does not' );
is( holds_at( $slide, \%neti, 2160 ), 0, 'and exactly sixty seconds across is not with in sixty' );
is( holds_at( $slide, \%neti, 2161 ), 1, 'three inside the window hold again' );
is( scalar( @{ $slide->{windows}{auth}{neti}{times} } ), 3, 'only the last count of them are kept' );

is( holds_at( $three, {}, 1005 ), 0, 'a offense lacking the by var has nothing to be counted under and is vetoed' );

#
# a compound key, and the sweep
#

my $pair = after_gate( { 'by' => [ 'SRC', 'USER' ], 'count' => 2, 'seconds' => 30 } );
my %from = ( 'SRC' => '203.0.113.9', 'USER' => 'neti' );
is( holds_at( $pair, \%from, 3000 ), 0, 'the first of a pair' );
is( holds_at( $pair, { 'SRC' => '203.0.113.10', 'USER' => 'neti' }, 3001 ), 0, 'a key differing in one part is another key' );
is( holds_at( $pair, \%from, 3002 ), 1, 'the second of the pair holds' );

$pair->sweep_state(3031);
is_deeply( [ keys( %{ $pair->{windows}{auth} } ) ], ["203.0.113.9\x1fneti"], 'a sweep drops a key not seen for seconds' );
$pair->sweep_state(3032);
is_deeply( $pair->{windows}, {}, 'and the last of them takes its scope with it' );

done_testing();
