#!perl
# direct unit tests for App::Baphomet::Gate::sum, the sum gate... what a key
# has added up to, and how that falls away
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::sum ();

sub sum_gate {
	my (%args) = @_;

	return App::Baphomet::Gate::sum->new(
		'type'  => 'sum',
		'args'  => { 'by' => 'host', 'of' => 'bytes', 'above' => 1000, 'seconds' => 600, %args },
		'where' => 'the gate'
	);
}

# asks the gate of a offense of the passed host and bytes at the passed
# time, on the watcher "web" unless a scope is passed
sub added {
	my ( $gate, $host, $bytes, $now, $scope ) = @_;

	return $gate->ask( { 'data' => { 'host' => $host, 'bytes' => $bytes }, 'now' => $now, 'scope' => $scope // 'web' } );
}

my $gate = sum_gate();
is( $gate->{span},          10, 'ten minutes are kept in sixty spans of ten seconds' );
is( $gate->reads_offenders, 0,  'it does not read the offenders, so it may sit above the ban_var' );
is( sum_gate( 'seconds' => 30 )->{span}, 1, 'a span is never less than a second' );

foreach my $missing ( 'by', 'of', 'above', 'seconds' ) {
	my %args = ( 'by' => 'host', 'of' => 'bytes', 'above' => 1000, 'seconds' => 600 );
	delete( $args{$missing} );
	ok( !eval { App::Baphomet::Gate::sum->new( 'type' => 'sum', 'args' => \%args, 'where' => 'the gate' ); 1 },
		'a entry with no ' . $missing . ' is refused' );
}
like( $@, qr/^the gate lacks a seconds/, 'and says what it lacks' );

#
# adding up
#

my $client = '203.0.113.9';
is( added( $gate, $client, 400, 1000 ), 0, 'four hundred is not above a thousand' );
is( added( $gate, $client, 600, 1005 ), 0, 'nor is a thousand exactly' );
is( added( $gate, $client, 1,   1006 ), 1, 'one more is' );
is( added( $gate, $client, 0,   1007 ), 1, 'and it goes on holding while the total stands, a nothing added or not' );
is( added( $gate, '203.0.113.10', 999, 1007 ), 0, 'another key adds up on its own' );
is( added( $gate, $client, 999, 1007, 'mail' ), 0, 'and the totals are kept apart by watcher' );
is( added( $gate, $client, 1500.5, 1007, 'mail' ), 1, 'a number with a fraction adds as one' );

#
# falling away, a span at a time
#

my $slide = sum_gate( 'above' => 100, 'seconds' => 600 );
added( $slide, $client, 90, 5000 );
is( added( $slide, $client, 20, 5300 ), 1, 'ninety and twenty with in the ten minutes is above a hundred' );
is( added( $slide, $client, 0,  5599 ), 1, 'the first still counts at the end of them' );
is( added( $slide, $client, 0,  5609 ), 1, 'and for the span it landed in, which is not yet wholly past' );
is( added( $slide, $client, 0,  5610 ), 0, 'that span wholly past, the ninety has fallen out' );
is_deeply( [ sort( keys( %{ $slide->{windows}{web}{$client}{spans} } ) ) ], [ 5300, 5590, 5600, 5610 ], 'and its span is dropped' );

#
# what adds nothing
#

my $strict = sum_gate( 'above' => 10 );
foreach my $not_a_number ( undef, '', 'lots', '-5', '1e9', [] ) {
	is( added( $strict, $client, $not_a_number, 9000 ), 0, 'a of that is no number of zero or more is vetoed' );
}
ok( !exists( $strict->{windows}{web} ), 'and adds nothing' );
is( $strict->ask( { 'data' => { 'bytes' => 50 }, 'now' => 9000, 'scope' => 'web' } ), 0, 'a offense lacking the by var is vetoed too' );

#
# a compound key, and the sweep
#

my $pair = sum_gate( 'by' => [ 'host', 'user' ], 'above' => 10, 'seconds' => 60 );
$pair->ask( { 'data' => { 'host' => $client, 'user' => 'neti', 'bytes' => 11 }, 'now' => 100, 'scope' => 'web' } );
is_deeply( [ keys( %{ $pair->{windows}{web} } ) ], ["$client\x1fneti"], 'a by of two vars is one key of both' );
$pair->sweep_state(159);
ok( exists( $pair->{windows}{web} ), 'a sweep before the seconds are up leaves the total' );
$pair->sweep_state(160);
is_deeply( $pair->{windows}, {}, 'and one after them drops it, and its scope with it' );

done_testing();
