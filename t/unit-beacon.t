#!perl
# direct unit tests for App::Baphomet::Gate::beacon and
# App::Baphomet::Gate::sample... a rhythm, and a fair cut
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::beacon ();
use App::Baphomet::Gate::sample ();

sub beacon_gate {
	my (%args) = @_;

	return App::Baphomet::Gate::beacon->new( 'type' => 'beacon', 'args' => { 'by' => 'SRC', 'count' => 3, %args }, 'where' => 'the gate' );
}

# what the gate says of a key seen at each of the passed times, on the
# watcher "fw" unless a scope is passed
sub rhythm {
	my ( $gate, $key, $scope, @times ) = @_;

	return [ map { $gate->ask( { 'data' => { 'SRC' => $key }, 'now' => $_, 'scope' => $scope // 'fw' } ) } @times ];
}

my $gate = beacon_gate();
is( $gate->{jitter},       0.1,   'a spread of a tenth of the average gap is allowed unless told otherwise' );
is( $gate->{min_interval}, 10,    'a beacon is at least ten seconds apart' );
is( $gate->{max_interval}, 86400, 'and a gap of over a day starts the key over' );
is( $gate->reads_offenders, 0, 'it does not read the offenders, so it may sit above the ban_var' );

is_deeply( rhythm( $gate, 'a', undef, 1000, 1300, 1602, 1900, 2201 ),
	[ 0, 0, 0, 1, 1 ], 'three even gaps hold, and so does each even one after' );
is_deeply( rhythm( $gate, 'a', undef, 2400, 2999 ), [ 0, 0 ], 'a uneven one breaks it, and holds again only once it is out of the last three' );

my $person = beacon_gate();
is_deeply( rhythm( $person, 'b', undef, 1000, 1040, 1300, 1310, 1900 ), [ 0, 0, 0, 0, 0 ], 'gaps as a person makes them never hold' );

my $burst = beacon_gate();
is_deeply( rhythm( $burst, 'c', undef, 1000, 1002, 1004, 1006 ), [ 0, 0, 0, 0 ], 'even gaps shorter than min_interval are a burst' );

my $stopped = beacon_gate( 'max_interval' => 3600 );
is_deeply( rhythm( $stopped, 'd', undef, 1000, 1300, 1600, 6000, 6300, 6600 ),
	[ 0, 0, 0, 0, 0, 0 ], 'a gap past max_interval starts the key over' );
is_deeply( rhythm( $stopped, 'd', undef, 6900 ), [1], 'and it holds once it has three even gaps again' );

my $loose = beacon_gate( 'jitter' => 0.5 );
is_deeply( rhythm( $loose, 'e', undef, 1000, 1040, 1300, 1310, 1900 ), [ 0, 0, 0, 0, 0 ], 'a jitter of half the gap is still uneven to a person' );
is_deeply( rhythm( beacon_gate( 'jitter' => 0.5 ), 'f', undef, 1000, 1300, 1700, 1950 ), [ 0, 0, 0, 1 ], 'but lets a rough rhythm hold' );

is_deeply( rhythm( $gate, 'a', 'mail', 1000, 1300, 1600, 1900 ), [ 0, 0, 0, 1 ], 'the keys are kept apart by watcher' );
is( $gate->ask( { 'data' => {}, 'now' => 1000, 'scope' => 'fw' } ), 0, 'a offense lacking the by var is vetoed' );

my $skewed = beacon_gate();
rhythm( $skewed, 'g', undef, 1000, 1300 );
is_deeply( rhythm( $skewed, 'g', undef, 1200 ), [0], 'a offense ahead of the last is no gap' );
is_deeply( rhythm( $skewed, 'g', undef, 1600, 1900 ), [ 0, 1 ], 'and is not counted as one' );

$skewed->sweep_state( 1900 + 86399 );
ok( exists( $skewed->{windows}{fw}{g} ), 'a sweep before max_interval leaves the key' );
$skewed->sweep_state( 1900 + 86400 );
ok( !exists( $skewed->{windows}{fw} ), 'and one at it drops it' );

foreach my $bad ( { 'count' => 1 }, { 'jitter' => 0 }, { 'min_interval' => 600, 'max_interval' => 600 } ) {
	ok( !eval { beacon_gate( %{$bad} ); 1 }, 'a entry of ' . join( ', ', map { $_ . ' ' . $bad->{$_} } sort( keys( %{$bad} ) ) ) . ' is refused' );
}
like( $@, qr/^the gate has a min_interval that is not under its max_interval/, 'and says why' );

#
# sample
#

sub sample_gate {
	return App::Baphomet::Gate::sample->new( 'type' => 'sample', 'args' => { 'every' => $_[0] }, 'where' => 'the gate' );
}

my $sample = sample_gate(4);
is( $sample->reads_offenders, 0, 'sample does not read the offenders' );
is_deeply( [ map { $sample->ask( { 'data' => { 'SRC' => $_ }, 'now' => 1000, 'scope' => 'fw' } ) } 1 .. 9 ],
	[ 1, 0, 0, 0, 1, 0, 0, 0, 1 ], 'the first is let by, and one in four after it, whatever the key' );
is( $sample->ask( { 'data' => {}, 'now' => 1000, 'scope' => 'mail' } ), 1, 'the count is kept apart by watcher' );

foreach my $bad ( 1, 0, 'often', undef ) {
	ok( !eval { sample_gate($bad); 1 }, 'a every of ' . ( $bad // 'nothing' ) . ' is refused' );
}

done_testing();
