#!perl
# direct unit tests for App::Baphomet::Gate::travel, the travel gate... a
# fixture map stands in for the city database and a hash for the mark store,
# so the distance, the speed, and what is kept of a sighting are pinned with
# out either
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::travel ();

# London, New York, and Paris, each good to a radius, and a place given
# exactly
my %places = (
	'198.51.100.5' => { 'lat' => 51.5072, 'lon' => -0.1276,  'radius' => 10 },
	'203.0.113.9'  => { 'lat' => 40.7128, 'lon' => -74.0060, 'radius' => 20 },
	'203.0.113.20' => { 'lat' => 48.8566, 'lon' => 2.3522,   'radius' => 0 },
	'192.0.2.50'   => { 'lat' => 51.5072, 'lon' => -0.1276,  'radius' => 0 },
);

# a travel gate told what a rule entry would tell it, bound over the places
# above and the passed mark store
my @gossiped;

sub travel_gate {
	my ( $store, %args ) = @_;

	my $gate = App::Baphomet::Gate::travel->new(
		'type'  => 'travel',
		'args'  => { 'name' => 'last-login', 'by' => 'USER', 'var' => 'SRC', 'faster_than_kmh' => 900, %args },
		'where' => 'the gate'
	);
	return $gate->bound(
		{
			'marks'        => sub { return $store; },
			'city_locator' => sub { return $places{ $_[0] }; },
			'on_set'       => sub { push( @gossiped, [@_] ); return; },
		},
		'the rule "x"'
	);
} ## end sub travel_gate

sub sighting {
	my ( $user, $address ) = @_;

	return { 'USER' => $user, 'SRC' => $address };
}

my $compiled = App::Baphomet::Gate::travel->new(
	'type'  => 'travel',
	'args'  => { 'name' => 'last-login', 'by' => 'USER', 'var' => 'SRC', 'faster_than_kmh' => 900 },
	'where' => 'the gate'
);
is( $compiled->pass,            'result', 'it is asked once of the offense' );
is( $compiled->reads_offenders, 0,        'and reads no offender, so it may sit above the ban_var' );
is( $compiled->{min_km},        100,      'a hundred kilometres is the least it asks the speed of' );
is( $compiled->{ttl},           2592000,  'and a sighting is kept thirty days' );
is_deeply( [ $compiled->needs ], [ 'marks', 'city_locator' ], 'it needs the marks and the city locator' );

foreach my $missing ( 'name', 'by', 'var', 'faster_than_kmh' ) {
	my %args = ( 'name' => 'last-login', 'by' => 'USER', 'var' => 'SRC', 'faster_than_kmh' => 900 );
	delete( $args{$missing} );
	ok(
		!eval { App::Baphomet::Gate::travel->new( 'type' => 'travel', 'args' => \%args, 'where' => 'the gate' ); 1 },
		'a entry with no ' . $missing . ' is refused'
	);
	like( $@, qr/^the gate lacks a $missing/, 'and says so' );
}

#
# a first sighting, and one too far off for the time
#

my %store;
my $gate = travel_gate( \%store, 'km_into' => 'KM', 'kmh_into' => 'KMH' );

my $first = sighting( 'neti', '198.51.100.5' );
is( $gate->holds( $first, undef, 1000 ), 0, 'a first sighting has nothing to be measured against' );
is( $store{'last-login'}{neti}{value}, '51.5072 -0.1276 10 1000', 'and is kept as latitude, longitude, radius, and time' );
is( $store{'last-login'}{neti}{expires}, 1000 + 2592000, 'for the ttl' );
ok( !exists( $first->{KM} ), 'with nothing measured nothing is lifted' );
is_deeply( [ @{ $gossiped[-1] }[ 0, 1 ] ], [ 'last-login', 'neti' ], 'the sighting is gossiped as any brand set is' );

# London to New York is 5570 km, less the 10 and the 20 the two are good to
my $second = sighting( 'neti', '203.0.113.9' );
is( $gate->holds( $second, undef, 1000 + 3600 ), 1, 'New York a hour after London holds' );
is( $second->{KM},  5540, 'the distance is lifted, the two radii off it' );
is( $second->{KMH}, 5540, 'and the speed' );
is( $store{'last-login'}{neti}{value}, '40.7128 -74.0060 20 4600', 'the sighting that tripped it takes the place of the last' );

# seven hours back is well under 900 km/h
my $third = sighting( 'neti', '198.51.100.5' );
is( $gate->holds( $third, undef, 4600 + 7 * 3600 ), 0, 'London again seven hours on is a flight, and does not hold' );
is( $third->{KM},  5540, 'though the distance is lifted all the same' );
is( $third->{KMH}, 791,  'and the speed it was under the mark by' );

#
# what keeps it from holding
#

%store = ();
my $near = travel_gate( \%store );
$near->holds( sighting( 'neti', '198.51.100.5' ), undef, 1000 );
is( $near->holds( sighting( 'neti', '192.0.2.50' ), undef, 1001 ), 0, 'the same place a second later is no distance at all' );

# London to Paris is 344 km, which a second apart is a great speed
is( $near->holds( sighting( 'neti', '203.0.113.20' ), undef, 1002 ), 1, 'Paris a second after London holds' );
my $far_floor = travel_gate( {}, 'min_km' => 500 );
$far_floor->holds( sighting( 'neti', '192.0.2.50' ), undef, 1000 );
is( $far_floor->holds( sighting( 'neti', '203.0.113.20' ), undef, 1001 ), 0, 'but not under a min_km it falls short of' );

%store = ();
my $plain = travel_gate( \%store );
is( $plain->holds( sighting( 'neti', '192.0.2.1' ), undef, 1000 ), 0, 'a address the locator can not place does not hold' );
is_deeply( \%store, {}, 'and is not kept as a sighting' );
is( $plain->holds( { 'USER' => 'neti' }, undef, 1000 ), 0, 'a offense lacking the address does not hold' );
is( $plain->holds( { 'SRC'  => '198.51.100.5' }, undef, 1000 ), 0, 'nor one lacking the key' );
is_deeply( \%store, {}, 'and neither is kept' );

$plain->holds( sighting( 'neti', '198.51.100.5' ), undef, 1000 );
is( $plain->holds( sighting( 'namtar', '203.0.113.9' ), undef, 1001 ), 0, 'another key is measured against its own last sighting' );

# a sighting that has run out is no sighting
is( $plain->holds( sighting( 'neti', '203.0.113.9' ), undef, 1000 + 2592000 ), 0, 'a last sighting past its ttl is not measured against' );

# a brand of the name with a value that is no sighting
%store = ( 'last-login' => { 'neti' => { 'expires' => 9000, 'set' => 1000, 'value' => 'something else' } } );
is( $plain->holds( sighting( 'neti', '203.0.113.9' ), undef, 2000 ), 0, 'a brand whose value is no sighting is not measured against' );
is( $store{'last-login'}{neti}{value}, '40.7128 -74.0060 20 2000', 'and is taken the place of by one that is' );

#
# time that does not run forward
#

%store = ();
my $skewed = travel_gate( \%store, 'kmh_into' => 'KMH' );
$skewed->holds( sighting( 'neti', '198.51.100.5' ), undef, 5000 );
my $same_second = sighting( 'neti', '203.0.113.9' );
is( $skewed->holds( $same_second, undef, 5000 ), 1, 'two sightings in the one second are taken as a second apart' );
cmp_ok( $same_second->{KMH}, '>', 19_000_000, 'so the speed is the distance over that second, and finite' );
is( $skewed->holds( sighting( 'neti', '198.51.100.5' ), undef, 4000 ), 1, 'and one that came in ahead of a earlier one is as far off as it is' );

#
# a compound key, and a value the offense already has
#

%store = ();
my $pair = travel_gate( \%store, 'by' => [ 'USER', 'REALM' ], 'km_into' => 'KM' );
$pair->holds( { 'USER' => 'neti', 'REALM' => 'mail', 'SRC' => '198.51.100.5' }, undef, 1000 );
is_deeply( [ keys( %{ $store{'last-login'} } ) ], ["neti\x1fmail"], 'a by of two vars is one key of both' );
my %held = ( 'USER' => 'neti', 'REALM' => 'mail', 'SRC' => '203.0.113.9', 'KM' => 'from the line' );
$pair->holds( \%held, undef, 2000 );
is( $held{KM}, 'from the line', 'a value the offense already has is not lifted over' );

done_testing();
