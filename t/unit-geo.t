#!perl
# direct unit tests for App::Baphomet::Gate::country, the country gate... a
# fixture map stands in for the GeoIP lookups, so the fail-closed rules and
# the token resolution are pinned with out a database
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::country ();

# a country gate told what a rule entry would tell it, and bound over a
# locator of the passed address to code map and the passed named lists
sub country_gate {
	my ( $args, $countries, $lists ) = @_;

	my $gate = App::Baphomet::Gate::country->new( 'type' => 'country', 'args' => $args, 'where' => 'the gate' );
	return $gate->bound( { 'locator' => sub { return $countries->{ $_[0] }; }, 'country_codes' => $lists },
		'the rule "x"' );
}

my %countries = ( '203.0.113.9' => 'NL', '198.51.100.5' => 'US' );

#
# compile... the mode, lone values as lists, and the pass
#

my $compiled = App::Baphomet::Gate::country->new(
	'type'  => 'country',
	'args'  => { 'isnot' => 'mx', 'vars' => 'src' },
	'where' => 'the gate'
);
is( $compiled->{mode}, 'isnot', 'the mode is the key that was written' );
is_deeply( $compiled->{entries}, ['mx'],  'a lone entry is a list of one' );
is_deeply( $compiled->{vars},    ['src'], 'and so is a lone var' );
is( $compiled->pass, 'result', 'a gate naming vars is of the result pass' );
is_deeply( [ $compiled->needs ], ['locator'], 'it needs the locator' );

my $offender_keyed
	= App::Baphomet::Gate::country->new( 'type' => 'country', 'args' => { 'is' => ['US'] }, 'where' => 'the gate' );
is( $offender_keyed->pass, 'offender', 'a gate naming no vars is of the offender pass' );

ok(
	!eval {
		App::Baphomet::Gate::country->new(
			'type'  => 'country',
			'args'  => { 'is' => 'USA' },
			'where' => 'the gate'
		);
		1;
	},
	'a entry that is neither a 2-letter code nor a import dies'
);
like( $@, qr/^the gate has a is that is not a 2-letter code/, 'and the die leads with the where it was passed' );

#
# bound... token expansion, upcasing, and the loud die on a undefined list
#

my $isnot = country_gate( { 'isnot' => [ '%%%country_codes{home}%%%', 'mx' ], 'vars' => ['src'] },
	\%countries, { 'home' => [ 'us', 'ca' ] } );
is_deeply(
	[ sort( keys( %{ $isnot->{codes} } ) ) ],
	[ 'CA', 'MX', 'US' ],
	'the token expands and every code is upcased into the set'
);

ok( !eval { country_gate( { 'is' => ['%%%country_codes{nope}%%%'] }, \%countries, { 'home' => ['US'] } ); 1; },
	'importing a list the context does not define dies' );
like( $@, qr/^the rule "x" imports country_codes\{nope\}/, 'and the die names the rule and the missing list' );

#
# holds... the two modes, and fail closed on what can not be placed
#

# a vars gate reads the found data
ok( $isnot->holds( { 'src'  => '203.0.113.9' },  undef ), 'isnot US counts a address abroad' );
ok( !$isnot->holds( { 'src' => '198.51.100.5' }, undef ), 'and spares one at home' );
ok( !$isnot->holds( { 'src' => '192.0.2.66' }, undef ), 'a unplaceable address fails closed, isnot never clearing it' );
ok( !$isnot->holds( {}, undef ), 'and so does a var the result lacks' );

my $both_vars = country_gate( { 'is' => ['NL'], 'vars' => [ 'src', 'dst' ] }, \%countries, {} );
ok( $both_vars->holds( { 'src' => '203.0.113.9', 'dst' => '203.0.113.9' }, undef ),
	'every var named has to satisfy the gate' );
ok( !$both_vars->holds( { 'src' => '203.0.113.9', 'dst' => '198.51.100.5' }, undef ), 'and one that does not vetoes' );

# a gate naming no vars reads the offender
my $is = country_gate( { 'is' => [ 'US', 'CA' ] }, \%countries, {} );
ok( $is->holds( {},  '198.51.100.5' ), 'is US counts a home offender' );
ok( !$is->holds( {}, '203.0.113.9' ),  'and drops a foreign one' );
ok( !$is->holds( {}, '192.0.2.66' ),   'a unplaceable offender fails closed under is too' );

#
# into... the code lifted for what is below the gate to read
#

my $lift_only = country_gate( { 'vars' => 'src', 'into' => 'COUNTRY' }, \%countries, {} );
is( $lift_only->{mode}, undef,    'a gate with only a into has no mode' );
is( $lift_only->pass,   'result', 'and is asked once of the offense' );

my %data = ( 'src' => '203.0.113.9' );
ok( $lift_only->holds( \%data, undef ), 'a gate that only lifts holds' );
is_deeply( \%data, { 'src' => '203.0.113.9', 'COUNTRY' => 'NL' }, 'and the code is lifted into its var' );

%data = ( 'src' => '192.0.2.66' );
ok( $lift_only->holds( \%data, undef ), 'it vetoes nothing on a address it can not place' );
is_deeply( \%data, { 'src' => '192.0.2.66' }, 'and lifts nothing' );

%data = ();
ok( $lift_only->holds( \%data, undef ), 'nor on a var the offense lacks' );
is_deeply( \%data, {}, 'which lifts nothing either' );

%data = ( 'src' => '203.0.113.9', 'COUNTRY' => 'from the line' );
$lift_only->holds( \%data, undef );
is( $data{COUNTRY}, 'from the line', 'a value the offense already has is not lifted over' );

my $judging_lift = country_gate( { 'isnot' => 'US', 'vars' => 'src', 'into' => 'COUNTRY' }, \%countries, {} );
%data = ( 'src' => '198.51.100.5' );
ok( !$judging_lift->holds( \%data, undef ), 'a gate that judges and lifts still vetoes' );
ok( !exists( $data{COUNTRY} ),              'and a vetoed offense is lifted nothing' );
%data = ( 'src' => '203.0.113.9' );
ok( $judging_lift->holds( \%data, undef ), 'and it lifts into what it holds for' );
is( $data{COUNTRY}, 'NL', 'the code of the address it judged' );
%data = ( 'src' => '192.0.2.66' );
ok( !$judging_lift->holds( \%data, undef ), 'one that judges still fails closed on a address it can not place' );

foreach my $bad ( { 'into' => 'COUNTRY' }, { 'is' => 'US', 'vars' => [ 'src', 'dst' ], 'into' => 'COUNTRY' } ) {
	ok(
		!eval {
			App::Baphomet::Gate::country->new( 'type' => 'country', 'args' => $bad, 'where' => 'the gate' );
			1;
		},
		'a into with ' . scalar( @{ ref( $bad->{vars} ) ? $bad->{vars} : [] } ) . ' vars is refused'
	);
	like( $@, qr/^the gate has a into, which needs exactly one var to lift the country of/, 'and says why' );
}
ok(
	!eval {
		App::Baphomet::Gate::country->new( 'type' => 'country', 'args' => { 'vars' => 'src' }, 'where' => 'the gate' );
		1;
	},
	'a gate with nothing to do is refused'
);
like( $@, qr/^the gate has none of is, isnot, or into/, 'and says so' );

done_testing;
