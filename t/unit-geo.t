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

done_testing;
