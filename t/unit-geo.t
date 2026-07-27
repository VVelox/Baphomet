#!perl
# direct unit tests for App::Baphomet::Geo, the country gate's pure
# judgment... a mock locator stands in for the GeoIP lookups, so the
# fail-closed rules and the token resolution are pinned without a database
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Geo qw( resolve_country_gate country_gate_pass );

# a locator over a fixture map... an upcased ISO code, or undef for a
# address it can not place
sub locator {
	my ($map) = @_;
	return sub { return $map->{ $_[0] }; };
}

#
# resolve_country_gate... token expansion, upcasing, and the loud die on a
# undefined list
#

my $gate = resolve_country_gate(
	{ 'mode' => 'isnot', 'entries' => [ '%%%country_codes{home}%%%', 'mx' ], 'vars' => ['src'] },
	{ 'home' => [ 'us', 'ca' ] },
	'the rule "x"'
);
is( $gate->{mode}, 'isnot', 'the mode carries through' );
is_deeply( $gate->{vars}, ['src'], 'the vars carry through' );
is_deeply(
	[ sort keys %{ $gate->{codes} } ],
	[ 'CA', 'MX', 'US' ],
	'the token expands and every code is upcased into the set'
);

is( resolve_country_gate( undef, {}, 'x' ), undef, 'no country key resolves to undef' );

ok(
	!eval {
		resolve_country_gate( { 'mode' => 'is', 'entries' => ['%%%country_codes{nope}%%%'], 'vars' => undef },
			{ 'home' => ['US'] }, 'the rule "x"' );
		1;
	},
	'importing a list the config does not define dies'
);
like( $@, qr/country_codes\{nope\}/, 'and the die names the missing list' );

#
# country_gate_pass... fail closed with no locator or on a unplaceable
# value, and the two modes
#

my $loc = locator( { '203.0.113.9' => 'NL', '198.51.100.5' => 'US' } );

# a vars gate is data-driven, ran in the data pass (ip undef)
my $isnot = { 'mode' => 'isnot', 'codes' => { 'US' => 1 }, 'vars' => ['src'] };
ok( country_gate_pass( $loc, $isnot, { 'src' => '203.0.113.9' }, undef ),
	'isnot US counts an address abroad' );
ok( !country_gate_pass( $loc, $isnot, { 'src' => '198.51.100.5' }, undef ),
	'and spares one at home' );

# a value it can not place fails closed... an unknown country is unclearable
ok( !country_gate_pass( $loc, $isnot, { 'src' => '192.0.2.66' }, undef ),
	'an unplaceable address fails closed, isnot never clearing it' );

# a undef locator fails closed even when the gate would otherwise hold
ok( !country_gate_pass( undef, $isnot, { 'src' => '203.0.113.9' }, undef ),
	'a undef locator fails closed' );

# the is form, var-less, ran in the offender pass (ip set)
my $is = { 'mode' => 'is', 'codes' => { 'US' => 1, 'CA' => 1 }, 'vars' => undef };
ok( country_gate_pass( $loc, $is, {}, '198.51.100.5' ), 'is US counts a home offender' );
ok( !country_gate_pass( $loc, $is, {}, '203.0.113.9' ), 'and drops a foreign one' );
ok( !country_gate_pass( $loc, $is, {}, '192.0.2.66' ), 'a unplaceable offender fails closed under is too' );

# the mode/pass split... a vars gate is skipped in the offender pass, a
# var-less one in the data pass
ok( country_gate_pass( $loc, $isnot, { 'src' => '198.51.100.5' }, '198.51.100.5' ),
	'a vars gate is skipped in the offender pass, holding vacuously' );
ok( country_gate_pass( $loc, $is, {}, undef ),
	'a var-less gate is skipped in the data pass, holding vacuously' );

# a undef gate always passes
ok( country_gate_pass( $loc, undef, {}, '203.0.113.9' ), 'a undef gate passes' );

done_testing;
