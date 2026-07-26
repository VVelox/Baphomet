#!perl
# the embedded-test geo fixtures... run_tests driving the extracted
# country gate core over a rule file's own geo: maps, so a
# geography-gated rule proves its judgment cold. exercised over ad-hoc
# json rules, no galla and no database anywhere
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Rules::JSON ();

sub results_for {
	my (%def) = @_;
	my %merged = (
		gate    => [ { field => 'event', values => ['fail'] } ],
		ban_var => ['ip'],
		%def,
	);
	foreach my $key ( keys(%merged) ) {
		delete( $merged{$key} ) if !defined( $merged{$key} );
	}
	my $rule = App::Baphomet::Rules::JSON->new( name => 'json/x', def => \%merged );
	return $rule->run_tests;
}

sub line {
	my (%fields) = @_;
	my @parts = map { '"' . $_ . '":"' . $fields{$_} . '"' } sort( keys(%fields) );
	return '{' . join( ',', @parts ) . '}';
}

#
# the foreign-login shape... a vars-form isnot gate over a named list,
# resolved from the fixture's lists and judged from its countries
#

my $foreign = results_for(
	country       => { isnot => ['%%%country_codes{home}%%%'], vars => ['ip'] },
	ban_var       => undef,
	detection_var => ['ip'],
	tests         => {
		positive => [
			# abroad... the gate lets it count
			{
				message => line( event => 'fail', ip => '203.0.113.9' ),
				geo     => {
					countries => { '203.0.113.9' => 'NL' },
					lists     => { home => ['US'] },
				},
			},
		],
		negative => [
			# at home... spared
			{
				message => line( event => 'fail', ip => '198.51.100.5' ),
				geo     => {
					countries => { '198.51.100.5' => 'us' },
					lists     => { home => ['US'] },
				},
			},
			# unplaceable fails closed... an unknown country is unclearable
			{
				message => line( event => 'fail', ip => '192.0.2.66' ),
				geo     => {
					countries => { '192.0.2.66' => 'unknown' },
					lists     => { home => ['US'] },
				},
			},
			# unfixtured is unplaceable too
			{
				message => line( event => 'fail', ip => '192.0.2.67' ),
				geo     => { lists => { home => ['US'] } },
			},
		],
	},
);
is( $foreign->{fail}, 0, 'the vars-form isnot gate proves all four ways' )
	|| diag( join( "\n", @{ $foreign->{failures} } ) );
is( $foreign->{pass}, 4, 'all four counted' );

#
# the is form with literal codes, and a var-less gate on a ban rule
# running the offender pass
#

my $is_form = results_for(
	country => { is => [ 'US', 'CA' ] },
	tests   => {
		positive => [
			{
				message => line( event => 'fail', ip => '198.51.100.5' ),
				geo     => { countries => { '198.51.100.5' => 'CA' } },
			},
		],
		negative => [
			{
				message => line( event => 'fail', ip => '203.0.113.9' ),
				geo     => { countries => { '203.0.113.9' => 'NL' } },
			},
		],
	},
);
is( $is_form->{fail}, 0, 'a var-less is gate proves both ways in the offender pass' )
	|| diag( join( "\n", @{ $is_form->{failures} } ) );

#
# galla parity... a var-less gate on a detection rule is inert there, so
# it is inert here, fixture or no
#

my $detection = results_for(
	country       => { isnot => ['US'] },
	ban_var       => undef,
	detection_var => ['ip'],
	tests         => {
		positive => [
			{
				message => line( event => 'fail', ip => '198.51.100.5' ),
				geo     => { countries => { '198.51.100.5' => 'US' } },
			},
		],
	},
);
is( $detection->{fail}, 0, 'a var-less gate on a detection rule stays inert, as in the galla' )
	|| diag( join( "\n", @{ $detection->{failures} } ) );

#
# no fixture, no gate... the old behavior holds for a gated rule whose
# test does not opt in
#

my $unfixtured = results_for(
	country => { isnot => ['%%%country_codes{home}%%%'], vars => ['ip'] },
	tests   => { positive => [ { message => line( event => 'fail', ip => '203.0.113.9' ) } ] },
);
is( $unfixtured->{fail}, 0, 'a gated rule with no geo fixture skips the gate as before' )
	|| diag( join( "\n", @{ $unfixtured->{failures} } ) );

#
# the typo guard... a malformed fixture or an unresolvable list is a
# failure, not silence
#

foreach my $broken (
	{ 'desc' => 'an unknown geo key', 'geo' => { countries => {}, list => {} } },
	{ 'desc' => 'a bad country code', 'geo' => { countries => { '1.2.3.4' => 'USA' } } },
	{
		'desc' => 'an import of an undefined list',
		'geo'  => { countries => { '203.0.113.9' => 'NL' }, lists => { hoem => ['US'] } }
	},
	)
{
	my $broken_results = results_for(
		country => { isnot => ['%%%country_codes{home}%%%'], vars => ['ip'] },
		tests   => {
			positive => [ { message => line( event => 'fail', ip => '203.0.113.9' ), geo => $broken->{geo} } ]
		},
	);
	cmp_ok( $broken_results->{fail}, '>', 0, $broken->{desc} . ' fails the tests' );
}

done_testing;
