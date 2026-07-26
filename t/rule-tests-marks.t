#!perl
# the embedded-test mark machinery... run_tests driving the extracted
# mark core against a throwaway store and a virtual clock, so a rule
# file proves its own branding and gating cold. exercised over ad-hoc
# json rules, no galla anywhere
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Rules::JSON ();

sub results_for {
	my (%def) = @_;
	my $rule = App::Baphomet::Rules::JSON->new(
		name => 'json/x',
		def  => {
			gate    => [ { field => 'event', values => ['fail'] } ],
			ban_var => ['ip'],
			%def,
		}
	);
	return $rule->run_tests;
}

sub line {
	my (%fields) = @_;
	my @parts = map { '"' . $_ . '":"' . $fields{$_} . '"' } sort( keys(%fields) );
	return '{' . join( ',', @parts ) . '}';
}

#
# a marked gate... unseeded it vetoes, seeded it holds, and the value
# compares hold or veto by the stored value
#

my $gated = results_for(
	marked => [ { name => 'known', var => 'ip' } ],
	tests  => {
		positive => [
			{
				message      => line( event => 'fail', ip => '1.2.3.4' ),
				marks_before => [ { name => 'known', key => '1.2.3.4' } ],
			},
		],
		negative => [
			# the same matching line, unseeded... the gate is load-bearing
			{ message => line( event => 'fail', ip => '1.2.3.4' ) },
			# seeded on a different key, still vetoed
			{
				message      => line( event => 'fail', ip => '1.2.3.4' ),
				marks_before => [ { name => 'known', key => '5.6.7.8' } ],
			},
		],
	},
);
is( $gated->{fail}, 0, 'a seeded marked gate holds and unseeded vetoes' ) || diag( join( "\n", @{ $gated->{failures} } ) );
is( $gated->{pass}, 3, 'all three gate tests counted' );

#
# value compares on the gate, driven by the seed's value
#

my $valued = results_for(
	marked => [ { name => 'acct', var => 'user', value_not => 'ip' } ],
	tests  => {
		positive => [
			{
				message      => line( event => 'fail', ip => '2.2.2.2', user => 'admin' ),
				marks_before => [ { name => 'acct', key => 'admin', value => '1.1.1.1' } ],
			},
		],
		negative => [
			{
				message      => line( event => 'fail', ip => '1.1.1.1', user => 'admin' ),
				marks_before => [ { name => 'acct', key => 'admin', value => '1.1.1.1' } ],
			},
		],
	},
);
is( $valued->{fail}, 0, 'value_not proves both ways from the seed' ) || diag( join( "\n", @{ $valued->{failures} } ) );

#
# branding asserted... marks_expected sees what the rule set, absent
# what it did not, and the compound vars key round-trips as a list
#

my $branded = results_for(
	mark  => [ { name => 'pair', ttl => 60, vars => [ 'ip', 'user' ], value_var => 'ip' } ],
	tests => {
		positive => [
			{
				message        => line( event => 'fail', ip => '3.3.3.3', user => 'bob' ),
				marks_expected => [
					{ name => 'pair', key => [ '3.3.3.3', 'bob' ], value => '3.3.3.3' },
					{ name => 'pair', key => [ '3.3.3.3', 'alice' ], absent => 1 },
					{ name => 'other', key => '3.3.3.3', absent => 1 },
				],
			},
		],
	},
);
is( $branded->{fail}, 0, 'marks_expected proves the vars brand, its value, and the absences' )
	|| diag( join( "\n", @{ $branded->{failures} } ) );

#
# the virtual clock... a seeded brand outlived by advance: expires, and
# the sequence gate orders by seeded set times
#

my $expired = results_for(
	marked => [ { name => 'known', var => 'ip' } ],
	tests  => {
		negative => [
			{
				marks_before => [ { name => 'known', key => '4.4.4.4', ttl => 60 } ],
				messages     => [ { message => line( event => 'fail', ip => '4.4.4.4' ), advance => 120 } ],
			},
		],
		positive => [
			{
				marks_before => [ { name => 'known', key => '4.4.4.4', ttl => 60 } ],
				messages     => [ { message => line( event => 'fail', ip => '4.4.4.4' ), advance => 30 } ],
			},
		],
	},
);
is( $expired->{fail}, 0, 'the clock expires a seeded brand past its ttl' )
	|| diag( join( "\n", @{ $expired->{failures} } ) );

my $sequenced = results_for(
	sequence => [ { marks => [ 'stage1', 'stage2' ], var => 'ip' } ],
	tests    => {
		positive => [
			{
				message      => line( event => 'fail', ip => '5.5.5.5' ),
				marks_before => [
					{ name => 'stage1', key => '5.5.5.5', set => 1_000_000_000 },
					{ name => 'stage2', key => '5.5.5.5', set => 1_000_000_100 },
				],
			},
		],
		negative => [
			# the same brands, set out of order... the sequence vetoes
			{
				message      => line( event => 'fail', ip => '5.5.5.5' ),
				marks_before => [
					{ name => 'stage1', key => '5.5.5.5', set => 1_000_000_100 },
					{ name => 'stage2', key => '5.5.5.5', set => 1_000_000_000 },
				],
			},
		],
	},
);
is( $sequenced->{fail}, 0, 'the sequence gate proves ordering from seeded set times' )
	|| diag( join( "\n", @{ $sequenced->{failures} } ) );

#
# found_after and marks_after assert mid-run, and a brand set by one
# line gates a later line in the same entry
#

my $staged = results_for(
	mark_only => 1,
	mark      => [ { name => 'seen', ttl => 3600, var => 'ip' } ],
	tests     => {
		positive => [
			{
				found    => 2,
				messages => [
					{
						message     => line( event => 'fail', ip => '6.6.6.6' ),
						found_after => 1,
						marks_after => [ { name => 'seen', key => '6.6.6.6' } ],
					},
					{ message => line( event => 'fail', ip => '6.6.6.6' ), found_after => 2 },
				],
			},
		],
	},
);
is( $staged->{fail}, 0, 'found_after and marks_after hold mid-run' )
	|| diag( join( "\n", @{ $staged->{failures} } ) );

#
# the typo guard... unknown keys anywhere in the new schema are failures,
# not silence
#

foreach my $broken (
	{ 'desc' => 'a test entry key', 'tests' => { positive => [ { message => line( event => 'fail', ip => '1.1.1.1' ), marks_befor => [] } ] } },
	{
		'desc'  => 'a marks_before key',
		'tests' => {
			positive => [
				{
					message      => line( event => 'fail', ip => '1.1.1.1' ),
					marks_before => [ { name => 'x', key => 'k', tttl => 5 } ],
				}
			]
		}
	},
	{
		'desc'  => 'a marks_expected key',
		'tests' => {
			positive => [
				{
					message        => line( event => 'fail', ip => '1.1.1.1' ),
					marks_expected => [ { name => 'x', key => 'k', absnt => 1 } ],
				}
			]
		}
	},
	{
		'desc'  => 'a messages entry key',
		'tests' => {
			positive => [ { messages => [ { message => line( event => 'fail', ip => '1.1.1.1' ), advanec => 5 } ] } ]
		}
	},
	)
{
	my $broken_results = results_for( tests => $broken->{tests} );
	cmp_ok( $broken_results->{fail}, '>', 0, 'a typo in ' . $broken->{desc} . ' fails the tests' );
}

done_testing;
