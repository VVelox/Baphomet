#!perl
# the embedded-test dns fixtures... run_tests driving the extracted
# reverse_dns core over a rule file's own dns: maps, so a lookup-gated
# rule proves its judgment cold. exercised over ad-hoc json rules, no
# galla and no resolver anywhere
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
	# a undef value means the caller wants the default key gone entirely...
	# how the detection variant sheds the ban_var
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
# the fakegooglebot shape... a negated, forward-confirmed gate, var-less
# so it runs the offender pass, driven wholly by the fixtures
#

my $negated = results_for(
	reverse_dns => [ { matches => '\.crawler\.example$', negate => 1 } ],
	tests       => {
		positive => [
			# a confirmed PTR that is not the crawler's... counted
			{
				message => line( event => 'fail', ip => '192.0.2.10' ),
				dns     => {
					ptr     => { '192.0.2.10' => ['other.example'] },
					forward => { 'other.example' => ['192.0.2.10'] },
				},
			},
			# no PTR at all is authoritative absence... counted
			{
				message => line( event => 'fail', ip => '192.0.2.11' ),
				dns     => { ptr => { '192.0.2.11' => 'nxdomain' } },
			},
			# a spoofed PTR fails forward confirmation... as good as absent
			{
				message => line( event => 'fail', ip => '192.0.2.12' ),
				dns     => {
					ptr     => { '192.0.2.12' => ['bot.crawler.example'] },
					forward => { 'bot.crawler.example' => ['198.51.100.9'] },
				},
			},
		],
		negative => [
			# the real crawler, confirmed... the negate spares it
			{
				message => line( event => 'fail', ip => '192.0.2.13' ),
				dns     => {
					ptr     => { '192.0.2.13' => ['bot.crawler.example'] },
					forward => { 'bot.crawler.example' => ['192.0.2.13'] },
				},
			},
			# a lookup failure vetoes even a negated gate
			{
				message => line( event => 'fail', ip => '192.0.2.14' ),
				dns     => { ptr => { '192.0.2.14' => 'servfail' } },
			},
			# unfixtured is servfail... fail closed
			{
				message => line( event => 'fail', ip => '192.0.2.15' ),
				dns     => { ptr => {} },
			},
		],
	},
);
is( $negated->{fail}, 0, 'the negated forward-confirmed gate proves all six ways' )
	|| diag( join( "\n", @{ $negated->{failures} } ) );
is( $negated->{pass}, 6, 'all six counted' );

#
# no fixture, no gate... the old behavior holds for a gated rule whose
# test does not opt in
#

my $unfixtured = results_for(
	reverse_dns => [ { matches => '\.crawler\.example$', negate => 1 } ],
	tests       => { positive => [ { message => line( event => 'fail', ip => '192.0.2.10' ) } ] },
);
is( $unfixtured->{fail}, 0, 'a gated rule with no dns fixture skips the gate as before' )
	|| diag( join( "\n", @{ $unfixtured->{failures} } ) );

#
# a var-keyed entry runs the data pass, and matches_var compares against
# the line's own claim
#

my $claimed = results_for(
	reverse_dns => [ { matches_var => 'claim', var => 'ip' } ],
	tests       => {
		positive => [
			{
				message => line( event => 'fail', ip => '192.0.2.20', claim => 'mail.example' ),
				dns     => {
					ptr     => { '192.0.2.20' => ['mail.example'] },
					forward => { 'mail.example' => ['192.0.2.20'] },
				},
			},
		],
		negative => [
			{
				message => line( event => 'fail', ip => '192.0.2.20', claim => 'other.example' ),
				dns     => {
					ptr     => { '192.0.2.20' => ['mail.example'] },
					forward => { 'mail.example' => ['192.0.2.20'] },
				},
			},
		],
	},
);
is( $claimed->{fail}, 0, 'a var-keyed matches_var entry proves both ways in the data pass' )
	|| diag( join( "\n", @{ $claimed->{failures} } ) );

#
# the knobs... forward_confirm refused takes the spoof, on_servfail
# compare counts through an outage under negate, on_servfail pass is
# terminal
#

my $knobs = results_for(
	reverse_dns => [ { matches => '\.crawler\.example$', negate => 1, forward_confirm => 0 } ],
	tests       => {
		negative => [
			# with confirmation refused the spoofed PTR is taken at its word
			{
				message => line( event => 'fail', ip => '192.0.2.30' ),
				dns     => { ptr => { '192.0.2.30' => ['bot.crawler.example'] } },
			},
		],
	},
);
is( $knobs->{fail}, 0, 'forward_confirm refused takes the PTR at its word' )
	|| diag( join( "\n", @{ $knobs->{failures} } ) );

my $sfcompare = results_for(
	reverse_dns => [ { matches => '\.crawler\.example$', negate => 1, on_servfail => 'compare' } ],
	tests       => {
		positive => [
			{
				message => line( event => 'fail', ip => '192.0.2.31' ),
				dns     => { ptr => { '192.0.2.31' => 'servfail' } },
			},
		],
	},
);
is( $sfcompare->{fail}, 0, 'on_servfail compare counts through the outage, knowingly' )
	|| diag( join( "\n", @{ $sfcompare->{failures} } ) );

my $sfpass = results_for(
	reverse_dns => [ { matches => '\.crawler\.example$', on_servfail => 'pass' } ],
	tests       => {
		positive => [
			{
				message => line( event => 'fail', ip => '192.0.2.32' ),
				dns     => { ptr => { '192.0.2.32' => 'servfail' } },
			},
		],
	},
);
is( $sfpass->{fail}, 0, 'on_servfail pass is a terminal verdict' )
	|| diag( join( "\n", @{ $sfpass->{failures} } ) );

#
# galla parity... a var-less gate on a detection rule is inert there, so
# it is inert here, fixture or no
#

my $detection = results_for(
	ban_var       => undef,
	detection_var => ['ip'],
	reverse_dns   => [ { matches => '\.crawler\.example$', negate => 1 } ],
	tests         => {
		positive => [
			{
				message => line( event => 'fail', ip => '192.0.2.40' ),
				dns     => { ptr => { '192.0.2.40' => 'servfail' } },
			},
		],
	},
);
is( $detection->{fail}, 0, 'a var-less gate on a detection rule stays inert, as in the galla' )
	|| diag( join( "\n", @{ $detection->{failures} } ) );

#
# the typo guard... a malformed fixture is a failure, not silence
#

foreach my $broken (
	{ 'desc' => 'an unknown dns key',    'dns' => { ptrs => {} } },
	{ 'desc' => 'a non-hash ptr map',    'dns' => { ptr => [] } },
	{ 'desc' => 'a bad answer spelling', 'dns' => { ptr => { '192.0.2.50' => 'nxdomian' } } },
	)
{
	my $broken_results = results_for(
		reverse_dns => [ { matches => '\.crawler\.example$', negate => 1 } ],
		tests       => {
			positive => [ { message => line( event => 'fail', ip => '192.0.2.50' ), dns => $broken->{dns} } ]
		},
	);
	cmp_ok( $broken_results->{fail}, '>', 0, $broken->{desc} . ' fails the tests' );
}

done_testing;
