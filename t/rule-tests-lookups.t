#!perl
# the embedded-test fixtures of the gates that look something up... run_tests
# driving the asn, dnsbl, account, and limit gates and the country lift over
# a rule file's own fixtures, so a rule using one proves itself cold.
# exercised over ad-hoc json rules, no galla, no database, and no resolver
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Rule ();

# every rule here leads with the one gate, and the rest of its list is the
# passed rule_gates
sub results_for {
	my (%def) = @_;
	$def{rule_gates} = [ { gate => [ { field => 'event', values => ['fail'] } ] }, @{ $def{rule_gates} } ];
	my $rule = App::Baphomet::Rule->new( name => 'json/x', def => \%def );
	return $rule->run_tests;
}

sub line {
	my (%fields) = @_;
	my @parts = map { '"' . $_ . '":"' . $fields{$_} . '"' } sort( keys(%fields) );
	return '{' . join( ',', @parts ) . '}';
}

# a run that has to pass whole
sub proves {
	my ( $results, $count, $description ) = @_;
	is( $results->{fail}, 0, $description ) || diag( join( "\n", @{ $results->{failures} } ) );
	is( $results->{pass}, $count, '...all ' . $count . ' entries of it' );
	return;
}

my $fail_line = line( event => 'fail', ip => '203.0.113.9' );

#
# the country lift
#

proves(
	results_for(
		rule_gates => [ { country => { vars => ['ip'], into => 'COUNTRY' } }, { ban_var => ['ip'] } ],
		tests      => {
			positive => [
				{ message => $fail_line, geo => { countries => { '203.0.113.9' => 'nl' } }, data => { COUNTRY => 'NL' } },
				# a address the fixture does not place is lifted nothing and not vetoed
				{ message => $fail_line, geo => { countries => {} }, undefed => ['COUNTRY'] },
			],
		},
	),
	2,
	'a country gate that only lifts proves its lift and its lack of a veto'
);

my $wrong_country = results_for(
	rule_gates => [ { country => { vars => ['ip'], into => 'COUNTRY' } }, { ban_var => ['ip'] } ],
	tests      => {
		positive =>
			[ { message => $fail_line, geo => { countries => { '203.0.113.9' => 'nl' } }, data => { COUNTRY => 'DE' } } ],
	},
);
is( $wrong_country->{fail}, 1, 'a data block expecting the wrong country fails, so the lift is really asserted' );

#
# asn
#

proves(
	results_for(
		rule_gates => [
			{
				asn => { is => [ 'AS64496', '%%%asn_lists{hosting}%%%' ], vars => ['ip'], into => 'ASN', org_into => 'ORG' }
			},
			{ ban_var => ['ip'] },
		],
		tests => {
			positive => [
				# listed outright, a fixture network given as a hash
				{
					message => $fail_line,
					geo     => {
						asns      => { '203.0.113.9' => { number => 64496, org => 'Example Hosting' } },
						asn_lists => { hosting       => [64500] },
					},
					data => { ASN => 64496, ORG => 'Example Hosting' },
				},
				# listed by the import, a fixture network given as a bare number
				{
					message => $fail_line,
					geo     => { asns => { '203.0.113.9' => 'AS64500' }, asn_lists => { hosting => ['AS64500'] } },
					data    => { ASN  => 64500 },
					undefed => ['ORG'],
				},
			],
			negative => [
				{
					message => $fail_line,
					geo     => { asns => { '203.0.113.9' => 64511 }, asn_lists => { hosting => [64500] } },
				},
				# unplaceable fails closed, said outright or left unfixtured
				{
					message => $fail_line,
					geo     => { asns => { '203.0.113.9' => 'unknown' }, asn_lists => { hosting => [64500] } },
				},
				{ message => $fail_line, geo => { asns => {}, asn_lists => { hosting => [64500] } } },
			],
		},
	),
	5,
	'a asn gate over numbers proves itself from the geo fixture'
);

proves(
	results_for(
		rule_gates => [ { ban_var => ['ip'] }, { asn => { org_isnot => '(?i)hosting' } } ],
		tests      => {
			positive => [
				{
					message => $fail_line,
					geo     => { asns => { '203.0.113.9' => { number => 64496, org => 'Example Telecom' } } },
				},
			],
			negative => [
				{
					message => $fail_line,
					geo     => { asns => { '203.0.113.9' => { number => 64496, org => 'Example HOSTING' } } },
				},
				# a network with no name can not be cleared by its name
				{ message => $fail_line, geo => { asns => { '203.0.113.9' => 64496 } } },
			],
		},
	),
	3,
	'a asn gate over the name proves itself in the offender pass'
);

#
# dnsbl
#

proves(
	results_for(
		rule_gates => [ { ban_var => ['ip'] }, { dnsbl => { zones => [ 'bl.example.org', 'bl2.example.org' ] } } ],
		tests      => {
			positive => [
				{ message => $fail_line, dns => { dnsbl => { 'bl.example.org' => { '203.0.113.9' => ['127.0.0.2'] } } } },
				# a listing stands though the zone ahead of it could not be asked
				{
					message => $fail_line,
					dns     => {
						dnsbl => {
							'bl.example.org'  => { '203.0.113.9' => 'servfail' },
							'bl2.example.org' => { '203.0.113.9' => ['127.0.0.4'] },
						}
					},
				},
			],
			negative => [
				{
					message => $fail_line,
					dns     => {
						dnsbl => {
							'bl.example.org'  => { '203.0.113.9' => 'nxdomain' },
							'bl2.example.org' => { '203.0.113.9' => 'nxdomain' },
						}
					},
				},
				# a refusal is no listing
				{
					message => $fail_line,
					dns     => {
						dnsbl => {
							'bl.example.org'  => { '203.0.113.9' => ['127.255.255.254'] },
							'bl2.example.org' => { '203.0.113.9' => 'nxdomain' },
						}
					},
				},
				# a zone the fixture never mentions could not be asked
				{ message => $fail_line, dns => { dnsbl => { 'bl.example.org' => { '203.0.113.9' => 'nxdomain' } } } },
			],
		},
	),
	5,
	'a dnsbl gate proves itself from the dns fixture'
);

#
# account
#

proves(
	results_for(
		rule_gates => [ { account => { var => 'user', exists => 0 } }, { ban_var => ['ip'] } ],
		tests      => {
			positive =>
				[ { message => line( event => 'fail', ip => '203.0.113.9', user => 'oracle' ), accounts => ['neti'] } ],
			negative => [
				{ message => line( event => 'fail', ip => '203.0.113.9', user => 'neti' ), accounts => ['neti'] },
				# no name at all fails closed
				{ message => $fail_line, accounts => ['neti'] },
			],
		},
	),
	3,
	'a account gate proves itself from the accounts fixture'
);

#
# limit, which needs no fixture, over the virtual clock
#

my $other_line = line( event => 'fail', ip => '203.0.113.10' );
proves(
	results_for(
		rule_gates => [ { detection_var => ['ip'] }, { limit => { by => 'ip', count => 2, seconds => 60 } } ],
		tests      => {
			positive => [
				{ messages => [ ($fail_line) x 4 ], found => 2 },
				# the window run out, the key is let by again
				{ messages => [ ($fail_line) x 3, { message => $fail_line, advance => 60 } ], found => 3 },
				# another key has a window of its own
				{ messages => [ $fail_line, $fail_line, $fail_line, $other_line ], found => 3 },
				# and a window does not outlive the entry that opened it
				{ messages => [ $fail_line, $fail_line ], found => 2 },
			],
		},
	),
	4,
	'a limit gate proves its windows over the virtual clock, each entry starting clean'
);

#
# a gate with out its fixture is skipped, and a fixture for one lookup does
# not stand in for another
#

proves(
	results_for(
		rule_gates => [
			{ ban_var => ['ip'] },
			{ asn     => { is    => 64496 } },
			{ dnsbl   => { zones => 'bl.example.org' } },
			{ account => { var   => 'user' } },
		],
		tests => { positive => [ { message => $fail_line } ] },
	),
	1,
	'the three lookups with no fixture go unjudged'
);

proves(
	results_for(
		rule_gates => [
			{ ban_var     => ['ip'] },
			{ dnsbl       => { zones   => 'bl.example.org' } },
			{ reverse_dns => { matches => '\.example\.org$' } },
		],
		tests => {
			positive => [
				{ message => $fail_line, dns => { dnsbl => { 'bl.example.org' => { '203.0.113.9' => ['127.0.0.2'] } } } }
			],
		},
	),
	1,
	'a dns fixture of blocklists alone leaves a reverse_dns gate unjudged'
);

proves(
	results_for(
		rule_gates => [ { ban_var => ['ip'] }, { asn => { is => 64496 } }, { country => { is => 'US' } } ],
		tests      => { positive => [ { message => $fail_line, geo => { asns => { '203.0.113.9' => 64496 } } } ] },
	),
	1,
	'a geo fixture of networks alone leaves a country gate unjudged'
);

#
# malformed fixtures are failures, not silence
#

my %malformed = (
	'a dnsbl zone that is not a hash' =>
		[ { dns => { dnsbl => { 'bl.example.org' => ['127.0.0.2'] } } }, qr/dns dnsbl "bl\.example\.org" is not a hash/ ],
	'a dnsbl answer that is no answer' => [
		{ dns => { dnsbl => { 'bl.example.org' => { '203.0.113.9' => 'listed' } } } },
		qr/dns dnsbl "bl\.example\.org" "203\.0\.113\.9" is not a list of names\/addresses, nxdomain, or servfail/
	],
	'a asns entry that is no number' =>
		[ { geo => { asns => { '203.0.113.9' => 'hosting' } } }, qr/geo asns "203\.0\.113\.9" is not a AS number/ ],
	'a asn_lists entry that is no array' =>
		[ { geo => { asn_lists => { hosting => 64496 } } }, qr/geo asn_lists "hosting" is not a array/ ],
	'a accounts that is no array' => [ { accounts => 'neti' }, qr/accounts is not a array of names/ ],
);
foreach my $description ( sort( keys(%malformed) ) ) {
	my ( $fixture, $message ) = @{ $malformed{$description} };
	my $results = results_for(
		rule_gates => [ { ban_var => ['ip'] } ],
		tests      => { positive => [ { message => $fail_line, %{$fixture} } ] },
	);
	is( $results->{fail}, 1, $description . ' fails the entry' );
	like( join( "\n", @{ $results->{failures} } ), $message, '...and says what is wrong with it' );
}

done_testing();
