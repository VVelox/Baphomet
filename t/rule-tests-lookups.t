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

# what is known of each account, as a hash in place of the list
my %host_accounts = (
	neti => { uid => 1001, shell => '/bin/sh', groups => ['wheel'] },
	www  => { uid => 80,   shell => '/usr/sbin/nologin' },
	kur  => undef,
);
proves(
	results_for(
		rule_gates => [ { account => { var => 'user', shell => 'nologin' } }, { ban_var => ['ip'] } ],
		tests      => {
			positive => [ { message => line( event => 'fail', ip => '203.0.113.9', user => 'www' ), accounts => \%host_accounts } ],
			negative => [
				{ message => line( event => 'fail', ip => '203.0.113.9', user => 'neti' ),   accounts => \%host_accounts },
				{ message => line( event => 'fail', ip => '203.0.113.9', user => 'oracle' ), accounts => \%host_accounts },
				# a account the fixture says nothing of fails closed, as does one out of a list
				{ message => line( event => 'fail', ip => '203.0.113.9', user => 'kur' ), accounts => \%host_accounts },
				{ message => line( event => 'fail', ip => '203.0.113.9', user => 'www' ), accounts => ['www'] },
			],
		},
	),
	5,
	'a account gate asking the shell proves itself from a accounts fixture that is a hash'
);
proves(
	results_for(
		rule_gates => [ { account => { var => 'user', group => 'wheel', system => 0 } }, { ban_var => ['ip'] } ],
		tests      => {
			positive => [ { message => line( event => 'fail', ip => '203.0.113.9', user => 'neti' ), accounts => \%host_accounts } ],
			negative => [ { message => line( event => 'fail', ip => '203.0.113.9', user => 'www' ), accounts => \%host_accounts } ],
		},
	),
	2,
	'and one asking the group and the uid'
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
# after, which needs no fixture either
#

proves(
	results_for(
		rule_gates => [ { after => { by => 'user', count => 3, seconds => 60 } }, { ban_var => ['ip'] } ],
		tests      => {
			positive => [
				# the third against one account holds, whoever it came from
				{
					messages => [
						line( event => 'fail', ip => '203.0.113.9',  user => 'neti' ),
						line( event => 'fail', ip => '203.0.113.10', user => 'neti' ),
						line( event => 'fail', ip => '203.0.113.11', user => 'neti' ),
					],
					found => 1,
					data  => { ip => '203.0.113.11' },
				},
			],
			negative => [
				# two is not three, and what a entry before this one saw is gone
				{
					messages => [
						line( event => 'fail', ip => '203.0.113.9',  user => 'neti' ),
						line( event => 'fail', ip => '203.0.113.10', user => 'neti' ),
					],
				},
				# three, but not with in the sixty seconds
				{
					messages => [
						line( event => 'fail', ip => '203.0.113.9', user => 'neti' ),
						line( event => 'fail', ip => '203.0.113.9', user => 'neti' ),
						{ message => line( event => 'fail', ip => '203.0.113.9', user => 'neti' ), advance => 60 },
					],
				},
				# three accounts once each are three keys
				{
					messages => [
						line( event => 'fail', ip => '203.0.113.9', user => 'neti' ),
						line( event => 'fail', ip => '203.0.113.9', user => 'namtar' ),
						line( event => 'fail', ip => '203.0.113.9', user => 'kur' ),
					],
				},
			],
		},
	),
	4,
	'a after gate proves its count over the virtual clock, each entry starting clean'
);

#
# travel, placed by the geo fixture and remembered in the entry's own marks
#

my %cities = (
	'198.51.100.5' => [ 51.5072, -0.1276 ],                                  # London
	'203.0.113.9'  => { lat => 40.7128, lon => -74.0060, radius => 20 },     # New York
);
my $london   = line( event => 'fail', ip => '198.51.100.5', user => 'neti' );
my $new_york = line( event => 'fail', ip => '203.0.113.9',  user => 'neti' );
proves(
	results_for(
		rule_gates => [
			{
				travel => {
					name => 'last-seen', by => 'user', var => 'ip', faster_than_kmh => 900, km_into => 'KM',
				}
			},
			{ detection_var => ['ip'] },
		],
		tests => {
			positive => [
				# New York a hour after London, both sightings the rule's own
				{
					messages       => [ $london, { message => $new_york, advance => 3600 } ],
					geo            => { locations => \%cities },
					found          => 1,
					data           => { KM => 5550 },
					marks_expected => [ { name => 'last-seen', key => 'neti', value => '40.7128 -74.0060 20 1000003600' } ],
				},
				# and against a sighting some line before the test left
				{
					message      => $new_york,
					geo          => { locations => \%cities },
					marks_before => [ { name => 'last-seen', key => 'neti', value => '51.5072 -0.1276 0 999999000' } ],
					found        => 1,
				},
			],
			negative => [
				# a first sighting holds on nothing, and is kept
				{
					message        => $london,
					geo            => { locations => \%cities },
					marks_expected => [ { name => 'last-seen', key => 'neti', value => '51.5072 -0.1276 0 1000000000' } ],
				},
				# eight hours is a flight
				{
					messages => [ $london, { message => $new_york, advance => 8 * 3600 } ],
					geo      => { locations => \%cities },
				},
				# a address the fixture does not place holds on nothing and is not kept
				{
					messages => [ $london, { message => line( event => 'fail', ip => '192.0.2.1', user => 'neti' ), advance => 60 } ],
					geo            => { locations => { %cities, '192.0.2.1' => 'unknown' } },
					marks_expected => [ { name => 'last-seen', key => 'neti', value => '51.5072 -0.1276 0 1000000000' } ],
				},
			],
		},
	),
	5,
	'a travel gate proves itself from the geo fixture and the entry\'s marks'
);

#
# network, lifting what after then counts by
#

proves(
	results_for(
		rule_gates => [
			{ network => { var => 'ip', into => 'NET' } },
			{ after   => { by  => 'NET', count => 3, seconds => 60 } },
			{ ban_var => ['ip'] },
		],
		tests => {
			positive => [
				# three addresses out of the one /24 are the one key
				{
					messages => [ map { line( event => 'fail', ip => '203.0.113.' . $_ ) } ( 9, 10, 11 ) ],
					found    => 1,
					data     => { NET => '203.0.113.0/24' },
				},
			],
			negative => [
				# three out of three networks are three
				{ messages => [ map { line( event => 'fail', ip => '203.0.' . $_ . '.9' ) } ( 113, 114, 115 ) ] },
				# a value that is no address lifts nothing, and after vetoes what has no key
				{ messages => [ ( line( event => 'fail', ip => 'crawl.example.org' ) ) x 3 ] },
			],
		},
	),
	3,
	'a network gate proves its lift by what a after gate below it counts'
);

#
# sum
#

proves(
	results_for(
		rule_gates => [ { sum => { by => 'ip', of => 'bytes', above => 1000, seconds => 600 } }, { ban_var => ['ip'] } ],
		tests      => {
			positive => [
				{
					messages => [
						line( event => 'fail', ip => '203.0.113.9', bytes => 600 ),
						line( event => 'fail', ip => '203.0.113.9', bytes => 600 ),
					],
					found => 1,
				},
			],
			negative => [
				# the first has fallen out by the time the second lands
				{
					messages => [
						line( event => 'fail', ip => '203.0.113.9', bytes => 600 ),
						{ message => line( event => 'fail', ip => '203.0.113.9', bytes => 600 ), advance => 620 },
					],
				},
				# and a line with no number adds nothing
				{ messages => [ ( line( event => 'fail', ip => '203.0.113.9' ) ) x 3 ] },
			],
		},
	),
	3,
	'a sum gate proves its total over the virtual clock'
);

#
# marked, by how old the brand is and by how many hosts set it
#

proves(
	results_for(
		rule_gates => [ { marked => { name => 'logged-in', var => 'user', newer_than => 300 } }, { ban_var => ['ip'] } ],
		tests      => {
			positive => [
				{
					message      => line( event => 'fail', ip => '203.0.113.9', user => 'neti' ),
					marks_before => [ { name => 'logged-in', key => 'neti', set => 1_000_000_000 - 60 } ],
				},
			],
			negative => [
				{
					message      => line( event => 'fail', ip => '203.0.113.9', user => 'neti' ),
					marks_before => [ { name => 'logged-in', key => 'neti', set => 1_000_000_000 - 600 } ],
				},
			],
		},
	),
	2,
	'a marked gate asking the age proves itself from a seeded set time'
);
proves(
	results_for(
		rule_gates => [ { ban_var => ['ip'] }, { marked => { name => 'recon', hosts => 3 } } ],
		tests      => {
			positive => [ { message => $fail_line, marks_before => [ { name => 'recon', key => '203.0.113.9', hosts => 3 } ] } ],
			negative => [
				{ message => $fail_line, marks_before => [ { name => 'recon', key => '203.0.113.9', hosts => 2 } ] },
				# a seed that does not say is one host's
				{ message => $fail_line, marks_before => [ { name => 'recon', key => '203.0.113.9' } ] },
			],
		},
	),
	3,
	'and one asking how many hosts from a seeded count of them'
);

#
# track, tallying the lines of a record
#

proves(
	results_for(
		track_only => 1,
		rule_gates => [ { track => { name => 'client', key => 'ip', fields => [], count => 'requests' } }, { ban_var => ['ip'] } ],
		tests      => {
			positive => [
				{
					messages         => [ ($fail_line) x 3, line( event => 'fail', ip => '203.0.113.10' ) ],
					found            => 4,
					tracked_expected => [
						{ name => 'client', key => '203.0.113.9',  fields => { requests => 3 } },
						{ name => 'client', key => '203.0.113.10', fields => { requests => 1 } },
					],
				},
				# a tally a line before the test left is added to
				{
					message          => $fail_line,
					tracked_before   => [ { name => 'client', key => '203.0.113.9', fields => { requests => 41 } } ],
					tracked_expected => [ { name => 'client', key => '203.0.113.9', fields => { requests => 42 } } ],
				},
			],
		},
	),
	2,
	'a track gate with a count tallies the lines of each record'
);
proves(
	results_for(
		rule_gates => [
			{ tracked => { name => 'client', where => [ { field => 'requests', op => 'gt', value => 2 } ] } },
			{ track   => { name => 'client', key   => 'ip', fields => [], count => 'requests' } },
			{ ban_var => ['ip'] },
		],
		tests => {
			# the read is above the write, so the fourth line is the first to find three before it
			positive => [ { messages => [ ($fail_line) x 4 ], found => 1 } ],
			negative => [ { messages => [ ($fail_line) x 3 ] } ],
		},
	),
	2,
	'and a tracked gate below reads the tally as a number'
);

#
# epoch and fresh, over a field of the line and the clock
#

proves(
	results_for(
		rule_gates => [
			{ epoch   => { var => 'when', into => 'WHEN' } },
			{ fresh   => { var => 'WHEN', within => 300 } },
			{ ban_var => ['ip'] },
		],
		tests => {
			positive => [
				# read a minute after it says it was written
				{
					message => line( event => 'fail', ip => '203.0.113.9', when => '2001-09-09T01:45:40Z' ),
					data    => { WHEN => 999999940, when => '2001-09-09T01:45:40Z' },
				},
			],
			negative => [
				# a hour old
				{ message => line( event => 'fail', ip => '203.0.113.9', when => '2001-09-09T00:46:40Z' ) },
				# no time at all, and one that can not be read
				{ message => $fail_line },
				{ message => line( event => 'fail', ip => '203.0.113.9', when => 'a while ago' ) },
			],
		},
	),
	4,
	'a epoch gate and a fresh gate below it prove themselves over the virtual clock'
);
proves(
	results_for(
		rule_gates => [ { epoch => { var => 'when', format => 'epoch_ms' } }, { ban_var => ['ip'] } ],
		tests      => {
			positive => [
				{ message => line( event => 'fail', ip => '203.0.113.9', when => '999999940123' ), data => { when => 999999940 } },
				# one that can not be read is left as it was, and nothing is vetoed
				{ message => line( event => 'fail', ip => '203.0.113.9', when => 'never' ), data => { when => 'never' } },
			],
		},
	),
	2,
	'and a epoch gate with no into converts the var where it is'
);

#
# novel, remembered in the entry's own marks
#

proves(
	results_for(
		rule_gates => [ { novel => { name => 'seen-from', by => 'user', of => 'country', after_seen => 2 } }, { detection_var => ['ip'] } ],
		tests      => {
			positive => [
				# the third login is the first from somewhere new
				{
					messages => [
						line( event => 'fail', ip => '203.0.113.9',  user => 'neti', country => 'US' ),
						line( event => 'fail', ip => '203.0.113.9',  user => 'neti', country => 'US' ),
						line( event => 'fail', ip => '203.0.113.10', user => 'neti', country => 'NL' ),
					],
					found          => 1,
					data           => { ip => '203.0.113.10' },
					marks_expected => [ { name => 'seen-from', key => 'neti', value => 3 }, { name => 'seen-from', key => [ 'neti', 'NL' ] } ],
				},
				# and against what lines before the test left
				{
					message      => line( event => 'fail', ip => '203.0.113.10', user => 'neti', country => 'NL' ),
					marks_before => [ { name => 'seen-from', key => 'neti', value => 40 }, { name => 'seen-from', key => [ 'neti', 'US' ] } ],
				},
			],
			negative => [
				# a new account's first country is new, and is no finding
				{ message => line( event => 'fail', ip => '203.0.113.9', user => 'neti', country => 'US' ) },
				# a country the account has had
				{
					message      => line( event => 'fail', ip => '203.0.113.9', user => 'neti', country => 'US' ),
					marks_before => [ { name => 'seen-from', key => 'neti', value => 40 }, { name => 'seen-from', key => [ 'neti', 'US' ] } ],
				},
			],
		},
	),
	4,
	'a novel gate proves itself from the entry\'s marks'
);

#
# banished, off the brands the galla sets
#

proves(
	results_for(
		rule_gates => [ { ban_var => ['ip'] }, { banished => { times => 2, within => 3600 } } ],
		tests      => {
			positive => [
				{
					message      => $fail_line,
					marks_before => [ { name => 'banishments', key => '203.0.113.9', value => '999999000 999999900' } ],
				},
			],
			negative => [
				{ message => $fail_line },
				{
					message      => $fail_line,
					marks_before => [ { name => 'banishments', key => '203.0.113.9', value => '999990000 999999900' } ],
				},
			],
		},
	),
	3,
	'a banished gate asking how often proves itself from a seeded banishments brand'
);
proves(
	results_for(
		rule_gates => [ { banished => { var => 'ip', now => 1, for => 60 } }, { detection_var => ['ip'] } ],
		tests      => {
			positive => [ { message => $fail_line, marks_before => [ { name => 'banished', key => '203.0.113.9', set => 1_000_000_000 - 90 } ] } ],
			negative => [
				{ message => $fail_line, marks_before => [ { name => 'banished', key => '203.0.113.9', set => 1_000_000_000 - 30 } ] },
				{ message => $fail_line },
			],
		},
	),
	3,
	'and one asking if it is banished now from a seeded banished brand'
);

#
# pressure
#

proves(
	results_for(
		rule_gates => [ { pressure => { above => 200, seconds => 60 } }, { ban_var => ['ip'] } ],
		tests      => {
			positive => [ { message => $fail_line, pressure => 201 } ],
			negative => [ { message => $fail_line, pressure => 200 }, { message => $fail_line, pressure => 0 } ],
		},
	),
	3,
	'a pressure gate proves its mark from the pressure fixture'
);

#
# a gate with out its fixture is skipped, and a fixture for one lookup does
# not stand in for another
#

proves(
	results_for(
		rule_gates => [
			{ pressure => { above   => 200, seconds => 60 } },
			{ travel   => { name    => 'last-seen', by => 'user', var => 'ip', faster_than_kmh => 900 } },
			{ ban_var  => ['ip'] },
			{ forgive  => { rules   => 'json/y' } },
		],
		tests => { positive => [ { message => $fail_line } ] },
	),
	1,
	'pressure and travel with no fixture go unjudged, and forgive always does'
);

proves(
	results_for(
		rule_gates => [
			{ travel  => { name => 'last-seen', by => 'user', var => 'ip', faster_than_kmh => 900 } },
			{ ban_var => ['ip'] },
			{ country => { is => 'US' } },
		],
		tests => { negative => [ { message => $london, geo => { locations => \%cities } } ] },
	),
	1,
	'a geo fixture of locations alone leaves a country gate unjudged'
);

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
	'a accounts that is no array' => [ { accounts => 'neti' }, qr/accounts is not a array of names or a hash of them/ ],
	'a account with a unknown detail' =>
		[ { accounts => { neti => { home => '/home/neti' } } }, qr/accounts "neti" is not a hash of uid, shell, and groups/ ],
	'a account whose groups is no array' =>
		[ { accounts => { neti => { groups => 'wheel' } } }, qr/accounts "neti" is not a hash of uid, shell, and groups/ ],
	'a location that is one number' => [
		{ geo => { locations => { '203.0.113.9' => 51.5 } } },
		qr/geo locations "203\.0\.113\.9" is not a \[ latitude, longitude \] pair/
	],
	'a location with no longitude' => [
		{ geo => { locations => { '203.0.113.9' => { lat => 51.5 } } } },
		qr/geo locations "203\.0\.113\.9" is not a \[ latitude, longitude \] pair/
	],
	'a pressure that is no count' => [ { pressure => 'high' }, qr/pressure is not a count of matched lines/ ],
	'a seeded brand whose hosts is no count' => [
		{ marks_before => [ { name => 'recon', key => '203.0.113.9', hosts => 'many' } ] },
		qr/has a marks_before entry whose hosts is not a count/
	],
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
