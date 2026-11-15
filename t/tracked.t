#!perl

use 5.006;
use strict;
use warnings;
use Test::More;
use App::Baphomet::Rule   ();
use App::Baphomet::Parser ();
use App::Baphomet::Tracks ();

plan tests => 34;

# a syslog rule built straight from a def, the way the loader builds one
sub build_rule {
	my ( $name, $def ) = @_;

	my $rule;
	eval { $rule = App::Baphomet::Rule->new( 'name' => 'syslog/' . $name, 'def' => $def ); };
	return ( $rule, $@ );
}

sub build_ok {
	my ( $name, $def ) = @_;

	my ( $rule, $error ) = build_rule( $name, $def );
	if ( !defined($rule) ) {
		die( 'the rule "' . $name . '" was meant to load and did not... ' . $error );
	}
	return $rule;
}

#
# the load-time rulings
#

my ( undef, $error ) = build_rule(
	'orphan-read',
	{
		'rule_gates' => [
			{ 'daemons'        => ['//^postfix(?:/\w+)?$//'] },
			{ 'message_regexp' => ['^bounced (?<postfix_queueid>[0-9A-F]+)'] },
			{ 'tracked'        => { 'name' => 'mail-queue', 'into' => ['client_ip'] } },
			{ 'ban_var'        => ['client_ip'] },
		],
	}
);
like(
	$error,
	qr/names the record "mail-queue", which the rule declares no track for/,
	'a tracked naming a record the rule declared no track for will not load'
);

( undef, $error ) = build_rule(
	'orphan-not',
	{
		'rule_gates' => [
			{ 'daemons'        => ['//^postfix(?:/\w+)?$//'] },
			{ 'message_regexp' => ['^bounced (?<postfix_queueid>[0-9A-F]+)'] },
			{ 'not_tracked'    => { 'name' => 'mail-queue' } },
			{ 'ban_var'        => ['postfix_queueid'] },
		],
	}
);
like(
	$error,
	qr/names the record "mail-queue", which the rule declares no track for/,
	'a not_tracked wants a track beside it too'
);

( undef, $error ) = build_rule(
	'does-nothing',
	{
		'rule_gates' => [
			{ 'daemons'        => ['//^postfix(?:/\w+)?$//'] },
			{ 'message_regexp' => ['^bounced (?<queueid>[0-9A-F]+)'] },
			{ 'tracked'        => { 'name' => 'mail-queue' } },
			{ 'track'          => { 'name' => 'mail-queue', 'key' => 'queueid' } },
			{ 'ban_var'        => ['queueid'] },
		],
	}
);
like(
	$error,
	qr/has neither where nor into, so it does nothing/,
	'a tracked with neither where nor into will not load'
);

( undef, $error ) = build_rule(
	'not-tracked-where',
	{
		'rule_gates' => [
			{ 'daemons'        => ['//^postfix(?:/\w+)?$//'] },
			{ 'message_regexp' => ['^bounced (?<queueid>[0-9A-F]+)'] },
			{ 'not_tracked'    => { 'name' => 'mail-queue', 'where' => [ { 'field' => 'x', 'op' => 'exists' } ] } },
			{ 'track'          => { 'name' => 'mail-queue', 'key'   => 'queueid' } },
			{ 'ban_var'        => ['queueid'] },
		],
	}
);
like( $error, qr/unknown key "where"/, 'a not_tracked takes no where, that being tracked with a negated one' );

( undef, $error ) = build_rule(
	'twice-declared',
	{
		'rule_gates' => [
			{ 'daemons'        => ['//^postfix(?:/\w+)?$//'] },
			{ 'message_regexp' => ['^bounced (?<queueid>[0-9A-F]+)'] },
			{ 'track'          => { 'name' => 'mail-queue', 'key' => 'queueid' } },
			{ 'track'          => { 'name' => 'mail-queue', 'key' => 'other' } },
			{ 'ban_var'        => ['queueid'] },
		],
	}
);
like( $error, qr/twice, which leaves its key ambiguous/, 'one rule may not declare the same track twice' );

( undef, $error ) = build_rule(
	'track-only-no-track',
	{
		'track_only' => 1,
		'rule_gates' => [
			{ 'daemons'        => ['//^postfix(?:/\w+)?$//'] },
			{ 'message_regexp' => ['^bounced (?<queueid>[0-9A-F]+)'] },
			{ 'ban_var'        => ['queueid'] },
		],
	}
);
like( $error, qr/is track_only but has no track gate/, 'a track_only rule that declares no track will not load' );

#
# the harvest rule and the reading rule, the postfix shape from the design
#

my $harvest = build_ok(
	'mail-harvest',
	{
		'track_only' => 1,
		'rule_gates' => [
			{ 'daemons' => ['//^postfix(?:/\w+)?$//'] },
			{
				'message_regexp' =>
					['^(?<postfix_queueid>[0-9A-F]{6,})\: client=\S+\[(?<postfix_client_ip>[0-9.]+)\]']
			},
			{
				'track' => {
					'name'   => 'mail-queue',
					'key'    => 'postfix_queueid',
					'fields' => ['postfix_client_ip'],
					'ttl'    => 3600,
				}
			},
			{ 'ban_var' => ['postfix_client_ip'] },
		],
	}
);

ok( $harvest->track_only, 'track_only reads back off the rule' );
is( scalar( @{ $harvest->tracks } ), 1, 'the declaration compiled onto the rule' );
is_deeply( $harvest->tracks->[0]{key}, ['postfix_queueid'], 'a plain key compiles to a list of one' );
is( $harvest->tracks->[0]{ttl}, 3600, 'the declared ttl rides the compiled track' );

my $reader = build_ok(
	'mail-bounce',
	{
		'rule_gates' => [
			{ 'daemons' => ['//^postfix(?:/\w+)?$//'] },
			{
				'message_regexp' =>
					['^(?<postfix_queueid>[0-9A-F]{6,})\: to=<(?<postfix_to>[^>]+)>.* status=bounced']
			},
			{
				'tracked' => {
					'name'  => 'mail-queue',
					'where' => [ { 'field' => 'postfix_client_ip', 'op' => 'exists' } ],
					'into'  => ['postfix_client_ip'],
				}
			},
			{ 'track'   => { 'name' => 'mail-queue', 'key' => 'postfix_queueid', 'fields' => ['postfix_to'] } },
			{ 'ban_var' => ['postfix_client_ip'] },
		],
	}
);

is( $reader->tracks->[0]{ttl}, 3600, 'an undeclared ttl defaults to the hour' );
my ($reader_tracked) = grep { $_->{type} eq 'tracked' } @{ $reader->rule_gates };
is_deeply( $reader_tracked->{key}, ['postfix_queueid'], 'the read takes its key from the declaration beside it' );

#
# the two rules over one transaction, sharing a store
#

my %store;
my $now = 1_000_000_000;

sub feed {
	my ( $rule, $message ) = @_;

	my $parsed = App::Baphomet::Parser::parse( 'syslog', $message );
	return $rule->check( $parsed, 'tracked.t', { 'seq' => 0, 'source' => '', 'now' => $now, 'tracked' => \%store } );
}

my $client_line = 'Jan  2 03:04:05 mx1 postfix/smtpd[111]: 1C36D185729: client=bad.example.net[203.0.113.9]';
my $bounce_line
	= 'Jan  2 04:00:00 mx1 postfix/local[222]: 1C36D185729: to=<victim@example.org>, relay=local, status=bounced (no such user)';

# the bounce arriving first has nothing to read... a where over no history
# leaves the assertion unproven, so it fails closed
is( feed( $reader, $bounce_line ), undef, 'the reading rule vetoes while there is no record to read' );

# ...but it still harvested, the track gate being asked though the tracked
# gate above it vetoed
is_deeply(
	App::Baphomet::Tracks::track_get( \%store, 'mail-queue', '1C36D185729', $now ),
	{ 'postfix_to' => 'victim@example.org' },
	'a rule whose tracked gate vetoed still contributed to the record'
);

# the smtpd line, which is not an offense at all, contributes the address
my $harvest_found = feed( $harvest, $client_line );
ok( defined($harvest_found), 'the harvest rule matched its own line' );
is_deeply(
	App::Baphomet::Tracks::track_get( \%store, 'mail-queue', '1C36D185729', $now ),
	{ 'postfix_to' => 'victim@example.org', 'postfix_client_ip' => '203.0.113.9' },
	'the two stages accumulated into one record rather than replacing each other'
);

# and now the bounce fires, banning an address that only ever appeared on the
# smtpd line... the whole point of the feature
my $found = feed( $reader, $bounce_line );
ok( defined($found), 'the reading rule fires once the record holds what its where wants' );
is( $found->{data}{postfix_client_ip}, '203.0.113.9',        'into lifted the address the bounce line never carried' );
is( $found->{data}{postfix_to},        'victim@example.org', 'the line keeps its own captures' );

#
# a lift never overwrites what the line itself carried
#

my %own;
App::Baphomet::Tracks::track_put( \%own, 'mail-queue', 'AAA111', { 'postfix_to' => 'stored@example.net' }, 3600, $now );
my $overwrite = build_ok(
	'mail-overwrite',
	{
		'rule_gates' => [
			{ 'daemons'        => ['//^postfix(?:/\w+)?$//'] },
			{ 'message_regexp' => ['^(?<postfix_queueid>[0-9A-F]{6,})\: to=<(?<postfix_to>[^>]+)>'] },
			{ 'tracked'        => { 'name' => 'mail-queue', 'into' => ['postfix_to'] } },
			{ 'track'          => { 'name' => 'mail-queue', 'key'  => 'postfix_queueid', 'fields' => [] } },
			{ 'ban_var'        => ['postfix_to'] },
		],
	}
);
my $parsed_own = App::Baphomet::Parser::parse( 'syslog',
	'Jan  2 03:04:05 mx1 postfix/local[222]: AAA111: to=<line@example.org>, status=sent' );
my $own_found
	= $overwrite->check( $parsed_own, 'tracked.t', { 'seq' => 0, 'source' => '', 'now' => $now, 'tracked' => \%own } );
is( $own_found->{data}{postfix_to}, 'line@example.org', 'a lift lands underneath the line and never over it' );
is_deeply(
	App::Baphomet::Tracks::track_get( \%own, 'mail-queue', 'AAA111', $now ),
	{ 'postfix_to' => 'stored@example.net' },
	'a fields: [] declaration reads a record and contributes nothing to it'
);

#
# the key that does not resolve, and not_tracked
#

my %quiet;
my $noqueue = build_ok(
	'mail-noqueue',
	{
		'rule_gates' => [
			{ 'daemons'        => ['//^postfix(?:/\w+)?$//'] },
			{ 'message_regexp' => ['^NOQUEUE\: reject\: RCPT from \S+\[(?<postfix_client_ip>[0-9.]+)\]'] },
			{ 'tracked'        => { 'name' => 'mail-queue', 'where' => [ { 'field' => 'x', 'op' => 'exists' } ] } },
			{ 'track'          => { 'name' => 'mail-queue', 'key'   => 'postfix_queueid' } },
			{ 'ban_var'        => ['postfix_client_ip'] },
		],
	}
);
my $noqueue_parsed = App::Baphomet::Parser::parse( 'syslog',
	'Jan  2 03:04:05 mx1 postfix/smtpd[111]: NOQUEUE: reject: RCPT from bad.example.net[203.0.113.9]' );
ok(
	defined(
		$noqueue->check(
			$noqueue_parsed, 'tracked.t', { 'seq' => 0, 'source' => '', 'now' => $now, 'tracked' => \%quiet }
		)
	),
	'a line whose key does not resolve sails through rather than being vetoed'
);
is_deeply( \%quiet, {}, 'and it harvests nothing, there being no key to file it under' );

my %first;
my $first_only = build_ok(
	'first-sighting',
	{
		'rule_gates' => [
			{ 'daemons'        => ['//^postfix(?:/\w+)?$//'] },
			{ 'message_regexp' => ['^(?<postfix_queueid>[0-9A-F]{6,})\: '] },
			{ 'not_tracked'    => { 'name' => 'seen' } },
			{ 'track'          => { 'name' => 'seen', 'key' => 'postfix_queueid', 'fields' => [] } },
			{ 'ban_var'        => ['postfix_queueid'] },
		],
	}
);
my $seen_parsed
	= App::Baphomet::Parser::parse( 'syslog', 'Jan  2 03:04:05 mx1 postfix/smtpd[111]: BBB222: client=x[1.2.3.4]' );
my $ctx_first = { 'seq' => 0, 'source' => '', 'now' => $now, 'tracked' => \%first };
ok( defined( $first_only->check( $seen_parsed, 'tracked.t', $ctx_first ) ),
	'not_tracked passes on the first sighting' );
is( $first_only->check( $seen_parsed, 'tracked.t', $ctx_first ),
	undef, 'and vetoes every later line of the same transaction' );

#
# a ignore hit stops the harvest, unlike every other refusal in section 1
#

my %ignored;
my $ignoring = build_ok(
	'mail-ignoring',
	{
		'rule_gates' => [
			{ 'daemons'        => ['//^postfix(?:/\w+)?$//'] },
			{ 'ignore_regexp'  => ['status=sent'] },
			{ 'message_regexp' => ['^(?<postfix_queueid>[0-9A-F]{6,})\: to=<(?<postfix_to>[^>]+)>'] },
			{ 'track'          => { 'name' => 'mail-queue', 'key' => 'postfix_queueid' } },
			{ 'ban_var'        => ['postfix_to'] },
		],
	}
);
my $sent_parsed = App::Baphomet::Parser::parse( 'syslog',
	'Jan  2 03:04:05 mx1 postfix/local[222]: CCC333: to=<ok@example.org>, status=sent' );
is(
	$ignoring->check(
		$sent_parsed, 'tracked.t', { 'seq' => 0, 'source' => '', 'now' => $now, 'tracked' => \%ignored }
	),
	undef,
	'a ignored line does not match'
);
is_deeply( \%ignored, {}, 'and a ignored line harvests nothing, ignore being the operator saying it is not evidence' );

#
# the rule file proves its own tracking, the run_tests seam
#

my $selftest = build_ok(
	'mail-selftest',
	{
		'rule_gates' => [
			{ 'daemons' => ['//^postfix(?:/\w+)?$//'] },
			{
				'message_regexp' =>
					['^(?<postfix_queueid>[0-9A-F]{6,})\: to=<(?<postfix_to>[^>]+)>.* status=bounced']
			},
			{
				'tracked' => {
					'name'  => 'mail-queue',
					'where' => [ { 'field' => 'postfix_client_ip', 'op' => 'exists' } ],
					'into'  => ['postfix_client_ip'],
				}
			},
			{ 'track'   => { 'name' => 'mail-queue', 'key' => 'postfix_queueid', 'fields' => ['postfix_to'] } },
			{ 'ban_var' => ['postfix_client_ip'] },
		],
		'tests' => {
			'positive' => [
				{
					'message'        => $bounce_line,
					'tracked_before' => [
						{
							'name'   => 'mail-queue',
							'key'    => '1C36D185729',
							'fields' => { 'postfix_client_ip' => '203.0.113.9' },
						}
					],
					'data'             => { 'postfix_client_ip' => '203.0.113.9' },
					'tracked_expected' => [
						{
							'name'   => 'mail-queue',
							'key'    => '1C36D185729',
							'fields' => { 'postfix_to' => 'victim@example.org' },
						}
					],
				}
			],
			'negative' => [ { 'message' => $bounce_line } ],
		},
	}
);

my $results = $selftest->run_tests;
is( $results->{fail}, 0, 'the embedded tests prove the seed, the lift, and the harvest' )
	or diag( join( "\n", @{ $results->{failures} } ) );
is( $results->{pass}, 2, 'both embedded tests ran' );

#
# a rule with no track, tracked, or not_tracked gate has none to be asked...
# reading its gates changes nothing of it, and a line goes down the gates the
# rule wrote and no others
#

my $plain = build_ok(
	'plain',
	{
		'rule_gates' => [
			{ 'daemons'        => ['sshd'] },
			{ 'message_regexp' => ['^bad thing from %%%%SRC%%%%$'] },
			{ 'ban_var'        => ['SRC'] },
		],
	}
);
my @plain_keys = sort( keys( %{$plain} ) );
is_deeply( $plain->tracks, [], 'a rule with no track gate reads back a empty list' );
is_deeply( [ grep { $_->{type} eq 'tracked' || $_->{type} eq 'not_tracked' } @{ $plain->rule_gates } ],
	[], 'and none of its gates is a tracked or a not_tracked' );
is_deeply( [ sort( keys( %{$plain} ) ) ], \@plain_keys, 'reading the gates stores nothing on the rule' );

# what the three sorts of tracked gate are asked with, swapped for a count...
# a line of a rule that has none of them is to ask none
my $tracked_asks = 0;
{
	no warnings qw( redefine once );
	local *App::Baphomet::Gate::tracked::ask     = sub { $tracked_asks++; return 1; };
	local *App::Baphomet::Gate::not_tracked::ask = sub { $tracked_asks++; return 1; };
	local *App::Baphomet::Gate::track::ask       = sub { $tracked_asks++; return 1; };
	my $plain_line
		= App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 mail01 sshd[1]: bad thing from 192.0.2.8' );
	my $found = $plain->check( $plain_line, 'plain-scope', { 'seq' => 0, 'source' => '', 'now' => 1_000_000_000 } );
	ok( defined($found), 'the plain rule still matches after its gates were read' );
}
is( $tracked_asks, 0, 'a rule with no tracked gates asks none of them of a line after its gates were read' );
