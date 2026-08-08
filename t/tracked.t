#!perl

use 5.006;
use strict;
use warnings;
use Test::More;
use App::Baphomet::Rules::Syslog ();
use App::Baphomet::Parser        ();
use App::Baphomet::Tracks        ();

plan tests => 29;

# a syslog rule built straight from a def, the way the loader builds one
sub build_rule {
	my ( $name, $def ) = @_;

	my $rule;
	eval { $rule = App::Baphomet::Rules::Syslog->new( 'name' => $name, 'def' => $def ); };
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
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^bounced (?<postfix_queueid>[0-9A-F]+)'],
		'tracked'        => [ { 'name' => 'mail-queue', 'into' => ['client_ip'] } ],
		'ban_var'        => ['client_ip'],
	}
);
like(
	$error,
	qr/names a record the rule declares no track for/,
	'a tracked naming a record the rule declared no track for will not load'
);

( undef, $error ) = build_rule(
	'orphan-not',
	{
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^bounced (?<postfix_queueid>[0-9A-F]+)'],
		'not_tracked'    => [ { 'name' => 'mail-queue' } ],
		'ban_var'        => ['postfix_queueid'],
	}
);
like( $error, qr/names a record the rule declares no track for/, 'a not_tracked wants a track beside it too' );

( undef, $error ) = build_rule(
	'does-nothing',
	{
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^bounced (?<queueid>[0-9A-F]+)'],
		'track'          => [ { 'name' => 'mail-queue', 'key' => 'queueid' } ],
		'tracked'        => [ { 'name' => 'mail-queue' } ],
		'ban_var'        => ['queueid'],
	}
);
like( $error, qr/carries neither where nor into/, 'a tracked with neither where nor into will not load' );

( undef, $error ) = build_rule(
	'not-tracked-where',
	{
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^bounced (?<queueid>[0-9A-F]+)'],
		'track'          => [ { 'name' => 'mail-queue', 'key'   => 'queueid' } ],
		'not_tracked'    => [ { 'name' => 'mail-queue', 'where' => [ { 'field' => 'x', 'op' => 'exists' } ] } ],
		'ban_var'        => ['queueid'],
	}
);
like( $error, qr/unknown key "where"/, 'a not_tracked takes no where, that being tracked with a negated one' );

( undef, $error ) = build_rule(
	'twice-declared',
	{
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^bounced (?<queueid>[0-9A-F]+)'],
		'track'          =>
			[ { 'name' => 'mail-queue', 'key' => 'queueid' }, { 'name' => 'mail-queue', 'key' => 'other' }, ],
		'ban_var' => ['queueid'],
	}
);
like( $error, qr/twice, which leaves its key ambiguous/, 'one rule may not declare the same track twice' );

( undef, $error ) = build_rule(
	'track-only-no-track',
	{
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^bounced (?<queueid>[0-9A-F]+)'],
		'track_only'     => 1,
		'ban_var'        => ['queueid'],
	}
);
like( $error, qr/track_only but declares no track/, 'a track_only rule that declares no track will not load' );

#
# the harvest rule and the reading rule, the postfix shape from the design
#

my $harvest = build_ok(
	'mail-harvest',
	{
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^(?<postfix_queueid>[0-9A-F]{6,})\: client=\S+\[(?<postfix_client_ip>[0-9.]+)\]'],
		'track'          => [
			{
				'name'   => 'mail-queue',
				'key'    => 'postfix_queueid',
				'fields' => ['postfix_client_ip'],
				'ttl'    => 3600,
			}
		],
		'track_only' => 1,
		'ban_var'    => ['postfix_client_ip'],
	}
);

ok( $harvest->track_only, 'track_only reads back off the rule' );
is( scalar( @{ $harvest->tracks } ), 1, 'the declaration compiled onto the rule' );
is_deeply( $harvest->tracks->[0]{key}, ['postfix_queueid'], 'a plain key compiles to a list of one' );
is( $harvest->tracks->[0]{ttl}, 3600, 'the declared ttl rides the compiled track' );

my $reader = build_ok(
	'mail-bounce',
	{
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^(?<postfix_queueid>[0-9A-F]{6,})\: to=<(?<postfix_to>[^>]+)>.* status=bounced'],
		'track'          => [ { 'name' => 'mail-queue', 'key' => 'postfix_queueid', 'fields' => ['postfix_to'] } ],
		'tracked'        => [
			{
				'name'  => 'mail-queue',
				'where' => [ { 'field' => 'postfix_client_ip', 'op' => 'exists' } ],
				'into'  => ['postfix_client_ip'],
			}
		],
		'ban_var' => ['postfix_client_ip'],
	}
);

is( $reader->tracks->[0]{ttl}, 3600, 'an undeclared ttl defaults to the hour' );
is_deeply( $reader->track_gates->{tracked}[0]{key},
	['postfix_queueid'], 'the read takes its key from the declaration beside it' );

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

# ...but it still harvested, the sweep not caring that the boolean vetoed
is_deeply(
	App::Baphomet::Tracks::track_get( \%store, 'mail-queue', '1C36D185729', $now ),
	{ 'postfix_to' => 'victim@example.org' },
	'a rule whose tracked clause vetoed still contributed to the record'
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
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^(?<postfix_queueid>[0-9A-F]{6,})\: to=<(?<postfix_to>[^>]+)>'],
		'track'          => [ { 'name' => 'mail-queue', 'key'  => 'postfix_queueid', 'fields' => [] } ],
		'tracked'        => [ { 'name' => 'mail-queue', 'into' => ['postfix_to'] } ],
		'ban_var'        => ['postfix_to'],
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
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^NOQUEUE\: reject\: RCPT from \S+\[(?<postfix_client_ip>[0-9.]+)\]'],
		'track'          => [ { 'name' => 'mail-queue', 'key'   => 'postfix_queueid' } ],
		'tracked'        => [ { 'name' => 'mail-queue', 'where' => [ { 'field' => 'x', 'op' => 'exists' } ] } ],
		'ban_var'        => ['postfix_client_ip'],
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
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^(?<postfix_queueid>[0-9A-F]{6,})\: '],
		'track'          => [ { 'name' => 'seen', 'key' => 'postfix_queueid', 'fields' => [] } ],
		'not_tracked'    => [ { 'name' => 'seen' } ],
		'ban_var'        => ['postfix_queueid'],
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
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'ignore_regexp'  => ['status=sent'],
		'message_regexp' => ['^(?<postfix_queueid>[0-9A-F]{6,})\: to=<(?<postfix_to>[^>]+)>'],
		'track'          => [ { 'name' => 'mail-queue', 'key' => 'postfix_queueid' } ],
		'ban_var'        => ['postfix_to'],
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
		'daemons'        => ['//^postfix(?:/\w+)?$//'],
		'message_regexp' => ['^(?<postfix_queueid>[0-9A-F]{6,})\: to=<(?<postfix_to>[^>]+)>.* status=bounced'],
		'track'          => [ { 'name' => 'mail-queue', 'key' => 'postfix_queueid', 'fields' => ['postfix_to'] } ],
		'tracked'        => [
			{
				'name'  => 'mail-queue',
				'where' => [ { 'field' => 'postfix_client_ip', 'op' => 'exists' } ],
				'into'  => ['postfix_client_ip'],
			}
		],
		'ban_var' => ['postfix_client_ip'],
		'tests'   => {
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
