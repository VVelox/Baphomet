#!perl

use 5.006;
use strict;
use warnings;
use Test::More;
use App::Baphomet::Tracks qw( track_key track_get track_put track_prune track_render TRACK_FIELD_CAP );

plan tests => 25;

my $now = 1_000_000_000;

#
# track_key... a plain key, a compound one, and the refusals
#

is( track_key( { 'key' => ['queueid'] }, { 'queueid' => '1C36D185729' } ),
	'1C36D185729', 'a single component resolves to the bare value' );

is( track_key( { 'key' => [ 'host', 'session' ] }, { 'host' => 'mx1', 'session' => '42' } ),
	"mx1\x1f42", 'a compound key joins on the unit separator' );

is( track_key( { 'key' => [ 'host', 'session' ] }, { 'host' => 'mx1' } ),
	undef, 'a missing component gives no key at all rather than a partial join' );

is( track_key( { 'key' => ['queueid'] }, { 'queueid' => '' } ),
	undef, 'an empty value is as unresolved as a missing one' );

is( track_key( { 'key' => ['queueid'] }, {} ), undef, 'a field the line never carried gives no key' );

#
# track_put / track_get... the accumulate-across-lines behavior the whole
# feature exists for
#

my %store;

track_put( \%store, 'mail-queue', 'Q1', { 'client_ip' => '203.0.113.9' }, 3600, $now );
is_deeply(
	track_get( \%store, 'mail-queue', 'Q1', $now ),
	{ 'client_ip' => '203.0.113.9' },
	'the first line lays down what it knows'
);

track_put( \%store, 'mail-queue', 'Q1', { 'rcpt' => 'victim@example.org' }, 3600, $now + 10 );
is_deeply(
	track_get( \%store, 'mail-queue', 'Q1', $now + 10 ),
	{ 'client_ip' => '203.0.113.9', 'rcpt' => 'victim@example.org' },
	'a later line adds to the record rather than replacing it'
);

track_put( \%store, 'mail-queue', 'Q1', { 'client_ip' => undef, 'status' => 'bounced' }, 3600, $now + 20 );
is_deeply(
	track_get( \%store, 'mail-queue', 'Q1', $now + 20 ),
	{ 'client_ip' => '203.0.113.9', 'rcpt' => 'victim@example.org', 'status' => 'bounced' },
	'a undef contribution leaves what the record holds standing'
);

track_put( \%store, 'mail-queue', 'Q1', { 'status' => 'deferred' }, 3600, $now + 30 );
is( track_get( \%store, 'mail-queue', 'Q1', $now + 30 )->{status},
	'deferred', 'a later line does overwrite a field it actually carries' );

is( track_get( \%store, 'mail-queue',    'nope', $now ), undef, 'an unknown key reads back as no record' );
is( track_get( \%store, 'no-such-track', 'Q1',   $now ), undef, 'an unknown track name reads back as no record' );

#
# the ttl... refreshed on every sighting, contributed field or not, and the
# record still ages out once the key stops appearing
#

track_put( \%store, 'mail-queue', 'Q2', { 'client_ip' => '198.51.100.4' }, 100, $now );
is( track_get( \%store, 'mail-queue', 'Q2', $now + 150 ), undef, 'a record past its ttl reads back as gone' );

track_put( \%store, 'mail-queue', 'Q3', { 'client_ip' => '198.51.100.7' }, 100, $now );
track_put( \%store, 'mail-queue', 'Q3', {},                                100, $now + 50 );
is_deeply(
	track_get( \%store, 'mail-queue', 'Q3', $now + 120 ),
	{ 'client_ip' => '198.51.100.7' },
	'a sighting contributing nothing still refreshes the ttl'
);

# a expired record is not revived... a queue id reappearing after the ttl is a
# new transaction reusing the id, not the old one carrying on
track_put( \%store, 'mail-queue', 'Q2', { 'rcpt' => 'someone@example.net' }, 100, $now + 200 );
is_deeply(
	track_get( \%store, 'mail-queue', 'Q2', $now + 200 ),
	{ 'rcpt' => 'someone@example.net' },
	'a key reappearing after expiry starts a fresh record rather than reviving the old'
);

#
# the field cap
#

my %capped;

# seeded in its own call so it is provably in the record before the flood...
# a hash hands its keys back in whatever order it likes, so which of the flood
# survives the cap is not something to assert on
track_put( \%capped, 'wide', 'K', { 'first_field' => 'original' }, 3600, $now );
my %many = map { ( 'field_' . $_ => $_ ) } ( 1 .. TRACK_FIELD_CAP() + 20 );
track_put( \%capped, 'wide', 'K', \%many, 3600, $now );
is( scalar( keys( %{ track_get( \%capped, 'wide', 'K', $now ) } ) ),
	TRACK_FIELD_CAP(), 'a record is capped at TRACK_FIELD_CAP fields' );

track_put( \%capped, 'wide', 'K', { 'first_field' => 'updated' }, 3600, $now );
is( track_get( \%capped, 'wide', 'K', $now )->{first_field},
	'updated', 'a field the capped record already holds still updates' );

track_put( \%capped, 'wide', 'K', { 'brand_new' => 'x' }, 3600, $now );
is( track_get( \%capped, 'wide', 'K', $now )->{brand_new}, undef, 'a new field name past the cap is dropped' );

#
# track_prune... the sweeper's half
#

my %pruning;
track_put( \%pruning, 'a', 'live', {}, 3600, $now );
track_put( \%pruning, 'a', 'dead', {}, 10,   $now );
track_put( \%pruning, 'b', 'dead', {}, 10,   $now );

is( track_prune( \%pruning, $now + 100 ), 2, 'prune reports how many records it dropped' );
ok( defined( $pruning{a}{live} ),  'a live record survives the prune' );
ok( !defined( $pruning{a}{dead} ), 'an expired record is dropped' );
ok( !defined( $pruning{b} ),       'a track name left holding nothing is dropped with its last record' );
is( track_prune( \%pruning, $now + 100 ), 0, 'a second prune finds nothing left to do' );

#
# track_render... the inverse of the join, for EVE and the command
#

is( track_render('1C36D185729'), '1C36D185729', 'a single key renders as a plain scalar' );
is_deeply( track_render("mx1\x1f42"), [ 'mx1', '42' ], 'a compound key renders as an array of its components' );
is( track_render(undef), undef, 'no key renders as no key' );
