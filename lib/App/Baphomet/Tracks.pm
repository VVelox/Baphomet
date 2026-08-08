package App::Baphomet::Tracks;

use 5.006;
use strict;
use warnings;
use Exporter             qw( import );
use App::Baphomet::Marks qw( bound_expiring_store );

our @EXPORT_OK = qw( track_key track_get track_put track_prune track_render TRACK_FIELD_CAP );

=head1 NAME

App::Baphomet::Tracks - The tracked record store's pure core, drivable with or without a galla.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Tracks qw( track_key track_get track_put );

    my %tracked;
    my $key    = track_key( $entry, $data );
    my $record = track_get( \%tracked, 'mail-queue', $key, $now );
    track_put( \%tracked, 'mail-queue', $key, $fields, 3600, $now );

=head1 DESCRIPTION

A daemon that logs one transaction over several lines spreads the facts
about it across all of them, and the only thing joining them is a key the
daemon repeats... a postfix queue id, a session id, a request id. This is
the store that accumulates those facts, so the line that finally says
something worth banning on can reach what an earlier line said.

Where a mark holds one scalar per branded key, a tracked record holds a
hash that accumulates. Later lines lay their fields over the record rather
than replacing it, and a field a line did not carry leaves what the record
already holds standing... each stage of a transaction contributes what it
knows.

Lifted out of the galla so it runs over any store hashref, the way
L<App::Baphomet::Marks> is. The galla passes its live C<< $self->{tracked} >>,
while C<run_tests> passes a throwaway store per test entry and a virtual
clock, so a rule file can prove its own tracking cold. Nothing here knows
of tablets, buses, or wall clocks... state in, records out. The predicate
judging of a C<where> stays in the rule, which owns the predicate
vocabulary; this owns only the store.

The store shape is per track name a hash of keys, each
C<< { expires, fields } >>.

=head1 CONSTANTS

=head2 TRACK_FIELD_CAP

The most fields one record will hold, 64. A transaction with more facts
than that about it is a transaction being used as a general purpose store,
which this is not... the cap is on the record and not on the store, which
L<App::Baphomet::Marks/bound_expiring_store> bounds at the shared 10000
keys.

=cut

sub TRACK_FIELD_CAP { return 64; }

=head1 FUNCTIONS

=head2 track_key

Resolves a track entry's key against a line's found data. A C<key> that is
a array joins each named field's value on the unit separator into one
compound key, a plain string takes that field alone. Any piece missing
means no key at all, a undef... never a partial join, as a partial key
would collide two transactions that merely share a prefix.

Takes the compiled entry, a hash ref carrying at least a C<key> (a string
or a array ref of strings), and the found data hash ref the key names its
fields in. Returns the resolved key as a string, or undef when any named
field is missing or empty.

    my $key = track_key( { 'key' => 'postfix_queueid' }, $data );
    my $key = track_key( { 'key' => [ 'host', 'session_id' ] }, $data );

=cut

sub track_key {
	my ( $entry, $data ) = @_;

	if ( !defined($entry) || !defined( $entry->{key} ) || !defined($data) ) {
		return undef;
	}

	my @components = ref( $entry->{key} ) eq 'ARRAY' ? @{ $entry->{key} } : ( $entry->{key} );

	my @parts;
	foreach my $field (@components) {
		# a empty string is as unresolved as a missing field... a daemon that
		# logs an empty queue id has told us nothing to join on
		if ( !defined( $data->{$field} ) || $data->{$field} eq '' ) {
			return undef;
		}
		push( @parts, $data->{$field} );
	}

	return join( "\x1f", @parts );
} ## end sub track_key

=head2 track_get

Reads a live record back out of a store. Takes the whole store hash ref,
the track name, the resolved key, and the current time. Returns the
record's fields as a hash ref, the caller's to read and never to modify,
or undef when there is no record for that key or the one there has aged
out.

An expired record answers undef rather than being deleted here, the
sweeper owning the pruning... a read on the per-line path does not pay for
housekeeping.

    my $fields = track_get( $store, 'mail-queue', $key, $now );
    if ( defined($fields) ) { ... }

=cut

sub track_get {
	my ( $store_all, $name, $key, $now ) = @_;

	if ( !defined($store_all) || !defined($name) || !defined($key) ) {
		return undef;
	}

	my $record = $store_all->{$name}{$key};
	if ( !defined($record) || $record->{expires} <= $now ) {
		return undef;
	}

	return $record->{fields};
} ## end sub track_get

=head2 track_put

Lays a line's contribution over whatever the key already holds, newest
winning, and refreshes the expiry. This is the harvest.

Takes the whole store hash ref, the track name, the resolved key, the
fields to contribute as a hash ref of name to value, the ttl in seconds,
and the current time. Returns nothing.

Three behaviors worth naming:

- undef is skipped, never stored :: so each stage of a transaction
  contributes what it knows and a later line silent on a field never
  blanks what an earlier one gave. The read side needs nothing for this,
  a undef stored value already failing every predicate operator but
  C<exists>.
- the ttl refreshes whether or not anything was contributed :: sighting
  the key at all is evidence the transaction is alive, and postfix
  retries deferred mail for days. The record still ages out once the key
  stops appearing.
- the record is capped at L</TRACK_FIELD_CAP> fields :: past it a field
  name the record does not already hold is dropped, while the names it
  does hold still update. So a runaway rule can not grow one record
  without bound, and the fields that were there first are the ones kept.

    track_put( $store, 'mail-queue', $key, { 'postfix_to' => 'a@example.org' }, 3600, $now );

=cut

sub track_put {
	my ( $store_all, $name, $key, $fields, $ttl, $now ) = @_;

	if ( !defined($store_all) || !defined($name) || !defined($key) ) {
		return;
	}

	my $store = $store_all->{$name};
	if ( !defined($store) ) {
		$store = $store_all->{$name} = {};
	}

	bound_expiring_store( $store, $key, $now );

	my $record = $store->{$key};
	if ( !defined($record) || $record->{expires} <= $now ) {
		# a record that aged out is not revived... an expired queue id
		# reappearing is a new transaction reusing the id, not the old one
		$record = $store->{$key} = { 'fields' => {} };
	}
	$record->{expires} = $now + $ttl;

	if ( defined($fields) ) {
		foreach my $field ( keys( %{$fields} ) ) {
			if ( !defined( $fields->{$field} ) ) {
				next;
			}
			if (  !exists( $record->{fields}{$field} )
				&& scalar( keys( %{ $record->{fields} } ) ) >= TRACK_FIELD_CAP() )
			{
				next;
			}
			$record->{fields}{$field} = $fields->{$field};
		} ## end foreach my $field ( keys( %{$fields} ) )
	} ## end if ( defined($fields) )

	return;
} ## end sub track_put

=head2 track_prune

Drops every expired record from a store and every track name left holding
none, so the store does not keep the shape of traffic long gone. Takes the
whole store hash ref and the current time, returns the number of records
dropped... the sweeper logs it beside what it pruned from the marks.

    my $dropped = track_prune( $store, $now );

=cut

sub track_prune {
	my ( $store_all, $now ) = @_;

	if ( !defined($store_all) ) {
		return 0;
	}

	my $dropped = 0;
	foreach my $name ( keys( %{$store_all} ) ) {
		foreach my $key ( keys( %{ $store_all->{$name} } ) ) {
			if ( $store_all->{$name}{$key}{expires} <= $now ) {
				delete( $store_all->{$name}{$key} );
				$dropped++;
			}
		}
		if ( !%{ $store_all->{$name} } ) {
			delete( $store_all->{$name} );
		}
	} ## end foreach my $name ( keys( %{$store_all} ) )

	return $dropped;
} ## end sub track_prune

=head2 track_render

Renders a resolved key for display, the inverse of the join L</track_key>
does. A compound key comes back as a array ref of its components and a
single key as a plain scalar, so a EVE consumer sees one keyword field
either way rather than the unit separator the store joins on.

Takes the resolved key. Returns the scalar or the array ref.

    my $shown = track_render( $key );

=cut

sub track_render {
	my ($key) = @_;

	if ( !defined($key) ) {
		return undef;
	}

	if ( index( $key, "\x1f" ) == -1 ) {
		return $key;
	}

	return [ split( /\x1f/, $key, -1 ) ];
} ## end sub track_render

1;
