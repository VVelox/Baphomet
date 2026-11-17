package App::Baphomet::Correlation;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util            qw( is_plain_arrayref is_plain_hashref );
use Exporter             qw( import );
use App::Baphomet::Marks qw( bound_expiring_store );

our @EXPORT_OK = qw(
	correlation_key_components
	correlation_key context_put context_get pending_park pending_complete
	fold_completions correlation_prune correlation_restore
);

=head1 NAME

App::Baphomet::Correlation - The correlation store's pure core, drivable with or without a rule.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Correlation qw( correlation_key context_put context_get );

    my %store = ( 'context' => {}, 'pending' => {} );
    my $key   = correlation_key( ['KEY'], $caps, undef );
    context_put( \%store, $scope, $key, $caps, 60, $now );
    my $data = context_get( \%store, $scope, $key, $now );

=head1 DESCRIPTION

A daemon that logs the offense on one line and the offender's address on
another is matched by joining the two on a key both lines repeat... a
connection id, a queue id, the logging process itself. This is the store
behind that. A capture line leaves its data under the key as context, a
offense that finds no context yet may be parked under the key as pending,
and the capture line that arrives later completes it.

This is the correlation machinery, lifted out of the rule handlers so it runs
over any store hashref, the way L<App::Baphomet::Marks> and
L<App::Baphomet::Tracks> do. A rule passes its own store, which is walled
off per scope, the watcher name, as a key is only unique within one log.
Nothing here knows of rules, tablets, or wall clocks... state in, data and
completions out.

The store shape is two hashes, C<context> and C<pending>, each per scope a
hash of keys. A context key holds C<< { data, expires } >> and a pending key
a array of C<< { caps, fields?, regexp, expires } >>. A rule dumps the store to the
context tablet as it is, so the shape is also the tablet's.

=head1 FUNCTIONS

=head2 correlation_key_components

Vets a correlation key as a rule wrote it and returns its components. A key
is a non-empty string or a non-empty array of them, each naming a capture or
field, or one of the reserved envelope fields when the rule's type has any.
Dies, the passed C<$where> leading the message, on a key that is neither, on
a component that is not a non-empty string, and on one naming a envelope
field the type does not have.

    - key :: The key as the rule file wrote it.

    - where :: The lead in for the die messages, naming what has the key.

    - envelope_fields :: Hash ref of the envelope fields the rule's type
          has, or undef for a type with none.

Returns the two item list of a array ref of the components and whether any
of them names a envelope field, 1 or 0, so the envelope is only built for a
key that reads it.

    my ( $components, $wants_envelope )
        = correlation_key_components( $entry->{key}, $where, $rule->envelope_fields );

=cut

sub correlation_key_components {
	my ( $key, $where, $envelope_fields ) = @_;

	my @components;
	if ( is_plain_arrayref($key) ) {
		@components = @{$key};
	} elsif ( defined($key) && ref($key) eq '' ) {
		@components = ($key);
	} else {
		die( $where . ' has a key that is not a string or a array' );
	}
	if ( !@components ) {
		die( $where . ' has a empty key array' );
	}

	my $wants_envelope = 0;
	foreach my $component (@components) {
		if ( !defined($component) || ref($component) ne '' || $component eq '' ) {
			die( $where . ' has a key component that is not a non-empty string' );
		}
		if ( $component =~ /^syslog\./ ) {
			if ( !is_plain_hashref($envelope_fields) || !$envelope_fields->{$component} ) {
				die( $where . ' keys on "' . $component . '", which is not a envelope field this rule type carries' );
			}
			$wants_envelope = 1;
		}
	} ## end foreach my $component (@components)

	return ( \@components, $wants_envelope );
} ## end sub correlation_key_components

=head2 correlation_key

Resolves a compiled key against a line. Each component names a capture, or a
reserved envelope field when it starts with C<syslog.>, and the values join
under a separator no log value can carry. Any component missing means no key
at all, a undef... never a partial join.

    - components :: Array ref of the key's components, as the rule compiled
          them.

    - caps :: Hash ref of the line's captures or fields.

    - envelope :: Hash ref of the C<syslog.*> envelope fields, or undef for
          a rule type with none.

Returns the joined key as a string, or undef.

    my $key = correlation_key( [ 'syslog.host', 'syslog.pid' ], $caps, $envelope );

=cut

sub correlation_key {
	my ( $components, $caps, $envelope ) = @_;

	my @values;
	foreach my $component ( @{$components} ) {
		my $value;
		if ( $component =~ /^syslog\./ ) {
			$value = defined($envelope) ? $envelope->{$component} : undef;
		} else {
			$value = $caps->{$component};
		}
		if ( !defined($value) ) {
			return undef;
		}
		push( @values, $value );
	} ## end foreach my $component ( @{$components} )

	return join( "\x00", @values );
} ## end sub correlation_key

=head2 context_put

Stores a capture line's data under a scope and key, bounding the keys held
per scope at 10000... on hitting the cap the expired are pruned first and
then the soonest to expire is evicted.

    - store :: The correlation store.

    - scope :: The correlation scope, the watcher name.

    - key :: The joined key, as L</correlation_key> gives it.

    - data :: Hash ref of what the capture line found.

    - ttl :: The seconds the data is held.

    - now :: The current time.

Returns nothing.

    context_put( $store, $scope, $key, $caps, 60, $now );

=cut

sub context_put {
	my ( $store, $scope, $key, $data, $ttl, $now ) = @_;

	my $scope_context = $store->{context}{$scope} //= {};

	bound_expiring_store( $scope_context, $key, $now );

	$scope_context->{$key} = { 'data' => $data, 'expires' => $now + $ttl };

	return;
} ## end sub context_put

=head2 context_get

Reads live context back out of a store, leaving the store as it was... a
scope or key that was never written is not created by the asking.

    - store :: The correlation store.

    - scope :: The correlation scope, the watcher name.

    - key :: The joined key, as L</correlation_key> gives it.

    - now :: The current time.

Returns the data hash ref a capture line left, the caller's to read and
never to modify, or undef when the key holds none or what it held has
expired.

    my $data = context_get( $store, $scope, $key, $now );

=cut

sub context_get {
	my ( $store, $scope, $key, $now ) = @_;

	my $scope_context = $store->{context}{$scope};
	if ( !defined($scope_context) ) {
		return undef;
	}

	my $held = $scope_context->{$key};
	if ( !defined($held) || $held->{expires} <= $now ) {
		return undef;
	}

	return $held->{data};
} ## end sub context_get

# the most deferred offenses held per correlation key... past it the oldest
# is dropped, so a key whose capture line never comes can not grow forever
my $PENDING_PER_KEY_MAX = 100;

=head2 pending_park

Parks a offense that can not be resolved yet under its key, to await a
capture line with the same key... the line was a offense, just one whose
context has not arrived. At most 100 wait per key, the oldest dropped to
make room.

    - store :: The correlation store.

    - scope :: The correlation scope, the watcher name.

    - key :: The joined key the offense produced.

    - caps :: Hash ref of the offense's data, authoritative on completion.

    - regexp :: The index of the entry that matched, or undef for a json
          rule with no match entries.

    - defer :: The seconds the offense waits before it is dropped.

    - now :: The current time.

    - fields :: Optional. Hash ref of the fields message_json and the
          mungers made of the offense's own line, which go under
          everything else on completion. A copy is kept, so a later write
          to the passed hash does not reach it.

Returns nothing.

    pending_park( $store, $scope, $key, $caps, 0, 60, $now );
    pending_park( $store, $scope, $key, $caps, 0, 60, $now, $passage->{fields} );

=cut

sub pending_park {
	my ( $store, $scope, $key, $caps, $regexp, $defer, $now, $fields ) = @_;

	my %pending = ( 'caps' => $caps, 'regexp' => $regexp, 'expires' => $now + $defer );
	if ( defined($fields) ) {
		$pending{fields} = { %{$fields} };
	}
	my $pendings = $store->{pending}{$scope}{$key} //= [];
	push( @{$pendings}, \%pending );
	if ( scalar( @{$pendings} ) > $PENDING_PER_KEY_MAX ) {
		shift( @{$pendings} );
	}

	return;
} ## end sub pending_park

=head2 pending_complete

Completes the offenses deferred under a key, now that a capture line has
brought its context... the pendings come off the key whether or not they
complete, a expired one simply being dropped.

    - store :: The correlation store.

    - scope :: The correlation scope, the watcher name.

    - key :: The joined key the capture line produced.

    - context :: Hash ref of the capture line's data. Each completion takes
          it over the fields the offense was parked with and under the
          offense's own captures, the same order a offense that found its
          context waiting is built in.

    - now :: The current time, against which the pendings expire.

Returns a list of completions, each a found hash of C<data> and C<regexp>,
the regexp being the one the deferred offense was parked with. Empty when
nothing was waiting or all of it had expired.

    push( @completions, pending_complete( $store, $scope, $key, $caps, $now ) );

=cut

sub pending_complete {
	my ( $store, $scope, $key, $context, $now ) = @_;

	my $scope_pending = $store->{pending}{$scope};
	if ( !defined($scope_pending) ) {
		return ();
	}
	my $pendings = delete( $scope_pending->{$key} );
	if ( !defined($pendings) ) {
		return ();
	}

	my @completions;
	foreach my $pending ( @{$pendings} ) {
		if ( $pending->{expires} <= $now ) {
			next;
		}
		push(
			@completions,
			{
				'data'   => { %{ $pending->{fields} // {} }, %{$context}, %{ $pending->{caps} } },
				'regexp' => $pending->{regexp}
			}
		);
	}

	return @completions;
} ## end sub pending_complete

=head2 fold_completions

Folds a line's own offense and the completions its capture lines brought
into the one found a check returns... the offense leads, else the first
completion does, and the rest ride in its C<more>.

    - found :: The line's own found hash, or undef when it was not one.

    - completions :: Array ref of completion found hashes, left untouched.

Returns the leading found hash, with a C<more> array ref of the others when
there are any, or undef when there was neither.

    return fold_completions( $found, \@completions );

=cut

sub fold_completions {
	my ( $found, $completions ) = @_;

	my @rest    = @{$completions};
	my $primary = $found // shift(@rest);
	if ( defined($primary) && @rest ) {
		$primary->{more} = \@rest;
	}

	return $primary;
} ## end sub fold_completions

=head2 correlation_prune

Drops expired context and expired pendings from a store, and every scope
left empty by it, so expiry does not depend on traffic. Takes the store and
the current time, and returns nothing.

    correlation_prune( $store, $now );

=cut

sub correlation_prune {
	my ( $store, $now ) = @_;

	my $context = $store->{context};
	foreach my $scope ( keys( %{$context} ) ) {
		foreach my $key ( keys( %{ $context->{$scope} } ) ) {
			if ( $context->{$scope}{$key}{expires} <= $now ) {
				delete( $context->{$scope}{$key} );
			}
		}
		if ( !%{ $context->{$scope} } ) {
			delete( $context->{$scope} );
		}
	} ## end foreach my $scope ( keys( %{$context} ) )

	my $pending = $store->{pending};
	foreach my $scope ( keys( %{$pending} ) ) {
		foreach my $key ( keys( %{ $pending->{$scope} } ) ) {
			my @live = grep { $_->{expires} > $now } @{ $pending->{$scope}{$key} };
			if (@live) {
				$pending->{$scope}{$key} = \@live;
			} else {
				delete( $pending->{$scope}{$key} );
			}
		}
		if ( !%{ $pending->{$scope} } ) {
			delete( $pending->{$scope} );
		}
	} ## end foreach my $scope ( keys( %{$pending} ) )

	return;
} ## end sub correlation_prune

=head2 correlation_restore

Merges a dumped store back into a live one, dropping anything already
expired as of the passed time. Merges rather than replaces, so it is safe to
call at start.

    - store :: The live correlation store.

    - state :: The dumped store, as it came back off the context tablet. A
          state that is not a hash restores nothing, a context or pending
          half that is not one is skipped, and a context entry or pending
          item that is not a hash or has no live expires is dropped.

    - now :: The current time.

Returns nothing.

Dies on a malformed scope within a half, a context scope or pending scope
that is not a hash, or a pending key whose value is not a array.

    correlation_restore( $store, $state, $now );

=cut

sub correlation_restore {
	my ( $store, $state, $now ) = @_;

	if ( !is_plain_hashref($state) ) {
		return;
	}

	if ( is_plain_hashref( $state->{context} ) ) {
		foreach my $scope ( keys( %{ $state->{context} } ) ) {
			foreach my ( $key, $entry ) ( %{ $state->{context}{$scope} } ) {
				if ( is_plain_hashref($entry) && defined( $entry->{expires} ) && $entry->{expires} > $now ) {
					$store->{context}{$scope}{$key} = $entry;
				}
			}
		}
	}

	if ( is_plain_hashref( $state->{pending} ) ) {
		foreach my $scope ( keys( %{ $state->{pending} } ) ) {
			foreach my $key ( keys( %{ $state->{pending}{$scope} } ) ) {
				my @live = grep { is_plain_hashref($_) && defined( $_->{expires} ) && $_->{expires} > $now }
					@{ $state->{pending}{$scope}{$key} };
				if (@live) {
					push( @{ $store->{pending}{$scope}{$key} }, @live );
				}
			}
		}
	} ## end if ( is_plain_hashref( $state->{pending} ))

	return;
} ## end sub correlation_restore

1;
