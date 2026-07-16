package App::Baphomet::ClayTablet::Redis;

use 5.006;
use strict;
use warnings;
use Sys::Hostname                   ();
use App::Baphomet::ClayTablet::File ();
use App::Baphomet::LogDrek          qw( log_drek );

=head1 NAME

App::Baphomet::ClayTablet::Redis - A Redis mark-sync backend for a galla, with optional local persistence.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

Shares a galla's marks across a fleet over Redis while keeping the galla's own
state authoritative and local. Marks live in the galla's memory and are gated
and branded there as always; this backend is a best-effort I<sync bus> the
fleet gossips brands over, not the store the gates read from. Lose the Redis and
a galla degrades cleanly to standalone per-host marks... it simply stops hearing
the other machines until the bus returns. Built on L<Redis::Fast>, a optional
dependency only real when this backend is chosen.

=head2 Storage, and the optional file backend

Storage and sharing are separate axes. The host-local tablets (counters,
pending bans, positions, cursors, stats, context, marks, and the mark stream
cursor) are not shared... a log offset means nothing on another machine. Where
they persist depends on C<options.local>:

=over 4

=item * With C<options.local> set, the host-local tablets go to a wrapped
L<App::Baphomet::ClayTablet::File> on the local disk, and Redis is used only for
the mark stream. This is the fleet-safe mode: a galla that loses the Redis and
is restarted while it is still gone resumes its whole state from disk, and only
the fleet gossip waits for the bus. C<options.local> may be a table carrying a
C<base_dir>, else the global C<tablet_base_dir> is used.

=item * Without it, the host-local tablets are Redis strings under
C<< <prefix>:tablet:<galla>:<kind> >>, the whole store living in the one Redis.
Simpler, but a Redis outage then takes the state with it, so this suits a deploy
that treats Redis as reliable infrastructure or a single galla per prefix.

=back

=head2 The mark sync bus

A Redis Stream per scope, C<< <prefix>:marklog:<scope> >>, is an append-only,
ordered, durable log of mark deltas... C<< { op, name, key, value?, expires,
origin } >>. C<XADD> is the atomic append that stands in for the ledger's flock;
one stream on one server is a single total order every machine folds identically
and so converges on. The galla publishes a delta after each local brand or lift,
and drains new deltas on its sweep into its own live marks. The stream is trimmed
by age (C<MINID>) to C<mark_max_ttl>, so it holds one longest-ttl worth of
events... enough that a cold or long-down galla replays the retained stream and
reconstructs every still-live mark, no separate snapshot needed.

=head2 options

Under C<ClayTablet.options>, all optional.

    - server :: host:port of the Redis. Default 127.0.0.1:6379.
    - sock :: A unix socket path, used instead of server when set.
    - password :: The AUTH password, when the Redis wants one.
    - prefix :: The key namespace. Default "baphomet".
    - scope :: The mark sharing unit. Machines sharing a scope share marks.
          Default the galla (kur) name, so same-named kurs across the fleet
          share while different kurs stay apart.
    - mark_max_ttl :: The stream trim horizon and cold-replay bound, in
          seconds. Default 604800 (a week). Must exceed the longest mark ttl.
    - host :: This machine's identity, stamped on published deltas so a galla
          skips its own on drain. Default the hostname.
    - local :: Enables local disk persistence of the host-local tablets. A
          table (optionally carrying base_dir) or a plain true value. Off, the
          tablets are Redis strings.
    - db :: The numbered database to SELECT into.
    - cnx_timeout :: Seconds a connect attempt waits before giving up, so a
          dead or firewalled server fails fast rather than hanging the galla.
          Default 1.
    - reconnect :: Seconds between our own reconnect attempts while the link
          is down, throttling so a persistent outage is not a connect storm.
          Default 5. The link is opened fast-fail (never blocking), so this is
          how often a down bus is retried, not how long a connect blocks.
    - outbox_max :: How many un-published deltas to buffer while the Redis is
          unreachable before dropping the oldest. Default 10000.

=head1 METHODS

=head2 new

    my $backend = App::Baphomet::ClayTablet::Redis->new(
        'name'            => $galla_name,
        'options'         => { 'server' => '127.0.0.1:6379', 'local' => 1 },
        'tablet_base_dir' => '/var/db/baphomet',
    );

Requires L<Redis::Fast>, dying clean if it is not installed, and opens the
connection. A connection that will not open is stashed rather than fatal, so a
galla with C<local> set can start and run standalone until the Redis returns;
L</verify> is where a galla learns whether it may proceed.

=cut

sub new {
	my ( $class, %opts ) = @_;

	my $options = ref( $opts{options} ) eq 'HASH' ? $opts{options} : {};

	my $self = {
		'name'    => $opts{name},
		'log_tag' => 'galla-' . ( defined( $opts{name} ) ? $opts{name} : '' ),
		'prefix'  => defined( $options->{prefix} ) ? $options->{prefix} : 'baphomet',
		'scope'   => defined( $options->{scope} )  ? $options->{scope}
		: ( defined( $opts{name} ) ? $opts{name} : 'default' ),
		'mark_max_ttl' => (
				   defined( $options->{mark_max_ttl} )
				&& $options->{mark_max_ttl} =~ /^[0-9]+$/
				&& $options->{mark_max_ttl} > 0
			) ? $options->{mark_max_ttl} + 0
		: 604800,
		'origin'     => defined( $options->{host} ) ? $options->{host} : Sys::Hostname::hostname(),
		'outbox'     => [],
		'outbox_max' => ( defined( $options->{outbox_max} ) && $options->{outbox_max} =~ /^[0-9]+$/ )
		? $options->{outbox_max} + 0
		: 10000,
		'outbox_warned' => 0,
		'options'       => $options,
		'redis'         => undef,
		'connect_error' => undef,
		'local'         => undef,
	};
	bless $self, $class;

	# the optional local disk persistence... the host-local tablets go to a
	# wrapped file backend, and the Redis is then only the mark bus
	if ( $options->{local} ) {
		my $local_opts = ref( $options->{local} ) eq 'HASH' ? $options->{local} : {};
		$self->{local} = App::Baphomet::ClayTablet::File->new(
			'name'            => $opts{name},
			'options'         => $local_opts,
			'tablet_base_dir' => $opts{tablet_base_dir},
		);
	}

	eval { require Redis::Fast; };
	if ($@) {
		die( 'the ClayTablet redis backend needs Redis::Fast, which is not installed... ' . $@ );
	}

	# fast-fail connect args... reconnect 0 and a short cnx_timeout so
	# Redis::Fast never blocks the galla retrying a dead server at startup or
	# stalls it mid-run. reconnection is ours to manage, throttled, so a down
	# bus is a quiet degradation rather than a hang
	my %args = (
		'reconnect'   => 0,
		'cnx_timeout' => ( defined( $options->{cnx_timeout} ) && $options->{cnx_timeout} =~ /^[0-9]+$/ )
		? $options->{cnx_timeout} + 0
		: 1,
	);
	if ( defined( $options->{sock} ) ) {
		$args{sock} = $options->{sock};
	} elsif ( defined( $options->{server} ) ) {
		$args{server} = $options->{server};
	} else {
		$args{server} = '127.0.0.1:6379';
	}
	if ( defined( $options->{password} ) ) {
		$args{password} = $options->{password};
	}
	if ( defined( $options->{name} ) ) {
		$args{name} = $options->{name};
	}
	$self->{redis_args} = \%args;
	$self->{reconnect_throttle}
		= ( defined( $options->{reconnect} ) && $options->{reconnect} =~ /^[0-9]+$/ )
		? $options->{reconnect} + 0
		: 5;
	$self->{last_connect_try} = undef;

	$self->_ensure_redis;

	return $self;
} ## end sub new

# (re)connects the Redis if it is down, throttled so a persistent outage does
# not mean a connect attempt on every call. sets connect_error and leaves redis
# undef on failure. returns true if the link is up after this
sub _ensure_redis {
	my ($self) = @_;

	if ( defined( $self->{redis} ) ) {
		return 1;
	}

	my $now = time;
	if ( defined( $self->{last_connect_try} ) && ( $now - $self->{last_connect_try} ) < $self->{reconnect_throttle} ) {
		return 0;
	}
	$self->{last_connect_try} = $now;

	eval {
		$self->{redis} = Redis::Fast->new( %{ $self->{redis_args} } );
		if ( defined( $self->{options}{db} ) ) {
			$self->{redis}->select( $self->{options}{db} );
		}
	};
	if ($@) {
		$self->{connect_error} = $@;
		$self->{redis}         = undef;
		return 0;
	}

	return 1;
} ## end sub _ensure_redis

# the key a host-local tablet of the given kind lives under, when the store is
# Redis rather than the local file backend
sub _key {
	my ( $self, $kind ) = @_;

	return $self->{prefix} . ':tablet:' . ( defined( $self->{name} ) ? $self->{name} : '' ) . ':' . $kind;
}

# the mark stream key for this scope, shared across the fleet
sub _marklog_key {
	my ($self) = @_;

	return $self->{prefix} . ':marklog:' . $self->{scope};
}

=head2 locator

    my $where = $backend->locator($kind);

The path or key a host-local tablet lives at, the local file's path when
C<local> is set, else the Redis key.

=cut

sub locator {
	my ( $self, $kind ) = @_;

	if ( $self->{local} ) {
		return $self->{local}->locator($kind);
	}

	return $self->_key($kind);
}

=head2 verify

    my $err = $backend->verify;

With C<local> set, returns the local backend's verify... the disk must be usable,
but the Redis being down is only a logged degradation, not fatal, so a galla can
start and run standalone until the bus returns. Without C<local>, the Redis must
answer, as it holds the whole store.

=cut

sub verify {
	my ($self) = @_;

	if ( $self->{local} ) {
		my $local_error = $self->{local}->verify;
		if ( defined($local_error) ) {
			return $local_error;
		}
		if ( !$self->_redis_ok ) {
			log_drek(
				'warning',
				'mark sync Redis is unreachable at start... running standalone on the local tablets until it returns'
					. ( defined( $self->{connect_error} ) ? '... ' . $self->{connect_error} : '' ),
				undef,
				$self->{log_tag}
			);
		}
		return undef;
	} ## end if ( $self->{local} )

	if ( !defined( $self->{redis} ) ) {
		return 'ClayTablet redis backend could not connect... '
			. ( defined( $self->{connect_error} ) ? $self->{connect_error} : 'unknown' );
	}
	if ( !$self->_redis_ok ) {
		return 'ClayTablet redis backend ping failed';
	}

	return undef;
} ## end sub verify

# true if the Redis link is up and answers a ping... drops the handle on a
# failed ping so the next call reconnects
sub _redis_ok {
	my ($self) = @_;

	if ( !$self->_ensure_redis ) {
		return 0;
	}
	my $ok;
	eval { $ok = $self->{redis}->ping; };
	if ( $@ || !$ok ) {
		$self->{redis} = undef;
		return 0;
	}

	return 1;
} ## end sub _redis_ok

=head2 write

    $backend->write( $kind, \@lines );

Writes a host-local tablet... to the local file backend when C<local> is set,
else to a Redis string (the joined lines, or a C<DEL> when there are none).

=cut

sub write {
	my ( $self, $kind, $lines ) = @_;

	if ( $self->{local} ) {
		return $self->{local}->write( $kind, $lines );
	}

	if ( !$self->_ensure_redis ) {
		return 0;
	}
	my $key = $self->_key($kind);
	eval {
		if ( @{$lines} ) {
			$self->{redis}->set( $key, join( "\n", @{$lines} ) . "\n" );
		} else {
			$self->{redis}->del($key);
		}
	};
	if ($@) {
		$self->{redis} = undef;
		log_drek( 'err', 'writing the ' . $kind . ' tablet "' . $key . '" failed... ' . $@, undef, $self->{log_tag} );
		return 0;
	}

	return 1;
} ## end sub write

=head2 read

    my @lines = $backend->read($kind);

Reads a host-local tablet back, from the local file backend when C<local> is
set, else from the Redis string.

=cut

sub read {
	my ( $self, $kind ) = @_;

	if ( $self->{local} ) {
		return $self->{local}->read($kind);
	}

	if ( !$self->_ensure_redis ) {
		return ();
	}
	my $key = $self->_key($kind);
	my $blob;
	eval { $blob = $self->{redis}->get($key); };
	if ($@) {
		$self->{redis} = undef;
		log_drek( 'err', 'reading the ' . $kind . ' tablet "' . $key . '" failed... ' . $@, undef, $self->{log_tag} );
		return ();
	}
	if ( !defined($blob) || $blob eq '' ) {
		return ();
	}

	return split( /\n/, $blob );
} ## end sub read

=head2 mark_sync

True... this backend provides the mark sync bus, so the galla publishes and
drains marks through it.

=cut

sub mark_sync { return 1; }

=head2 origin

This machine's identity, stamped on published deltas.

=cut

sub origin {
	my ($self) = @_;

	return $self->{origin};
}

=head2 mark_publish

    $backend->mark_publish( $op, $name, $key, $value, $expires );

Queues a mark delta (C<$op> being C<set> or C<unset>) and flushes the queue to
the stream. A delta that can not be sent, the Redis being down, stays buffered
up to C<outbox_max> and flushes on the next call that finds the link back... a
brief outage loses nothing to the fleet, a long one drops the oldest with a log.
Best-effort by design: a failed publish never touches the local brand that has
already happened.

=cut

sub mark_publish {
	my ( $self, $op, $name, $key, $value, $expires ) = @_;

	push(
		@{ $self->{outbox} },
		{
			'op'      => $op,
			'name'    => $name,
			'key'     => $key,
			'value'   => $value,
			'expires' => $expires,
			'origin'  => $self->{origin}
		}
	);
	while ( scalar( @{ $self->{outbox} } ) > $self->{outbox_max} ) {
		shift( @{ $self->{outbox} } );
		if ( !$self->{outbox_warned} ) {
			log_drek( 'warning', 'the mark sync outbox is full, dropping the oldest un-published deltas',
				undef, $self->{log_tag} );
			$self->{outbox_warned} = 1;
		}
	}

	$self->_flush_outbox;

	return;
} ## end sub mark_publish

# pushes as many buffered deltas as the Redis will take, oldest first, stopping
# at the first that fails so the rest stay queued for the next attempt
sub _flush_outbox {
	my ($self) = @_;

	if ( !@{ $self->{outbox} } ) {
		return;
	}
	if ( !$self->_ensure_redis ) {
		return;
	}

	my $stream = $self->_marklog_key;
	my $minid  = ( time - $self->{mark_max_ttl} ) * 1000;

	while ( @{ $self->{outbox} } ) {
		my $delta  = $self->{outbox}[0];
		my @fields = (
			'op',      $delta->{op}, 'name', $delta->{name}, 'key', $delta->{key}, 'origin', $delta->{origin},
			'expires', defined( $delta->{expires} ) ? $delta->{expires} : '',
		);
		if ( defined( $delta->{value} ) ) {
			push( @fields, 'value', $delta->{value} );
		}
		my $sent;
		eval {
			$self->{redis}->xadd( $stream, 'MINID', '~', $minid, '*', @fields );
			$sent = 1;
		};
		if ( !$sent ) {
			# the link went away... keep the rest for the next flush and drop
			# the handle so the next attempt reconnects
			$self->{redis} = undef;
			last;
		}
		shift( @{ $self->{outbox} } );
		$self->{outbox_warned} = 0;
	} ## end while ( @{ $self->{outbox} } )

	return;
} ## end sub _flush_outbox

=head2 mark_drain

    my ( $events, $new_id ) = $backend->mark_drain($last_id);

Flushes any buffered deltas, then reads the stream forward from C<$last_id>
(undef or empty meaning from the start, so a cold galla replays the retained
stream). Returns the new deltas as hashrefs, its own C<origin> filtered out, and
the id to resume from next time. A Redis that will not answer returns no events
and the same id, so the galla just keeps its local marks and tries again.

=cut

sub mark_drain {
	my ( $self, $last_id ) = @_;

	$self->_flush_outbox;

	if ( !$self->_ensure_redis ) {
		return ( [], $last_id );
	}
	if ( !defined($last_id) || $last_id eq '' ) {
		$last_id = '0';
	}

	my $stream = $self->_marklog_key;
	my $reply;
	eval { $reply = $self->{redis}->xread( 'COUNT', 1000, 'STREAMS', $stream, $last_id ); };
	if ($@) {
		$self->{redis} = undef;
		log_drek( 'err', 'draining the mark stream "' . $stream . '" failed... ' . $@, undef, $self->{log_tag} );
		return ( [], $last_id );
	}
	if ( ref($reply) ne 'ARRAY' ) {
		return ( [], $last_id );
	}

	my @events;
	my $new_id = $last_id;
	foreach my $stream_reply ( @{$reply} ) {
		# each is [ stream_name, [ [ id, [ f, v, f, v, ... ] ], ... ] ]
		next if ( ref($stream_reply) ne 'ARRAY' || ref( $stream_reply->[1] ) ne 'ARRAY' );
		foreach my $entry ( @{ $stream_reply->[1] } ) {
			next if ( ref($entry) ne 'ARRAY' || ref( $entry->[1] ) ne 'ARRAY' );
			my ( $id, $fields ) = @{$entry};
			$new_id = $id;
			my %field = @{$fields};
			# skip our own deltas, already applied locally when we made them
			next if ( defined( $field{origin} ) && $field{origin} eq $self->{origin} );
			push(
				@events,
				{
					'op'      => $field{op},
					'name'    => $field{name},
					'key'     => $field{key},
					'expires' => $field{expires},
					'origin'  => $field{origin},
					exists( $field{value} ) ? ( 'value' => $field{value} ) : (),
				}
			);
		} ## end foreach my $entry ( @{ $stream_reply->[1] } )
	} ## end foreach my $stream_reply ( @{$reply} )

	return ( \@events, $new_id );
} ## end sub mark_drain

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991, or (at your
  option) any later version, matching fail2ban, which parts of this
  project, most notably the shipped rules, are derived from.

=cut

1;
