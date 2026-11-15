package App::Baphomet::Marks;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Exporter qw( import );

our @EXPORT_OK = qw( mark_key live_mark mark_hosts value_verdict mark_set mark_unset bound_expiring_store );

=head1 NAME

App::Baphomet::Marks - The mark store's pure core, drivable with or without a galla.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Marks qw( mark_key live_mark mark_set mark_unset );

    my %marks;
    my $key = mark_key( $entry, $data, $ip );
    mark_set( \%marks, 'failed_login', $key, undef, 3600, $now );
    my $mark = live_mark( \%marks, 'failed_login', $key, $now );
    mark_unset( \%marks, 'failed_login', $key );

=head1 DESCRIPTION

The mark machinery, lifted out of the galla so it runs over any store
hashref... the galla passes its live C<< $self->{marks} >> and layers the
fleet gossip and the ignore pre-filter around these, while C<run_tests>
passes a throwaway store per test entry and a virtual clock, so a rule
file can prove its own branding and gating cold. Nothing here knows of
tablets, buses, or wall clocks... state in, verdicts and brands out.

The store shape is per mark name a hash of branded keys, each
C<< { expires, set?, value?, here?, hosts? } >>... C<here> is true for a
brand set on this host, and C<hosts> is a hash keyed by the other hosts of
a fleet that have set it.

=head1 FUNCTIONS

=head2 mark_key

Resolves a mark entry's key against a line... C<vars> joins each named
capture's value on the unit separator into one compound key, C<var> takes
that capture alone, and neither takes the passed offender IP. Any piece
missing means no key at all, a undef... never a partial join.

    my $key = mark_key( $entry, $data, $ip );

=cut

sub mark_key {
	my ( $entry, $data, $ip ) = @_;

	if ( defined( $entry->{vars} ) ) {
		my @parts;
		foreach my $var ( @{ $entry->{vars} } ) {
			if ( !defined( $data->{$var} ) ) {
				return undef;
			}
			push( @parts, $data->{$var} );
		}
		return join( "\x1f", @parts );
	} ## end if ( defined( $entry->{vars} ) )

	if ( defined( $entry->{var} ) ) {
		return $data->{ $entry->{var} };
	}

	return $ip;
} ## end sub mark_key

=head2 live_mark

Looks a brand up in a store, live ones only. Returns the mark's hash ref,
C<< { expires, set?, value? } >>, or undef when the key is not branded under
the name or the brand has expired.

    my $mark = live_mark( $store, 'brute_force', '192.0.2.7', $now );

=cut

sub live_mark {
	my ( $store_all, $mark_name, $key, $now ) = @_;

	my $mark = $store_all->{$mark_name}{$key};
	if ( !defined($mark) || $mark->{expires} <= $now ) {
		return undef;
	}
	return $mark;
}

=head2 mark_hosts

Returns how many hosts have set a brand, this one when it has and each
other host of the fleet the brand says did.

    if ( mark_hosts($mark) >= 3 ) { ... }

=cut

sub mark_hosts {
	my ($mark) = @_;

	return ( $mark->{here} ? 1 : 0 ) + scalar( keys( %{ $mark->{hosts} // {} } ) );
}

=head2 value_verdict

Judges a marked or not_marked gate's value compares against a live mark...
C<value_is> wants the mark's value to equal the found var it names,
C<value_not> wants it to differ. Returns C<fails> when a compare provably
fails, both sides present and disagreeing, else C<unknown> when a compare
could not be judged for a side missing, else C<holds>, which is also the
answer with no compares at all.

    if ( value_verdict( $gate, $mark, $data ) eq 'holds' ) { ... }

=cut

sub value_verdict {
	my ( $entry, $mark, $data ) = @_;

	my $verdict = 'holds';
	foreach my $compare ( 'value_is', 'value_not' ) {
		if ( !defined( $entry->{$compare} ) ) {
			next;
		}
		my $against = $data->{ $entry->{$compare} };
		if ( !defined( $mark->{value} ) || !defined($against) ) {
			$verdict = 'unknown';
			next;
		}
		my $same = $mark->{value} eq $against;
		if ( ( $compare eq 'value_is' && !$same ) || ( $compare eq 'value_not' && $same ) ) {
			return 'fails';
		}
	} ## end foreach my $compare ( 'value_is', 'value_not' )

	return $verdict;
} ## end sub value_verdict

=head2 bound_expiring_store

Bounds a store of expiring entries at the shared 10000 cap ahead of
inserting a new key... expired entries are pruned first, then the soonest
to expire is evicted, found by a linear min-scan rather than a sort, as
this can run per line under a deliberate key flood. Used by the galla's
DNS and geo caches too, being nothing mark-specific.

    bound_expiring_store( $store, $key, $now );

=cut

sub bound_expiring_store {
	my ( $store, $key_value, $now ) = @_;

	if ( defined( $store->{$key_value} ) || scalar( keys( %{$store} ) ) < 10000 ) {
		return;
	}

	foreach my $key ( keys( %{$store} ) ) {
		if ( $store->{$key}{expires} <= $now ) {
			delete( $store->{$key} );
		}
	}
	if ( scalar( keys( %{$store} ) ) >= 10000 ) {
		my $soonest;
		foreach my $key ( keys( %{$store} ) ) {
			if ( !defined($soonest) || $store->{$key}{expires} < $store->{$soonest}{expires} ) {
				$soonest = $key;
			}
		}
		delete( $store->{$soonest} );
	}

	return;
} ## end sub bound_expiring_store

=head2 mark_set

Brands a key into a mark name's store... setting refreshes the expiry
while the set time stays first-seen, so the sequence gate orders by when
each stage first fired rather than when it was last touched. A full store
first drops the expired, then the soonest-expiring. The optional
C<$on_set> callback hears C<< ( $name, $key, $value, $expires, $set ) >>
after the brand lands... the galla's fleet gossip rides it, a cold caller
passes none.

    mark_set( $store, $name, $key, $value, $ttl, $now, $on_set );

=cut

sub mark_set {
	my ( $store_all, $name, $key, $value, $ttl, $now, $on_set ) = @_;

	my $store = $store_all->{$name};
	$store //= $store_all->{$name} = {};

	bound_expiring_store( $store, $key, $now );

	# a live brand keeps when it was first set, a new or lapsed one starts now
	my $held = $store->{$key};
	my $set  = $now;
	if ( defined($held) && defined( $held->{set} ) && $held->{expires} > $now ) {
		$set = $held->{set};
	}
	# set here, and still set by whichever other hosts a live brand says
	my $hosts = ( defined($held) && $held->{expires} > $now ) ? $held->{hosts} : undef;
	$store->{$key} = {
		'expires' => $now + $ttl,
		'set'     => $set,
		'here'    => 1,
		defined($value) ? ( 'value' => $value ) : (),
		defined($hosts) ? ( 'hosts' => $hosts ) : (),
	};

	if ( defined($on_set) ) {
		$on_set->( $name, $key, $value, $now + $ttl, $set );
	}

	return;
} ## end sub mark_set

=head2 mark_unset

Lifts a brand from a key, and drops the mark name's store with it once that
leaves it empty. Returns 1 when there was such a brand to lift, else 0. The
optional C<$on_unset> callback hears C<< ( $name, $key ) >> after a lift...
the galla's fleet gossip rides it, a cold caller passes none.

    if ( mark_unset( $store, $name, $key, $on_unset ) ) { ... }

=cut

sub mark_unset {
	my ( $store_all, $name, $key, $on_unset ) = @_;

	my $store = $store_all->{$name};
	if ( !defined($store) || !defined( $store->{$key} ) ) {
		return 0;
	}

	delete( $store->{$key} );
	if ( !%{$store} ) {
		delete( $store_all->{$name} );
	}
	if ( defined($on_unset) ) {
		$on_unset->( $name, $key );
	}

	return 1;
} ## end sub mark_unset

1;
