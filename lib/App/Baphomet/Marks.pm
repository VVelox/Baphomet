package App::Baphomet::Marks;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Exporter qw( import );

our @EXPORT_OK = qw( mark_key live_mark value_verdict mark_set apply_marks bound_expiring_store );

=head1 NAME

App::Baphomet::Marks - The mark store's pure core, drivable with or without a galla.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Marks qw( mark_key live_mark apply_marks );

    my %marks;
    my $mark = live_mark( \%marks, 'failed_login', mark_key( $entry, $data, $ip ), $now );
    my ( $set, $lifted ) = apply_marks( \%marks, $rule->marks, $rule->unmarks,
        $data, \@brandable, $now );

=head1 DESCRIPTION

The mark machinery, lifted out of the galla so it runs over any store
hashref... the galla passes its live C<< $self->{marks} >> and layers the
fleet gossip and the ignore pre-filter around these, while C<run_tests>
passes a throwaway store per test entry and a virtual clock, so a rule
file can prove its own branding and gating cold. Nothing here knows of
tablets, buses, or wall clocks... state in, verdicts and brands out.

The store shape is per mark name a hash of branded keys, each
C<< { expires, set?, value? } >>.

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
	$store->{$key} = { 'expires' => $now + $ttl, 'set' => $set, defined($value) ? ( 'value' => $value ) : () };

	if ( defined($on_set) ) {
		$on_set->( $name, $key, $value, $now + $ttl, $set );
	}

	return;
} ## end sub mark_set

=head2 apply_marks

Applies a rule's mark and unmark entries for one found result... var
entries key by that capture, vars ones by the joined captures, var-less
ones by each passed offender. The offenders come pre-filtered... the
galla drops the ignored before calling, a cold caller passes what it
means. Returns the set and lifted lists, each entry C<{ name, key }>,
the shape the EVE event carries. The optional callbacks hear each brand
set (as L</mark_set> tells it) and each lift as C<( $name, $key )>.

    my ( $set, $lifted ) = apply_marks( $store, $marks, $unmarks, $data,
        $offenders, $now, $on_set, $on_unset );

=cut

sub apply_marks {
	my ( $store_all, $marks, $unmarks, $data, $offenders, $now, $on_set, $on_unset ) = @_;

	my @set;
	foreach my $entry ( @{$marks} ) {
		my $value = defined( $entry->{value_var} ) ? $data->{ $entry->{value_var} } : undef;
		foreach my $key ( _entry_keys( $entry, $data, $offenders ) ) {
			mark_set( $store_all, $entry->{name}, $key, $value, $entry->{ttl}, $now, $on_set );
			push( @set, { 'name' => $entry->{name}, 'key' => $key } );
		}
	}

	# a lift deletes the brand, and the mark name's store with it once that
	# leaves it empty... a key not branded under the name lifts nothing
	my @lifted;
	foreach my $entry ( @{$unmarks} ) {
		my $name = $entry->{name};
		foreach my $key ( _entry_keys( $entry, $data, $offenders ) ) {
			my $name_store = $store_all->{$name};
			if ( !defined($name_store) || !defined( $name_store->{$key} ) ) {
				next;
			}
			delete( $name_store->{$key} );
			if ( !%{$name_store} ) {
				delete( $store_all->{$name} );
			}
			push( @lifted, { 'name' => $name, 'key' => $key } );
			if ( defined($on_unset) ) {
				$on_unset->( $name, $key );
			}
		} ## end foreach my $key ( _entry_keys( $entry, $data, $offenders...))
	} ## end foreach my $entry ( @{$unmarks} )

	return ( \@set, \@lifted );
} ## end sub apply_marks

# the keys a mark or unmark entry applies to for one found result... a var
# or vars entry its one capture key, a var-less entry every offender.
#
# args:
#   $entry     :: the mark or unmark entry
#   $data      :: the result's data hash, which a var or vars entry keys by
#   $offenders :: arrayref of the result's offenders, which a var-less entry
#                 keys by
#
# returns the list of keys... empty for a var or vars entry whose capture is
# missing, as mark_key gives no partial key.
#
#   foreach my $key ( _entry_keys( $entry, $data, $offenders ) ) { ... }
sub _entry_keys {
	my ( $entry, $data, $offenders ) = @_;

	if ( defined( $entry->{var} ) || defined( $entry->{vars} ) ) {
		my $key = mark_key( $entry, $data, undef );
		return defined($key) ? ($key) : ();
	}
	return @{$offenders};
}

1;
