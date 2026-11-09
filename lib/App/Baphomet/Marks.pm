package App::Baphomet::Marks;

use 5.006;
use strict;
use warnings;
use Exporter   qw( import );
use List::Util qw( any );

our @EXPORT_OK = qw( mark_key mark_gates_pass mark_set apply_marks bound_expiring_store );

=head1 NAME

App::Baphomet::Marks - The mark store's pure core, drivable with or without a galla.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Marks qw( mark_gates_pass apply_marks );

    my %marks;
    if ( mark_gates_pass( \%marks, $rule->mark_gates, $data, $ip, $now ) ) { ... }
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

# whether a gate entry belongs to the pass being run... a data-keyed entry,
# one with a var or vars, to the data pass ran with a undef $ip, and a
# var-less entry to the offender pass ran with one.
#
# args:
#   $entry :: a marked, not_marked, or sequence gate entry
#   $ip    :: the offender of the offender pass, or undef for the data pass
#
# returns 1 when the entry is judged in this pass, else 0.
#
#   next if !_entry_in_pass( $entry, $ip );
sub _entry_in_pass {
	my ( $entry, $ip ) = @_;

	my $data_keyed = defined( $entry->{var} ) || defined( $entry->{vars} );
	if ($data_keyed) {
		return defined($ip) ? 0 : 1;
	}
	return defined($ip) ? 1 : 0;
}

# looks a brand up in the store, live ones only.
#
# args:
#   $store_all :: the mark store, per mark name a hash of branded keys
#   $mark_name :: the mark name
#   $key       :: the branded key, as mark_key gives it
#   $now       :: the current time
#
# returns the mark's hash ref, { expires, set?, value? }, or undef when the
# key carries no such brand or it has expired.
#
#   my $mark = _live_mark( $store_all, 'brute_force', '192.0.2.7', $now );
sub _live_mark {
	my ( $store_all, $mark_name, $key, $now ) = @_;

	my $mark = $store_all->{$mark_name}{$key};
	if ( !defined($mark) || $mark->{expires} <= $now ) {
		return undef;
	}
	return $mark;
}

# judges a gate entry's value compares against a live mark... value_is wants
# the mark's value to equal the named data var, value_not wants it to differ.
#
# args:
#   $entry :: the gate entry, whose value_is and value_not, either optional,
#             name the data var to compare against
#   $mark  :: the live mark's hash ref
#   $data  :: the result's data hash
#
# returns 'fails' when a compare provably fails, both sides present and
# disagreeing, else 'unknown' when a compare could not be judged for a side
# missing, else 'holds', which is also the answer with no compares at all.
#
#   if ( _value_verdict( $entry, $mark, $data ) eq 'holds' ) { ... }
sub _value_verdict {
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
} ## end sub _value_verdict

=head2 mark_gates_pass

Evaluates a rule's marked/not_marked/sequence gates against a store, in
one of two modes... with a undef C<$ip> the data-keyed entries (a C<var>
or C<vars>), ran once per found result, with a C<$ip> the var-less
entries, offender-keyed and ran once per candidate. Returns true when
every applicable gate holds. A marked gate with nothing to look up fails,
a not_marked one passes, and a value compare with either side missing can
not be proven... so a marked gate does not hold on it, and a not_marked
brand still vetoes. Conservative on every count.

    if ( mark_gates_pass( $store, $gates, $data, $ip, $now ) ) { ... }

=cut

sub mark_gates_pass {
	my ( $store_all, $gates, $data, $ip, $now ) = @_;

	# a marked gate holds when one of its brands is live for the key and its
	# value compares all hold... a names entry on any of its listed brands, a
	# name entry on its one, so a any-of never rides a value it did not prove
	foreach my $entry ( grep { _entry_in_pass( $_, $ip ) } @{ $gates->{marked} } ) {
		my $key = mark_key( $entry, $data, $ip );
		if ( !defined($key) ) {
			return 0;
		}
		my @names = defined( $entry->{names} ) ? @{ $entry->{names} } : ( $entry->{name} );
		my $held  = any {
			my $mark = _live_mark( $store_all, $_, $key, $now );
			defined($mark) && _value_verdict( $entry, $mark, $data ) eq 'holds';
		} @names;
		if ( !$held ) {
			return 0;
		}
	} ## end foreach my $entry ( grep { _entry_in_pass( $_, ...)})

	# a not_marked gate is vetoed by a live brand, unless a value compare
	# provably fails... "not marked with this value" spares a brand whose
	# stored value differs (value_is) or agrees (value_not), while a compare
	# with either side missing still vetoes
	foreach my $entry ( grep { _entry_in_pass( $_, $ip ) } @{ $gates->{not_marked} } ) {
		my $key = mark_key( $entry, $data, $ip );
		if ( !defined($key) ) {
			next;
		}
		my $mark = _live_mark( $store_all, $entry->{name}, $key, $now );
		if ( defined($mark) && _value_verdict( $entry, $mark, $data ) ne 'fails' ) {
			return 0;
		}
	} ## end foreach my $entry ( grep { _entry_in_pass( $_, ...)})

	# the sequence gate... ordered temporal correlation. every named mark must
	# be live for the key and their first-seen times non-decreasing in the
	# listed order, so "stage a then b then c" only holds when a fired no later
	# than b and b no later than c. keyed like the marked gate, by a var's
	# capture, a vars compound, or, var-less, by the offender
	foreach my $entry ( grep { _entry_in_pass( $_, $ip ) } @{ $gates->{sequence} } ) {
		my $key = mark_key( $entry, $data, $ip );
		if ( !defined($key) ) {
			return 0;
		}
		my $prev_set;
		foreach my $mark_name ( @{ $entry->{marks} } ) {
			my $mark = _live_mark( $store_all, $mark_name, $key, $now );
			if ( !defined($mark) ) {
				return 0;
			}
			my $set = $mark->{set};
			# order only enforced between marks that both carry a set time... a
			# mark from before set times existed simply is not ordered against
			if ( defined($set) && defined($prev_set) && $set < $prev_set ) {
				return 0;
			}
			if ( defined($set) ) {
				$prev_set = $set;
			}
		} ## end foreach my $mark_name ( @{ $entry->{marks} } )
	} ## end foreach my $entry ( grep { _entry_in_pass( $_, ...)})

	return 1;
} ## end sub mark_gates_pass

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
	if ( !defined($store) ) {
		$store = $store_all->{$name} = {};
	}

	bound_expiring_store( $store, $key, $now );

	my $set
		= ( defined( $store->{$key} ) && defined( $store->{$key}{set} ) && $store->{$key}{expires} > $now )
		? $store->{$key}{set}
		: $now;
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
