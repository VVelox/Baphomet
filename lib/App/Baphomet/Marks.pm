package App::Baphomet::Marks;

use 5.006;
use strict;
use warnings;
use Exporter qw( import );

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

=head2 mark_gates_pass

Evaluates a rule's marked/not_marked/sequence gates against a store, in
one of two modes... with a undef C<$ip> the data-keyed entries (a C<var>
or C<vars>), ran once per found result, with a C<$ip> the var-less
entries, offender-keyed and ran once per candidate. Returns true when
every applicable gate holds. A marked gate with nothing to look up fails,
a not_marked one passes, and a value compare with either side missing
counts as holding... conservative on every count.

    if ( mark_gates_pass( $store, $gates, $data, $ip, $now ) ) { ... }

=cut

sub mark_gates_pass {
	my ( $store_all, $gates, $data, $ip, $now ) = @_;

	foreach my $entry ( @{ $gates->{marked} } ) {
		my $data_keyed = defined( $entry->{var} ) || defined( $entry->{vars} );
		if ( $data_keyed ? defined($ip) : !defined($ip) ) {
			next;
		}
		my $key = mark_key( $entry, $data, $ip );
		if ( !defined($key) ) {
			return 0;
		}
		# a names entry holds on any of its listed brands, a name entry on
		# its one... whichever brand is live must also pass the value
		# compares, so a any-of never rides a value it did not prove
		my @names = defined( $entry->{names} ) ? @{ $entry->{names} } : ( $entry->{name} );
		my $held;
	NAME: foreach my $mark_name (@names) {
			my $mark = $store_all->{$mark_name}{$key};
			if ( !defined($mark) || $mark->{expires} <= $now ) {
				next NAME;
			}
			foreach my $compare ( 'value_is', 'value_not' ) {
				if ( !defined( $entry->{$compare} ) ) {
					next;
				}
				my $against = $data->{ $entry->{$compare} };
				if ( !defined( $mark->{value} ) || !defined($against) ) {
					next NAME;
				}
				if ( $compare eq 'value_is' ? $mark->{value} ne $against : $mark->{value} eq $against ) {
					next NAME;
				}
			} ## end foreach my $compare ( 'value_is', 'value_not' )
			$held = 1;
			last NAME;
		} ## end NAME: foreach my $mark_name (@names)
		if ( !$held ) {
			return 0;
		}
	} ## end foreach my $entry ( @{ $gates->{marked} } )

	foreach my $entry ( @{ $gates->{not_marked} } ) {
		my $data_keyed = defined( $entry->{var} ) || defined( $entry->{vars} );
		if ( $data_keyed ? defined($ip) : !defined($ip) ) {
			next;
		}
		my $key = mark_key( $entry, $data, $ip );
		if ( !defined($key) ) {
			next;
		}
		my $mark = $store_all->{ $entry->{name} }{$key};
		if ( !defined($mark) || $mark->{expires} <= $now ) {
			next;
		}
		# a live brand vetoes, unless a value compare provably fails to
		# hold... "not marked with this value" spares a brand whose stored
		# value differs (value_is) or agrees (value_not), while a compare
		# with either side missing still vetoes
		my $vetoes = 1;
		foreach my $compare ( 'value_is', 'value_not' ) {
			if ( !defined( $entry->{$compare} ) ) {
				next;
			}
			my $against = $data->{ $entry->{$compare} };
			if (   defined( $mark->{value} )
				&& defined($against)
				&& ( $compare eq 'value_is' ? $mark->{value} ne $against : $mark->{value} eq $against ) )
			{
				$vetoes = 0;
			}
		} ## end foreach my $compare ( 'value_is', 'value_not' )
		if ($vetoes) {
			return 0;
		}
	} ## end foreach my $entry ( @{ $gates->{not_marked} } )

	# the sequence gate... ordered temporal correlation. every named mark must
	# be live for the key and their first-seen times non-decreasing in the
	# listed order, so "stage a then b then c" only holds when a fired no later
	# than b and b no later than c. keyed like the marked gate, by a var's
	# capture, a vars compound, or, var-less, by the offender
	foreach my $entry ( @{ $gates->{sequence} } ) {
		my $data_keyed = defined( $entry->{var} ) || defined( $entry->{vars} );
		if ( $data_keyed ? defined($ip) : !defined($ip) ) {
			next;
		}
		my $key = mark_key( $entry, $data, $ip );
		if ( !defined($key) ) {
			return 0;
		}
		my $prev_set;
		foreach my $mark_name ( @{ $entry->{marks} } ) {
			my $mark = $store_all->{$mark_name}{$key};
			if ( !defined($mark) || $mark->{expires} <= $now ) {
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
	} ## end foreach my $entry ( @{ $gates->{sequence} } )

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
		my @keys;
		if ( defined( $entry->{var} ) || defined( $entry->{vars} ) ) {
			my $key = mark_key( $entry, $data, undef );
			@keys = defined($key) ? ($key) : ();
		} else {
			@keys = @{$offenders};
		}
		foreach my $key (@keys) {
			mark_set( $store_all, $entry->{name}, $key, $value, $entry->{ttl}, $now, $on_set );
			push( @set, { 'name' => $entry->{name}, 'key' => $key } );
		}
	} ## end foreach my $entry ( @{$marks} )

	my @lifted;
	foreach my $entry ( @{$unmarks} ) {
		my @keys;
		if ( defined( $entry->{var} ) || defined( $entry->{vars} ) ) {
			my $key = mark_key( $entry, $data, undef );
			@keys = defined($key) ? ($key) : ();
		} else {
			@keys = @{$offenders};
		}
		foreach my $key (@keys) {
			if ( defined( $store_all->{ $entry->{name} } ) && defined( $store_all->{ $entry->{name} }{$key} ) ) {
				delete( $store_all->{ $entry->{name} }{$key} );
				if ( !%{ $store_all->{ $entry->{name} } } ) {
					delete( $store_all->{ $entry->{name} } );
				}
				push( @lifted, { 'name' => $entry->{name}, 'key' => $key } );
				if ( defined($on_unset) ) {
					$on_unset->( $entry->{name}, $key );
				}
			} ## end if ( defined( $store_all->{ $entry->{name}...}))
		} ## end foreach my $key (@keys)
	} ## end foreach my $entry ( @{$unmarks} )

	return ( \@set, \@lifted );
} ## end sub apply_marks

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
