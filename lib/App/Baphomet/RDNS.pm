package App::Baphomet::RDNS;

use 5.006;
use strict;
use warnings;
use Exporter              qw( import );
use List::Util            qw( any );
use Socket                qw( AF_INET AF_INET6 inet_pton );
use App::Baphomet::Config qw( ip_family );

our @EXPORT_OK = qw( rdns_gate_pass rdns_entry_pass rdns_addr_eq );

=head1 NAME

App::Baphomet::RDNS - The reverse_dns gate's pure core, drivable over any resolver.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::RDNS qw( rdns_gate_pass );

    my $resolver = {
        'reverse' => sub { ... },   # address -> arrayref of names, [] for none, undef on failure
        'forward' => sub { ... },   # name -> arrayref of addresses, likewise
    };
    if ( rdns_gate_pass( $resolver, $rule->reverse_dns, $data, $ip ) ) { ... }

=head1 DESCRIPTION

The reverse_dns gate's judgment, lifted out of the galla so it runs over
any resolver... the galla passes closures over its cached, background
lookups, while C<run_tests> passes a fixture map from the rule file's own
C<dns:> test key, so a rule proves its gate cold. The resolver answers
tri-state, the way the galla's caches do... a arrayref of names or
addresses, a empty arrayref for authoritative absence, undef for a
failure. Nothing here knows of caches, timeouts, or wall clocks.

=head1 FUNCTIONS

=head2 rdns_gate_pass

Evaluates a rule's reverse_dns gate in one of two modes... with a undef
C<$ip> the C<var>-keyed entries, data-driven and ran once per found
result, with a C<$ip> the var-less entries, offender-keyed and ran once
per candidate. Returns true when every applicable entry holds. A undef
gate passes, a undef resolver fails closed.

    if ( rdns_gate_pass( $resolver, $gate, $data, $ip ) ) { ... }

=cut

sub rdns_gate_pass {
	my ( $resolver, $gate, $data, $ip ) = @_;

	if ( !defined($gate) ) {
		return 1;
	}

	foreach my $entry ( @{$gate} ) {
		if ( defined( $entry->{var} ) ) {
			# a var entry belongs to the data pass... let the offender pass by
			if ( defined($ip) ) {
				next;
			}
			my $value = $data->{ $entry->{var} };
			if ( !defined($value) || !rdns_entry_pass( $resolver, $entry, $value, $data ) ) {
				return 0;
			}
		} else {
			# a var-less entry belongs to the offender pass... let the data
			# pass by
			if ( !defined($ip) ) {
				next;
			}
			if ( !rdns_entry_pass( $resolver, $entry, $ip, $data ) ) {
				return 0;
			}
		} ## end else [ if ( defined( $entry->{var} ) ) ]
	} ## end foreach my $entry ( @{$gate} )

	return 1;
} ## end sub rdns_gate_pass

# the terminal verdict a lookup outcome knob gives... on_nxdomain or
# on_servfail set to pass or fail settles the entry outright, the comparison
# and negate never seeing it, while compare carries on over whatever names
# there are.
#
# args:
#   $knob :: the knob's value, 'pass', 'fail', or 'compare'
#
# returns 1 for pass, 0 for fail, or undef for compare, meaning no verdict yet.
#
#   my $verdict = _outcome_verdict( $entry->{on_servfail} );
#   if ( defined($verdict) ) { return $verdict; }
sub _outcome_verdict {
	my ($knob) = @_;

	if ( $knob eq 'pass' ) {
		return 1;
	}
	if ( $knob eq 'fail' ) {
		return 0;
	}
	return undef;
} ## end sub _outcome_verdict

# folds a host name the way matches_var compares them... case-insensitive and
# with any trailing root dots off, so "Crawl.Example.com." equals
# "crawl.example.com".
#
# args:
#   $name :: the host name, a PTR answer or a found value
#
# returns the folded name.
#
#   my $folded = _fold_name('Crawl.Example.com.');    # 'crawl.example.com'
sub _fold_name {
	my ($name) = @_;

	my $folded = lc($name);
	$folded =~ s/\.+$//;

	return $folded;
}

=head2 rdns_entry_pass

Runs one reverse_dns entry against one address... the PTR names, forward
confirmed unless refused, compared against the regexp or the named found
value, negated when asked. By default authoritative absence is data... no
names means the comparison is false and negate makes it count... while
inability to ask is not... a lookup failure vetoes regardless of negate,
so an outage can never get anyone counted by a negated gate. The entry's
C<on_nxdomain> and C<on_servfail> knobs override those defaults per rule.
Always fails closed with out a resolver, on a non-address value, and on a
missing matches_var.

    if ( rdns_entry_pass( $resolver, $entry, $address, $data ) ) { ... }

=cut

sub rdns_entry_pass {
	my ( $resolver, $entry, $address, $data ) = @_;

	if ( !defined($resolver) || !defined( $resolver->{reverse} ) ) {
		return 0;
	}
	if ( !defined( ip_family($address) ) ) {
		return 0;
	}

	# a reverse lookup that failed, or answered no names, may settle the entry
	# outright by its knob... a failure left to compare simply has no names
	my $names = $resolver->{reverse}->($address);
	if ( !defined($names) ) {
		my $verdict = _outcome_verdict( $entry->{on_servfail} );
		if ( defined($verdict) ) {
			return $verdict;
		}
		$names = [];
	} elsif ( !@{$names} ) {
		my $verdict = _outcome_verdict( $entry->{on_nxdomain} );
		if ( defined($verdict) ) {
			return $verdict;
		}
	}

	# forward confirmation... a name only participates when it resolves
	# back to the address, a spoofed PTR being as good as absent. a forward
	# lookup that failed may settle the entry by on_servfail, else that name
	# is simply unconfirmed
	my @confirmed = @{$names};
	if ( $entry->{forward_confirm} ) {
		@confirmed = ();
		foreach my $ptr_name ( @{$names} ) {
			my $addrs = $resolver->{forward}->($ptr_name);
			if ( !defined($addrs) ) {
				my $verdict = _outcome_verdict( $entry->{on_servfail} );
				if ( defined($verdict) ) {
					return $verdict;
				}
				next;
			}
			if ( any { rdns_addr_eq( $_, $address ) } @{$addrs} ) {
				push( @confirmed, $ptr_name );
			}
		} ## end foreach my $ptr_name ( @{$names} )
	} ## end if ( $entry->{forward_confirm} )

	# the comparison, against the regexp or the named found value... a
	# missing or empty value fails closed, before negate can flip it
	my $hit;
	if ( defined( $entry->{regexp} ) ) {
		$hit = any { $_ =~ $entry->{regexp} } @confirmed;
	} else {
		my $expected = $data->{ $entry->{matches_var} };
		if ( !defined($expected) || $expected eq '' ) {
			return 0;
		}
		$expected = _fold_name($expected);
		$hit      = any { _fold_name($_) eq $expected } @confirmed;
	}

	if ( $entry->{negate} ) {
		return $hit ? 0 : 1;
	}
	return $hit ? 1 : 0;
} ## end sub rdns_entry_pass

=head2 rdns_addr_eq

Compares two address strings for equality by packed value with in one
family, so C<::FFFF:1.2.3.4> spellings and case differences can not dodge
a forward confirmation. False when the two parse in no common family.

    if ( rdns_addr_eq( $left, $right ) ) { ... }

=cut

sub rdns_addr_eq {
	my ( $left, $right ) = @_;

	foreach my $family ( AF_INET, AF_INET6 ) {
		my $left_packed  = inet_pton( $family, $left );
		my $right_packed = inet_pton( $family, $right );
		if ( defined($left_packed) && defined($right_packed) ) {
			return $left_packed eq $right_packed ? 1 : 0;
		}
	}

	return 0;
} ## end sub rdns_addr_eq

1;
