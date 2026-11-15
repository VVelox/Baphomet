package App::Baphomet::Gate::reverse_dns;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util            qw( any first );
use Socket                qw( AF_INET AF_INET6 inet_pton );
use App::Baphomet::Config qw( ip_family );
use App::Baphomet::Shape  qw( check_hash );

our @EXPORT_OK = qw( rdns_addr_eq );

=head1 NAME

App::Baphomet::Gate::reverse_dns - The reverse_dns gate, holding a client to what its address says it is.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - reverse_dns: { var: PEER, matches_var: HELO }
      - ban_var: [ SRC ]
      - reverse_dns: { matches: '\.googlebot\.com$', negate: true }

=head1 DESCRIPTION

Holds when the PTR names of the address checked, forward confirmed unless
refused, compare as the entry asks. By default authoritative absence is
data... no names means the comparison is false and C<negate> makes it
count... while inability to ask is not... a lookup failure vetoes regardless
of C<negate>, so a outage can never get anyone counted by a negated gate.
It always fails closed with out a resolver, on a value that is not a
address, and on a missing C<matches_var>.

A entry is told...

    - matches / matches_var :: Exactly one. A regexp a PTR name has to
          match, or the found var a PTR name has to equal, case and a
          trailing dot aside.

    - var :: Optional. The found var holding the address to check. With out
          it the offender is checked.

    - negate :: Optional. True to hold when the comparison does not.

    - forward_confirm :: Optional. False to take a PTR name at its word. By
          default a name only takes part when it resolves back to the
          address.

    - on_nxdomain / on_servfail :: Optional. What a lookup that gave no
          names, or that failed, does... C<pass> or C<fail> settles the gate
          outright, and C<compare> carries on over whatever names there are.
          C<compare> and C<fail> by default.

    - into :: Optional. The found var a PTR name of the address is lifted
          into when the gate holds, for what is below the gate and the
          counting to read... the name the comparison hit on, or with none
          hit, as under C<negate>, the first that took part. It needs a
          C<var>, a offense being able to have several offenders and the
          var only one value. It is never lifted over a value the offense
          already has, and a address with no name to give lifts nothing.

It needs the C<resolver> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

# what a entry may do with a lookup that gave no names
my $FAILURE_ACTION = { 'in' => [qw( pass fail compare )], 'says' => 'one of pass, fail, or compare' };

my $SHAPE = {
	'optional' => {
		'var'             => 'string',
		'matches'         => 'string',
		'matches_var'     => 'string',
		'negate'          => 'any',
		'forward_confirm' => 'any',
		'into'            => 'string',
		'on_nxdomain'     => $FAILURE_ACTION,
		'on_servfail'     => $FAILURE_ACTION,
	},
	'one_of' => [ [ 'matches', 'matches_var' ] ],
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it with the defaults filled in and
C<matches> compiled. Dies on a C<matches> that does not compile.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{var}  = $args->{var};
	$self->{into} = $args->{into};
	if ( defined( $self->{into} ) && !defined( $self->{var} ) ) {
		die( $where . ' has a into, which needs a var to lift the name of' );
	}
	$self->{matches_var} = $args->{matches_var};
	$self->{negate}      = $args->{negate} ? 1 : 0;
	$self->{on_nxdomain} = $args->{on_nxdomain} // 'compare';
	$self->{on_servfail} = $args->{on_servfail} // 'fail';

	# forward confirmation is on unless it is refused outright
	$self->{forward_confirm} = ( defined( $args->{forward_confirm} ) && !$args->{forward_confirm} ) ? 0 : 1;

	if ( defined( $args->{matches} ) ) {
		my $regexp = $args->{matches};
		try {
			$self->{regexp} = qr/$regexp/;
		} catch ($caught) {
			die( $where . ' matches does not compile... ' . $caught );
		}
	}

	return;
} ## end sub compile

=head2 needs

Returns C<resolver>.

=cut

sub needs {
	return ('resolver');
}

# the terminal verdict a lookup outcome knob gives... on_nxdomain or
# on_servfail set to pass or fail settles the gate outright, the comparison
# and negate never seeing it, while compare carries on over whatever names
# there are.
#
# args:
#   $knob :: the knob's value, 'pass', 'fail', or 'compare'
#
# returns 1 for pass, 0 for fail, or undef for compare, meaning no verdict yet.
#
#   my $verdict = _outcome_verdict( $self->{on_servfail} );
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

=head2 holds

Returns 1 when the address checked passes the gate, else 0. The address is
the value of the gate's var, or the offender with out one.

    if ( $gate->holds( $data, $ip ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip ) = @_;

	my $address  = defined( $self->{var} ) ? $data->{ $self->{var} } : $ip;
	my $resolver = $self->{context}{resolver}->();

	if ( !defined($address) || !defined($resolver) || !defined( $resolver->{reverse} ) ) {
		return 0;
	}
	if ( !defined( ip_family($address) ) ) {
		return 0;
	}

	# a reverse lookup that failed, or answered no names, may settle the gate
	# outright by its knob... a failure left to compare simply has no names
	my $names = $resolver->{reverse}->($address);
	if ( !defined($names) ) {
		my $verdict = _outcome_verdict( $self->{on_servfail} );
		if ( defined($verdict) ) {
			return $verdict;
		}
		$names = [];
	} elsif ( !@{$names} ) {
		my $verdict = _outcome_verdict( $self->{on_nxdomain} );
		if ( defined($verdict) ) {
			return $verdict;
		}
	}

	# forward confirmation... a name only participates when it resolves
	# back to the address, a spoofed PTR being as good as absent. a forward
	# lookup that failed may settle the gate by on_servfail, else that name
	# is simply unconfirmed
	my @confirmed = @{$names};
	if ( $self->{forward_confirm} ) {
		@confirmed = ();
		foreach my $ptr_name ( @{$names} ) {
			my $addrs = $resolver->{forward}->($ptr_name);
			if ( !defined($addrs) ) {
				my $verdict = _outcome_verdict( $self->{on_servfail} );
				if ( defined($verdict) ) {
					return $verdict;
				}
				next;
			}
			if ( any { rdns_addr_eq( $_, $address ) } @{$addrs} ) {
				push( @confirmed, $ptr_name );
			}
		} ## end foreach my $ptr_name ( @{$names} )
	} ## end if ( $self->{forward_confirm} )

	# the comparison, against the regexp or the named found value... a
	# missing or empty value fails closed, before negate can flip it
	my $hit_name;
	if ( defined( $self->{regexp} ) ) {
		$hit_name = first { $_ =~ $self->{regexp} } @confirmed;
	} else {
		my $expected = $data->{ $self->{matches_var} };
		if ( !defined($expected) || $expected eq '' ) {
			return 0;
		}
		$expected = _fold_name($expected);
		$hit_name = first { _fold_name($_) eq $expected } @confirmed;
	}

	my $hit   = defined($hit_name)      ? 1 : 0;
	my $holds = $hit != $self->{negate} ? 1 : 0;

	# the name it hit on, or under negate, where it holds on hitting none,
	# the first that took part
	my $lifted = $hit_name // $confirmed[0];
	if ( $holds && defined( $self->{into} ) && defined($lifted) && !exists( $data->{ $self->{into} } ) ) {
		$data->{ $self->{into} } = $lifted;
	}

	return $holds;
} ## end sub holds

=head1 FUNCTIONS

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
