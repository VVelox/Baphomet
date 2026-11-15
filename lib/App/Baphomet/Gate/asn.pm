package App::Baphomet::Gate::asn;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util           qw( any );
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::asn - The asn gate, narrowing a offense by whose network a address is on.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - asn: { org_is: '(?i)hosting|cloud', vars: [ dest ] }
      - ban_var: [ SRC ]
      - asn: { isnot: [ 64496, '%%%asn_lists{office}%%%' ] }
      - asn: { vars: [ SRC ], into: ASN, org_into: ASN_ORG }

=head1 DESCRIPTION

Holds when the autonomous system of each address checked satisfies the
gate... by its number for C<is> and C<isnot>, by the name of who runs it for
C<org_is> and C<org_isnot>. A address the locator can not place fails
closed, a unknown network being one that can not be cleared, and so does a
network with no name when it is the name that is judged.

A entry is told...

    - is / isnot :: A AS number, bare or written C<AS64496>, a
          C<%%%asn_lists{name}%%%> import of a named list, or a array of
          either. The number has to be one of them, or none of them.

    - org_is / org_isnot :: A regexp, or a array of them. The name has to
          match one of them, or none of them.

    - vars :: Optional. The found var or vars holding the addresses to
          check. With out it the offender is checked.

    - into / org_into :: Optional. The found vars the AS number and the name
          of the address are lifted into, for what is below the gate and the
          counting to read. Either needs exactly one var, a offense being
          able to have several offenders and the var only one value. Neither
          is lifted over a value the offense already has.

At most one of C<is>, C<isnot>, C<org_is>, and C<org_isnot> may be there,
and one of those or a lift has to be. A entry that only lifts judges
nothing... a address the locator can not place then lifts nothing and
vetoes nothing, what reads the var failing closed on its own.

It needs the C<asn_locator> of the L<context|App::Baphomet::Gate/THE CONTEXT>,
and reads the C<asn_lists> of it for what it imports. A import of a list
the context does not define is fatal when the gate is bound.

=cut

# what is or isnot may hold... a AS number or a named import, or a non-empty
# array of them
my $ASN_ENTRIES = {
	'each'   => { 'match' => qr/^(?:(?:[Aa][Ss])?[0-9]{1,10}|%%%asn_lists\{[a-zA-Z0-9_\-]+\}%%%)$/ },
	'min'    => 1,
	'or_one' => 1,
	'says'   => 'a AS number or a %%%asn_lists{name}%%% import, or a non-empty array of them',
};

my $SHAPE = {
	'optional' => {
		'is'        => $ASN_ENTRIES,
		'isnot'     => $ASN_ENTRIES,
		'org_is'    => 'string_or_strings',
		'org_isnot' => 'string_or_strings',
		'vars'      => 'string_or_strings',
		'into'      => 'string',
		'org_into'  => 'string',
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps the mode, undef for a gate that only
lifts, the entries or the compiled regexps as a list however they were
written, the vars as a list when there are any, and the vars to lift into.
The imports are left unexpanded, the lists they name being a watcher's.
Dies on two modes at once, on a entry with nothing to do, on a regexp that
does not compile, and on a lift with out exactly one var.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	my @modes = grep { defined( $args->{$_} ) } qw( is isnot org_is org_isnot );
	if ( @modes > 1 ) {
		die( $where . ' has both ' . $modes[0] . ' and ' . $modes[1] );
	}
	$self->{mode}     = $modes[0];
	$self->{into}     = $args->{into};
	$self->{org_into} = $args->{org_into};
	my $lifts = defined( $self->{into} ) || defined( $self->{org_into} );
	if ( !@modes && !$lifts ) {
		die( $where . ' has none of is, isnot, org_is, org_isnot, into, or org_into' );
	}

	# a lone entry or var is a list of one, so each lands as a list
	my $entries = @modes                      ? $args->{ $modes[0] } : [];
	my @entries = is_plain_arrayref($entries) ? @{$entries}          : ($entries);
	if ( @modes && $modes[0] =~ /^org_/ ) {
		foreach my $regexp (@entries) {
			try {
				push( @{ $self->{regexps} }, qr/$regexp/ );
			} catch ($caught) {
				die( $where . ' has a ' . $modes[0] . ' that does not compile... ' . $caught );
			}
		}
	} else {
		$self->{entries} = \@entries;
	}
	if ( defined( $args->{vars} ) ) {
		$self->{vars} = is_plain_arrayref( $args->{vars} ) ? [ @{ $args->{vars} } ] : [ $args->{vars} ];
	}

	# a offense may have several offenders and several vars several
	# addresses, each on a network of its own, and a var lifted into holds
	# one value
	if ( $lifts && scalar( @{ $self->{vars} // [] } ) != 1 ) {
		die( $where . ' has a into or org_into, which needs exactly one var to lift the network of' );
	}

	return;
} ## end sub compile

=head2 needs

Returns C<asn_locator>.

=cut

sub needs {
	return ('asn_locator');
}

=head2 bound

Returns a copy of the gate bound over a context, its numbers and imports
expanded into one set of bare AS numbers. Dies on a import of a list the
context's C<asn_lists> does not define.

    my $bound = $gate->bound( \%context, $where );

=cut

sub bound {
	my ( $self, $context, $where ) = @_;

	my $lists = $context->{asn_lists} // {};
	my %numbers;
	foreach my $entry ( @{ $self->{entries} // [] } ) {
		my @listed = ($entry);
		if ( $entry =~ /^%%%asn_lists\{([a-zA-Z0-9_\-]+)\}%%%$/ ) {
			if ( !is_plain_arrayref( $lists->{$1} ) ) {
				die( $where . ' imports asn_lists{' . $1 . '}, which is not a defined list for it' );
			}
			@listed = @{ $lists->{$1} };
		}
		foreach my $number (@listed) {
			# the AS prefix off and the number as perl prints one, so 064496,
			# AS64496, and 64496 are the one key
			$numbers{ ( $number =~ s/^[Aa][Ss]//r ) + 0 } = 1;
		}
	} ## end foreach my $entry ( @{ $self->{entries} // [] })

	my $bound = $self->SUPER::bound( $context, $where );
	$bound->{numbers} = \%numbers;

	return $bound;
} ## end sub bound

=head2 holds

Returns 1 when the network of every address checked satisfies the gate, else
0. With C<vars> the addresses are the values of those vars, and one the
result lacks fails. With out, the address is the offender. A gate that lifts
then writes the AS number and the name into its vars of the passed data,
unless the data already has them. One that only lifts returns 1 whatever it
finds.

    if ( $gate->holds( $data, $ip ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip ) = @_;

	my $mode      = $self->{mode};
	my @addresses = defined( $self->{vars} ) ? ( map { $data->{$_} } @{ $self->{vars} } ) : ($ip);
	my $network;
	foreach my $address (@addresses) {
		$network = defined($address) ? $self->{context}{asn_locator}->($address) : undef;
		if ( !defined($network) ) {
			# nothing to lift, and with nothing judged nothing to veto
			return defined($mode) ? 0 : 1;
		}
		if ( !defined($mode) ) {
			next;
		}

		# whether the network is one the entry names, by number or by name...
		# a network with no name can not be said to be or not to be one
		my $named;
		if ( defined( $self->{regexps} ) ) {
			my $org = $network->{org};
			if ( !defined($org) ) {
				return 0;
			}
			$named = any { $org =~ $_ } @{ $self->{regexps} };
		} else {
			$named = $self->{numbers}{ $network->{number} };
		}

		# is and org_is pass only a named network, the other two only one
		# that is not
		my $wants_named = ( $mode eq 'is' || $mode eq 'org_is' ) ? 1 : 0;
		if ( $wants_named != ( $named ? 1 : 0 ) ) {
			return 0;
		}
	} ## end foreach my $address (@addresses)

	# a lift has exactly one var, so the network left standing is that var's
	if ( defined( $self->{into} ) && !exists( $data->{ $self->{into} } ) ) {
		$data->{ $self->{into} } = $network->{number};
	}
	if ( defined( $self->{org_into} ) && defined( $network->{org} ) && !exists( $data->{ $self->{org_into} } ) ) {
		$data->{ $self->{org_into} } = $network->{org};
	}

	return 1;
} ## end sub holds

1;
