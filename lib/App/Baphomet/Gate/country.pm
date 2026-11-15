package App::Baphomet::Gate::country;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::country - The country gate, narrowing a offense by geography.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - country: { is: GB, vars: [ dest ] }
      - ban_var: [ SRC ]
      - country: { isnot: [ US, '%%%country_codes{allies}%%%' ] }
      - country: { vars: [ SRC ], into: COUNTRY }

=head1 DESCRIPTION

Holds when the country of each address checked satisfies the gate... on one
of the listed countries for C<is>, on none of them for C<isnot>. A address
the locator can not place fails closed, a unknown country being one that can
not be cleared.

A entry is told...

    - is / isnot :: Never both. A 2-letter ISO 3166 code, a
          C<%%%country_codes{name}%%%> import of a named list, or a array of
          either.

    - vars :: Optional. The found var or vars holding the addresses to
          check. With out it the offender is checked.

    - into :: Optional. The found var the country code of the address is
          lifted into, for what is below the gate and the counting to read.
          It needs exactly one var, a offense being able to have several
          offenders and the var only one value. It is never lifted over a
          value the offense already has.

One of C<is>, C<isnot>, or C<into> has to be there. A entry with only a
C<into> judges nothing... a address the locator can not place then lifts
nothing and vetoes nothing, what reads the var failing closed on its own.

It needs the C<locator> of the L<context|App::Baphomet::Gate/THE CONTEXT>,
and reads the C<country_codes> of it for what it imports. A import of a list
the context does not define is fatal when the gate is bound.

=cut

# what is or isnot may hold... a code or a named import, or a non-empty array
# of them
my $COUNTRY_ENTRIES = {
	'each'   => { 'match' => qr/^(?:[A-Za-z]{2}|%%%country_codes\{[a-zA-Z0-9_\-]+\}%%%)$/ },
	'min'    => 1,
	'or_one' => 1,
	'says'   => 'a 2-letter code or a %%%country_codes{name}%%% import, or a non-empty array of them',
};

my $SHAPE = {
	'optional' => {
		'is'    => $COUNTRY_ENTRIES,
		'isnot' => $COUNTRY_ENTRIES,
		'vars'  => 'string_or_strings',
		'into'  => 'string',
	},
	'not_both' => [ [ 'is', 'isnot' ] ],
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps the mode, undef for a gate that only
lifts, the entries as a list however they were written, the vars as a list
when there are any, and the var to lift into. The imports are left
unexpanded, the lists they name being a watcher's. Dies on a entry with
nothing to do, and on a C<into> with out exactly one var.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	if ( defined( $args->{is} ) ) {
		$self->{mode} = 'is';
	} elsif ( defined( $args->{isnot} ) ) {
		$self->{mode} = 'isnot';
	}
	$self->{into} = $args->{into};
	if ( !defined( $self->{mode} ) && !defined( $self->{into} ) ) {
		die( $where . ' has none of is, isnot, or into' );
	}

	# a lone entry or var is a list of one, so each lands as a list
	my $entries = defined( $self->{mode} ) ? $args->{ $self->{mode} } : [];
	$self->{entries} = is_plain_arrayref($entries) ? [ @{$entries} ] : [$entries];
	if ( defined( $args->{vars} ) ) {
		$self->{vars} = is_plain_arrayref( $args->{vars} ) ? [ @{ $args->{vars} } ] : [ $args->{vars} ];
	}

	# a offense may have several offenders and several vars several
	# addresses, each in a country of its own, and the var lifted into holds
	# one value
	if ( defined( $self->{into} ) && scalar( @{ $self->{vars} // [] } ) != 1 ) {
		die( $where . ' has a into, which needs exactly one var to lift the country of' );
	}

	return;
} ## end sub compile

=head2 needs

Returns C<locator>.

=cut

sub needs {
	return ('locator');
}

=head2 bound

Returns a copy of the gate bound over a context, its codes and imports
expanded into one set of upcased codes. Dies on a import of a list the
context's C<country_codes> does not define.

    my $bound = $gate->bound( \%context, $where );

=cut

sub bound {
	my ( $self, $context, $where ) = @_;

	my $lists = $context->{country_codes} // {};
	my %codes;
	foreach my $entry ( @{ $self->{entries} } ) {
		if ( $entry =~ /^%%%country_codes\{([a-zA-Z0-9_\-]+)\}%%%$/ ) {
			my $list = $lists->{$1};
			if ( !is_plain_arrayref($list) ) {
				die( $where . ' imports country_codes{' . $1 . '}, which is not a defined list for it' );
			}
			foreach my $code ( @{$list} ) {
				$codes{ uc($code) } = 1;
			}
		} else {
			$codes{ uc($entry) } = 1;
		}
	} ## end foreach my $entry ( @{ $self->{entries} } )

	my $bound = $self->SUPER::bound( $context, $where );
	$bound->{codes} = \%codes;

	return $bound;
} ## end sub bound

=head2 holds

Returns 1 when the country of every address checked satisfies the gate, else
0. With C<vars> the addresses are the values of those vars, and one the
result lacks fails. With out, the address is the offender. A gate with a
C<into> then writes the country code into that var of the passed data,
unless the data already has one. One that only lifts returns 1 whatever it
finds.

    if ( $gate->holds( $data, $ip ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip ) = @_;

	my $mode      = $self->{mode};
	my @addresses = defined( $self->{vars} ) ? ( map { $data->{$_} } @{ $self->{vars} } ) : ($ip);
	my $country;
	foreach my $address (@addresses) {
		$country = defined($address) ? $self->{context}{locator}->($address) : undef;
		if ( !defined($country) ) {
			# nothing to lift, and with nothing judged nothing to veto
			return defined($mode) ? 0 : 1;
		}
		if ( !defined($mode) ) {
			next;
		}

		# is passes only a listed country, isnot only a unlisted one
		my $listed = $self->{codes}{$country} ? 1 : 0;
		if ( $mode eq 'is' && !$listed ) {
			return 0;
		}
		if ( $mode ne 'is' && $listed ) {
			return 0;
		}
	} ## end foreach my $address (@addresses)

	# a into has exactly one var, so the country left standing is that var's
	if ( defined( $self->{into} ) && !exists( $data->{ $self->{into} } ) ) {
		$data->{ $self->{into} } = $country;
	}

	return 1;
} ## end sub holds

1;
