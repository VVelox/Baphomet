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

=head1 DESCRIPTION

Holds when the country of each address checked satisfies the gate... on one
of the listed countries for C<is>, on none of them for C<isnot>. A address
the locator can not place fails closed, a unknown country being one that can
not be cleared.

A entry is told...

    - is / isnot :: Exactly one. A 2-letter ISO 3166 code, a
          C<%%%country_codes{name}%%%> import of a named list, or a array of
          either.

    - vars :: Optional. The found var or vars holding the addresses to
          check. With out it the offender is checked.

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
	'optional' => { 'is' => $COUNTRY_ENTRIES, 'isnot' => $COUNTRY_ENTRIES, 'vars' => 'string_or_strings' },
	'one_of'   => [ [ 'is', 'isnot' ] ],
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps the mode, the entries as a list
however they were written, and the vars as a list when there are any. The
imports are left unexpanded, the lists they name being a watcher's.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	# a lone entry or var is a list of one, so each lands as a list
	$self->{mode} = defined( $args->{is} ) ? 'is' : 'isnot';
	my $entries = $args->{ $self->{mode} };
	$self->{entries} = is_plain_arrayref($entries) ? [ @{$entries} ] : [$entries];
	if ( defined( $args->{vars} ) ) {
		$self->{vars} = is_plain_arrayref( $args->{vars} ) ? [ @{ $args->{vars} } ] : [ $args->{vars} ];
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
result lacks fails. With out, the address is the offender.

    if ( $gate->holds( $data, $ip ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip ) = @_;

	my @addresses = defined( $self->{vars} ) ? ( map { $data->{$_} } @{ $self->{vars} } ) : ($ip);

	foreach my $address (@addresses) {
		my $country = defined($address) ? $self->{context}{locator}->($address) : undef;
		if ( !defined($country) ) {
			return 0;
		}
		# is passes only a listed country, isnot only a unlisted one
		my $listed = $self->{codes}{$country} ? 1 : 0;
		if ( $self->{mode} eq 'is' && !$listed ) {
			return 0;
		}
		if ( $self->{mode} ne 'is' && $listed ) {
			return 0;
		}
	} ## end foreach my $address (@addresses)

	return 1;
} ## end sub holds

1;
