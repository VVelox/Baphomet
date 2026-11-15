package App::Baphomet::Gate::account;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::account - The account gate, telling a real account from a name that is nobody's.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - account: { var: USER, exists: false }
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Holds when the name checked is, or is not, a account of the host the galla
runs on. A failed login for a name that is nobody's is a guess, and one for
a real account may be its owner's typo, which most daemons log the same.

The accounts are the galla's own host's, so the gate only means something
over logs that host wrote. A name the offense lacks fails closed whichever
way the gate asks.

A entry is told...

    - var :: The found var holding the name to check.

    - exists :: Optional. False to hold on a name that is no account. With
          out it, or true, the gate holds on one that is.

It needs the C<accounts> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

my $SHAPE = {
	'required' => { 'var'    => 'string' },
	'optional' => { 'exists' => 'any' },
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps the var and which answer it holds on.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{var} = $args->{var};

	# it holds on a real account unless told outright to hold on the lack of
	# one
	$self->{exists} = ( defined( $args->{exists} ) && !$args->{exists} ) ? 0 : 1;

	return;
} ## end sub compile

=head2 needs

Returns C<accounts>.

=cut

sub needs {
	return ('accounts');
}

=head2 holds

Returns 1 when the name in the gate's var is a account or not, as the gate
asks, else 0. Returns 0 on a name the data lacks or holds empty.

    if ( $gate->holds($data) ) { ... }

=cut

sub holds {
	my ( $self, $data ) = @_;

	my $name = $data->{ $self->{var} };
	if ( !defined($name) || $name eq '' ) {
		return 0;
	}

	my $is_account = $self->{context}{accounts}->($name) ? 1 : 0;

	return $is_account == $self->{exists} ? 1 : 0;
} ## end sub holds

1;
