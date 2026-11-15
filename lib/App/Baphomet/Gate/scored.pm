package App::Baphomet::Gate::scored;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::scored - The scored gate, holding on a address already counted for enough.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - ban_var: [ SRC ]
      - scored: { above: 8 }

=head1 DESCRIPTION

Holds when the hits the galla is counting against the address checked add
up to more than C<above>, over every rule. A breadth gate says how many
rules have counted a address, and this how much they have counted it for...
a source sitting just under the thresholds of several rules at once is
nearer to a ban than any one of them shows.

What it reads is the weight of each live hit, observe mode's included, so a
hit a ban already cleared, or one older than its rule's C<find_time>, is not
there to be read. The hit this offense is about to be is not counted, its
weight not being known until it is.

A entry is told...

    - above :: What the hits have to add up to more than.

    - seconds :: Optional. How far back a hit is read. With out it every
          live hit is.

    - var :: Optional. The found var holding the address. With out it the
          offender is checked.

It needs the C<score_of> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

my $SHAPE = {
	'required' => { 'above'   => 'positive_number' },
	'optional' => { 'seconds' => 'seconds', 'var' => 'string' },
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{above}   = $args->{above};
	$self->{seconds} = $args->{seconds};
	$self->{var}     = $args->{var};

	return;
} ## end sub compile

=head2 needs

Returns C<score_of>.

=cut

sub needs {
	return ('score_of');
}

=head2 holds

Returns 1 when the live hits against the address checked add up to more than
C<above>, else 0. The address is the value of the gate's var, or the
offender with out one.

    if ( $gate->holds( $data, $ip, $now ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip, $now ) = @_;

	my $address = defined( $self->{var} ) ? $data->{ $self->{var} } : $ip;
	if ( !defined($address) ) {
		return 0;
	}
	my $since = defined( $self->{seconds} ) ? $now - $self->{seconds} : 0;

	return $self->{context}{score_of}->( $address, $since ) > $self->{above} ? 1 : 0;
} ## end sub holds

1;
