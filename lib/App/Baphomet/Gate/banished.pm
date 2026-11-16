package App::Baphomet::Gate::banished;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Marks qw( live_mark );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::banished - The banished gate, asking what a address has already been banished for.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - banished: { var: SRC, now: true, for: 60 }
      - ban_var: [ SRC ]
      - banished: { times: 3, within: 2592000 }

=head1 DESCRIPTION

Holds on a address by what the galla has banished it for... that it is
banished now, or that it has been so many times of late. A line from a
address that is banished is a ban that is not holding, the wrong table or a
path round it, and a address banished three times this month has earned a
shorter rope than one that has not been.

The galla brands each address it banishes, under C<banished> for as long as
the ban is to last and under C<banishments> with when each one was, and this
reads those two brands. So what it knows is what any brand is... kept across
a restart, and shared with a fleet, where a ban made by one host is seen by
the rest. It is the galla's own account of it, and one lifted by hand in
the kur is not known of here. A ban whose length is the kur's to choose is
taken as a day long.

A entry is told...

    - var :: Optional. The found var holding the address. With out it the
          offender is checked.

    - now :: Optional. True to hold on a address that is banished, false on
          one that is not.

    - for :: Optional, beside a true C<now>. Seconds it has to have been
          banished for, a line or two just after a ban being ones already
          on their way.

    - times / within :: Optional, and only together. How many times it has
          to have been banished, and with in how many seconds back, 90 days
          at the most.

It needs the C<marks> of the L<context|App::Baphomet::Gate/THE CONTEXT>,
and reads its C<banished_history>, how many bans of a address the galla
remembers, as the most a C<times> may ask.

=cut

# as far back as the galla remembers when a address was banished
my $REMEMBERED = 7776000;

my $SHAPE = {
	'optional' => {
		'var'    => 'string',
		'now'    => 'any',
		'for'    => 'seconds',
		'times'  => 'positive_int',
		'within' => {
			'test' => sub { return ( $_[0] // '' ) =~ /^[0-9]+$/ && $_[0] >= 1 && $_[0] <= $REMEMBERED; },
			'says' => 'a positive int of seconds, 7776000 at the most',
		},
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it. Dies on one that asks nothing, on
a C<times> and a C<within> that are not together, and on a C<for> with out a
true C<now>.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{var}    = $args->{var};
	$self->{for}    = $args->{for};
	$self->{times}  = $args->{times};
	$self->{within} = $args->{within};
	if ( defined( $args->{now} ) ) {
		$self->{now} = $args->{now} ? 1 : 0;
	}

	if ( !defined( $self->{now} ) && !defined( $self->{times} ) ) {
		die( $where . ' has neither now nor times' );
	}
	if ( defined( $self->{times} ) != defined( $self->{within} ) ) {
		die( $where . ' has a times with out a within, or a within with out a times' );
	}
	if ( defined( $self->{for} ) && !$self->{now} ) {
		die( $where . ' has a for with out a now that is true' );
	}

	return;
} ## end sub compile

=head2 needs

Returns C<marks>.

=cut

sub needs {
	return ('marks');
}

=head2 wants

Returns C<banished_history>, read when the gate is bound and absent from a
context that does not set it, as a rule's own tests do not.

=cut

sub wants {
	return ('banished_history');
}

=head2 bound

Returns a copy of the gate bound over a context, as
L<App::Baphomet::Gate/bound> does. Dies on a C<times> greater than the
context's C<banished_history>, which could never hold, the galla keeping no
more bans of a address than that. A context with no C<banished_history>
checks nothing.

    my $bound = $gate->bound( $context, $where );

=cut

sub bound {
	my ( $self, $context, $where ) = @_;

	my $history = $context->{banished_history};
	if ( defined( $self->{times} ) && defined($history) && $self->{times} > $history ) {
		die(      $where
				. ' has a banished gate asking for '
				. $self->{times}
				. ' bans, and the galla remembers only the last '
				. $history
				. ' of a address... raise banished_history to ask that many' );
	}

	return $self->SUPER::bound( $context, $where );
} ## end sub bound

=head2 holds

Returns 1 when the address checked is all the gate asks, else 0. The
address is the value of the gate's var, or the offender with out one.

    if ( $gate->holds( $data, $ip, $now ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip, $now ) = @_;

	my $address = defined( $self->{var} ) ? $data->{ $self->{var} } : $ip;
	if ( !defined($address) ) {
		return 0;
	}
	my $store = $self->{context}{marks}->();

	if ( defined( $self->{now} ) ) {
		my $ban      = live_mark( $store, 'banished', $address, $now );
		my $banished = defined($ban) ? 1 : 0;
		if ( $banished != $self->{now} ) {
			return 0;
		}

		# a ban with no saying when it was made can not be shown to be old
		# enough
		if ( defined( $self->{for} ) && ( !defined( $ban->{set} ) || $now - $ban->{set} < $self->{for} ) ) {
			return 0;
		}
	} ## end if ( defined( $self->{now} ) )

	if ( defined( $self->{times} ) ) {
		# the value is when each ban was made, a space between them
		my $history = live_mark( $store, 'banishments', $address, $now );
		my @recent  = grep { /^[0-9]+$/ && $_ > $now - $self->{within} }
			split( / /, defined($history) ? $history->{value} // '' : '' );
		if ( @recent < $self->{times} ) {
			return 0;
		}
	}

	return 1;
} ## end sub holds

1;
