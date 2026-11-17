package App::Baphomet::Gate::pressure;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::pressure - The pressure gate, letting a rule by only while its watcher is under attack.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - pressure: { above: 200, seconds: 60, hold: 300 }
      - message_regexp:
          - '^Failed password for \S+ from %%%%SRC%%%%'
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Lets a line by only while more than C<above> lines have matched in the last
C<seconds>, and turns it away otherwise. It is for a harsher copy of a rule,
listed ahead of the one it shadows, that only has its say during a attack.

What is counted is the lines some banning rule named a offender on, each
once however many rules did, on the gate's watcher or over the whole galla.
A line the harsher rule took is counted like any other, so the gate letting
lines by does not lower what it reads. The count is kept in spans of ten
seconds, so it is exact to that and no finer, and is forgotten at a restart.

It reads nothing of the line, so written first in a rule it turns a line
away before anything else is done with it, and a rule behind it costs next
to nothing while there is no attack.

A entry is told...

    - above :: How many matched lines it takes more than. Optional beside a
          C<times>, where it is the least the count may be for the C<times>
          to be asked.

    - seconds :: How far back they are counted over.

    - times / baseline :: Optional, and only together. How many times what
          is usual the count has to be more than, what is usual being what
          the C<baseline> seconds before the C<seconds> came to, evened out
          to as long. A mark that is a count wants setting for each host,
          and this one sets itself. With nothing matched in the baseline
          there is no saying what is usual, and it is not above it.

    - hold :: Optional. Seconds the gate goes on letting lines by after the
          count was last above the mark, so a lull between two waves does
          not shut it.
        Default :: 0

    - scope :: Optional. What is counted over, C<watcher> for the watcher
          the rule is on or C<galla> for every watcher of the galla.
        Default :: watcher

It needs the C<pressure> of the L<context|App::Baphomet::Gate/THE CONTEXT>,
and uses its C<notice> when it is there, to say when it starts and stops
letting lines by.

=cut

my $SHAPE = {
	'required' => { 'seconds' => 'seconds' },
	'optional' => {
		'above'    => 'positive_int',
		'times'    => 'positive_number',
		'baseline' => 'seconds',
		'hold'     => 'seconds_or_zero',
		'scope'    => { 'in' => [qw( watcher galla )], 'says' => 'one of watcher or galla' },
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it with the defaults filled in.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{above}    = $args->{above};
	$self->{seconds}  = $args->{seconds};
	$self->{times}    = $args->{times};
	$self->{baseline} = $args->{baseline};

	if ( !defined( $self->{above} ) && !defined( $self->{times} ) ) {
		die( $where . ' has neither above nor times' );
	}
	if ( defined( $self->{times} ) != defined( $self->{baseline} ) ) {
		die( $where . ' has a times with out a baseline, or a baseline with out a times' );
	}
	$self->{hold}  = $args->{hold}  // 0;
	$self->{scope} = $args->{scope} // 'watcher';

	return;
} ## end sub compile

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 early

Returns 1. It reads nothing of the line, only the clock.

=cut

sub early {
	return 1;
}

=head2 needs

Returns C<pressure>.

=cut

sub needs {
	return ('pressure');
}

=head2 wants

Returns C<notice>.

=cut

sub wants {
	return ('notice');
}

=head2 bound

Returns a copy of the gate bound over a context, shut, and holding the
passed C<$where> to lead what it says when it opens and shuts.

    my $bound = $gate->bound( \%context, $where );

=cut

sub bound {
	my ( $self, $context, $where ) = @_;

	my $bound = $self->SUPER::bound( $context, $where );
	$bound->{bound_where} = $where;
	$bound->{open}        = 0;

	return $bound;
}

=head2 ask

Returns 1 while the count is above the mark, or was within C<hold> seconds
ago, else 0. Says so through the context's C<notice> each time that
changes.

    if ( !$gate->ask($passage) ) { ... }

=cut

sub ask {
	my ( $self, $passage ) = @_;

	my $now   = $passage->{now} // time;
	my $count = $self->{context}{pressure}->( $self->{scope}, $self->{seconds}, $now );

	my $above_mark = ( !defined( $self->{above} ) || $count > $self->{above} ) ? 1 : 0;
	if ( $above_mark && defined( $self->{times} ) ) {
		# what the baseline before the seconds came to, evened out to as
		# long as the seconds are
		my $before = $self->{context}{pressure}->( $self->{scope}, $self->{baseline}, $now - $self->{seconds} );
		my $usual  = $before * $self->{seconds} / $self->{baseline};
		$above_mark = ( $before > 0 && $count > $self->{times} * $usual ) ? 1 : 0;
	}

	my $open = 0;
	if ($above_mark) {
		$open = 1;
		$self->{held_until} = $now + $self->{hold};
	} elsif ( defined( $self->{held_until} ) && $now < $self->{held_until} ) {
		$open = 1;
	}

	if ( $open != ( $self->{open} // 0 ) ) {
		$self->{open} = $open;
		my $notice = $self->{context}{notice};
		if ( defined($notice) ) {
			my $counted = $count . ' matched lines in the last ' . $self->{seconds} . ' seconds';
			$notice->( ( $self->{bound_where} // $self->{where} )
				. ( $open ? ' is under pressure, ' . $counted : ' is no longer under pressure, ' . $counted ) );
		}
	}

	return $open;
} ## end sub ask

1;
