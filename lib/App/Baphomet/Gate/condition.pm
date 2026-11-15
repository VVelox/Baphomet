package App::Baphomet::Gate::condition;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util                  qw( first );
use App::Baphomet::Rules::Gates qw( gates_pass compile_condition eval_condition );

=head1 NAME

App::Baphomet::Gate::condition - The condition gate, folding a rule's selections into one judgment.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - selections:
          login: [ { field: event, values: [ login ] } ]
          admin: [ { field: user, values: [ root, admin ] } ]
      - condition: login and not admin

=head1 DESCRIPTION

Holds when its expression over the rule's C<selections> does... C<and>,
C<or>, C<not>, parentheses, and the C<1 of> and C<all of> forms over the
selection names. A selection is only evaluated when the expression gets to
it, and only once.

It judges the offenses standing when it is asked, and while the line's own
offense is still only its fields, those.

It is told the expression, a string. A rule with one has to have a
C<selections> gate.

=head1 METHODS

=head2 compile

Keeps the expression. It is compiled once the selections are in hand, in
L</settle>.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	if ( !defined($args) || ref($args) ne '' || $args eq '' ) {
		die( $where . ' is not a non-empty string' );
	}
	$self->{expression} = $args;

	return;
} ## end sub compile

=head2 settle

Compiles the expression against the rule's C<selections> gate. Dies when
the rule has none, or on a expression that does not compile.

=cut

sub settle {
	my ( $self, $gates ) = @_;

	my $selections = first { $_->{type} eq 'selections' } @{$gates};
	if ( !defined($selections) ) {
		die( $self->{where} . ' has no selections gate beside it to fold' );
	}
	$self->{selections} = $selections->{compiled};
	$self->{ast}        = compile_condition( $self->{expression}, $self->{selections}, $self->{where} );

	return;
} ## end sub settle

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 once

Returns 1, a rule having the one condition.

=cut

sub once {
	return 1;
}

=head2 passes

Returns true when the expression holds over the passed data.

    if ( $gate->passes( $data, $passage ) ) { ... }

=cut

sub passes {
	my ( $self, $data, $passage ) = @_;

	# selections evaluate lazily and memoized, so a expression that
	# short-circuits, a failed and-arm or a satisfied or-arm, never pays for
	# the selections it did not need
	my %verdicts;
	my $selection_holds = sub {
		my ($selection_name) = @_;
		if ( !exists( $verdicts{$selection_name} ) ) {
			$verdicts{$selection_name}
				= gates_pass( $self->{selections}{$selection_name}, $data, $passage->{message} );
		}
		return $verdicts{$selection_name};
	};

	return eval_condition( $self->{ast}, $selection_holds );
} ## end sub passes

=head2 ask

Judges the offenses standing and the line's own, as
L<App::Baphomet::Gate/filter_line> has it. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	return $self->filter_line($passage);
}

1;
