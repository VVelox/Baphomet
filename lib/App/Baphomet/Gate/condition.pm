package App::Baphomet::Gate::condition;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape        qw( check_hash );
use App::Baphomet::Rules::Gates qw( compile_gates gates_pass compile_condition eval_condition );

=head1 NAME

App::Baphomet::Gate::condition - The condition gate, folding a rule's selections into one judgment.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - condition:
          condition: login and not admin
          selections:
            login: [ { field: event, values: [ login ] } ]
            admin: [ { field: user, values: [ root, admin ] } ]

=head1 DESCRIPTION

Holds when its expression over its named selections does, the boolean form
of what C<gate> says flat. The expression is C<and>, C<or>, C<not>,
parentheses, and the C<1 of> and C<all of> forms over the selection names.
A selection is only evaluated when the expression gets to it, and only once.

It judges the offenses standing when it is asked, and while the line's own
offense is still only its fields, those.

It is told a hash of...

    - condition :: The expression, a string.

    - selections :: A hash of selection name to a list as C<gate> takes. A
          name is a plain identifier, and none of the words a expression
          reads as its own.

A rule with one can not have a C<gate>, the two being two forms of the same
thing.

=head1 METHODS

=head2 compile

Vets the selection names, compiles each list, and compiles the expression
against them.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, { 'required' => { 'condition' => 'string', 'selections' => 'hash' } }, $where );
	if ( !%{ $args->{selections} } ) {
		die( $where . ' has a selections that is empty' );
	}

	my %selections;
	foreach my $selection_name ( sort( keys( %{ $args->{selections} } ) ) ) {
		if (   $selection_name !~ /^[A-Za-z_][A-Za-z0-9_]*$/
			|| $selection_name =~ /^(?:and|or|not|of|them|all)$/i )
		{
			die( $where . ' has the selection name "' . $selection_name . '", which is not a plain identifier' );
		}
		$selections{$selection_name}
			= compile_gates( $args->{selections}{$selection_name}, $where . ' selection "' . $selection_name . '"' );
	}
	$self->{selections} = \%selections;
	$self->{ast}        = compile_condition( $args->{condition}, \%selections, $where );

	return;
} ## end sub compile

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
