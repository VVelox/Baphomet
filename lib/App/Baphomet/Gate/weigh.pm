package App::Baphomet::Gate::weigh;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Rules::Gates qw( compile_gates gates_pass );
use App::Baphomet::Shape        qw( check_hash );

=head1 NAME

App::Baphomet::Gate::weigh - The weigh gate, making a hit count for more or less.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - weigh: { times: 3, when: [ { field: USER, op: eq, values: [ root, admin ] } ] }
      - weigh: { by: severity_score }
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Multiplies the weight a hit of the offense is counted with, where every
other gate would veto or let by. A failure against a administrator's account
is worth more than one against anyone else's, and the rule that counts them
can say so with out a second rule to do it in.

With C<times> the weight is multiplied by that, with C<by> by the number in
a found var, which one that is not a number of more than nothing leaves as
it was. With C<when> it is only multiplied when every entry of the list
holds over the offense, in the vocabulary of a C<gate>. Several weigh gates
multiply one after another.

It vetoes nothing. It is honored where the rule's own C<weight> is... with
the watcher's C<allow_per_rule_thresholds>, or the rule's C<weight> in the
operator's C<rule_config>. A rule counting C<distinct> values has no weights
to multiply.

A entry is told...

    - times / by :: Exactly one. The number to multiply by, or the found
          var holding it.

    - when :: Optional. A list of entries as a C<gate> takes, every one of
          which has to hold.

=cut

my $SHAPE = {
	'optional' => { 'times' => 'positive_number', 'by' => 'string', 'when' => 'any' },
	'one_of'   => [ [ 'times', 'by' ] ],
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, the C<when> compiled. Dies on a
C<when> a C<gate> would not take.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{times} = $args->{times};
	$self->{by}    = $args->{by};
	if ( defined( $args->{when} ) ) {
		$self->{when} = compile_gates( $args->{when}, $where . ' when' );
	}

	return;
} ## end sub compile

=head2 reads_offenders

Returns 0. It weighs the offense, whoever it is of.

=cut

sub reads_offenders {
	return 0;
}

=head2 ask

Multiplies the offense's C<weight_times> by the gate's number when the
C<when> holds, or there is none. Always returns 1.

    $gate->ask($offense);

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $data = $offense->{data};
	if ( defined( $self->{when} ) && !gates_pass( $self->{when}, $data, undef ) ) {
		return 1;
	}

	my $times = $self->{times};
	if ( defined( $self->{by} ) ) {
		my $number = $data->{ $self->{by} };
		if ( !defined($number) || ref($number) ne '' || $number !~ /^[0-9]+(?:\.[0-9]+)?$/ || $number <= 0 ) {
			return 1;
		}
		$times = $number;
	}
	$offense->{weight_times} = ( $offense->{weight_times} // 1 ) * $times;

	return 1;
} ## end sub ask

1;
