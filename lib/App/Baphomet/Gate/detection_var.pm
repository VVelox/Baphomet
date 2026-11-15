package App::Baphomet::Gate::detection_var;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape qw( check_value );

=head1 NAME

App::Baphomet::Gate::detection_var - The detection_var gate, naming what a detection-only rule counts by.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - detection_var: [ USER ]

=head1 DESCRIPTION

The parallel of C<ban_var> for a rule that only detects. Names the subjects
of a offense, the value of each var it is told, under no obligation to be a
address... a username, a hostname, a URI. A var the offense has no value
for, or a empty one, names nothing. Its being in a rule's list is what makes
the rule detection-only, counting by its subjects and banishing nobody.

It is told a array of one or more vars.

A detection rule has no offenders, so a gate keyed by the offender can not
be in a list with it.

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps the vars.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_value( $args, 'strings', $where );
	$self->{names} = [ @{$args} ];

	return;
}

=head2 reads_offenders

Returns 0, the gate naming the subjects and not reading any offender.

=cut

sub reads_offenders {
	return 0;
}

=head2 ask

Names the offense's subjects, one per var that holds a value that is not
empty, leaves it with no offenders, and marks it as having reached its
naming. Always returns 1.

    $gate->ask($offense);

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $data = $offense->{data};
	my @subjects;
	foreach my $var ( @{ $self->{names} } ) {
		if ( defined( $data->{$var} ) && $data->{$var} ne '' ) {
			push( @subjects, { 'var' => $var, 'value' => $data->{$var} } );
		}
	}
	$offense->{subjects}  = \@subjects;
	$offense->{offenders} = [];
	$offense->{detection} = 1;
	$offense->{named}     = 1;

	return 1;
} ## end sub ask

1;
