package App::Baphomet::Gate::ban_var;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape qw( check_value );

=head1 NAME

App::Baphomet::Gate::ban_var - The ban_var gate, naming who a offense is counted against and banished.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Names the offenders of a offense, the value of each var it is told, a
capture or a field of the found data. A var the offense has no value for
names nobody. It vetoes nothing... a offense it names nobody for still
stands, counting against no one.

It is told a array of one or more vars.

Where it sits in the list is where the offenders come to be. A gate keyed by
the offender has to be below it, and a gate above it can only read the
offense.

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

Returns 0, the gate naming the offenders and not reading them.

=cut

sub reads_offenders {
	return 0;
}

=head2 ask

Names the offense's subjects, one per var that holds a value, and marks the
offense as having reached its naming. Always returns 1.

    $gate->ask($offense);

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $data = $offense->{data};
	my @subjects;
	foreach my $var ( @{ $self->{names} } ) {
		if ( defined( $data->{$var} ) ) {
			push( @subjects, { 'var' => $var, 'value' => $data->{$var} } );
		}
	}
	$offense->{subjects} = \@subjects;
	$offense->{named}    = 1;

	return 1;
} ## end sub ask

1;
