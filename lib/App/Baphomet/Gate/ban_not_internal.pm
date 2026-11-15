package App::Baphomet::Gate::ban_not_internal;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util qw( is_ref );

=head1 NAME

App::Baphomet::Gate::ban_not_internal - The ban_not_internal gate, sparing the operator's own hosts.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - ban_var: [ src_ip, dest_ip ]
      - ban_not_internal: true

=head1 DESCRIPTION

Drops from a offense each offender that is one of the operator's own hosts,
so a rule naming both ends of a flow banishes whichever end is not theirs.
It vetoes nothing... a offense left with no offender still stands, counting
against no one. A detection rule banishes nobody, so on one it does
nothing.

It is told true to do so, and anything false to do nothing.

It needs the C<internal> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=head1 METHODS

=head2 compile

Vets what the gate was told, which is read only for its truth.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	if ( is_ref($args) ) {
		die( $where . ' is not a boolean' );
	}
	$self->{on} = $args ? 1 : 0;

	return;
} ## end sub compile

=head2 reads_offenders

Returns 0. It reads the subjects a C<ban_var> named, but does nothing with
out them, so it is not refused where there are none.

=cut

sub reads_offenders {
	return 0;
}

=head2 idle

Returns true for one told to do nothing.

=cut

sub idle {
	my ($self) = @_;

	return $self->{on} ? 0 : 1;
}

=head2 needs

Returns C<internal>.

=cut

sub needs {
	return ('internal');
}

=head2 ask

Drops the offense's subjects that are internal, and its offenders with them
when they are already settled. Always returns 1.

    $gate->ask($offense);

=cut

sub ask {
	my ( $self, $offense ) = @_;

	# a detection rule has subjects and no offenders, and none of its
	# subjects is anyone to spare
	if ( $offense->{detection} || !defined( $offense->{subjects} ) ) {
		return 1;
	}

	my $internal = $self->{context}{internal};
	$offense->{subjects} = [ grep { !$internal->( $_->{value} ) } @{ $offense->{subjects} } ];
	if ( defined( $offense->{offenders} ) ) {
		$offense->{offenders} = [ grep { !$internal->($_) } @{ $offense->{offenders} } ];
	}

	return 1;
} ## end sub ask

1;
