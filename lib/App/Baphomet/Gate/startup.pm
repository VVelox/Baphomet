package App::Baphomet::Gate::startup;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::startup - The startup gate, turning lines away while the galla has only just started.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - startup: { grace: 120 }
      - message_regexp:
          - '^Failed password for \S+ from %%%%SRC%%%%'
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Turns a line away while the galla has been up for less than C<grace>
seconds. A galla that starts reads what was written to its logs while it was
down, and counts all of it as happening now, so a minute of failures from a
hour ago reads as a burst. A rule this gate leads lets that by uncounted.

A C<fresh> gate does the same by the time a line says it was written, and is
the better where the lines carry a time that can be read. This is for the
logs whose lines do not.

It reads nothing of the line. A galla not started as a server, as one a
test drives, has nothing to wait out, and every line is let by.

A entry is told...

    - grace :: How many seconds after the galla starts lines are turned
          away for.

It needs the C<uptime> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

my $SHAPE = { 'required' => { 'grace' => 'seconds' } };

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{grace} = $args->{grace};

	return;
}

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 early

Returns 1. It reads nothing of the line, only how long the galla has been
up.

=cut

sub early {
	return 1;
}

=head2 needs

Returns C<uptime>.

=cut

sub needs {
	return ('uptime');
}

=head2 ask

Returns 0 to turn the line away while the galla has been up for less than
C<grace> seconds, else 1.

    if ( !$gate->ask($passage) ) { ... }

=cut

sub ask {
	my ($self) = @_;

	my $uptime = $self->{context}{uptime}->();

	return ( !defined($uptime) || $uptime >= $self->{grace} ) ? 1 : 0;
}

1;
