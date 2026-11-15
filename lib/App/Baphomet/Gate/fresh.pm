package App::Baphomet::Gate::fresh;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Gate  qw( passage_fields );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::fresh - The fresh gate, turning away a line that is old news.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - epoch: { into: WHEN }
      - fresh: { var: WHEN, within: 300 }
      - message_regexp:
          - '^Failed password for \S+ from %%%%SRC%%%%'
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Turns a line away when the time it says it was written is more than
C<within> seconds before it was read. A hit is counted when the line is
read, so a hour of backlog handed over at once, by a relay catching up or a
log picked up after a outage, reads as a burst happening now. With this
ahead of a rule's matcher, old news is not counted at all.

The time is read out of a field, as seconds since the epoch, which is what
a C<epoch> gate above it makes of a timestamp. A line whose time is still to
come, the clock that wrote it running ahead, is fresh.

A line with no time to read can not be shown to be fresh, and is turned
away, unless C<on_unparsed> says to let it by.

A entry is told...

    - var :: The field holding the time, in seconds since the epoch.

    - within :: How many seconds old a line may be.

    - on_unparsed :: Optional. What a line with no time to read does,
          C<pass> or C<fail>.
        Default :: fail

=cut

my $SHAPE = {
	'required' => { 'var'         => 'string', 'within' => 'seconds' },
	'optional' => { 'on_unparsed' => { 'in' => [qw( pass fail )], 'says' => 'one of pass or fail' } },
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it with the default filled in.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{var}         = $args->{var};
	$self->{within}      = $args->{within};
	$self->{on_unparsed} = $args->{on_unparsed} // 'fail';

	return;
} ## end sub compile

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 ask

Returns 0 to turn the line away when the time in the gate's field is more
than C<within> seconds before the line's own, else 1. A line with no time in
the field is settled by C<on_unparsed>.

    if ( !$gate->ask($passage) ) { ... }

=cut

sub ask {
	my ( $self, $passage ) = @_;

	my $written = ( passage_fields($passage) // {} )->{ $self->{var} };
	if ( !defined($written) || ref($written) ne '' || $written !~ /^[0-9]+(?:\.[0-9]+)?$/ ) {
		return $self->{on_unparsed} eq 'pass' ? 1 : 0;
	}

	return ( $passage->{now} - $written ) <= $self->{within} ? 1 : 0;
} ## end sub ask

1;
