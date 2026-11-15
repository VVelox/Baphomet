package App::Baphomet::Gate::sample;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::sample - The sample gate, letting one offense in so many by.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - detection_var: [ SRC ]
      - sample: { every: 100 }

=head1 DESCRIPTION

Lets the first offense by, and then one in every C<every> after it,
whatever its key, and vetoes the rest. It thins a whole rule that sights
more than anyone will read, where a limit gate holds each key to so many,
and what it lets by is a fair cut of all of it.

A offense it vetoes is vetoed as by any gate, so the line is not consumed
and goes on to the rules after this one. The count is kept by the scope the
offense is of, a watcher, and starts over at a restart.

A entry is told...

    - every :: One offense in how many is let by, two or more.

=cut

my $SHAPE = {
	'required' => {
		'every' => {
			'test' =>
				sub { return ( defined( $_[0] ) && ref( $_[0] ) eq '' && $_[0] =~ /^[0-9]+$/ && $_[0] >= 2 ) ? 1 : 0; },
			'says' => 'a int of two or more',
		},
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, with a empty count.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{every} = $args->{every};

	# how many offenses have been asked of it, by scope
	$self->{counts} = {};

	return;
} ## end sub compile

=head2 reads_offenders

Returns 0. It counts offenses, whoever they are of.

=cut

sub reads_offenders {
	return 0;
}

=head2 ask

Counts the offense. Returns 1 for the first and for each C<every>th after
it, else 0.

    if ( !$gate->ask($offense) ) { ... }

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $count = $self->{counts}{ $offense->{scope} // '' }++;

	return ( $count % $self->{every} ) == 0 ? 1 : 0;
}

1;
