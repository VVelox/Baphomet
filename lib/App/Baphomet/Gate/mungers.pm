package App::Baphomet::Gate::mungers;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util            qw( is_plain_hashref );
use List::Util           qw( uniqstr );
use App::Baphomet::Shape qw( check_value );

=head1 NAME

App::Baphomet::Gate::mungers - The mungers gate, decoding a line's message into fields with Log::Munger.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - mungers: [ fortinet ]
      - gate: [ { field: fg_type, values: [ event ] } ]
      - ban_var: [ fg_offender_ip ]

=head1 DESCRIPTION

Runs the line through the named L<Log::Munger> sets and lays the fields they
decode down as the line's fields, underneath any already there. The gates
below read those fields, and a rule with no C<message_regexp> makes its
offense of them, which is how a appliance rule names a parsed field as its
offender instead of scanning the line for a address. A regexp's captures
win over a decoded field of the same name.

A line the sets decode nothing of is left as it was, and is not turned away.

The syslog envelope is handed to Log::Munger under its own names... the
daemon as C<program>, the level as C<priority>, and the facility as
C<facility>. The decode is kept on the line, so every rule of a watcher that
names the same sets shares the one.

It is told a non-empty array of the set names. Only a syslog or raw rule can
have one.

=head1 METHODS

=head2 compile

Vets the names and keeps them, sorted and each once, under C<set>.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'syslog', 'raw' );
	check_value( $args, 'strings', $where );
	$self->{set} = [ sort( uniqstr( @{$args} ) ) ];
	# what the decode is kept under on the line, two rules of a watcher being
	# free to name different sets
	$self->{set_key} = join( "\x1f", @{ $self->{set} } );

	return;
} ## end sub compile

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 processor

Returns the L<Log::Munger::LogProcessor> of the gate's sets, building it on
first asking and sharing it with every gate naming the same ones. Dies when
Log::Munger is not loadable or a set does not load. The galla asks at start,
so a bad set is found then and not on the first line.

    my $processor = $gate->processor;

=cut

# the processors built so far, by set key
my %processor_of;

sub processor {
	my ($self) = @_;

	my $set_key = $self->{set_key};
	if ( defined( $processor_of{$set_key} ) ) {
		return $processor_of{$set_key};
	}

	my $names = join( ', ', @{ $self->{set} } );
	try {
		require Log::Munger::LogProcessor;
	} catch ($caught) {
		die( $self->{where} . ' names mungers (' . $names . ') but Log::Munger is not loadable... ' . $caught );
	}

	my $processor;
	try {
		$processor = Log::Munger::LogProcessor->new( 'rules' => [ @{ $self->{set} } ] );
	} catch ($caught) {
		die( $self->{where} . ' names mungers (' . $names . ') that could not be loaded... ' . $caught );
	}
	if ( !defined($processor) ) {
		die(      $self->{where}
				. ' names mungers ('
				. $names
				. ') that could not be loaded... Log::Munger::LogProcessor->new returned undef' );
	}

	$processor_of{$set_key} = $processor;

	return $processor;
} ## end sub processor

=head2 ask

Lays what the sets decode of the line down as its fields, underneath any
already there. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	# kept on the parsed line, so the one decode serves every rule naming
	# these sets... it is the same for each and only ever read. a undef, kept
	# too, is a line the sets made nothing of
	my $parsed  = $passage->{parsed};
	my $set_key = $self->{set_key};
	if ( !is_plain_hashref( $parsed->{_munge_fields} ) || !exists( $parsed->{_munge_fields}{$set_key} ) ) {
		my $processor = $self->processor;

		my %feed = ( 'message' => $parsed->{message} );
		if ( defined( $parsed->{daemon} ) )   { $feed{program}  = $parsed->{daemon}; }
		if ( defined( $parsed->{level} ) )    { $feed{priority} = $parsed->{level}; }
		if ( defined( $parsed->{facility} ) ) { $feed{facility} = $parsed->{facility}; }

		my $decoded;
		eval { $decoded = $processor->process_item(%feed); };
		$parsed->{_munge_fields}{$set_key} = is_plain_hashref($decoded) ? $decoded : undef;
	} ## end if ( !is_plain_hashref( $parsed->{_munge_fields...}))

	my $decoded = $parsed->{_munge_fields}{$set_key};
	if ( !defined($decoded) || !%{$decoded} ) {
		return 1;
	}

	if ( defined( $passage->{fields} ) ) {
		$passage->{fields}       = { %{$decoded}, %{ $passage->{fields} } };
		$passage->{fields_owned} = 1;
	} else {
		# shared with every other rule on the line, so not this rule's to
		# write to
		$passage->{fields}       = $decoded;
		$passage->{fields_owned} = 0;
	}

	return 1;
} ## end sub ask

1;
