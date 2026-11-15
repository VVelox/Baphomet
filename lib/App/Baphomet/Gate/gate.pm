package App::Baphomet::Gate::gate;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util                  qw( any );
use App::Baphomet::Rules::Gates qw( compile_gates gates_pass );

=head1 NAME

App::Baphomet::Gate::gate - The gate gate, the flat list of field tests a line has to pass.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - gate:
          - { field: event_type, values: [ alert ] }
          - { field: src_port, op: lt, value: 1024 }

=head1 DESCRIPTION

Holds when every entry of the list does, each a test of one field... the
string-or-C<//regexp//> matcher lists and the typed predicates of
L<App::Baphomet::Rules::Gates>, which is where the vocabulary is compiled
and ran.

It judges the offenses standing when it is asked, and while the line's own
offense is still only its fields, those. So on a json or http rule, where it
sits above the C<match>, it is a filter ahead of the match over the line's
fields, and on a syslog or raw rule, where it sits below the
C<message_regexp>, it is a refinement over the captures.

It is told a array of entries, each a hash with a C<field>. A rule may have
this or C<selections>, the two being two forms of the same thing, never
both.

=head1 METHODS

=head2 compile

Vets and compiles the list. When every entry of it is a plain field test
that compiled to a code ref, those are kept on their own, and walking them
is then the whole judgment.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	$self->{gates} = compile_gates( $args, $where );

	my @code = map { $_->{code} } @{ $self->{gates} };
	if ( !any { !defined($_) } @code ) {
		$self->{code} = \@code;
	}

	return;
} ## end sub compile

=head2 settle

Dies when the rule also has a C<selections> gate.

=cut

sub settle {
	my ( $self, $gates ) = @_;

	if ( any { $_->{type} eq 'selections' } @{$gates} ) {
		die( $self->{where} . ' is beside a selections gate, and the two are two forms of the same thing' );
	}

	return;
}

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 passes

Returns true when every entry of the list holds over the passed data.

    if ( $gate->passes( $data, $passage ) ) { ... }

=cut

sub passes {
	my ( $self, $data, $passage ) = @_;

	my $code = $self->{code};
	if ( defined($code) ) {
		foreach my $test ( @{$code} ) {
			if ( !$test->($data) ) {
				return 0;
			}
		}
		return 1;
	}

	return gates_pass( $self->{gates}, $data, $passage->{message} );
} ## end sub passes

=head2 ask

Judges the offenses standing and the line's own, as
L<App::Baphomet::Gate/filter_line> has it. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	# the line most lines are... nothing made of it yet, its fields in hand,
	# and a list of plain tests to walk. the same judgment filter_line would
	# come to, with out the going round
	my $code = $self->{code};
	if (   defined($code)
		&& !defined( $passage->{results} )
		&& !defined( $passage->{own} )
		&& !$passage->{refused}
		&& defined( $passage->{fields} ) )
	{
		my $fields = $passage->{fields};
		foreach my $test ( @{$code} ) {
			if ( !$test->($fields) ) {
				$passage->{refused} = 1;
				last;
			}
		}
		return 1;
	} ## end if ( defined($code) && !defined( $passage->...))

	return $self->filter_line($passage);
} ## end sub ask

=head2 pins

Returns the field values a line has to have for the list to hold, a hash of
field to the set of values it may be, for the galla to index a watcher's
rules on. Only a entry that is a plain equality over a named field pins
anything... a keyword fan pins no one field, a predicate no exact value, and
a C<//regexp//> a set that can not be listed. Every entry being ANDed, two
on one field pin only the values in both.

    my $pins = $gate->pins;    # { 'event_type' => { 'alert' => 1 } }

=cut

sub pins {
	my ($self) = @_;

	my %pins;
	foreach my $entry ( @{ $self->{gates} } ) {
		if ( $entry->{keyword} || defined( $entry->{predicate} ) || !defined( $entry->{field} ) ) {
			next;
		}
		if ( @{ $entry->{matchers}{regexps} } ) {
			next;
		}

		# narrowing is always safe... the index may hand the rule a line its
		# other gates then refuse, never withhold one they would have taken
		my $held = $pins{ $entry->{field} };
		if ( !defined($held) ) {
			$pins{ $entry->{field} } = { %{ $entry->{matchers}{strings} } };
		} else {
			foreach my $value ( keys( %{$held} ) ) {
				if ( !defined( $entry->{matchers}{strings}{$value} ) ) {
					delete( $held->{$value} );
				}
			}
		}
	} ## end foreach my $entry ( @{ $self->{gates} } )

	return \%pins;
} ## end sub pins

1;
