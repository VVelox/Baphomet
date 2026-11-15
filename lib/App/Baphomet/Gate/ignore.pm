package App::Baphomet::Gate::ignore;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape         qw( check_entries );
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp match_tokened );

=head1 NAME

App::Baphomet::Gate::ignore - The ignore gate, turning away a line a field of which matches.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - ignore:
          - { field: user_agent, regexp: 'HealthCheck' }

=head1 DESCRIPTION

Turns the line away outright when any of its entries matches, nothing below
it then being asked... no context is stored, no deferred offense completes,
and nothing is harvested. Put it above what it is to stop.

It is told a array of entries, each a hash of C<field>, the field of the
line to read, and C<regexp>. On a http rule the field has to be one a access
log line has and the regexp is a plain one. On a json rule the field is a
flattened dotted path and the regexp may use the C<%%%%TOKEN%%%%> tokens.

Only a http or a json rule can have one. The types that match on a message
have C<ignore_regexp>.

=head1 METHODS

=head2 compile

Vets and compiles the entries the way the rule's type reads them.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'http', 'json' );
	check_entries( $args, { 'required' => { 'field' => 'scalar', 'regexp' => 'scalar' } }, $where );

	my $known_fields = $rule->known_fields;
	$self->{tokened} = defined($known_fields) ? 0 : 1;

	my @entries;
	foreach my ( $entry_int, $entry ) ( indexed @{$args} ) {
		my $entry_where = $where . ' entry ' . $entry_int;
		if ( $self->{tokened} ) {
			push( @entries,
				{ 'field' => $entry->{field}, 'entry' => compile_tokened_regexp( $entry->{regexp}, $entry_where ) }
			);
			next;
		}

		if ( !defined( $known_fields->{ $entry->{field} } ) ) {
			die( $entry_where . ' names the unknown field "' . $entry->{field} . '"' );
		}
		my $regexp = $entry->{regexp};
		my $compiled;
		try {
			$compiled = qr/$regexp/;
		} catch ($caught) {
			die( $entry_where . ', "' . $regexp . '", does not compile... ' . $caught );
		}
		push( @entries, { 'field' => $entry->{field}, 'regexp' => $compiled } );
	} ## end foreach my ( $entry_int, $entry ) ( indexed @{$args...})
	$self->{entries} = \@entries;

	return;
} ## end sub compile

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 early

Returns 1, the parsed line being all it reads and turning a line away all it
does.

=cut

sub early {
	return 1;
}

=head2 ask

Returns 0 when a entry matches its field of the line, else 1.

    if ( !$gate->ask($passage) ) { ... }

=cut

sub ask {
	my ( $self, $passage ) = @_;

	if ( $self->{tokened} ) {
		# the record's own fields, as the parser flattened them
		my $fields = $passage->{parsed}{fields};
		foreach my $entry ( @{ $self->{entries} } ) {
			if ( defined( match_tokened( $entry->{entry}, $fields->{ $entry->{field} } ) ) ) {
				return 0;
			}
		}
		return 1;
	} ## end if ( $self->{tokened} )

	my $parsed = $passage->{parsed};
	foreach my $entry ( @{ $self->{entries} } ) {
		my $value = $parsed->{ $entry->{field} };
		if ( defined($value) && $value =~ $entry->{regexp} ) {
			return 0;
		}
	}

	return 1;
} ## end sub ask

1;
