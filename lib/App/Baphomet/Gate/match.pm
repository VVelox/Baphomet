package App::Baphomet::Gate::match;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Gate          qw( own_fields );
use App::Baphomet::Shape         qw( check_entries );
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp match_tokened );

=head1 NAME

App::Baphomet::Gate::match - The match gate, making a offense of a line a field of which matches.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - match:
          - { field: path, regexp: '^/wp-login\.php' }
          - { field: path, regexp: '^/xmlrpc\.php' }

=head1 DESCRIPTION

Makes the line's own offense when one of its entries matches, tried in order
and the first to hit winning, which entry it was going down as the
offense's C<regexp>. A line none of them matches makes no offense of its
own. A rule with out one makes its offense of the line's fields, once every
gate has let them by.

A gate above it that judges the fields has judged before it is asked, so a
line already refused is not matched at all.

It is told a array of entries, each a hash of C<field>, the field of the
line to read, and C<regexp>. On a http rule the field has to be one a access
log line has, the regexp is a plain one, and the offense's data is the
line's fields. On a json rule the field is a flattened dotted path, the
regexp may use the C<%%%%TOKEN%%%%> tokens, and the offense's data is the
captures with the line's fields over them.

Only a http or a json rule can have one. The types that match on a message
have C<message_regexp>.

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

=head2 once

Returns 1, a rule having the one matcher.

=cut

sub once {
	return 1;
}

=head2 ask

Makes the line's own offense of the first entry to match, or refuses it when
none does. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	if ( $passage->{refused} || defined( $passage->{own} ) ) {
		return 1;
	}

	my $own;
	if ( $self->{tokened} ) {
		my $fields = $passage->{fields};
		foreach my ( $entry_int, $entry ) ( indexed @{ $self->{entries} } ) {
			my $caps = match_tokened( $entry->{entry}, $fields->{ $entry->{field} } );
			if ( defined($caps) ) {
				# the flattened fields over the captures, the fields
				# authoritative
				$own = { 'data' => { %{$caps}, %{$fields} }, 'regexp' => $entry_int };
				last;
			}
		}
	} else {
		my $parsed = $passage->{parsed};
		foreach my ( $entry_int, $entry ) ( indexed @{ $self->{entries} } ) {
			my $value = $parsed->{ $entry->{field} };
			if ( defined($value) && $value =~ $entry->{regexp} ) {
				$own = { 'data' => own_fields($passage), 'regexp' => $entry_int };
				last;
			}
		}
	} ## end else [ if ( $self->{tokened} ) ]

	if ( defined($own) ) {
		$passage->{own} = $own;
		unshift( @{ $passage->{results} //= [] }, $own );
	} else {
		$passage->{refused} = 1;
	}

	return 1;
} ## end sub ask

1;
