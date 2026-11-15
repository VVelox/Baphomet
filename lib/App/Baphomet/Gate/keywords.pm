package App::Baphomet::Gate::keywords;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util                   qw( is_plain_arrayref is_plain_hashref );
use App::Baphomet::Shape        qw( check_hash );
use App::Baphomet::Rules::Gates qw( compile_gates gates_pass );

=head1 NAME

App::Baphomet::Gate::keywords - The keywords gate, a string searched for across a line's fields.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - keywords: [ 'union select', 'information_schema' ]
      - keywords: { in: '%%%ANY:http%%%', values: [ sqlmap ] }

=head1 DESCRIPTION

Holds when any of its values is found in what it searches. The shorthand for
a contains test fanned over many fields, ANDed with whatever other gates the
rule has, and able to stand alone.

It judges the offenses standing when it is asked, and while the line's own
offense is still only its fields, those.

It is told either...

    - a array :: The values to search every field for.

    - a hash :: Of C<values>, the same, and C<in>, where to search... a
          named field, a C<%%%ANY:prefix%%%> subtree, or C<%%%ANY%%%>, every
          field, which it is with out a C<in>.

=head1 METHODS

=head2 compile

Vets what the gate was told and compiles it to the one contains test it is.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	my ( $in, $values );
	if ( is_plain_arrayref($args) ) {
		$in     = '%%%ANY%%%';
		$values = $args;
	} elsif ( is_plain_hashref($args) ) {
		check_hash( $args, { 'optional' => { 'in' => 'string', 'values' => 'any' } }, $where );
		$in     = $args->{in} // '%%%ANY%%%';
		$values = $args->{values};
	} else {
		die( $where . ' is not a list of strings or a table' );
	}

	if ( !is_plain_arrayref($values) || !@{$values} ) {
		die( $where . ' lacks a non-empty values list' );
	}

	$self->{gates} = compile_gates( [ { 'field' => $in, 'op' => 'contains', 'values' => $values } ], $where );

	return;
} ## end sub compile

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 passes

Returns true when a value is found in the passed data, or in the line's
message where the search reaches it.

    if ( $gate->passes( $data, $passage ) ) { ... }

=cut

sub passes {
	my ( $self, $data, $passage ) = @_;

	return gates_pass( $self->{gates}, $data, $passage->{message} );
}

=head2 ask

Judges the offenses standing and the line's own, as
L<App::Baphomet::Gate/filter_line> has it. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	return $self->filter_line($passage);
}

1;
