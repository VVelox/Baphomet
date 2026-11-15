package App::Baphomet::Gate::level;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util                   qw( is_plain_arrayref );
use App::Baphomet::Rules::Gates qw( compile_matchers matchers_hit );

=head1 NAME

App::Baphomet::Gate::level - The level gate, turning away a error log line of a level other than the ones named.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - level: [ error ]

=head1 DESCRIPTION

Turns the line away outright unless the log level of the line is one of the
ones named, nothing below it then being asked.

It is told a non-empty array, each entry a string the level has to equal or
a C<//regexp//> it has to match.

Only a http_error rule can have one, the level being a field only a error
log line has.

=head1 METHODS

=head2 compile

Vets and compiles the list.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'http_error' );
	if ( !is_plain_arrayref($args) || !@{$args} ) {
		die( $where . ' is not a array or is empty' );
	}
	$self->{matchers} = compile_matchers( $args, $where );

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

Returns 1 when the line's level is one of the ones named, else 0.

    if ( !$gate->ask($passage) ) { ... }

=cut

sub ask {
	my ( $self, $passage ) = @_;

	return matchers_hit( $self->{matchers}, $passage->{parsed}{level} );
}

1;
