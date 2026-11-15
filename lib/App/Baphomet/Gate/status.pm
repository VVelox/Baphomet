package App::Baphomet::Gate::status;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util                   qw( is_plain_arrayref );
use App::Baphomet::Rules::Gates qw( compile_matchers matchers_hit );

=head1 NAME

App::Baphomet::Gate::status - The status gate, turning away a request with a status other than the ones named.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - status: [ '401', '403' ]

=head1 DESCRIPTION

Turns the line away outright unless the HTTP status of the request is one of
the ones named, nothing below it then being asked.

It is told a non-empty array, each entry a string the status has to equal or
a C<//regexp//> it has to match. A status is matched as a string, so it is
C<'404'> and never a range of numbers... C<//^5//> is how every server
error is named.

Only a http rule can have one, the status being a field only a access log
line has.

=head1 METHODS

=head2 compile

Vets and compiles the list.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'http' );
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

Returns 1 when the line's status is one of the ones named, else 0.

    if ( !$gate->ask($passage) ) { ... }

=cut

sub ask {
	my ( $self, $passage ) = @_;

	return matchers_hit( $self->{matchers}, $passage->{parsed}{status} );
}

1;
