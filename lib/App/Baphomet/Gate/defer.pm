package App::Baphomet::Gate::defer;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util           qw( any );
use App::Baphomet::Shape qw( check_value );

=head1 NAME

App::Baphomet::Gate::defer - The defer gate, how long a json offense waits for its context.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - gate: [ { field: event, values: [ auth_fail ] } ]
      - key: conn_id
      - defer: 30

=head1 DESCRIPTION

Says how long a offense the rule's C<key> gate could not resolve waits for a
capture line to bring its context, where with out it such a offense is
dropped. It judges nothing itself and is not asked... the C<key> beside it
is what reads it.

It is told a number of seconds. A rule with one has to have a C<key> gate,
and only a json rule can have either.

=head1 METHODS

=head2 compile

Vets the seconds and keeps them under C<seconds>.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'json' );
	check_value( $args, 'seconds', $where );
	$self->{seconds} = $args;

	return;
}

=head2 settle

Dies when the rule has no C<key> gate for a offense to wait on.

=cut

sub settle {
	my ( $self, $gates ) = @_;

	if ( !any { $_->{type} eq 'key' } @{$gates} ) {
		die( $self->{where} . ' has no key gate beside it for a offense to wait on' );
	}

	return;
}

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 once

Returns 1, the one key having the one wait.

=cut

sub once {
	return 1;
}

=head2 idle

Returns 1, there being nothing to ask of it.

=cut

sub idle {
	return 1;
}

1;
