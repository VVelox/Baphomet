package App::Baphomet::Gate::key;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util                 qw( first );
use App::Baphomet::Gate        qw( stand );
use App::Baphomet::Correlation qw( correlation_key_components correlation_key context_get pending_park );

=head1 NAME

App::Baphomet::Gate::key - The key gate, resolving a json offense through the context a capture kept.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - capture:
          - key: conn_id
            gate: [ { field: event, values: [ connect ] } ]
      - gate: [ { field: event, values: [ auth_fail ] } ]
      - key: conn_id
      - defer: 30

=head1 DESCRIPTION

Resolves the line's own offense through the context a C<capture> gate of the
rule kept under the same key, the context going under the offense's own
data. A offense with no value for the whole key has nothing to resolve by
and stands as it is. One whose key has no context is not a offense on this
line... it is dropped, or with a C<defer> gate in the rule left waiting that
long for a capture line to bring the context.

Put it below the gates that make and judge the offense, as it reads the
offense they leave standing.

It is told the field the offense is keyed by, or a array of them to join
into one key. Only a json rule can have one. The types that match on a
message key each C<message_regexp> entry.

=head1 METHODS

=head2 compile

Vets the key and takes the rule's correlation store.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'json' );
	( $self->{key} ) = correlation_key_components( $args, $where, $rule->envelope_fields );
	$self->{correlation} = $rule->correlation;

	return;
}

=head2 settle

Takes how long a unresolved offense waits from the rule's C<defer> gate,
when it has one.

=cut

sub settle {
	my ( $self, $gates ) = @_;

	my $defer = first { $_->{type} eq 'defer' } @{$gates};
	if ( defined($defer) ) {
		$self->{defer} = $defer->{seconds};
	}

	return;
} ## end sub settle

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 once

Returns 1, a offense resolving by the one key.

=cut

sub once {
	return 1;
}

=head2 ask

Resolves the line's own offense, when one stands. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	# a rule that leaves the offense to the line's fields has not made it yet
	my $results = stand($passage);
	my $own     = $passage->{own};
	if ( !defined($own) || !grep { $_ == $own } @{$results} ) {
		return 1;
	}

	# a key component that does not resolve leaves the offense standing plain
	my $key_value = correlation_key( $self->{key}, $own->{data}, undef );
	if ( !defined($key_value) ) {
		return 1;
	}

	my $stored = context_get( $self->{correlation}, $passage->{scope}, $key_value, $passage->{now} );
	if ( defined($stored) ) {
		$own->{data} = { %{$stored}, %{ $own->{data} } };
		return 1;
	}

	# unresolved, so not a offense on this line
	if ( defined( $self->{defer} ) ) {
		pending_park( $self->{correlation}, $passage->{scope}, $key_value, $own->{data}, $own->{regexp},
			$self->{defer}, $passage->{now} );
	}
	$passage->{results} = [ grep { $_ != $own } @{$results} ];
	$passage->{refused} = 1;

	return 1;
} ## end sub ask

1;
