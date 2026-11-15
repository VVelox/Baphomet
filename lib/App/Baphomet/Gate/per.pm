package App::Baphomet::Gate::per;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util                 qw( any );
use App::Baphomet::Correlation qw( correlation_key_components );

=head1 NAME

App::Baphomet::Gate::per - The per gate, what the sequences of a staged rule are kept apart by.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - stages:
          - message_regexp: [ 'probe from %%%%SRC%%%%' ]
          - message_regexp: [ 'exploit from %%%%SRC%%%%' ]
      - per: SRC

=head1 DESCRIPTION

Says what the C<stages> gate beside it keeps its sequences apart by, so the
stages of one offender are never completed by the lines of another. With out
it there is one sequence per log file, the stages having to be hit by lines
that follow one another. It judges nothing itself and is not asked... the
C<stages> is what reads it.

It is told a capture of the stages' regexps, or a array of them to join into
one key. On a syslog rule a component may be one of the reserved
C<syslog.daemon>, C<syslog.host>, and C<syslog.pid>. A line with out a value
for all of it is part of no sequence.

A rule with one has to have a C<stages> gate, and only a syslog or raw rule
can have either.

=head1 METHODS

=head2 compile

Vets the key, keeping its components under C<key> and if any of them reads
the envelope under C<wants_envelope>.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'syslog', 'raw' );
	( $self->{key}, $self->{wants_envelope} ) = correlation_key_components( $args, $where, $rule->envelope_fields );

	return;
}

=head2 settle

Dies when the rule has no C<stages> gate for it to key.

=cut

sub settle {
	my ( $self, $gates ) = @_;

	if ( !any { $_->{type} eq 'stages' } @{$gates} ) {
		die( $self->{where} . ' has no stages gate beside it to key' );
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

Returns 1, the one stages gate having the one key.

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
