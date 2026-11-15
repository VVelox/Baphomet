package App::Baphomet::Gate::ignore_regexp;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util                    qw( is_plain_arrayref );
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp );

=head1 NAME

App::Baphomet::Gate::ignore_regexp - The ignore_regexp gate, turning away a line whose message matches.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - ignore_regexp:
          - 'from 192\.0\.2\.\d+ port'

=head1 DESCRIPTION

Turns the line away outright when any of its regexps matches the line's
message, nothing below it then being asked... no context is stored, no
sequence advances, no deferred offense completes, and nothing is harvested.
Put it above what it is to stop.

It is told a array of regexp strings. On a syslog or raw rule a regexp may
use the C<%%%%TOKEN%%%%> tokens, nothing being captured from them. On a
http_error rule it is a plain one.

Only a syslog, raw, or http_error rule can have one. The types that match
on fields have C<ignore>.

=head1 METHODS

=head2 compile

Vets and compiles the regexps the way the rule's type reads them.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'syslog', 'raw', 'http_error' );
	if ( !is_plain_arrayref($args) ) {
		die( $where . ' is not a array' );
	}
	foreach my $regexp ( @{$args} ) {
		if ( !defined($regexp) || ref($regexp) ne '' ) {
			die( $where . ' contains a non-string entry' );
		}
	}

	my @regexps;
	foreach my ( $entry_int, $regexp ) ( indexed @{$args} ) {
		my $entry_where = $where . ' entry ' . $entry_int;
		if ( $rule->type ne 'http_error' ) {
			push( @regexps, compile_tokened_regexp( $regexp, $entry_where )->{regexp} );
			next;
		}

		my $compiled;
		try {
			$compiled = qr/$regexp/;
		} catch ($caught) {
			die( $entry_where . ', "' . $regexp . '", does not compile... ' . $caught );
		}
		push( @regexps, $compiled );
	} ## end foreach my ( $entry_int, $regexp ) ( indexed @{...})
	$self->{regexps} = \@regexps;

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

Returns 0 when a regexp matches the line's message, else 1.

    if ( !$gate->ask($passage) ) { ... }

=cut

sub ask {
	my ( $self, $passage ) = @_;

	my $message = $passage->{parsed}{message};
	foreach my $regexp ( @{ $self->{regexps} } ) {
		if ( $message =~ $regexp ) {
			return 0;
		}
	}

	return 1;
} ## end sub ask

1;
