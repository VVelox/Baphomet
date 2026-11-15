package App::Baphomet::Gate::message_json;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util             qw( is_plain_hashref );
use App::Baphomet::Parser ();

=head1 NAME

App::Baphomet::Gate::message_json - The message_json gate, reading a syslog message that is a JSON object into fields.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - daemons: [ suricata ]
      - message_json: 1
      - gate: [ { field: event_type, values: [ alert ] } ]
      - ban_var: [ src_ip ]

=head1 DESCRIPTION

For a daemon that logs a JSON object as its message. The object is flattened
into dotted path fields, the way the json parser flattens a record, and laid
down as the line's fields, with the syslog envelope beside them under the
reserved C<syslog.daemon>, C<syslog.host>, C<syslog.pid>, C<syslog.time>,
and C<syslog.message>. The gates below read those fields, and a rule with no
C<message_regexp> makes its offense of them.

A line whose message is not a JSON object is not what the rule was told to
expect, and is turned away outright.

It is told a boolean, a false one leaving the gate out. Only a syslog rule
can have one.

=head1 METHODS

=head2 compile

Vets the boolean.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'syslog' );
	if ( defined($args) && ref($args) ne '' ) {
		die( $where . ' is not a boolean' );
	}
	$self->{on} = $args ? 1 : 0;

	return;
} ## end sub compile

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 idle

Returns 1 for a gate told a false value, which reads nothing.

=cut

sub idle {
	my ($self) = @_;

	return $self->{on} ? 0 : 1;
}

=head2 ask

Lays the flattened message and the envelope down as the line's fields, over
any already there. Returns 0 for a message that is not a JSON object, else
1.

    if ( !$gate->ask($passage) ) { ... }

=cut

sub ask {
	my ( $self, $passage ) = @_;

	# kept on the parsed line, so the one decode serves every message_json
	# rule of the watcher... it is the same for each and only ever read. a
	# undef, kept too, is a message that is not a JSON object
	my $parsed = $passage->{parsed};
	if ( !exists( $parsed->{_message_json_extra} ) ) {
		my $decoded;
		eval { $decoded = App::Baphomet::Parser::parse( 'json', $parsed->{message} ); };
		my $extra;
		if ( is_plain_hashref($decoded) && is_plain_hashref( $decoded->{fields} ) ) {
			$extra = { %{ $decoded->{fields} } };
			if ( defined( $parsed->{daemon} ) )   { $extra->{'syslog.daemon'} = $parsed->{daemon}; }
			if ( defined( $parsed->{hostname} ) ) { $extra->{'syslog.host'}   = $parsed->{hostname}; }
			if ( defined( $parsed->{pid} ) )      { $extra->{'syslog.pid'}    = $parsed->{pid}; }
			if ( defined( $parsed->{time} ) )     { $extra->{'syslog.time'}   = $parsed->{time}; }
			$extra->{'syslog.message'} = $parsed->{message};
		}
		$parsed->{_message_json_extra} = $extra;
	} ## end if ( !exists( $parsed->{_message_json_extra...}))

	my $extra = $parsed->{_message_json_extra};
	if ( !defined($extra) ) {
		return 0;
	}

	if ( defined( $passage->{fields} ) ) {
		$passage->{fields}       = { %{ $passage->{fields} }, %{$extra} };
		$passage->{fields_owned} = 1;
	} else {
		# shared with every other rule on the line, so not this rule's to
		# write to
		$passage->{fields}       = $extra;
		$passage->{fields_owned} = 0;
	}

	return 1;
} ## end sub ask

1;
