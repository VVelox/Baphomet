package App::Baphomet::Gate::capture_regexp;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Gate          qw( passage_envelope );
use App::Baphomet::Shape         qw( check_entries );
use App::Baphomet::Correlation   qw( correlation_key_components correlation_key context_put pending_complete );
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp match_tokened );

=head1 NAME

App::Baphomet::Gate::capture_regexp - The capture_regexp gate, keeping a line's captures for a offense on another line.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - daemons: [ mongod ]
      - capture_regexp:
          - regexp: '^\[(?<CONN>conn\d+)\] end connection %%%%SRC%%%%:\d+'
            key: CONN
            ttl: 120
      - message_regexp:
          - { regexp: '^\[(?<CONN>conn\d+)\] auth failed', key: CONN, defer: 30 }
      - ban_var: [ SRC ]

=head1 DESCRIPTION

For a offense and the address it is to count against being on different
lines. A line one of its entries matches has its captures kept as context
under that entry's key, where a keyed entry of the rule's C<message_regexp>
finds them for a offense of the same key. And a offense C<message_regexp>
left waiting on that key completes here and now, standing beside whatever
the line itself comes to, to be judged by the gates below like any other. It
turns no line away.

It is told a array of entries, each a hash of...

    - regexp :: The regexp to match the message with, which may use the
          C<%%%%TOKEN%%%%> tokens.

    - key :: The capture the context is kept under, or a array of them to
          join into one key. On a syslog rule a component may be one of the
          reserved C<syslog.daemon>, C<syslog.host>, and C<syslog.pid>. A
          line with out a value for all of it is not kept.

    - ttl :: Optional. How long the context is kept, 60 seconds by default.

Only a syslog or raw rule can have one. A json rule has C<capture>.

=head1 METHODS

=head2 compile

Vets and compiles the entries, and takes the rule's correlation store.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'syslog', 'raw' );
	check_entries( $args,
		{ 'required' => { 'regexp' => 'scalar', 'key' => 'any' }, 'optional' => { 'ttl' => 'seconds' } }, $where );

	my @entries;
	foreach my ( $entry_int, $entry ) ( indexed @{$args} ) {
		my $entry_where = $where . ' entry ' . $entry_int;
		my $compiled    = compile_tokened_regexp( $entry->{regexp}, $entry_where );
		( $compiled->{key}, my $wants_envelope )
			= correlation_key_components( $entry->{key}, $entry_where, $rule->envelope_fields );
		$compiled->{ttl} = $entry->{ttl} // 60;
		# the envelope is only built for a rule with a key that reads it
		if ($wants_envelope) {
			$self->{wants_envelope} = 1;
		}
		push( @entries, $compiled );
	} ## end foreach my ( $entry_int, $entry ) ( indexed @{$args...})
	$self->{entries}     = \@entries;
	$self->{correlation} = $rule->correlation;

	return;
} ## end sub compile

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 ask

Keeps the captures of each entry the message matches under its key, and
stands every offense that was waiting on one of those keys, the line's
fields laid underneath it. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	my $message  = $passage->{message};
	my $envelope = $self->{wants_envelope} ? passage_envelope($passage) : undef;
	foreach my $entry ( @{ $self->{entries} } ) {
		my $caps = match_tokened( $entry, $message );
		if ( !defined($caps) ) {
			next;
		}
		my $key_value = correlation_key( $entry->{key}, $caps, $envelope );
		if ( !defined($key_value) ) {
			next;
		}

		context_put( $self->{correlation}, $passage->{scope}, $key_value, $caps, $entry->{ttl}, $passage->{now} );
		foreach my $completion (
			pending_complete( $self->{correlation}, $passage->{scope}, $key_value, $caps, $passage->{now} ) )
		{
			# what message_json and the mungers made of this line goes
			# under the offense, its own captures winning on a clash
			if ( defined( $passage->{fields} ) ) {
				$completion->{data} = { %{ $passage->{fields} }, %{ $completion->{data} } };
			}
			push( @{ $passage->{results} //= [] }, $completion );
		} ## end foreach my $completion ( pending_complete( $self...))
	} ## end foreach my $entry ( @{ $self->{entries} } )

	return 1;
} ## end sub ask

1;
