package App::Baphomet::Gate::capture;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape         qw( check_entries );
use App::Baphomet::Correlation   qw( correlation_key_components correlation_key context_put pending_complete );
use App::Baphomet::Rules::Gates  qw( compile_gates gates_pass );
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp match_tokened );

=head1 NAME

App::Baphomet::Gate::capture - The capture gate, keeping a json line's fields for a offense on another line.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - capture:
          - key: conn_id
            gate: [ { field: event, values: [ connect ] } ]
            ttl: 120
      - gate: [ { field: event, values: [ auth_fail ] } ]
      - key: { key: conn_id, defer: 30 }

=head1 DESCRIPTION

For a offense and the address it is to count against being on different
lines of a json log. A line one of its entries takes is kept as context
under that entry's key, where the rule's C<key> gate finds it for a offense
of the same key. And a offense the C<key> gate left waiting on that key,
under a C<defer>, completes here and now, standing beside whatever the line
itself comes to. It turns no line away and judges no offense.

A context line is rarely shaped like the offense, so a entry judges a line
by its own C<gate> and C<match> and never by the rule's. A offense it
completes was judged by the rule's gates when it was left waiting, and is
not judged by them again.

It is told a array of entries, each a hash of...

    - key :: The field the context is kept under, or a array of them to
          join into one key. A line with out a value for all of it is not
          kept.

    - gate :: A list as the C<gate> gate takes, which the line has to pass.

    - match :: A array of C<field> and C<regexp> hashes, the first to match
          taking the line, its captures kept with the fields.

    - ttl :: Optional. How long the context is kept, 60 seconds by default.

At least one of C<gate> and C<match>. Only a json rule can have one. The
types that match on a message have C<capture_regexp>.

=head1 METHODS

=head2 compile

Vets and compiles the entries, and takes the rule's correlation store.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'json' );
	check_entries(
		$args,
		{
			'required' => { 'key'  => 'any' },
			'optional' => { 'gate' => 'any', 'match' => 'any', 'ttl' => 'seconds' },
			'any_of'   => [ [ 'gate', 'match', 'so it would harvest every line' ] ],
		},
		$where
	);

	my @entries;
	foreach my ( $entry_int, $entry ) ( indexed @{$args} ) {
		my $entry_where = $where . ' entry ' . $entry_int;

		my ($key) = correlation_key_components( $entry->{key}, $entry_where, $rule->envelope_fields );
		my $compiled = { 'key' => $key, 'ttl' => $entry->{ttl} // 60, 'gates' => undef, 'matches' => [] };
		if ( defined( $entry->{gate} ) ) {
			$compiled->{gates} = compile_gates( $entry->{gate}, $entry_where . ' gate' );
		}
		if ( defined( $entry->{match} ) ) {
			check_entries(
				$entry->{match},
				{ 'required' => { 'field' => 'scalar', 'regexp' => 'scalar' } },
				$entry_where . ' match'
			);
			foreach my ( $match_int, $match ) ( indexed @{ $entry->{match} } ) {
				push(
					@{ $compiled->{matches} },
					{
						'field' => $match->{field},
						'entry' =>
							compile_tokened_regexp( $match->{regexp}, $entry_where . ' match entry ' . $match_int ),
					}
				);
			} ## end foreach my ( $match_int, $match ) ( indexed @{ ...})
		} ## end if ( defined( $entry->{match} ) )
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

Keeps the line under the key of each entry that takes it, and stands every
offense that was waiting on one of those keys beside the line's own, marked
as judged. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	my $fields = $passage->{fields};
	foreach my $entry ( @{ $self->{entries} } ) {
		if ( defined( $entry->{gates} ) && !gates_pass( $entry->{gates}, $fields, undef ) ) {
			next;
		}
		my $caps = {};
		if ( @{ $entry->{matches} } ) {
			$caps = undef;
			foreach my $match ( @{ $entry->{matches} } ) {
				$caps = match_tokened( $match->{entry}, $fields->{ $match->{field} } );
				if ( defined($caps) ) {
					last;
				}
			}
			if ( !defined($caps) ) {
				next;
			}
		} ## end if ( @{ $entry->{matches} } )

		# the context kept is the whole event... the captures with the
		# flattened fields over them, the fields authoritative, same as a
		# offense's data
		my %context   = ( %{$caps}, %{$fields} );
		my $key_value = correlation_key( $entry->{key}, \%context, undef );
		if ( !defined($key_value) ) {
			next;
		}

		context_put( $self->{correlation}, $passage->{scope}, $key_value, \%context, $entry->{ttl}, $passage->{now} );
		foreach my $completion (
			pending_complete( $self->{correlation}, $passage->{scope}, $key_value, \%context, $passage->{now} ) )
		{
			$completion->{judged} = 1;
			push( @{ $passage->{results} //= [] }, $completion );
		}
	} ## end foreach my $entry ( @{ $self->{entries} } )

	return 1;
} ## end sub ask

1;
