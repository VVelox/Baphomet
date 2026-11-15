package App::Baphomet::Gate::track;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util             qw( is_plain_arrayref is_plain_hashref );
use App::Baphomet::Gate   qw( passage_fields );
use App::Baphomet::Shape  qw( check_hash );
use App::Baphomet::Tracks qw( track_key track_put );

=head1 NAME

App::Baphomet::Gate::track - The track gate, harvesting a line into a tracked record.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - tracked: { name: mail-queue, into: [ postfix_client_ip ] }
      - track: { name: mail-queue, key: postfix_queueid }

=head1 DESCRIPTION

Declares a tracked record the rule is party to, and lays what each line
found over it, newest winning. It vetoes nothing. A record is a record of
the transaction and not of offenses, so it is asked though no offense
stands... only a gate above it that turns the line away outright stops it.

Put it below the C<tracked> and C<not_tracked> gates that read the record,
so they judge the history and not what this line just wrote.

A entry is told...

    - name :: The record's name.

    - key :: The found var the record is kept under, or a array of them to
          join into one key. A line with out a value for all of it is no
          part of any record.

    - fields :: Optional. The found vars to contribute. With out it
          everything found is, and a empty list contributes nothing, which
          is how a rule that only reads a record declares it.

    - ttl :: Optional. How long the record lives with out a line, 3600
          seconds by default.

It harvests into the C<tracked> store of the passage's line context, and
does nothing when the line has none.

=cut

# fields absent means everything found is contributed, which is not the same
# as a empty list, which means nothing is
my $SHAPE = {
	'required' => { 'name'   => 'name',        'key' => 'string_or_strings' },
	'optional' => { 'fields' => 'string_list', 'ttl' => 'seconds' },
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, the key as a list however it was
written.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{name} = $args->{name};
	# a list of one is the same thing as the plain string, so both compile to
	# a list and the harvest has one shape to resolve
	$self->{key}    = is_plain_arrayref( $args->{key} ) ? [ @{ $args->{key} } ]    : [ $args->{key} ];
	$self->{fields} = defined( $args->{fields} )        ? [ @{ $args->{fields} } ] : undef;
	$self->{ttl}    = $args->{ttl} // 3600;

	return;
} ## end sub compile

=head2 settle

Dies when a gate above it declares the same record, which would leave its
key ambiguous.

=cut

sub settle {
	my ( $self, $gates ) = @_;

	foreach my $gate ( @{$gates} ) {
		if ( $gate == $self ) {
			last;
		}
		if ( $gate->{type} eq 'track' && $gate->{name} eq $self->{name} ) {
			die( $self->{where} . ' declares "' . $self->{name} . '" twice, which leaves its key ambiguous' );
		}
	}

	return;
} ## end sub settle

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 always

Returns 1, the harvest not caring if the line was a offense.

=cut

sub always {
	return 1;
}

=head2 ask

Harvests the line into the record. What is taken is the data of each
offense the line made, as it stood before the rule's own gates judged any
away, or the line's fields when it made none. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	my $store = $passage->{line_ctx}{tracked};
	if ( !is_plain_hashref($store) ) {
		return 1;
	}

	# worked out once for the line, however many records the rule is party to
	my $sources = $passage->{sweep};
	if ( !defined($sources) ) {
		my @taken = @{ $passage->{harvest} // [] };
		if ( !@taken ) {
			@taken = map { $_->{data} } grep { !$_->{judged} } @{ $passage->{results} // [] };
		}
		if ( !@taken ) {
			@taken = ( passage_fields($passage) // {} );
		}
		$sources = \@taken;
		$passage->{sweep} = $sources;
	} ## end if ( !defined($sources) )

	foreach my $data ( @{$sources} ) {
		my $key = track_key( $self, $data );
		if ( !defined($key) ) {
			next;
		}

		# the ttl refreshes whatever is contributed, sighting the key being
		# evidence enough that the transaction is alive
		my %fields;
		foreach my $field ( defined( $self->{fields} ) ? @{ $self->{fields} } : keys( %{$data} ) ) {
			if ( defined( $data->{$field} ) ) {
				$fields{$field} = $data->{$field};
			}
		}

		track_put( $store, $self->{name}, $key, \%fields, $self->{ttl}, $passage->{now} );
	} ## end foreach my $data ( @{$sources} )

	return 1;
} ## end sub ask

1;
