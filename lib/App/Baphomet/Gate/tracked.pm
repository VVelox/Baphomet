package App::Baphomet::Gate::tracked;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util                  qw( first );
use Ref::Util                   qw( is_plain_hashref );
use App::Baphomet::Gate         qw( passage_fields own_fields );
use App::Baphomet::Shape        qw( check_hash );
use App::Baphomet::Tracks       qw( track_key track_get );
use App::Baphomet::Rules::Gates qw( compile_gates gates_pass );

=head1 NAME

App::Baphomet::Gate::tracked - The tracked gate, judging a line by the record of its transaction.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - tracked: { name: mail-queue, where: [ { field: postfix_sasl_username, op: exists } ] }
      - tracked: { name: mail-queue, into: [ postfix_client_ip ] }
      - track: { name: mail-queue, key: postfix_queueid }

=head1 DESCRIPTION

Reads the tracked record a line is part of, to judge the line by it or to
lift fields of it into what the line found.

    - a line of no record :: One with no value for the record's key. It
          holds, a line outside any transaction being no evidence of
          anything.

    - no record yet :: A C<where> asserts something of the history, and no
          history leaves it unproven, so it fails closed. With only a
          C<into> there is nothing to assert, so it holds and lifts nothing.

    - a record :: It holds when the record passes the C<where>, and the
          C<into> fields are then lifted, never over a field the line itself
          has.

It judges the offenses standing when it is asked, and while the line's own
offense is still only its fields, those. A offense a earlier line left
already judged is only lifted into.

A entry is told...

    - name :: The record, one a C<track> gate of the rule declares.

    - where :: Optional. A list as C<gate> takes, judged against the record.

    - into :: Optional. The fields of the record to lift.

At least one of C<where> and C<into>. It reads the C<tracked> store of the
passage's line context, a line with none being read as one with no records.

=cut

# a entry with neither where nor into would do nothing, which is worth
# saying out loud
my $SHAPE = {
	'required' => { 'name'  => 'name' },
	'optional' => { 'where' => 'any', 'into' => 'strings' },
	'any_of'   => [ [ 'where', 'into', 'so it does nothing' ] ],
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, the C<where> compiled under
C<where_gates>, the gate's C<where> being the lead in for its messages.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{name} = $args->{name};
	if ( defined( $args->{where} ) ) {
		# the ordinary gate vocabulary, judged against the stored record
		# rather than the line... so a undef stored value already fails every
		# operator but exists
		$self->{where_gates} = compile_gates( $args->{where}, $where . ' where' );
	}
	if ( defined( $args->{into} ) ) {
		$self->{into} = [ @{ $args->{into} } ];
	}

	return;
} ## end sub compile

=head2 settle

Takes the key of the C<track> gate that declares the record. Dies when the
rule has none for it, the declaration being what the read is a read of.

=cut

sub settle {
	my ( $self, $gates ) = @_;

	my $track = first { $_->{type} eq 'track' && $_->{name} eq $self->{name} } @{$gates};
	if ( !defined($track) ) {
		die( $self->{where} . ' names the record "' . $self->{name} . '", which the rule declares no track for' );
	}
	$self->{key} = $track->{key};

	return;
} ## end sub settle

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

# the live record a data hash is part of.
#
# args:
#   $data  :: the found data, or the line's fields, the record's key is read
#             out of
#   $store :: the tracked store
#   $now   :: the time of the line
#
# returns the two item list ( $keyed, $record )... keyed is 1 when the data
# has a value for the whole key, and record the record's fields, or undef
# when there is no live one.
#
#   my ( $keyed, $record ) = $self->_record( $data, $store, $now );
sub _record {
	my ( $self, $data, $store, $now ) = @_;

	my $key = track_key( $self, $data );
	if ( !defined($key) ) {
		return ( 0, undef );
	}

	return ( 1, track_get( $store, $self->{name}, $key, $now ) );
} ## end sub _record

# lifts the into fields of a record into a data hash, never over a field the
# data already has... the lift lands underneath the line's own fields, as the
# munger fields do, so a capture of the same name always wins.
#
# args:
#   $data   :: the data hash to lift into
#   $record :: the record's fields
#
# returns nothing.
#
#   $self->_lift( $data, $record );
sub _lift {
	my ( $self, $data, $record ) = @_;

	foreach my $field ( @{ $self->{into} // [] } ) {
		if ( defined( $record->{$field} ) && !exists( $data->{$field} ) ) {
			$data->{$field} = $record->{$field};
		}
	}

	return;
} ## end sub _lift

# judges one data hash by the record it is part of, lifting into it when it
# holds.
#
# args:
#   $data  :: the found data, or the line's fields
#   $store :: the tracked store
#   $now   :: the time of the line
#
# returns 1 when the gate holds, else 0.
#
#   if ( $self->_holds( $offense->{data}, $store, $now ) ) { ... }
sub _holds {
	my ( $self, $data, $store, $now ) = @_;

	my ( $keyed, $record ) = $self->_record( $data, $store, $now );
	if ( !$keyed ) {
		return 1;
	}
	if ( !defined($record) ) {
		return defined( $self->{where_gates} ) ? 0 : 1;
	}
	if ( defined( $self->{where_gates} ) && !gates_pass( $self->{where_gates}, $record, undef ) ) {
		return 0;
	}
	$self->_lift( $data, $record );

	return 1;
} ## end sub _holds

=head2 ask

Judges the offenses standing and the line's own, lifting into what holds.
Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	# a line with no store is read as one with no records
	my $store = is_plain_hashref( $passage->{line_ctx}{tracked} ) ? $passage->{line_ctx}{tracked} : {};
	my $now   = $passage->{now};

	my $results = $passage->{results};
	if ( defined($results) && @{$results} ) {
		my @kept;
		foreach my $offense ( @{$results} ) {
			if ( $offense->{judged} ) {
				# judged already by what left it waiting, so a record can not
				# un-fire it... it is only lifted into
				my ( $keyed, $record ) = $self->_record( $offense->{data}, $store, $now );
				if ( defined($record) ) {
					$self->_lift( $offense->{data}, $record );
				}
				push( @kept, $offense );
			} elsif ( $self->_holds( $offense->{data}, $store, $now ) ) {
				push( @kept, $offense );
			} elsif ( defined( $passage->{own} ) && $offense == $passage->{own} ) {
				$passage->{refused} = 1;
			}
		} ## end foreach my $offense ( @{$results} )
		$passage->{results} = \@kept;
	} ## end if ( defined($results) && @{$results} )

	if ( !defined( $passage->{own} ) && !$passage->{refused} ) {
		# a lift writes to the fields, which every rule on the line may share
		my $fields = defined( $self->{into} ) ? own_fields($passage) : passage_fields($passage);
		if ( defined($fields) && !$self->_holds( $fields, $store, $now ) ) {
			$passage->{refused} = 1;
		}
	}

	return 1;
} ## end sub ask

1;
