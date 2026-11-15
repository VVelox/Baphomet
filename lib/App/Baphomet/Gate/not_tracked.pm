package App::Baphomet::Gate::not_tracked;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util            qw( first );
use Ref::Util             qw( is_plain_hashref );
use App::Baphomet::Shape  qw( check_hash );
use App::Baphomet::Tracks qw( track_key track_get );

=head1 NAME

App::Baphomet::Gate::not_tracked - The not_tracked gate, sparing a line whose transaction has a record.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - not_tracked: { name: mail-queue }
      - track: { name: mail-queue, key: postfix_queueid }

=head1 DESCRIPTION

Holds unless the line is part of a live tracked record. A line with no value
for the record's key holds, being part of none.

It judges the offenses standing when it is asked, and while the line's own
offense is still only its fields, those.

A entry is told the C<name> of the record, one a C<track> gate of the rule
declares. It reads the C<tracked> store of the passage's line context, a
line with none being read as one with no records.

=cut

my $SHAPE = { 'required' => { 'name' => 'name' } };

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps the name.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );
	$self->{name} = $args->{name};

	return;
}

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

=head2 passes

Returns true unless the passed data is part of a live record.

    if ( $gate->passes( $data, $passage ) ) { ... }

=cut

sub passes {
	my ( $self, $data, $passage ) = @_;

	my $key = track_key( $self, $data );
	if ( !defined($key) ) {
		return 1;
	}

	# a line with no store is read as one with no records
	my $store = is_plain_hashref( $passage->{line_ctx}{tracked} ) ? $passage->{line_ctx}{tracked} : {};

	return defined( track_get( $store, $self->{name}, $key, $passage->{now} ) ) ? 0 : 1;
} ## end sub passes

=head2 ask

Judges the offenses standing and the line's own, as
L<App::Baphomet::Gate/filter_line> has it. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	return $self->filter_line($passage);
}

1;
