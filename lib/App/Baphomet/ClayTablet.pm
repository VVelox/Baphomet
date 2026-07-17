package App::Baphomet::ClayTablet;

use 5.006;
use strict;
use warnings;

=head1 NAME

App::Baphomet::ClayTablet - Pluggable state tablet storage for a galla.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::ClayTablet ();

    my $tablet = App::Baphomet::ClayTablet->new(
        'config'          => $config->{ClayTablet},   # the global table, may be undef
        'name'            => 'sshd',                   # this galla, for namespacing
        'tablet_base_dir' => '/var/db/baphomet',       # the file backend default
    );

    my $err = $tablet->verify;
    die($err) if defined($err);

    $tablet->write( 'marks', [ '{"name":"x",...}' ] );
    my @lines = $tablet->read('marks');

The frontend a galla holds for its state tablets... counters, pending bans,
log positions, journal cursors, running stats, correlation context, and the
persistent marks. It reads the global C<ClayTablet> config, picks a backend by
name, and proxies the line-oriented C<read>/C<write>/C<locator>/C<verify> the
galla speaks straight through to it.

The abstraction is one line-oriented tablet per kind. Everything above it,
the CSV headers and the one-JSON-line-per-thing shapes, lives in the galla, so
a backend never has to understand what it is storing... only how to hold a list
of lines under a (galla, kind) name and hand it back.

A backend is a plain object under C<App::Baphomet::ClayTablet::> named for the
lower-cased, ucfirst'd backend name, so C<backend = "file"> loads
L<App::Baphomet::ClayTablet::File> and C<backend = "redis"> loads
L<App::Baphomet::ClayTablet::Redis>. A third party can drop its own alongside
and select it the same way.

=head1 METHODS

=head2 new

    my $tablet = App::Baphomet::ClayTablet->new(
        'config'          => $config->{ClayTablet},
        'name'            => $galla_name,
        'tablet_base_dir' => $config->{tablet_base_dir},
    );

Loads and constructs the configured backend. Dies on an unusable backend
name or one that will not load. The chosen backend interprets C<config-E<gt>{options}>;
C<name> namespaces its storage and C<tablet_base_dir> is passed through as the
file backend's default base dir. A undef or empty config means the C<file>
backend, which is the current on-disk system.

=cut

sub new {
	my ( $class, %opts ) = @_;

	my $config = $opts{config};
	if ( ref($config) ne 'HASH' ) {
		$config = {};
	}

	my $backend_name = defined( $config->{backend} ) ? $config->{backend} : 'file';
	if ( ref($backend_name) ne '' || $backend_name !~ /^[A-Za-z][A-Za-z0-9]*$/ ) {
		die(      'ClayTablet backend "'
				. ( defined($backend_name) ? $backend_name : 'undef' )
				. '" is not a plain backend name matching /^[A-Za-z][A-Za-z0-9]*$/' );
	}

	my $backend_class = 'App::Baphomet::ClayTablet::' . ucfirst( lc($backend_name) );
	eval "require $backend_class; 1;"    ## no critic (ProhibitStringyEval)
		or die( 'ClayTablet could not load the backend "' . $backend_name . '" (' . $backend_class . ')... ' . $@ );

	my $options = ref( $config->{options} ) eq 'HASH' ? $config->{options} : {};

	my $backend = $backend_class->new(
		'name'            => $opts{name},
		'options'         => $options,
		'tablet_base_dir' => $opts{tablet_base_dir},
	);

	my $self = {
		'backend'      => $backend,
		'backend_name' => $backend_name,
	};
	bless $self, $class;

	return $self;
} ## end sub new

=head2 read

    my @lines = $tablet->read($kind);

Returns the tablet's lines, chomped, an empty list for a tablet never written
or that can not be read.

=cut

sub read {
	my ( $self, $kind ) = @_;

	return $self->{backend}->read($kind);
}

=head2 write

    $tablet->write( $kind, \@lines );

Replaces the whole tablet with the given lines. Whole-tablet replace, never
append. Failures are the backend's to log and swallow, so a lost checkpoint
never takes the galla down.

=cut

sub write {
	my ( $self, $kind, $lines ) = @_;

	return $self->{backend}->write( $kind, $lines );
}

=head2 locator

    my $where = $tablet->locator($kind);

A human string naming where the tablet lives, a path for the file backend or a
key for the redis one, for logs and diagnostics.

=cut

sub locator {
	my ( $self, $kind ) = @_;

	return $self->{backend}->locator($kind);
}

=head2 verify

    my $err = $tablet->verify;

Checks the store is usable at start, returning undef when it is or a error
string when it is not, for the galla to raise as a fatal startup error.

=cut

sub verify {
	my ($self) = @_;

	return $self->{backend}->verify;
}

=head2 backend_name

The name of the backend in use.

=cut

sub backend_name {
	my ($self) = @_;

	return $self->{backend_name};
}

=head2 mark_sync

    if ( $tablet->mark_sync ) { ... }

True when the backend provides a fleet mark sync bus (the redis backend), so the
galla publishes and drains marks through it. False for a plain storage backend
(the file backend), where marks stay local and in memory.

=cut

sub mark_sync {
	my ($self) = @_;

	if ( $self->{backend}->can('mark_sync') ) {
		return $self->{backend}->mark_sync;
	}

	return 0;
}

=head2 mark_publish

    $tablet->mark_publish( $op, $name, $key, $value, $expires, $set );

Publishes a mark delta to the sync bus. Only call when L</mark_sync> is true.

=cut

sub mark_publish {
	my ( $self, @args ) = @_;

	return $self->{backend}->mark_publish(@args);
}

=head2 mark_drain

    my ( $events, $new_id ) = $tablet->mark_drain($last_id);

Drains new mark deltas from the sync bus. Only call when L</mark_sync> is true.

=cut

sub mark_drain {
	my ( $self, @args ) = @_;

	return $self->{backend}->mark_drain(@args);
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991, or (at your
  option) any later version, matching fail2ban, which parts of this
  project, most notably the shipped rules, are derived from.

=cut

1;
