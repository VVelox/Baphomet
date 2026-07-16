package App::Baphomet::ClayTablet::File;

use 5.006;
use strict;
use warnings;
use File::Path             qw( make_path );
use App::Baphomet::LogDrek qw( log_drek );

=head1 NAME

App::Baphomet::ClayTablet::File - The file backend for a galla's state tablets.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

The default backend, the current on-disk system a galla has always used. Each
tablet is a file under the base dir named C<galla.E<lt>nameE<gt>.E<lt>kindE<gt>.E<lt>suffixE<gt>>,
the suffix C<jsonl> for the structured C<context> and C<stats> tablets and
C<csv> for the rest. Writes go via a temp file and a rename so a tablet is
swapped in whole, never seen half-written. A missing tablet reads as a empty
list; a read or write that throws is logged and swallowed, as a lost checkpoint
must never take the galla down.

=head1 METHODS

=head2 new

    my $backend = App::Baphomet::ClayTablet::File->new(
        'name'            => $galla_name,
        'options'         => { 'base_dir' => '/var/db/baphomet' },  # optional
        'tablet_base_dir' => '/var/db/baphomet',
    );

The base dir is C<options-E<gt>{base_dir}> when set, else the passed
C<tablet_base_dir>. The dir is created if missing; whether it ended up usable
is left to L</verify>.

=cut

sub new {
	my ( $class, %opts ) = @_;

	my $options  = ref( $opts{options} ) eq 'HASH' ? $opts{options}       : {};
	my $base_dir = defined( $options->{base_dir} ) ? $options->{base_dir} : $opts{tablet_base_dir};

	my $self = {
		'name'     => $opts{name},
		'base_dir' => $base_dir,
		'log_tag'  => 'galla-' . ( defined( $opts{name} ) ? $opts{name} : '' ),
	};
	bless $self, $class;

	if ( defined($base_dir) && $base_dir ne '' && !-e $base_dir ) {
		# make_path, as /var/db does not exist on every system... verify
		# handles a failure here
		eval { make_path($base_dir); };
	}

	return $self;
} ## end sub new

=head2 locator

    my $path = $backend->locator($kind);

The path of the tablet of the given kind for this galla.

=cut

sub locator {
	my ( $self, $kind ) = @_;

	my $suffix = ( $kind eq 'context' || $kind eq 'stats' ) ? 'jsonl' : 'csv';

	return $self->{base_dir} . '/galla.' . $self->{name} . '.' . $kind . '.' . $suffix;
}

=head2 verify

    my $err = $backend->verify;

Returns undef when the base dir is a read/writable directory, else a error
string.

=cut

sub verify {
	my ($self) = @_;

	my $base = $self->{base_dir};
	if ( !defined($base) || $base eq '' ) {
		return 'ClayTablet file backend has no base_dir... set tablet_base_dir or ClayTablet.options.base_dir';
	}
	if ( !-d $base || !-r $base || !-w $base ) {
		return 'tablet_base_dir,"' . $base . '", is not a directory or is not read/writable';
	}

	return undef;
} ## end sub verify

=head2 write

    $backend->write( $kind, \@lines );

Writes the lines out atomically via a temp file and a rename, one line per
element with a trailing newline. Logs and swallows a failure, returning 0;
returns 1 on success.

=cut

sub write {
	my ( $self, $kind, $lines ) = @_;

	my $path = $self->locator($kind);
	eval {
		my $tmp = $path . '.tmp';
		open( my $fh, '>', $tmp ) || die( 'open failed... ' . $! );
		foreach my $line ( @{$lines} ) {
			print $fh $line . "\n";
		}
		close($fh);
		rename( $tmp, $path ) || die( 'rename failed... ' . $! );
	};
	if ($@) {
		log_drek( 'err', 'writing the ' . $kind . ' tablet "' . $path . '" failed... ' . $@, undef, $self->{log_tag} );
		return 0;
	}

	return 1;
} ## end sub write

=head2 mark_sync

False... the file backend is host-local storage with no fleet bus, so the galla
keeps marks purely in memory and checkpointed to the marks tablet, as always.

=cut

sub mark_sync { return 0; }

=head2 read

    my @lines = $backend->read($kind);

Returns the tablet's lines chomped, a missing tablet a empty list, a unreadable
one logged and a empty list.

=cut

sub read {
	my ( $self, $kind ) = @_;

	my $path = $self->locator($kind);
	if ( !-f $path ) {
		return ();
	}

	my @lines;
	eval {
		open( my $fh, '<', $path ) || die( 'open failed... ' . $! );
		@lines = <$fh>;
		close($fh);
	};
	if ($@) {
		log_drek( 'err', 'reading the ' . $kind . ' tablet "' . $path . '" failed... ' . $@, undef, $self->{log_tag} );
		return ();
	}

	chomp(@lines);
	return @lines;
} ## end sub read

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
