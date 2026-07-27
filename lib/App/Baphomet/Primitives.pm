package App::Baphomet::Primitives;

use 5.006;
use strict;
use warnings;
use JSON::MaybeXS ();
use File::Temp    ();

=head1 NAME

App::Baphomet::Primitives - Regexp-fragment library for rule authors, from Log-Munger.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

A named library of regexp fragments... IP, INT, WORD, TIMESTAMP_ISO8601,
and the rest... for composing C<message_regexp> and C<capture_regexp>
patterns without hand-rolling the same sub-patterns. Referenced in a rule
regexp as C<%%%%NAME%%%%>, expanded NON-capturing (wrapped C<(?:...)>),
unlike the offender tokens (SRC/ADDR/HOST/...) which capture under their
name. Compose a capture around one when wanted:
C<(?E<lt>USERE<gt>%%%%USERNAME%%%%)>.

The fragments are L<Log::Munger>'s C<base> primitive library, resolved at
run time (its C<vars> and C<vars_templated>, templated into final
regexps). Log-Munger is a real dependency, but the resolution is lazy...
it happens only the first time a rule actually references a fragment, so a
deployment using only the offender tokens never loads it. The names it
reserves for the offender tokens (SRC/ADDR/HOST/DNS/...) are dropped from
the imported set, so those keep their capturing meaning.

Resolving parses YAML and runs Template Toolkit, so the result is cached
under a galla's tablet dir and reused across restarts and across the
kur's gallas until the source changes... see L</configure> and
L</primitives>.

=head1 FUNCTIONS

=cut

# the offender tokens Baphomet owns... a Log-Munger primitive of the same
# name is dropped so those keep their capturing meaning in _expand_token
my %reserved = map { $_ => 1 } qw( IP4 IP6 ADDR DNS HOST SUBNET SRC DEST );

# the cache file name under the cache dir... not galla.<kur>.* like the
# tablets, so it never collides with one and is shared by every galla
my $cache_file = 'primitives-cache.json';

# the process-wide memo... resolved once, however many rules or kurs ask
my $resolved;

# the cache dir the galla names at startup, remembered so the lazy resolve
# can read and write it. undef in a cache-less CLI or test run
my $cache_dir;

=head2 configure

Names the directory (a galla's tablet dir) the resolved map is cached in,
without resolving anything... cheap, so a galla calls it at startup and a
deployment that never uses a fragment pays nothing beyond this. The
resolve happens later, lazily, the first time a rule reaches for a
fragment (L</primitives>), reading the cache instead of re-parsing YAML
and re-running Template Toolkit when the signature still matches.

    App::Baphomet::Primitives::configure( 'cache_dir' => $tablet_dir );

=cut

sub configure {
	my (%opts) = @_;

	if ( exists( $opts{cache_dir} ) ) {
		$cache_dir = $opts{cache_dir};
	}

	return;
} ## end sub configure

=head2 primitives

Returns the resolved primitive map, a hashref of name to regexp-fragment
string, memoized for the process. The first call resolves... reading the
cache under the configured dir when its signature (the Log-Munger version
and the C<base> file's mtime and size) still matches, else resolving live
and writing the cache best-effort (a unwritable dir just means the next
galla resolves again, never a failure). With no configured dir it resolves
live and still memoizes. Dies loudly if Log-Munger can not be loaded or
its C<base> can not be resolved... the fragments are a declared
dependency, so this is C<_expand_token>'s lazy getter and a failure means
a rule that uses a fragment can not load.

    my $primitives = App::Baphomet::Primitives::primitives();

=cut

sub primitives {
	if ( defined($resolved) ) {
		return $resolved;
	}

	my $signature = _signature();
	if ( defined($cache_dir) && defined($signature) ) {
		my $cached = _read_cache( $cache_dir, $signature );
		if ( defined($cached) ) {
			$resolved = $cached;
			return $resolved;
		}
	}

	$resolved = _resolve();

	if ( defined($cache_dir) && defined($signature) ) {
		_write_cache( $cache_dir, $signature, $resolved );
	}

	return $resolved;
} ## end sub primitives

# drops the memo and the configured dir, so a test can exercise the
# resolve/cache path more than once in one process. not used at run time
sub _reset {
	$resolved  = undef;
	$cache_dir = undef;
	return;
}

# resolves Log-Munger's base into a flat name -> regexp map, less the
# reserved offender-token names. dies loudly on any failure... the
# fragments are a declared dependency, so a broken one is a real error
sub _resolve {
	eval {
		require Log::Munger::RuleFileParser;
		1;
	} or die( 'the primitive fragments need Log::Munger, which could not be loaded... ' . $@ );

	my $rules;
	eval {
		$rules = Log::Munger::RuleFileParser->new->load( 'file' => 'base' );
		1;
	} or die( 'resolving the Log-Munger base primitive library failed... ' . $@ );

	my $vars = ( ref($rules) eq 'HASH' && ref( $rules->{vars} ) eq 'HASH' ) ? $rules->{vars} : {};

	my %map;
	foreach my $name ( keys( %{$vars} ) ) {
		next if ( $reserved{$name} );
		my $re = $vars->{$name};
		next if ( ref($re) ne '' || !defined($re) || $re eq '' );
		$map{$name} = $re;
	}

	return \%map;
} ## end sub _resolve

# the source signature... the Log-Munger version plus the base file's
# mtime and size, so a version bump (code change) or a base edit (data
# change) both invalidate the cache. undef when the base file can not be
# located, which makes load skip the cache and resolve live
sub _signature {
	my $version = eval { require Log::Munger; $Log::Munger::VERSION; };
	if ( !defined($version) || $version eq '' ) {
		$version = 'unknown';
	}

	my $base = eval {
		require File::ShareDir;
		File::ShareDir::dist_dir('Log-Munger') . '/base.yaml';
	};
	if ( !defined($base) || !-f $base ) {
		return undef;
	}

	my ( $size, $mtime ) = ( stat($base) )[ 7, 9 ];
	return join( ':', 'logmunger', $version, $mtime, $size );
} ## end sub _signature

# reads the cache map when the file is present, parseable, and carries the
# current signature... undef otherwise, which tells load to re-resolve
sub _read_cache {
	my ( $cache_dir, $signature ) = @_;

	my $path = $cache_dir . '/' . $cache_file;
	if ( !-f $path ) {
		return undef;
	}

	my $text;
	eval {
		open( my $fh, '<', $path ) || die("$!");
		binmode($fh);
		local $/;
		$text = <$fh>;
		close($fh);
		1;
	} or return undef;

	# the fragments are character strings (a primitive like MONTH carries a
	# ä), so the cache is UTF-8 bytes read raw and decoded utf8, symmetric
	# with the write... a plain decode_json would choke on the lone byte
	my $decoded = eval { JSON::MaybeXS->new->utf8->decode($text); };
	if (   ref($decoded) ne 'HASH'
		|| !defined( $decoded->{signature} )
		|| $decoded->{signature} ne $signature
		|| ref( $decoded->{primitives} ) ne 'HASH' )
	{
		return undef;
	}

	return $decoded->{primitives};
} ## end sub _read_cache

# writes the resolved map and its signature to the cache, best-effort... a
# unwritable dir or a failed write is swallowed, the resolution having
# already succeeded, so the only cost is the next galla resolving again.
#
# the write is atomic: the bytes go to a uniquely-named temp file in the
# SAME directory (File::Temp, O_EXCL, so no two writers ever share a name
# and no stale temp is reused), fully written and closed, then renamed
# over the target. rename(2) within one filesystem is atomic, so a reader
# ever opens the whole old file or the whole new one, never a half write,
# and concurrent gallas just race to be last, each leaving a complete
# file. any failure unlinks the temp and leaves the target as it was
sub _write_cache {
	my ( $cache_dir, $signature, $map ) = @_;

	if ( !-d $cache_dir ) {
		return;
	}

	my $path = $cache_dir . '/' . $cache_file;
	# utf8-encode to bytes and write raw, so a fragment carrying a non-ASCII
	# character (MONTH's ä) round-trips through the read
	my $text = eval {
		JSON::MaybeXS->new->canonical->utf8->encode( { 'signature' => $signature, 'primitives' => $map } );
	};
	if ( !defined($text) ) {
		return;
	}

	eval {
		# UNLINK 0... the file is handed off by rename, so its lifetime is
		# ours to manage, not File::Temp's at-exit reaping
		my ( $fh, $tmp ) = File::Temp::tempfile( $cache_file . '.XXXXXXXX', 'DIR' => $cache_dir, 'UNLINK' => 0 );
		binmode($fh);
		print $fh $text or die( 'write failed... ' . $! );
		close($fh)      or die( 'close failed... ' . $! );
		if ( !rename( $tmp, $path ) ) {
			my $error = $!;
			unlink($tmp);
			die( 'rename failed... ' . $error );
		}
		1;
	};

	return;
} ## end sub _write_cache

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
