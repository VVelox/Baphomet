#!perl
# the primitive fragment library and its expansion... proves the library
# resolves from Log-Munger (with the tablet-dir cache round-tripping) and
# that %%%%NAME%%%% fragments compose into a rule's message_regexp
# non-capturing, beside the capturing offender tokens
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );

BEGIN {
	eval { require Log::Munger; 1 }
		or plan skip_all => 'Log::Munger not available';
}

use App::Baphomet::Primitives ();
use App::Baphomet::Parser      ();
use App::Baphomet::Rules::Raw  ();

#
# the library resolves from Log-Munger... every fragment a compilable
# regexp, and the common atoms present
#

my $p = App::Baphomet::Primitives::primitives();
ok( scalar( keys( %{$p} ) ) > 40, 'the primitive library resolves and is populated' );
my @bad = grep { !eval { my $r = qr/(?:$p->{$_})/; 1 } } sort( keys( %{$p} ) );
is_deeply( \@bad, [], 'every resolved primitive compiles as a regexp fragment' );
foreach my $atom (qw( INT WORD USERNAME IP HOSTNAME SYSLOGTIMESTAMP TIMESTAMP_ISO8601 MONTH )) {
	ok( defined( $p->{$atom} ), "the $atom primitive is present" );
}

# the offender-token names are NOT shadowed by primitives... they stay the
# capturing tokens Baphomet owns
foreach my $reserved (qw( SRC ADDR HOST DNS )) {
	ok( !defined( $p->{$reserved} ), "the offender token $reserved is not imported as a primitive" );
}

#
# the cache round-trips... configure a fresh dir, resolve writes it, a
# reset-and-reconfigure reads it back without re-resolving
#

my $cache_dir = tempdir( CLEANUP => 1 );
App::Baphomet::Primitives::_reset();
App::Baphomet::Primitives::configure( 'cache_dir' => $cache_dir );
my $first = App::Baphomet::Primitives::primitives();
ok( -f $cache_dir . '/primitives-cache.json', 'resolving under a configured dir writes the cache' );

# the write is atomic... only the final file lands, no temp litter left in
# the dir (File::Temp temp renamed away)
opendir( my $dh, $cache_dir ) || die($!);
my @files = sort grep { $_ !~ /^\.\.?$/ } readdir($dh);
closedir($dh);
is_deeply( \@files, ['primitives-cache.json'], 'the atomic write leaves only the final file, no temp' );

App::Baphomet::Primitives::_reset();
App::Baphomet::Primitives::configure( 'cache_dir' => $cache_dir );
# break Log-Munger resolution so a cache MISS would die... a hit must not
{
	no warnings 'redefine';
	local *Log::Munger::RuleFileParser::load = sub { die("must not resolve on a cache hit\n"); };
	my $second = App::Baphomet::Primitives::primitives();
	is_deeply( $second, $first, 'a warm cache is read back without re-resolving' );
}

# a stale cache (signature mismatch) is ignored... rewrite the file with a
# bogus signature and confirm it re-resolves rather than trusting it
App::Baphomet::Primitives::_reset();
App::Baphomet::Primitives::configure( 'cache_dir' => $cache_dir );
open( my $cfh, '>', $cache_dir . '/primitives-cache.json' ) || die($!);
print $cfh '{"signature":"stale","primitives":{"BOGUS":"x"}}';
close($cfh);
my $fresh = App::Baphomet::Primitives::primitives();
ok( !defined( $fresh->{BOGUS} ), 'a cache whose signature no longer matches is ignored and re-resolved' );
ok( defined( $fresh->{INT} ),    'the re-resolve produced the real library' );

# back to a clean live resolution for the composition tests below
App::Baphomet::Primitives::_reset();

sub raw_rule {
	my (%def) = @_;
	return App::Baphomet::Rules::Raw->new( name => 'raw/x', def => { ban_var => ['SRC'], %def } );
}

sub line { return App::Baphomet::Parser::parse( 'raw', $_[0] ); }

#
# a composed pattern... a syslog timestamp fragment, then a bare INT port,
# then the capturing SRC token. the fragments contribute NO field; only
# SRC is captured
#

my $rule = raw_rule(
	message_regexp => ['^%%%%SYSLOGTIMESTAMP%%%% \S+ sshd\[%%%%INT%%%%\]: Failed password for \S+ from %%%%SRC%%%%'] );
my $found = $rule->check( line('Jul 12 08:15:50 host sshd[1234]: Failed password for root from 192.0.2.7') );
ok( defined($found), 'a pattern built from primitive fragments plus SRC matches a real line' );
is( $found->{data}{SRC}, '192.0.2.7', 'the capturing SRC token yields the offender field' );
is_deeply(
	[ sort keys %{ $found->{data} } ],
	['SRC'],
	'and the fragments (SYSLOGTIMESTAMP, INT) capture nothing... only SRC is a field'
);

# the same primitive twice in one pattern is fine, being non-capturing...
# no duplicate-capture-name compile error
my $twice = raw_rule( message_regexp => ['^%%%%INT%%%%\.%%%%INT%%%% from %%%%SRC%%%%'] );
ok( defined( $twice->check( line('10.20 from 192.0.2.7') ) ),
	'a fragment used twice compiles and matches... no aliasing needed for the non-capturing kind' );

# an author may wrap a fragment in their own named capture to keep it as a
# field under a name of their choosing
my $named = raw_rule(
	message_regexp => ['^user (?<USER>%%%%USERNAME%%%%) from %%%%SRC%%%%'],
	src_ip_var     => 'SRC',
);
my $nf = $named->check( line('user alice from 192.0.2.7') );
is( $nf->{data}{USER}, 'alice',     'a fragment wrapped in (?<USER>...) captures under the chosen name' );
is( $nf->{data}{SRC},  '192.0.2.7', 'beside the SRC token' );

# the negative... the timestamp fragment really is anchored/structured, so
# a garbage prefix does not match
ok( !defined( $rule->check( line('NOTATIME host sshd[1234]: Failed password for root from 192.0.2.7') ) ),
	'the SYSLOGTIMESTAMP fragment rejects a non-timestamp prefix' );

#
# an unknown token still dies at load, whichever map it is missing from
#

ok(
	!eval { raw_rule( message_regexp => ['^%%%%NOSUCHTHING%%%% from %%%%SRC%%%%'] ); 1 },
	'an unknown token name is a load error'
);
like( $@, qr/unknown token "NOSUCHTHING"/, 'and the error names it' );

done_testing;
