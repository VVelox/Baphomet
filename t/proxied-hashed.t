#!perl
# the extract, forwarded, concurrent, and digest gates under a galla... the
# digest_key behind digest, what is kept of a hashed name, a rule leaving
# the line out of its EVE events, and the manager's digest command
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );
use JSON::MaybeXS ();

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();
use App::Baphomet ();
use App::Baphomet::Config qw( load_config read_digest_key );
use App::Baphomet::Gate::digest qw( digest_of );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run' );

my $key_path = $dir . '/digest.key';
open( my $key_fh, '>', $key_path ) || die($!);
print $key_fh "a key of sixteen bytes or more\n";
close($key_fh);
my $key = 'a key of sixteen bytes or more';

open( my $short_fh, '>', $dir . '/short.key' ) || die($!);
print $short_fh "too short\n";
close($short_fh);

#
# read_digest_key
#

is( read_digest_key($key_path), $key, 'the key is read less its trailing newline' );
ok( !eval { read_digest_key( $dir . '/short.key' ); 1 }, 'a key under 16 bytes is refused' );
like( $@, qr/holds a key of under 16 bytes/, 'and says so' );
ok( !eval { read_digest_key( $dir . '/missing.key' ); 1 }, 'a file that is not there is refused' );
like( $@, qr/could not be read/, 'and says so' );

sub write_rule {
	my ( $name, $top_level, $gates ) = @_;

	open( my $fh, '>', $dir . '/rules/json/' . $name . '.yaml' ) || die($!);
	print $fh "---\n" . $top_level . "rule_gates:\n  - gate:\n      - field: event\n        values: [ fail ]\n" . $gates;
	close($fh);
	return;
}

write_rule( 'proxied', "max_score: 1\n",
	"  - forwarded: { var: xff, peer: host, trusted: [ 10.0.0.0/8 ], into: CLIENT }\n  - ban_var: [ CLIENT ]\n" );
write_rule( 'by-domain', "max_score: 1\n",
	"  - extract: { var: user, regexp: '\@(?<DOMAIN>[^\@]+)\$' }\n  - after: { by: DOMAIN, count: 3, seconds: 600 }\n  - ban_var: [ ip ]\n" );
write_rule( 'shared', '', "  - concurrent: { by: user, of: ip, more_than: 1, seconds: 600 }\n  - detection_var: [ ip ]\n" );
write_rule( 'hashed', "user_var: user\neve_line: false\n",
	"  - digest: { var: user }\n  - mark: { name: hashed-user, var: user, ttl: 600 }\n  - ban_var: [ ip ]\n" );

my @sent;
my @events;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
	*App::Baphomet::Galla::log_drek  = sub { return; };
	*App::Baphomet::Galla::_eve_emit = sub {
		my ( $self, $event_type, $fields ) = @_;
		push( @events, [ $event_type, $fields ] );
		return;
	};
}

my $config_count = 0;

sub config_of {
	my ( $top_level, %watchers ) = @_;

	$config_count++;
	my $path = $dir . '/config' . $config_count . '.toml';
	open( my $fh, '>', $path ) || die($!);
	print $fh "run_base_dir = \"$dir/run\"\n"
		. "tablet_base_dir = \"$dir/cache$config_count\"\n"
		. "rules_dir = \"$dir/rules\"\n"
		. "ereshkigal_socket = \"$dir/nonexistent.sock\"\n"
		. "eve_enable = true\n"
		. "eve_log = \"$dir/eve.json\"\n"
		. $top_level
		. "\n[kur.app]\nmax_score = 5\nallow_per_rule_thresholds = true\n";
	foreach my $watcher_name ( sort( keys(%watchers) ) ) {
		my $rule_list = join( ', ', map { '"json/' . $_ . '"' } @{ $watchers{$watcher_name} } );
		print $fh "\n[kur.app.$watcher_name]\nlog = \"$dir/l-$watcher_name\"\nparser = \"json\"\nrule = [ $rule_list ]\n";
	}
	close($fh);
	return $path;
} ## end sub config_of

my $json = JSON::MaybeXS->new( 'canonical' => 1 );

sub feed {
	my ( $galla, $watcher, %fields ) = @_;
	$galla->_handle_line( $watcher, $json->encode( \%fields ), $dir . '/l' );
	return;
}

#
# forwarded, extract, and concurrent
#

my $galla = App::Baphomet::Galla->new( config => config_of( '', 'web' => ['proxied'], 'mail' => ['by-domain'], 'auth' => ['shared'] ), name => 'app' );
ok( defined($galla) && !$galla->{perror}, 'a galla with no digest rule needs no digest_key' ) || diag( $galla->{errorString} );

feed( $galla, 'web', event => 'fail', host => '10.0.0.5', xff => '192.0.2.66, 198.51.100.7, 10.0.0.9' );
is_deeply( \@sent, ['198.51.100.7'], 'a request through a trusted proxy banishes the client the header names, not the proxy' );
@sent = ();
feed( $galla, 'web', event => 'fail', host => '203.0.113.9', xff => '198.51.100.8' );
is_deeply( \@sent, ['203.0.113.9'], 'and one not through a proxy banishes its peer, whatever header it sent' );
@sent = ();
feed( $galla, 'web', event => 'fail', host => '10.0.0.5', xff => '10.0.0.6' );
is_deeply( \@sent, [], 'one with nothing but proxies in its header banishes no one' );

@sent = ();
my @mail = map { 'user' . $_ . '@mail.example.org' } 1 .. 3;
feed( $galla, 'mail', event => 'fail', ip => '198.51.100.' . ( 20 + $_ ), user => $mail[$_] ) foreach 0 .. 1;
is_deeply( \@sent, [], 'two failures against the one domain are not yet three' );
feed( $galla, 'mail', event => 'fail', ip => '198.51.100.22', user => $mail[2] );
is_deeply( \@sent, ['198.51.100.22'], 'the third, the domain extracted from the address, banishes' );

@events = ();
feed( $galla, 'auth', event => 'fail', ip => '198.51.100.40', user => 'neti' );
feed( $galla, 'auth', event => 'fail', ip => '198.51.100.41', user => 'neti' );
my @shared_sightings = grep { $_->[1]{rule}{name} eq 'json/shared' } @events;
is( scalar(@shared_sightings), 1, 'the one account from a second address at once is sighted, the first not' );
is( $shared_sightings[0][1]{found}{ip}, '198.51.100.41', 'on the second address' );

#
# digest
#

ok( !eval { App::Baphomet::Galla->new( config => config_of( '', 'auth' => ['hashed'] ), name => 'app' ); 1 },
	'a galla with a digest rule and no digest_key does not come up' );
like( $@, qr/has a digest gate, which can not judge with out digest_key/, 'and says why' );

ok( !eval { App::Baphomet::Galla->new( config => config_of( "digest_key = \"$dir/short.key\"\n", 'auth' => ['hashed'] ), name => 'app' ); 1 },
	'nor does one whose digest_key is too short' );
like( $@, qr/holds a key of under 16 bytes/, 'which says so' );

my $hashing = App::Baphomet::Galla->new( config => config_of( "digest_key = \"$key_path\"\n", 'auth' => ['hashed'] ), name => 'app' );
ok( defined($hashing) && !$hashing->{perror}, 'one with a digest_key comes up' ) || diag( $hashing->{errorString} );

@events = ();
feed( $hashing, 'auth', event => 'fail', ip => '203.0.113.30', user => 'neti' );
my $hashed = digest_of( 'neti', $key );
is_deeply( [ keys( %{ $hashing->{marks}{'hashed-user'} } ) ], [$hashed], 'the brand is keyed by the hash, not the name' );
is( $hashing->{counters}{'203.0.113.30'}[0][3], $hashed, 'and the hit is about the hash' );

my ($found) = grep { $_->[0] eq 'found' } @events;
is( $found->[1]{found}{user}, $hashed, 'the EVE event found the hash' );
is( $found->[1]{user},        $hashed, 'and says the hash is who it was about' );
ok( !exists( $found->[1]{raw} ),    'eve_line false leaves the raw line out' );
ok( !exists( $found->[1]{parsed} ), 'and the parsed one' );

$hashing->checkpoint;
my $tablets = join( "\n", map { $hashing->{tablet}->read($_) } qw( counters marks ) );
ok( index( $tablets, $hashed ) >= 0, 'the tablets hold the hash' );
is( index( $tablets, 'neti' ), -1, 'and nowhere the name' );

#
# the manager's digest command
#

my $manager = App::Baphomet->new( 'config' => config_of( "digest_key = \"$key_path\"\n", 'auth' => ['shared'] ) );
ok( App::Baphomet::Config::known_command('digest'), 'digest is a nameable, gateable command' );
is_deeply( $manager->_cmd_digest( { 'args' => { 'value' => 'neti' } } ), { 'digest' => $hashed }, 'the manager hashes as a digest gate does' );
ok( !eval { $manager->_cmd_digest( { 'args' => {} } ); 1 }, 'and refuses with no value' );
like( $@, qr/^args\.value must be the value to hash/, 'saying so' );
my $no_key_manager = App::Baphomet->new( 'config' => config_of( '', 'auth' => ['shared'] ) );
ok( !eval { $no_key_manager->_cmd_digest( { 'args' => { 'value' => 'neti' } } ); 1 }, 'a manager with no digest_key refuses' );
like( $@, qr/^no digest_key is set in the config/, 'saying so' );

done_testing();
