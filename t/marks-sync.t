#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
	eval { require Redis::Fast; };
	if ($@) {
		plan skip_all => 'Redis::Fast not installed';
	}
}

use FindBin ();
use lib "$FindBin::Bin/lib";
use BaphometTestRedis ();

use JSON::MaybeXS ();
use App::Baphomet::Galla ();

# a fake stream handle, injected into a galla's redis backend so the fleet bus
# is exercised end to end with no server
{

	package FakeRedis;
	sub new { return bless { 'streams' => {}, 'seq' => {} }, shift; }
	sub ping { return 'PONG'; }

	sub xadd {
		my ( $s, $stream, @args ) = @_;
		if ( @args >= 3 && $args[0] eq 'MINID' ) { splice( @args, 0, 3 ); }
		shift(@args);
		$s->{seq}{$stream} = ( $s->{seq}{$stream} || 0 ) + 1;
		my $id = $s->{seq}{$stream} . '-0';
		push( @{ $s->{streams}{$stream} }, [ $id, [@args] ] );
		return $id;
	}

	sub xread {
		my ( $s, @args ) = @_;
		my ( $stream, $lastid );
		while (@args) {
			my $tok = shift(@args);
			if ( uc($tok) eq 'COUNT' ) { shift(@args); }
			elsif ( uc($tok) eq 'STREAMS' ) { $stream = shift(@args); $lastid = shift(@args); }
		}
		$lastid = 0 if !defined($lastid) || $lastid eq '';
		$lastid =~ s/-.*//;
		my @out;
		foreach my $entry ( @{ $s->{streams}{$stream} || [] } ) {
			my ($ms) = split( /-/, $entry->[0] );
			if ( $ms > $lastid ) { push( @out, [ $entry->[0], $entry->[1] ] ); }
		}
		return undef if !@out;
		return [ [ $stream, \@out ] ];
	}
}

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/localA', $dir . '/localB', $dir . '/cache' );

# a rule that brands the offender IP under the mark 'seen', branding only
open( my $r, '>', $dir . '/rules/json/brand.yaml' ) || die($!);
print $r <<'EOR';
---
gate:
  - field: event
    values: [ brand ]
ban_var:
  - ip
mark:
  - name: seen
    ttl: 600
mark_only: true
EOR
close($r);

sub write_config {
	my ( $name, $host, $localdir ) = @_;
	open( my $c, '>', $dir . '/' . $name . '.toml' ) || die($!);
	print $c <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
ignore_ips = [ "127.0.0.0/8" ]

[ClayTablet]
backend = "redis"

[ClayTablet.options]
host = "$host"
scope = "shared"
reconnect = 3600

[ClayTablet.options.local]
base_dir = "$localdir"

[kur.shared]
max_score = 5

[kur.shared.w]
log = "$dir/log"
parser = "json"
rule = [ "json/brand" ]
EOC
	close($c);
	return $dir . '/' . $name . '.toml';
}

my $cfg_a = write_config( 'a', 'hostA', $dir . '/localA' );
my $cfg_b = write_config( 'b', 'hostB', $dir . '/localB' );

{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { return; };
}

my $json = JSON::MaybeXS->new( 'canonical' => 1 );

sub feed {
	my ( $galla, %fields ) = @_;
	$galla->_handle_line( 'w', $json->encode( \%fields ), $dir . '/log' );
	return;
}

# both gallas share one injected fake stream
my $bus = FakeRedis->new;

my $a = App::Baphomet::Galla->new( config => $cfg_a, name => 'shared' );
my $b = App::Baphomet::Galla->new( config => $cfg_b, name => 'shared' );

is( $a->{mark_sync}, 1, 'the redis backend gives the galla a mark bus' );
$a->{tablet}{backend}{redis} = $bus;
$b->{tablet}{backend}{redis} = $bus;

# a brand on A lands locally and is published to the bus
feed( $a, event => 'brand', ip => '1.2.3.4' );
ok( defined( $a->{marks}{seen}{'1.2.3.4'} ), 'A brands the offender locally' );

# B has not heard it yet
ok( !defined( $b->{marks}{seen} ), 'B has not seen the brand before a sweep' );

# B sweeps, drains the bus, and converges
$b->_sweep;
ok( defined( $b->{marks}{seen}{'1.2.3.4'} ), 'B ingests the fleet brand on its sweep' );
is( $b->{marks}{seen}{'1.2.3.4'}{expires}, $a->{marks}{seen}{'1.2.3.4'}{expires}, 'with the same expiry, so the fleet agrees' );

# A does not re-ingest its own brand (origin skip), and does not double it
my $a_expires = $a->{marks}{seen}{'1.2.3.4'}{expires};
$a->_sweep;
is( $a->{marks}{seen}{'1.2.3.4'}{expires}, $a_expires, 'A skips its own delta on drain' );

#
# the fold logic directly... extend-only expiry, unset, expired dropped
#

my $now = time;
$b->_ingest_mark_event( { op => 'set', name => 'x', key => 'k', expires => $now + 100 }, $now );
is( $b->{marks}{x}{k}{expires}, $now + 100, 'a set folds in' );
$b->_ingest_mark_event( { op => 'set', name => 'x', key => 'k', expires => $now + 50 }, $now );
is( $b->{marks}{x}{k}{expires}, $now + 100, 'a shorter re-brand does not shorten it (extend-only)' );
$b->_ingest_mark_event( { op => 'set', name => 'x', key => 'k', expires => $now + 500 }, $now );
is( $b->{marks}{x}{k}{expires}, $now + 500, 'a longer re-brand extends it' );
$b->_ingest_mark_event( { op => 'unset', name => 'x', key => 'k' }, $now );
ok( !defined( $b->{marks}{x} ), 'an unset lifts the brand and drops the emptied name' );
$b->_ingest_mark_event( { op => 'set', name => 'x', key => 'old', expires => $now - 1 }, $now );
ok( !defined( $b->{marks}{x} ), 'an already-expired set is dropped' );

#
# restart while the bus is down resumes state from the local file
#

my $c = App::Baphomet::Galla->new( config => $cfg_a, name => 'shared' );    # redis stays down, no inject
ok( !$c->{tablet}{backend}{redis}, 'C could not reach the bus' );
$c->{marks} = {};
feed( $c, event => 'brand', ip => '9.9.9.9' );
ok( defined( $c->{marks}{seen}{'9.9.9.9'} ), 'C brands locally even with the bus down' );
is( scalar( @{ $c->{tablet}{backend}{outbox} } ), 1, 'the brand buffers in the outbox for the fleet' );
$c->checkpoint;    # persist to the local file backend

# a fresh galla on the same local dir, bus still down, resumes the brand
my $c2 = App::Baphomet::Galla->new( config => $cfg_a, name => 'shared' );
ok( defined( $c2->{marks}{seen}{'9.9.9.9'} ), 'a restart resumes the mark from local disk with the bus still down' );

#
# the whole thing end to end against a real redis, if one can be had... two
# gallas, a real stream, a brand on one converging into the other on its sweep
#

SKIP: {
	my ( $server, $redis );
	if ( defined( $ENV{BAPHOMET_TEST_REDIS} ) ) {
		$server = $ENV{BAPHOMET_TEST_REDIS};
	} else {
		$redis = BaphometTestRedis->start;
		skip( 'no redis-server to spin up and no BAPHOMET_TEST_REDIS', 3 ) if !defined($redis);
		$server = $redis->server;
	}

	make_path( $dir . '/liveA', $dir . '/liveB' );
	my $prefix = 'baphomet-marks-sync-' . $$;

	my $write_live = sub {
		my ( $name, $host, $localdir ) = @_;
		open( my $c, '>', $dir . '/' . $name . '.toml' ) || die($!);
		print $c <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
ignore_ips = [ "127.0.0.0/8" ]

[ClayTablet]
backend = "redis"

[ClayTablet.options]
server = "$server"
prefix = "$prefix"
host   = "$host"
scope  = "shared"

[ClayTablet.options.local]
base_dir = "$localdir"

[kur.shared]
max_score = 5

[kur.shared.w]
log = "$dir/log"
parser = "json"
rule = [ "json/brand" ]
EOC
		close($c);
		return $dir . '/' . $name . '.toml';
	};

	my $la = App::Baphomet::Galla->new( config => $write_live->( 'la', 'liveA', $dir . '/liveA' ), name => 'shared' );
	my $lb = App::Baphomet::Galla->new( config => $write_live->( 'lb', 'liveB', $dir . '/liveB' ), name => 'shared' );

	feed( $la, event => 'brand', ip => '4.4.4.4' );
	ok( defined( $la->{marks}{seen}{'4.4.4.4'} ), 'live: A brands locally' );
	$lb->_sweep;
	ok( defined( $lb->{marks}{seen}{'4.4.4.4'} ), 'live: B ingests the brand from the real stream on its sweep' );
	is( $lb->{marks}{seen}{'4.4.4.4'}{expires}, $la->{marks}{seen}{'4.4.4.4'}{expires}, 'live: with the same expiry' );

	# clean up the keys
	eval {
		require Redis::Fast;
		my $r    = Redis::Fast->new( 'server' => $server, 'reconnect' => 0, 'cnx_timeout' => 1 );
		my @keys = $r->keys( $prefix . ':*' );
		$r->del(@keys) if @keys;
	};

	# tear the throwaway server down now
	$redis->stop if defined($redis);
}

done_testing;
