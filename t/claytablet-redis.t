#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

# the redis backend. its own join/split/del logic is proven offline against a
# fake handle, always. a live round trip against a real server is a bonus when
# Redis::Fast is installed and a server answers... set BAPHOMET_TEST_REDIS to a
# host:port to point it somewhere other than 127.0.0.1:6379

use FindBin ();
use lib "$FindBin::Bin/lib";
use BaphometTestRedis ();

use App::Baphomet::ClayTablet         ();
use App::Baphomet::ClayTablet::Redis ();

# a tiny in-memory stand-in for a Redis::Fast handle, enough for the backend
{

	package FakeRedis;
	sub new { return bless { 'store' => {}, 'streams' => {}, 'seq' => {} }, shift; }
	sub ping { return 'PONG'; }
	sub set { my ( $s, $k, $v ) = @_; $s->{store}{$k} = $v; return 'OK'; }
	sub get { my ( $s, $k ) = @_; return $s->{store}{$k}; }
	sub del { my ( $s, @k ) = @_; delete( $s->{store}{$_} ) for @k; return scalar(@k); }

	# just enough of the stream commands the mark bus uses
	sub xadd {
		my ( $s, $stream, @args ) = @_;
		if ( @args >= 3 && $args[0] eq 'MINID' ) { splice( @args, 0, 3 ); }    # MINID ~ <minid>
		shift(@args);                                                          # the '*' id placeholder
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
		my @out;
		foreach my $entry ( @{ $s->{streams}{$stream} || [] } ) {
			if ( _id_gt( $entry->[0], $lastid ) ) { push( @out, [ $entry->[0], $entry->[1] ] ); }
		}
		return undef if !@out;
		return [ [ $stream, \@out ] ];
	}

	sub _id_gt {
		my ( $a, $b ) = @_;
		$b = '0-0' if !defined($b) || $b eq '';
		$a .= '-0' if $a !~ /-/;
		$b .= '-0' if $b !~ /-/;
		my ( $am, $as ) = split( /-/, $a );
		my ( $bm, $bs ) = split( /-/, $b );
		return 1 if $am > $bm;
		return 0 if $am < $bm;
		return $as > $bs ? 1 : 0;
	}
}

# build a backend but swap its handle for the fake, so no server is needed
sub fake_backend {
	my ($name) = @_;
	my $backend = bless {
		'name'    => $name,
		'log_tag' => 'galla-' . $name,
		'prefix'  => 'baphomet',
		'options' => {},
		'redis'   => FakeRedis->new,
	}, 'App::Baphomet::ClayTablet::Redis';
	return $backend;
}

my $backend = fake_backend('sshd');

is( $backend->verify, undef, 'a pinging handle verifies' );
is( $backend->locator('marks'), 'baphomet:tablet:sshd:marks', 'the key is prefix:tablet:galla:kind' );

# a never-written tablet reads empty
is_deeply( [ $backend->read('marks') ], [], 'a missing key reads empty' );

# write joins with newlines, read splits back
ok( $backend->write( 'marks', [ 'line one', 'line two' ] ), 'write a tablet' );
is( $backend->{redis}{store}{'baphomet:tablet:sshd:marks'}, "line one\nline two\n", 'stored as the joined blob' );
is_deeply( [ $backend->read('marks') ], [ 'line one', 'line two' ], 'read the lines back' );

# whole-tablet replace, not append
ok( $backend->write( 'marks', ['only this now'] ), 'rewrite the tablet' );
is_deeply( [ $backend->read('marks') ], ['only this now'], 'the rewrite replaced, did not append' );

# an empty write deletes the key
ok( $backend->write( 'marks', [] ), 'write no lines' );
ok( !exists( $backend->{redis}{store}{'baphomet:tablet:sshd:marks'} ), 'the key is deleted' );
is_deeply( [ $backend->read('marks') ], [], 'an empty tablet reads empty' );

# keys are per-galla-name, so two gallas stay isolated even sharing a handle
my $shared = FakeRedis->new;
my $web    = fake_backend('web');
$backend->{redis} = $shared;
$web->{redis}     = $shared;
$backend->write( 'counters', ['sshd row'] );
$web->write( 'counters', ['web row'] );
is_deeply( [ $backend->read('counters') ], ['sshd row'], 'sshd sees only its own' );
is_deeply( [ $web->read('counters') ],     ['web row'],  'web sees only its own' );

# a handle that never connected refuses to verify and no-ops safely... its
# reconnect is throttled shut so it stays down for the test rather than retrying
my $dead = bless {
	'name'               => 'sshd',
	'log_tag'            => 'galla-sshd',
	'prefix'             => 'baphomet',
	'options'            => {},
	'redis'              => undef,
	'connect_error'      => 'could not connect',
	'redis_args'         => { 'server' => '127.0.0.1:1', 'reconnect' => 0, 'cnx_timeout' => 1 },
	'reconnect_throttle' => 3600,
	'last_connect_try'   => time,
}, 'App::Baphomet::ClayTablet::Redis';
ok( defined( $dead->verify ), 'an unconnected backend fails verify' );
is( $dead->write( 'marks', ['x'] ), 0,  'write on a dead backend is a no-op' );
is_deeply( [ $dead->read('marks') ], [], 'read on a dead backend is empty' );

# the mark sync bus and local persistence, offline against the fake stream.
# these go through new(), which needs Redis::Fast to be installed even with no
# server, so they skip without it
SKIP: {
	eval { require Redis::Fast; };
	skip( 'Redis::Fast not installed', 20 ) if $@;

	require File::Temp;
	my $dir = File::Temp::tempdir( CLEANUP => 1 );

	# a real backend (redis undef, no server) with its handle swapped for a fake
	my $make = sub {
		my ( $name, $host, %extra ) = @_;
		my $b = App::Baphomet::ClayTablet::Redis->new(
			'name'            => $name,
			'options'         => { 'host' => $host, 'scope' => 'sshd', %extra },
			'tablet_base_dir' => $dir,
		);
		return $b;
	};

	# publish on one machine, drain on another
	my $bus = FakeRedis->new;
	my $a   = $make->( 'sshd', 'hostA' );
	my $b   = $make->( 'sshd', 'hostB' );
	$a->{redis} = $bus;
	$b->{redis} = $bus;

	is( $a->mark_sync, 1, 'the redis backend carries a mark bus' );
	is( $a->origin, 'hostA', 'origin is the configured host' );

	$a->mark_publish( 'set', 'acct', 'admin', '1.1.1.1', time + 600 );
	my ( $events, $id ) = $b->mark_drain(undef);
	is( scalar( @{$events} ), 1, 'the other machine drains the delta' );
	is( $events->[0]{op},     'set',     'op' );
	is( $events->[0]{name},   'acct',    'name' );
	is( $events->[0]{key},    'admin',   'key' );
	is( $events->[0]{value},  '1.1.1.1', 'the value rides along' );
	is( $events->[0]{origin}, 'hostA',   'origin' );

	# a machine skips its own deltas on drain
	my ( $own, $own_id ) = $a->mark_drain(undef);
	is( scalar( @{$own} ), 0, 'a machine does not re-ingest its own brand' );

	# a valueless brand round-trips with no value key
	$a->mark_publish( 'set', 'seen', '9.9.9.9', undef, time + 600 );
	( $events, $id ) = $b->mark_drain($id);
	is( scalar( @{$events} ), 1, 'the valueless brand drains' );
	ok( !exists( $events->[0]{value} ), 'and carries no value' );

	# an unset propagates
	$a->mark_publish( 'unset', 'acct', 'admin', undef, undef );
	( $events, $id ) = $b->mark_drain($id);
	is( $events->[0]{op}, 'unset', 'the lift propagates as an unset' );

	# the outbox buffers while the bus is down, and flushes on reconnect
	my $c = $make->( 'sshd', 'hostC' );    # redis undef, no fake yet
	$c->mark_publish( 'set', 'acct', 'root', 'x', time + 600 );
	is( scalar( @{ $c->{outbox} } ), 1, 'a delta buffers while the bus is unreachable' );
	is( $c->mark_sync, 1, 'still advertises the bus while down' );
	$c->{redis} = $bus;
	$c->mark_drain($id);    # a drain flushes the outbox first
	is( scalar( @{ $c->{outbox} } ), 0, 'the outbox flushes on reconnect' );
	( $events, $id ) = $b->mark_drain($id);
	is( $events->[0]{origin}, 'hostC', 'and the buffered brand reaches the fleet' );

	# local persistence... redis down, storage still works off the disk, so a
	# restart while the bus is gone resumes state
	my $local = App::Baphomet::ClayTablet::Redis->new(
		'name'            => 'sshd',
		'options'         => { 'local' => { 'base_dir' => $dir . '/localstore' }, 'host' => 'hostL' },
		'tablet_base_dir' => $dir,
	);
	is( $local->verify, undef, 'local mode verifies even with the bus down' );
	like( $local->locator('marks'), qr{localstore/galla\.sshd\.marks\.csv$}, 'host-local tablets land on the disk' );
	ok( $local->write( 'marks', ['a line'] ), 'storage writes to the local file' );
	is_deeply( [ $local->read('marks') ], ['a line'], 'and reads back with the bus down' );
}

# a live server... an already-running one via BAPHOMET_TEST_REDIS, else a
# throwaway redis-server spun up on a free port if the binary is around. no
# server and no binary just runs fewer tests, done_testing counts what ran
SKIP: {
	eval { require Redis::Fast; };
	skip( 'Redis::Fast not installed', 1 ) if $@;

	my ( $server, $guard );
	if ( defined( $ENV{BAPHOMET_TEST_REDIS} ) ) {
		$server = $ENV{BAPHOMET_TEST_REDIS};
		my $reachable;
		eval {
			my $r = Redis::Fast->new( 'server' => $server, 'reconnect' => 0, 'cnx_timeout' => 1 );
			$reachable = $r->ping;
		};
		skip( 'no redis reachable at ' . $server, 1 ) if !$reachable;
	} else {
		$guard = BaphometTestRedis->start;
		skip( 'no redis-server to spin up and no BAPHOMET_TEST_REDIS', 1 ) if !defined($guard);
		$server = $guard->server;
	}

	my $prefix = 'baphomet-test-' . $$;

	# blob storage against a real server (non-local mode)
	my $tablet = App::Baphomet::ClayTablet->new(
		'config' => { 'backend' => 'redis', 'options' => { 'server' => $server, 'prefix' => $prefix } },
		'name'   => 'sshd',
	);
	is( $tablet->backend_name, 'redis', 'backend = redis is the redis backend' );
	is( $tablet->verify,       undef,   'the frontend verifies through to a live redis' );
	$tablet->write( 'marks', [ 'a', 'b' ] );
	is_deeply( [ $tablet->read('marks') ], [ 'a', 'b' ], 'a live blob round trip' );
	$tablet->write( 'marks', [] );
	is_deeply( [ $tablet->read('marks') ], [], 'an emptied tablet reads empty off the server' );

	# the mark bus against a real stream, so real XADD/XREAD/MINID are exercised
	my $la = App::Baphomet::ClayTablet::Redis->new(
		'name' => 'sshd', 'options' => { 'server' => $server, 'prefix' => $prefix, 'scope' => 'sshd', 'host' => 'hostA' } );
	my $lb = App::Baphomet::ClayTablet::Redis->new(
		'name' => 'sshd', 'options' => { 'server' => $server, 'prefix' => $prefix, 'scope' => 'sshd', 'host' => 'hostB' } );

	$la->mark_publish( 'set', 'acct', 'admin', '1.1.1.1', time + 600 );
	my ( $events, $id ) = $lb->mark_drain(undef);
	is( scalar( @{$events} ), 1,         'the other machine drains a live delta' );
	is( $events->[0]{key},    'admin',   'the key survives the stream' );
	is( $events->[0]{value},  '1.1.1.1', 'and the value' );
	is( $events->[0]{origin}, 'hostA',   'and the origin' );

	my ( $own, $own_id ) = $la->mark_drain(undef);
	is( scalar( @{$own} ), 0, 'a machine skips its own live delta' );

	# a valueless brand and an unset over the wire
	$la->mark_publish( 'set', 'seen', '9.9.9.9', undef, time + 600 );
	( $events, $id ) = $lb->mark_drain($id);
	ok( !exists( $events->[0]{value} ), 'a valueless brand carries no value over the wire' );
	$la->mark_publish( 'unset', 'acct', 'admin', undef, undef );
	( $events, $id ) = $lb->mark_drain($id);
	is( $events->[0]{op}, 'unset', 'an unset propagates over the wire' );

	# local mode against a real server... storage on disk, bus live
	require File::Temp;
	my $ldir  = File::Temp::tempdir( 'CLEANUP' => 1 );
	my $local = App::Baphomet::ClayTablet::Redis->new(
		'name'    => 'sshd',
		'options' => { 'server' => $server, 'prefix' => $prefix, 'scope' => 'sshd', 'host' => 'hostL', 'local' => { 'base_dir' => $ldir } },
	);
	is( $local->verify, undef, 'local mode verifies with a live bus' );
	like( $local->locator('counters'), qr/\Q$ldir\E/, 'storage is on the local disk, not the server' );
	$local->write( 'counters', ['row'] );
	is_deeply( [ $local->read('counters') ], ['row'], 'local storage round-trips beside a live bus' );
	$local->mark_publish( 'set', 'seen', '2.2.2.2', undef, time + 600 );
	( $events, $id ) = $lb->mark_drain($id);
	is( $events->[0]{origin}, 'hostL', 'and its brands still reach the fleet over the shared bus' );

	# clean up the keys we made
	eval {
		my $r    = Redis::Fast->new( 'server' => $server, 'reconnect' => 0, 'cnx_timeout' => 1 );
		my @keys = $r->keys( $prefix . ':*' );
		$r->del(@keys) if @keys;
	};

	# and tear the throwaway server down now, not at global destruction
	$guard->stop if defined($guard);
}

done_testing;
