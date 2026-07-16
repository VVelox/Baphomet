package BaphometTestRedis;

# Spins up a throwaway redis-server on a free local port for the optional live
# ClayTablet redis tests, and kills it on DESTROY. Returns undef when there is
# no redis-server to run, so a caller just skips. Set BAPHOMET_TEST_REDIS to a
# host:port to use an already-running server instead, or REDIS_SERVER_BIN to
# point at a particular redis-server binary.

use 5.006;
use strict;
use warnings;
use File::Temp       ();
use IO::Socket::INET ();
use Time::HiRes      ();
use POSIX            ();

# the path of a redis-server to run, or undef if none is around
sub _find_bin {
	if ( defined( $ENV{REDIS_SERVER_BIN} ) && -x $ENV{REDIS_SERVER_BIN} ) {
		return $ENV{REDIS_SERVER_BIN};
	}
	foreach my $dir ( split( /:/, ( defined( $ENV{PATH} ) ? $ENV{PATH} : '' ) ) ) {
		my $path = $dir . '/redis-server';
		if ( -x $path ) {
			return $path;
		}
	}
	return undef;
}

# true if a live redis-server could be spun up
sub available {
	return defined( _find_bin() ) ? 1 : 0;
}

# a free loopback TCP port... a small race between the probe and redis binding
# it, negligible for an opt-in test
sub _free_port {
	my $probe = IO::Socket::INET->new(
		'Listen'    => 5,
		'LocalAddr' => '127.0.0.1',
		'LocalPort' => 0,
		'ReuseAddr' => 1,
	);
	if ( !defined($probe) ) {
		return undef;
	}
	my $port = $probe->sockport;
	$probe->close;
	return $port;
}

# Spawns a redis-server on a free port with persistence off, waits for it to
# answer a ping, and returns the guard object (server via ->server). Returns
# undef if there is no redis-server or it would not come up in time. The caller
# must have loaded Redis::Fast already, this uses it to poll for readiness.
sub start {
	my ($class) = @_;

	my $bin = _find_bin();
	if ( !defined($bin) ) {
		return undef;
	}

	my $port = _free_port();
	if ( !defined($port) ) {
		return undef;
	}

	my $tmp = File::Temp->newdir( 'CLEANUP' => 1 );

	my $pid = fork();
	if ( !defined($pid) ) {
		return undef;
	}
	if ( !$pid ) {
		# child... redis-server, TCP on the free port, nothing written to disk
		open( STDOUT, '>', "$tmp/redis.out" ) or exit(127);
		open( STDERR, '>&', \*STDOUT )         or exit(127);
		exec(
			$bin,          '--port', $port, '--bind', '127.0.0.1',
			'--save',      '',       '--appendonly', 'no',
			'--protected-mode', 'no', '--dir', "$tmp", '--daemonize', 'no'
		);
		exit(127);
	} ## end if ( !$pid )

	my $self = bless { 'pid' => $pid, 'port' => $port, 'tmp' => $tmp }, $class;

	# poll for readiness, up to ~5s
	my $up = 0;
	for ( 1 .. 50 ) {
		eval {
			my $r = Redis::Fast->new( 'server' => '127.0.0.1:' . $port, 'reconnect' => 0, 'cnx_timeout' => 1 );
			$up = $r->ping ? 1 : 0;
		};
		last if $up;
		Time::HiRes::sleep(0.1);
	}
	if ( !$up ) {
		$self->stop;
		return undef;
	}

	return $self;
} ## end sub start

sub server {
	my ($self) = @_;
	return '127.0.0.1:' . $self->{port};
}

sub port {
	my ($self) = @_;
	return $self->{port};
}

sub stop {
	my ($self) = @_;
	if ( $self->{pid} ) {
		kill( 'TERM', $self->{pid} );
		# reap promptly, escalating to KILL if it dawdles, so nothing lingers
		# even down the DESTROY path at global destruction where waitpid is
		# unreliable... the KILL syscall still fires and the OS reaps it
		my $reaped = 0;
		for ( 1 .. 10 ) {
			if ( waitpid( $self->{pid}, POSIX::WNOHANG() ) == $self->{pid} ) {
				$reaped = 1;
				last;
			}
			Time::HiRes::sleep(0.1);
		}
		if ( !$reaped ) {
			kill( 'KILL', $self->{pid} );
			waitpid( $self->{pid}, 0 );
		}
		delete( $self->{pid} );
	} ## end if ( $self->{pid} )
	return;
} ## end sub stop

sub DESTROY {
	my ($self) = @_;
	$self->stop;
	return;
}

1;
