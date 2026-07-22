#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );

# the CLI talking to a live manager socket... a real POE::Component::Server::
# JSONUnix server stands in for the manager, the Neti gate on and a
# command_perms-style policy in force, and the actual baphomet CLI drives it
# through App::Baphomet::App's manager_call. this proves the whole chain the
# rewrite rides... BlockingClient, the authenticate handshake, and the
# per-command gating... rather than any of it in isolation.
#
# POE is never loaded in this, the parent... its kernel is a per-process
# singleton, and a copy inherited across the fork would wedge the child's
# server. so the parent drives only the blocking client (raw sockets, no
# event loop) and the server child loads POE for it's self after the fork

BEGIN {
	eval { require App::Cmd::Tester; 1 } or plan skip_all => 'App::Cmd::Tester not available';

	# probe the server dist in a throwaway child, so requiring it never
	# initializes POE::Kernel here in the parent
	my $probe = fork();
	if ( !defined($probe) ) {
		plan skip_all => 'fork failed';
	}
	if ( !$probe ) {
		my $have = eval { require POE::Component::Server::JSONUnix; 1 } ? 0 : 1;
		exit $have;
	}
	waitpid( $probe, 0 );
	if ( $? != 0 ) {
		plan skip_all => 'POE::Component::Server::JSONUnix not available';
	}
}

use App::Cmd::Tester;
use App::Baphomet::App ();
use JSON::MaybeXS      ();

my $dir  = tempdir( CLEANUP => 1 );
my $sock = $dir . '/manager.sock';

# canned answers the stand-in manager hands back for the read commands
my $banished_answer = {
	'kurs' => {
		'sshd' => { 'banned' => [ '1.2.3.4', '5.6.7.8' ], 'expires' => {}, 'pending' => [] },
		'smtp' => { 'banned' => [],                        'expires' => {}, 'pending' => ['9.9.9.9'] },
	},
};
my $status_answer = { 'pid' => 4242, 'uptime' => 5, 'gallas' => {} };

# the stand-in manager runs in its own process, as the real one does, so the
# blocking client is never sharing an event loop with the server it calls
my $server_pid = fork();
if ( !defined($server_pid) ) {
	plan skip_all => 'fork failed';
}
if ( !$server_pid ) {
	require POE::Kernel;
	require POE::Component::Server::JSONUnix;
	POE::Component::Server::JSONUnix->spawn(
		'socket_path'   => $sock,
		'alias'         => 'stand_in_manager',
		'auth_required' => 1,
		'auth_temp_dir' => $dir,
		# the Neti gate... the caller (this test's own uid) is let through
		# everything by the baseline, but stop is denied outright, exactly the
		# shape _neti_permissions builds from command_perms
		'permissions' => {
			'default'  => 'deny',
			'commands' => {
				'%DEFAULT%' => { 'users' => [ 0, $< ] },
				'stop'      => 'deny',
			},
		},
		'commands' => {
			'banished' => sub { return $banished_answer; },
			'status'   => sub { return $status_answer; },
			'stop'     => sub { return { 'stopping' => 1, 'pid' => $$ }; },
		},
	);
	POE::Kernel->run;
	exit 0;
} ## end if ( !$server_pid )

# wait for the socket to appear before driving anything at it
my $ready;
foreach my $try ( 1 .. 50 ) {
	if ( -S $sock ) {
		$ready = 1;
		last;
	}
	select( undef, undef, undef, 0.1 );
}

sub reap_server {
	kill( 'TERM', $server_pid );
	waitpid( $server_pid, 0 );
	return;
}

if ( !$ready ) {
	reap_server();
	plan skip_all => 'the stand-in manager socket never came up';
}

# a permitted read command... the CLI authenticates through the Neti gate and
# gets the answer, proving BlockingClient + authenticate + call end to end
my $result = App::Cmd::Tester->test_app( 'App::Baphomet::App', [ '--socket', $sock, 'status' ] );
is( $result->exit_code, 0, 'status against a live authed manager exits 0' ) || diag( $result->error );
my $status = eval { JSON::MaybeXS::decode_json( $result->stdout ) };
is( $status->{pid}, 4242, 'status carries the manager answer back through the gate' );

# banished too, and its --ip paring works on the manager's answer
$result = App::Cmd::Tester->test_app( 'App::Baphomet::App', [ '--socket', $sock, 'banished' ] );
is( $result->exit_code, 0, 'banished exits 0' ) || diag( $result->error );
my $banished = eval { JSON::MaybeXS::decode_json( $result->stdout ) };
is_deeply( $banished->{kurs}{sshd}{banned}, [ '1.2.3.4', '5.6.7.8' ], 'banished carries the held list' );

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App', [ '--socket', $sock, 'banished', '--ip', '9.9.9.9' ] );
$banished = eval { JSON::MaybeXS::decode_json( $result->stdout ) };
is( $banished->{ip}, '9.9.9.9', '--ip pares to the one address' );
is( $banished->{kurs}{smtp}{pending}, 1, 'and finds it pending on smtp' );
ok( !defined( $banished->{kurs}{sshd} ), 'the kur not holding it is dropped' );

# a denied command... the gate refuses stop, so the CLI errors rather than
# stopping, proving the per-command policy actually bites through the real
# client
$result = App::Cmd::Tester->test_app( 'App::Baphomet::App', [ '--socket', $sock, 'stop', '--no-wait' ] );
isnt( $result->exit_code, 0, 'a command the Neti gate denies exits non-zero' );
like( $result->error, qr/refused|denied/, 'and the error names the refusal' );

reap_server();

done_testing;
