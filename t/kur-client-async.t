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
	eval { require POE::Component::Server::JSONUnix::Client; };
	if ($@) {
		plan skip_all => 'POE::Component::Server::JSONUnix::Client not available';
	}
}

use POE;
use POE::Component::Server::JSONUnix ();
use App::Baphomet::Galla             ();

# the async ban path... a galla under POE bans through the persistent kur
# client, a down Ereshkigal pends for the sweeper, and a manager demanding
# authentication gets the ownership challenge completed and the ban resent.
# short tempdir, as AF_UNIX paths are bound at 104 chars

my $dir = tempdir( 'bphXXXXXX', TMPDIR => 1, CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run', $dir . '/cache', $dir . '/cache2' );

open( my $fh, '>', $dir . '/rules/syslog/sshd.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
EOR
close($fh);

# distinct kur names, as each galla's kur client carries a per-name POE
# alias... two same-named gallas only ever coexist in a test process
sub write_config {
	my ( $path, $cache, $socket, $kur ) = @_;
	open( my $config_fh, '>', $path ) || die($!);
	print $config_fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/$cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/$socket"
timeout = 5

[kur.$kur]
ban_time = 300

[kur.$kur.authlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"
EOC
	close($config_fh);
	return;
}
write_config( $dir . '/config.toml',  'cache',  'kur.sock',  'sshd' );
write_config( $dir . '/config2.toml', 'cache2', 'kur2.sock', 'sshd-authed' );
open( $fh, '>', $dir . '/log' ) || die($!);
close($fh);

# the fake Ereshkigal managers... one open, one demanding the challenge
my @bans;
POE::Component::Server::JSONUnix->spawn(
	'socket_path' => $dir . '/kur.sock',
	'alias'       => 'fake_kur',
	'commands'    => {
		'ban' => sub {
			my ( undef, $request ) = @_;
			push( @bans, $request->{args} );
			return { 'banned' => scalar( @{ $request->{args}{ips} } ) };
		},
	},
);
my @authed_bans;
POE::Component::Server::JSONUnix->spawn(
	'socket_path'   => $dir . '/kur2.sock',
	'alias'         => 'fake_kur_authed',
	'auth_required' => 1,
	'auth_temp_dir' => $dir,
	'commands'      => {
		'ban' => sub {
			my ( undef, $request, $ctx ) = @_;
			push( @authed_bans, { 'args' => $request->{args}, 'uid' => $ctx->uid } );
			return { 'banned' => scalar( @{ $request->{args}{ips} } ) };
		},
	},
);

my $galla = App::Baphomet::Galla->new( 'config' => $dir . '/config.toml', 'name' => 'sshd' );
ok( defined($galla), 'galla built' );
$galla->_spawn_kur_client;
ok( defined( $galla->{kur_client} ), 'kur client spawned' );

my $galla2 = App::Baphomet::Galla->new( 'config' => $dir . '/config2.toml', 'name' => 'sshd-authed' );
$galla2->_spawn_kur_client;

POE::Session->create(
	'inline_states' => {
		'_start' => sub {
			$galla->_ban_ip( '9.9.9.9', 300, undef, undef );
			# async... the judgment tail has not run yet at initiation
			is( $galla->{stats}{bans}, 0, 'initiation returns before the ban lands' );
			ok( $galla->{inflight_bans}{'ip:9.9.9.9'}, 'the ban is marked in flight' );
			# a re-crossing while in flight is absorbed
			$galla->_ban_ip( '9.9.9.9', 300, undef, undef );
			$_[KERNEL]->delay( 'landed', 1 );
			return;
		},
		'landed' => sub {
			is( scalar(@bans),         1,   'the fake manager got exactly one ban request' );
			is( $bans[0]{ips}[0],      '9.9.9.9', 'carrying the offender' );
			is( $bans[0]{kur},         'sshd',    'on the galla\'s kur' );
			is( $galla->{stats}{bans}, 1,   'the delivered tail ran from the answer' );
			ok( !%{ $galla->{inflight_bans} },  'nothing left in flight' );
			ok( !%{ $galla->{pending_bans} },   'nothing pending' );

			# the authed manager... the first call is refused, the client
			# completes the ownership challenge, and the resend lands
			$galla2->_ban_ip( '7.7.7.7', 300, undef, undef );
			$_[KERNEL]->delay( 'authed_landed', 1 );
			return;
		},
		'authed_landed' => sub {
			is( scalar(@authed_bans),      1,         'the challenge-demanding manager got the ban' );
			is( $authed_bans[0]{args}{ips}[0], '7.7.7.7', 'carrying the offender' );
			is( $authed_bans[0]{uid},      $>,        'as the authenticated uid' );
			is( $galla2->{stats}{bans},    1,         'delivered on galla2' );

			# a manager gone away... the ban errors and pends for the sweep
			$_[KERNEL]->post( 'fake_kur', 'shutdown' );
			$_[KERNEL]->delay( 'kur_gone', 1 );
			return;
		},
		'kur_gone' => sub {
			$galla->_ban_ip( '8.8.8.8', 300, undef, undef );
			$_[KERNEL]->delay( 'pended', 1 );
			return;
		},
		'pended' => sub {
			is( $galla->{pending_bans}{'8.8.8.8'}, 300, 'the unreachable ban pends for the sweeper' );
			is( $galla->{stats}{ban_errors},       1,   'and ticked ban_errors' );
			ok( !%{ $galla->{inflight_bans} }, 'nothing left in flight' );

			$galla->{kur_client}->shutdown;
			$galla2->{kur_client}->shutdown;
			$_[KERNEL]->post( 'fake_kur_authed', 'shutdown' );
			return;
		},
	},
);

POE::Kernel->run;

done_testing;
