package App::Baphomet;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use POE                              qw( Wheel::Run );
use POE::Component::Server::JSONUnix ();
use Ereshkigal::Client               ();
use App::Baphomet::Config            qw( load_config check_kur_def kur_split watcher_rules );
use App::Baphomet::Rules             ();
use App::Baphomet::LogDrek           qw( log_drek );

=head1 NAME

App::Baphomet - Log watcher that banishes misbehaving IPs to Kur via Ereshkigal.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet;

    my $baphomet = App::Baphomet->new( config => '/usr/local/etc/baphomet/config.toml' );

    $baphomet->start_server;

Baphomet is the accuser half of a fail2ban style split, with L<Ereshkigal>
being the punisher half. It reads logs, matches lines against rules, and
forwards the IPs of repeat offenders to the Ereshkigal manager socket to be
banned.

Structurally it mirrors Ereshkigal. The manager, this module, watches no
logs itself... it spawns one L<App::Baphomet::Galla> worker per hash under
C<kur> in the config, supervises them, restarting any that die, and serves
up status info on a unix socket, by default C</var/run/baphomet/socket>,
speaking the newline delimited JSON protocol of
L<POE::Component::Server::JSONUnix>. The gallas do the actual work, each
following the logs of its kur and talking to Ereshkigal directly.

The kur names used in the config are what ban requests get targeted at on
the Ereshkigal side, so they should match kurs over there.

=head1 CONFIG FILE

The config file is TOML, by default
C</usr/local/etc/baphomet/config.toml>. See L<App::Baphomet::Config> for
the settings and the kur/watcher format, and L<App::Baphomet::Rules> for
the rules the watchers reference.

Example...

    ereshkigal_socket = "/var/run/ereshkigal/socket"

    # the base kur config for sshd
    [kur.sshd]
    max_score=5
    ban_time=300
    # read authlog
    # the key for the hash under sshd is just a freeform name
    [kur.sshd.authlog]
    log=/var/log/auth.log
    parser=bsd_syslog
    rule=syslog/sshd

=head1 METHODS

=head2 new

Initiates the object. All errors are considered fatal, meaning if new fails
it will die.

    - config :: Path to the TOML config file.
        Default :: /usr/local/etc/baphomet/config.toml

Every kur def is checked and every rule referenced by a watcher is loaded,
compiled, and has its embedded tests ran, so a broken config or rule is
fatal here rather than something the gallas trip over one by one after
being spawned.

=cut

sub new {
	my ( $blank, %opts ) = @_;

	my $self = {
		perror        => undef,
		error         => undef,
		errorLine     => undef,
		errorFilename => undef,
		errorString   => "",
		errorExtra    => {
			# the installed Error::Helper reads all_fatal where its POD says
			# all_errors_fatal... both are set so the contract holds either way
			all_errors_fatal => 1,
			all_fatal        => 1,
			flags            => {
				1 => 'configLoadFailed',
				2 => 'invalidKurDef',
				3 => 'rulesLoadFailed',
				4 => 'runBaseDirError',
				5 => 'badSocketGroup',
			},
			fatal_flags      => {},
			perror_not_fatal => 0,
		},
		config         => '/usr/local/etc/baphomet/config.toml',
		gallas         => {},
		wheel_to_galla => {},
		pid_to_galla   => {},
		shutting_down  => 0,
		started        => undef,
		server         => undef,
	};
	bless( $self, ref($blank) || $blank );

	if ( defined( $opts{config} ) ) {
		$self->{config} = $opts{config};
	}

	my $config;
	eval { $config = load_config( $self->{config} ); };
	if ($@) {
		$self->{perror}      = 1;
		$self->{error}       = 1;
		$self->{errorString} = $@;
		$self->warn;
	}
	foreach my $item (
		'run_base_dir',  'rules_dir',    'ereshkigal_socket', 'galla_bin',
		'timeout',       'socket_group', 'enable_auth',       'authed_users',
		'authed_groups', 'auth_temp_dir'
		)
	{
		$self->{$item} = $config->{$item};
	}
	$self->{socket_mode} = oct( '' . $config->{socket_mode} );

	# default to the default group of the root user... wheel on the BSDs, root on Linux
	if ( !defined( $self->{socket_group} ) ) {
		$self->{socket_gid} = ( getpwnam('root') )[3];
	} else {
		$self->{socket_gid} = getgrnam( $self->{socket_group} );
	}
	if ( !defined( $self->{socket_gid} ) ) {
		$self->{perror} = 1;
		$self->{error}  = 5;
		$self->{errorString}
			= 'Failed to resolve the socket group'
			. ( defined( $self->{socket_group} ) ? ', "' . $self->{socket_group} . '",' : ' for the root user' )
			. ' to a GID';
		$self->warn;
	}

	# check every kur def and load every referenced rule now, so a broken
	# config fails here instead of after the gallas have been spawned
	my $rules;
	eval { $rules = App::Baphomet::Rules->new( 'rules_dir' => $config->{rules_dir} ); };
	if ($@) {
		$self->{perror}      = 1;
		$self->{error}       = 3;
		$self->{errorString} = $@;
		$self->warn;
	}

	foreach my $name ( sort( keys( %{ $config->{kur} } ) ) ) {
		my $def = $config->{kur}{$name};

		eval { check_kur_def( $name, $def ); };
		if ($@) {
			$self->{perror}      = 1;
			$self->{error}       = 2;
			$self->{errorString} = $@;
			$self->warn;
		}

		my ( undef, $watchers ) = kur_split($def);
		foreach my $watcher_name ( sort( keys( %{$watchers} ) ) ) {
			foreach my $rule ( watcher_rules( $watchers->{$watcher_name} ) ) {
				eval { $rules->load($rule); };
				if ($@) {
					$self->{perror} = 1;
					$self->{error}  = 3;
					$self->{errorString}
						= 'Failed to load the rule "'
						. $rule
						. '" of the watcher "'
						. $watcher_name
						. '" of the kur "'
						. $name . '"... '
						. $@;
					$self->warn;
				} ## end if ($@)
			} ## end foreach my $rule ( watcher_rules( $watchers->{$watcher_name...}))
		} ## end foreach my $watcher_name ( sort( keys( %{$watchers...})))

		$self->{gallas}{$name} = {
			'wheel'    => undef,
			'pid'      => undef,
			'restarts' => 0,
			'delay'    => 1,
			'enabled'  => 1,
			'spawned'  => undef,
		};
	} ## end foreach my $name ( sort( keys( %{ $config->{kur...}})))

	# create these here rather than in start_server as the PID file gets
	# written prior to start_server being called
	foreach my $dir ( $self->{run_base_dir}, $self->{run_base_dir} . '/galla' ) {
		if ( !-e $dir ) {
			# a failure here surfaces via the usability check below
			mkdir($dir);
		}
		# sockets and PID files land under here, so it must be traversable too
		if ( !-d $dir || !-r $dir || !-w $dir || !-x $dir ) {
			$self->{perror}      = 1;
			$self->{error}       = 4;
			$self->{errorString} = 'The dir "' . $dir . '" is not a directory or is not read/write/traversable';
			$self->warn;
		}
	} ## end foreach my $dir ( $self->{run_base_dir}, $self->...)

	return $self;
} ## end sub new

=head2 socket_path

Returns the path of the manager unix socket.

    my $socket_path = $baphomet->socket_path;

=cut

sub socket_path {
	my ($self) = @_;

	return $self->{run_base_dir} . '/socket';
}

=head2 pid_path

Returns the path of the manager PID file.

    my $pid_path = $baphomet->pid_path;

=cut

sub pid_path {
	my ($self) = @_;

	return $self->{run_base_dir} . '/pid';
}

=head2 galla_socket_path

Returns the path of the unix socket for the specified galla.

    my $galla_socket_path = $baphomet->galla_socket_path($name);

=cut

sub galla_socket_path {
	my ( $self, $name ) = @_;

	return $self->{run_base_dir} . '/galla/' . $name . '.sock';
}

=head2 start_server

Starts the manager. Spawns a galla for each kur, each supervised and
restarted with a backoff should it die, and brings up the
L<POE::Component::Server::JSONUnix> server on the manager socket, then
calls $poe_kernel->run.

This should not be expected to return till the manager is told to stop.

After binding, the manager socket is chowned to the configured group and
chmoded to the configured mode.

The JSON commands handled are as below.

    - status :: Manager status... uptime and galla list with up/down state.

    - status_all :: The above plus each galla's full status block.

    - status_galla :: Full status of the galla args.name.

    - accused :: The IPs each galla is counting but has not yet
          banished... every galla, or just args.name if given. Per IP
          the live hit count and the epochs of the first and last hit.

    - marked :: The live marks each galla holds... every galla, or just
          args.name if given. Per mark name a hash of the branded keys
          with their expiries and stored values.

    - watching :: What each galla watches... every galla, or just
          args.name if given. Per watcher the log specs and globs it is
          set to watch and the concrete files it is following now, or the
          journalctl matches for a journal watcher.

    - stop :: Stop all the gallas and then the manager. Returns
          C<stopping> and the manager's C<pid>, so the caller can wait for
          the process to actually die before it returns... a restart's
          start would otherwise race the still-present PID file.

=cut

sub start_server {
	my ($self) = @_;

	$self->errorblank;

	POE::Session->create(
		object_states => [
			$self => {
				'_start'        => '_poe_start',
				'spawn_galla'   => '_poe_spawn_galla',
				'restart_galla' => '_poe_restart_galla',
				'galla_stdout'  => '_poe_galla_stdout',
				'galla_stderr'  => '_poe_galla_stderr',
				'galla_reaped'  => '_poe_galla_reaped',
				'stop_all'      => '_poe_stop_all',
				'stop_escalate' => '_poe_stop_escalate',
			},
		],
	);

	my $server = POE::Component::Server::JSONUnix->spawn(
		'socket_path'   => $self->socket_path,
		'socket_mode'   => $self->{socket_mode},
		'alias'         => 'baphomet_server',
		'auth_required' => $self->{enable_auth} ? 1 : 0,
		defined( $self->{auth_temp_dir} ) ? ( 'auth_temp_dir' => $self->{auth_temp_dir} ) : (),
		'on_error' => sub {
			my ( $operation, $errnum, $errstr ) = @_;
			log_drek( 'err', 'socket error during ' . $operation . '... ' . $errstr . ' (' . $errnum . ')' );
		},
		'commands' => {
			'status' => sub {
				my ( undef, undef, $ctx ) = @_;
				$self->_authorize($ctx);
				return $self->_cmd_status;
			},
			'status_all' => sub {
				my ( undef, undef, $ctx ) = @_;
				$self->_authorize($ctx);
				return $self->_cmd_status_all;
			},
			'status_galla' => sub {
				my ( undef, $request, $ctx ) = @_;
				$self->_authorize($ctx);
				return $self->_cmd_status_galla($request);
			},
			'accused' => sub {
				my ( undef, $request, $ctx ) = @_;
				$self->_authorize($ctx);
				return $self->_cmd_accused($request);
			},
			'marked' => sub {
				my ( undef, $request, $ctx ) = @_;
				$self->_authorize($ctx);
				return $self->_cmd_marked($request);
			},
			'watching' => sub {
				my ( undef, $request, $ctx ) = @_;
				$self->_authorize($ctx);
				return $self->_cmd_watching($request);
			},
			'stop' => sub {
				my ( undef, undef, $ctx ) = @_;
				$self->_authorize($ctx);
				log_drek( 'info', 'stop requested' );
				$poe_kernel->post( 'baphomet_manager', 'stop_all' );
				# the current session is the JSONUnix server session, so this
				# fires its shutdown state after the response has had time to flush
				$poe_kernel->delay( 'shutdown', 1 );
				# the PID rides back so the stop command can wait for this
				# process to actually die before returning, else a restart's
				# start races the still-present PID file
				return { 'stopping' => 1, 'pid' => $$ };
			},
		},
	);
	$self->{server} = $server;

	# group ownership gates who may drive the manager
	if ( !chown( $>, $self->{socket_gid}, $self->socket_path ) ) {
		log_drek( 'err', 'chown of "' . $self->socket_path . '" to GID ' . $self->{socket_gid} . ' failed... ' . $! );
	}

	$self->{started} = time;

	log_drek( 'info',
			  'started... socket='
			. $self->socket_path
			. ' auth='
			. ( $self->{enable_auth} ? 'on' : 'off' )
			. ' gallas='
			. join( ',', sort( keys( %{ $self->{gallas} } ) ) ) );

	$poe_kernel->run;

	log_drek( 'info', 'stopped' );

	return;
} ## end sub start_server

# checks if the user is in the passed users list or a member of one of the
# passed groups... membership is resolved at request time so user/group
# database changes apply with out a restart
sub _user_in_lists {
	my ( $self, $username, $uid, $users, $groups ) = @_;

	foreach my $user ( @{$users} ) {
		if ( $user eq $username ) {
			return 1;
		}
	}

	# the user's primary group
	my $primary_gid = ( getpwuid($uid) )[3];
	my $primary_group;
	if ( defined($primary_gid) ) {
		$primary_group = getgrgid($primary_gid);
	}

	foreach my $group ( @{$groups} ) {
		if ( defined($primary_group) && $group eq $primary_group ) {
			return 1;
		}
		# unknown groups just never match rather than erroring
		my $members = ( getgrnam($group) )[3];
		if ( defined($members) ) {
			foreach my $member ( split( /\s+/, $members ) ) {
				if ( $member eq $username ) {
					return 1;
				}
			}
		}
	} ## end foreach my $group ( @{$groups} )

	return 0;
} ## end sub _user_in_lists

# the Neti gate... authorizes the authenticated user behind the context,
# dieing if they are not allowed... a no-op when enable_auth is off. UID 0
# always passes, as does any user in authed_users or a authed_groups
sub _authorize {
	my ( $self, $ctx ) = @_;

	if ( !$self->{enable_auth} ) {
		return;
	}

	my $uid      = $ctx->uid;
	my $username = $ctx->username;
	if ( !defined($uid) ) {
		# should be unreachable as JSONUnix gates unauthed commands first
		die('authentication required');
	}
	if ( $uid == 0 ) {
		return;
	}
	$username = '' if !defined($username);

	if ( $self->_user_in_lists( $username, $uid, $self->{authed_users}, $self->{authed_groups} ) ) {
		return;
	}

	die( 'The user "' . $username . '" is not permitted past the Neti gate' );
} ## end sub _authorize

sub _galla_client {
	my ( $self, $name ) = @_;

	return Ereshkigal::Client->new(
		'socket'  => $self->galla_socket_path($name),
		'timeout' => $self->{timeout},
	);
}

sub _build_galla_cmd {
	my ( $self, $name ) = @_;

	return ( $self->{galla_bin}, '--foreground', '--name', $name, '--config', $self->{config} );
}

#
# POE states for the manager session
#

sub _poe_start {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	$kernel->alias_set('baphomet_manager');

	foreach my $name ( sort( keys( %{ $self->{gallas} } ) ) ) {
		$kernel->yield( 'spawn_galla', $name );
	}

	return;
} ## end sub _poe_start

sub _poe_spawn_galla {
	my ( $self, $kernel, $name ) = @_[ OBJECT, KERNEL, ARG0 ];

	my $entry = $self->{gallas}{$name};
	if ( !defined($entry) || !$entry->{enabled} || defined( $entry->{wheel} ) || $self->{shutting_down} ) {
		return;
	}

	my @cmd = $self->_build_galla_cmd($name);

	my $wheel = POE::Wheel::Run->new(
		'Program'     => \@cmd,
		'StdoutEvent' => 'galla_stdout',
		'StderrEvent' => 'galla_stderr',
	);

	$kernel->sig_child( $wheel->PID, 'galla_reaped' );

	$entry->{wheel}   = $wheel;
	$entry->{pid}     = $wheel->PID;
	$entry->{spawned} = time;

	$self->{wheel_to_galla}{ $wheel->ID } = $name;
	$self->{pid_to_galla}{ $wheel->PID }  = $name;

	log_drek( 'info', 'spawned galla "' . $name . '" as PID ' . $wheel->PID . '... ' . join( ' ', @cmd ) );

	return;
} ## end sub _poe_spawn_galla

sub _poe_restart_galla {
	my ( $self, $kernel, $name ) = @_[ OBJECT, KERNEL, ARG0 ];

	$kernel->yield( 'spawn_galla', $name );

	return;
}

sub _poe_galla_stdout {
	my ( $self, $line, $wheel_id ) = @_[ OBJECT, ARG0, ARG1 ];

	my $name = $self->{wheel_to_galla}{$wheel_id};
	$name = 'unknown' if !defined($name);
	log_drek( 'info', 'galla "' . $name . '" stdout... ' . $line );

	return;
}

sub _poe_galla_stderr {
	my ( $self, $line, $wheel_id ) = @_[ OBJECT, ARG0, ARG1 ];

	my $name = $self->{wheel_to_galla}{$wheel_id};
	$name = 'unknown' if !defined($name);
	log_drek( 'err', 'galla "' . $name . '" stderr... ' . $line );

	return;
}

sub _poe_galla_reaped {
	my ( $self, $kernel, $pid, $exit ) = @_[ OBJECT, KERNEL, ARG1, ARG2 ];

	my $name = delete( $self->{pid_to_galla}{$pid} );
	if ( !defined($name) ) {
		return;
	}

	my $entry = $self->{gallas}{$name};
	if ( defined($entry) && defined( $entry->{wheel} ) ) {
		delete( $self->{wheel_to_galla}{ $entry->{wheel}->ID } );
		$entry->{wheel} = undef;
		$entry->{pid}   = undef;
	}

	log_drek( 'info', 'galla "' . $name . '" PID ' . $pid . ' exited with ' . ( $exit >> 8 ) );

	if ( $self->{shutting_down} || !defined($entry) || !$entry->{enabled} ) {
		return;
	}

	# it ran long enough to be considered to have started fine, so reset the backoff
	if ( defined( $entry->{spawned} ) && ( time - $entry->{spawned} ) > 60 ) {
		$entry->{delay} = 1;
	}

	my $delay = $entry->{delay};
	$entry->{delay} = $delay * 2 > 60 ? 60 : $delay * 2;
	$entry->{restarts}++;

	log_drek( 'err', 'galla "' . $name . '" died, restarting in ' . $delay . ' seconds' );

	$kernel->delay_set( 'restart_galla', $delay, $name );

	return;
} ## end sub _poe_galla_reaped

sub _poe_stop_all {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	$self->{shutting_down} = 1;

	foreach my $name ( sort( keys( %{ $self->{gallas} } ) ) ) {
		my $entry = $self->{gallas}{$name};
		if ( !defined( $entry->{pid} ) ) {
			next;
		}
		eval { $self->_galla_client($name)->call_ok('stop'); };
		if ($@) {
			log_drek( 'err', 'stopping galla "' . $name . '" via it\'s socket failed, sending TERM... ' . $@ );
			if ( defined( $entry->{wheel} ) ) {
				$entry->{wheel}->kill('TERM');
			}
		}
	} ## end foreach my $name ( sort( keys( %{ $self->{gallas...}})))

	$kernel->alarm_remove_all;
	$kernel->alias_remove('baphomet_manager');

	# a galla that acknowledged the stop but never exits would leave the
	# manager waiting on its sig_child forever... after a grace period any
	# still-running galla is TERMed. set after the alarm sweep so it survives
	$kernel->delay( 'stop_escalate', $self->{timeout} );

	return;
} ## end sub _poe_stop_all

# the stop escalation... TERM whoever is still alive after the grace period
sub _poe_stop_escalate {
	my ($self) = @_[OBJECT];

	foreach my $name ( sort( keys( %{ $self->{gallas} } ) ) ) {
		my $entry = $self->{gallas}{$name};
		if ( !defined( $entry->{pid} ) || !defined( $entry->{wheel} ) ) {
			next;
		}
		log_drek( 'err', 'galla "' . $name . '" is still running past the stop grace period, sending TERM' );
		$entry->{wheel}->kill('TERM');
	}

	return;
} ## end sub _poe_stop_escalate

#
# JSONUnix command handlers
#

sub _galla_summary {
	my ($self) = @_;

	my $gallas = {};
	foreach my $name ( keys( %{ $self->{gallas} } ) ) {
		my $entry = $self->{gallas}{$name};
		$gallas->{$name} = {
			'running'  => defined( $entry->{pid} ) ? 1 : 0,
			'pid'      => $entry->{pid},
			'restarts' => $entry->{restarts},
			'enabled'  => $entry->{enabled} ? 1 : 0,
		};
	}

	return $gallas;
} ## end sub _galla_summary

sub _cmd_status {
	my ($self) = @_;

	return {
		'pid'    => $$,
		'uptime' => time - $self->{started},
		'config' => $self->{config},
		'gallas' => $self->_galla_summary,
	};
} ## end sub _cmd_status

sub _cmd_status_all {
	my ($self) = @_;

	my $status = $self->_cmd_status;

	foreach my $name ( keys( %{ $status->{gallas} } ) ) {
		if ( $status->{gallas}{$name}{running} ) {
			my $galla_status;
			eval { $galla_status = $self->_galla_client($name)->call_ok('status'); };
			if ($@) {
				$status->{gallas}{$name}{error} = $@;
			} else {
				$status->{gallas}{$name}{status} = $galla_status;
			}
		}
	} ## end foreach my $name ( keys( %{ $status->{gallas} }...))

	return $status;
} ## end sub _cmd_status_all

sub _cmd_status_galla {
	my ( $self, $request ) = @_;

	my $args = $request->{args};
	if ( !defined($args) || !defined( $args->{name} ) ) {
		die('args.name must be the name of a galla');
	}
	my $name = $args->{name};

	my $entry = $self->{gallas}{$name};
	if ( !defined($entry) ) {
		die( 'No such galla, "' . $name . '"' );
	}

	my $status = {
		'name'     => $name,
		'running'  => defined( $entry->{pid} ) ? 1 : 0,
		'pid'      => $entry->{pid},
		'restarts' => $entry->{restarts},
		'enabled'  => $entry->{enabled} ? 1 : 0,
	};

	if ( $status->{running} ) {
		# trapped like the other fan-out handlers, so a dead-but-unreaped
		# galla yields a partial status with a error rather than a raw die
		my $galla_status;
		eval { $galla_status = $self->_galla_client($name)->call_ok('status'); };
		if ($@) {
			$status->{error} = $@;
		} else {
			$status->{status} = $galla_status;
		}
	}

	return $status;
} ## end sub _cmd_status_galla

# the shared shape of the per-galla fan-out commands... one galla when
# args.name says so, else all, each asked over its socket with errors held
# per galla so one dead worker never takes the whole reply down
sub _cmd_fanout {
	my ( $self, $request, $command ) = @_;

	my $args = defined( $request->{args} ) ? $request->{args} : {};

	my @names;
	if ( defined( $args->{name} ) ) {
		if ( !defined( $self->{gallas}{ $args->{name} } ) ) {
			die( 'No such galla, "' . $args->{name} . '"' );
		}
		@names = ( $args->{name} );
	} else {
		@names = sort( keys( %{ $self->{gallas} } ) );
	}

	my $gallas = {};
	foreach my $name (@names) {
		if ( !defined( $self->{gallas}{$name}{pid} ) ) {
			$gallas->{$name} = { 'error' => 'not running' };
			next;
		}
		my $result;
		eval { $result = $self->_galla_client($name)->call_ok($command); };
		if ($@) {
			$gallas->{$name} = { 'error' => $@ };
		} else {
			$gallas->{$name} = $result;
		}
	} ## end foreach my $name (@names)

	return { 'gallas' => $gallas };
} ## end sub _cmd_fanout

sub _cmd_accused {
	my ( $self, $request ) = @_;

	return $self->_cmd_fanout( $request, 'accused' );
}

sub _cmd_marked {
	my ( $self, $request ) = @_;

	return $self->_cmd_fanout( $request, 'marked' );
}

sub _cmd_watching {
	my ( $self, $request ) = @_;

	return $self->_cmd_fanout( $request, 'watching' );
}

=head1 ERRORS CODES / ERROR FLAGS

Error handling is provided by L<Error::Helper>. All errors
are considered fatal.

=head2 1, configLoadFailed

Failed to read or parse the config file.

=head2 2, invalidKurDef

A kur def in the config is invalid. See L<App::Baphomet::Config>.

=head2 3, rulesLoadFailed

Failed to load a rule referenced by a watcher... no such rule, unparsable,
uncompilable, or its embedded tests failing.

=head2 4, runBaseDirError

The run base dir or the galla dir under it could not be created or is not
read/writable.

=head2 5, badSocketGroup

Failed to resolve the socket group to a GID.

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-app-baphomet at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=App-Baphomet>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc App::Baphomet

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=App-Baphomet>

=item * Search CPAN

L<https://metacpan.org/release/App-Baphomet>

=back

=head1 ACKNOWLEDGEMENTS

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991, or (at your
  option) any later version, matching fail2ban, which parts of this
  project, most notably the shipped rules, are derived from.

=cut

1;    # End of App::Baphomet
