package App::Baphomet;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use POE                                              qw( Wheel::Run );
use POE::Component::Server::JSONUnix                  ();
use POE::Component::Server::JSONUnix::Client          ();
use POE::Component::Server::JSONUnix::BlockingClient  ();
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
		galla_clients  => {},
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
		'run_base_dir',  'rules_dir',     'ereshkigal_socket', 'galla_bin',
		'timeout',       'socket_group',  'enable_auth',       'authed_users',
		'authed_groups', 'auth_temp_dir', 'command_perms',     'recidive'
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

    - banished :: Who Kur holds for the kurs this Baphomet feeds, seen
          from the watcher's seat. The manager asks Ereshkigal, the source
          of truth for who Kur holds, for its banned lists, pares them to
          the fed kurs (the recidive kur included), expands any fan_out
          gate to its members, and folds in each galla's pending bans...
          banishments spoken but not yet heard. With args.name, just that
          one kur. So every CLI query rides the one manager socket rather
          than reaching around it to Ereshkigal.

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

	my %command_handlers = (
		'status' => sub {
			return $self->_cmd_status;
		},
		'status_all' => sub {
			my ( undef, undef, $ctx ) = @_;
			return $self->_cmd_status_all($ctx);
		},
		'status_galla' => sub {
			my ( undef, $request, $ctx ) = @_;
			return $self->_cmd_status_galla( $request, $ctx );
		},
		'accused' => sub {
			my ( undef, $request, $ctx ) = @_;
			return $self->_cmd_accused( $request, $ctx );
		},
		'marked' => sub {
			my ( undef, $request, $ctx ) = @_;
			return $self->_cmd_marked( $request, $ctx );
		},
		'watching' => sub {
			my ( undef, $request, $ctx ) = @_;
			return $self->_cmd_watching( $request, $ctx );
		},
		'banished' => sub {
			my ( undef, $request, $ctx ) = @_;
			return $self->_cmd_banished( $request, $ctx );
		},
		'stop' => sub {
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
	);

	# the config validates per-command authorization rules against
	# App::Baphomet::Config's command list... guard both ways here so the
	# handler table and that list can never drift, which would leave a
	# command answerable but not nameable in a rule, or the reverse
	foreach my $handled ( keys(%command_handlers) ) {
		if ( !App::Baphomet::Config::known_command($handled) ) {
			die( 'BUG... the command "' . $handled . '" is handled but absent from @App::Baphomet::Config::COMMANDS' );
		}
	}
	foreach my $named (@App::Baphomet::Config::COMMANDS) {
		if ( !$command_handlers{$named} ) {
			die( 'BUG... the command "' . $named . '" is in @App::Baphomet::Config::COMMANDS but has no handler' );
		}
	}

	my $server = POE::Component::Server::JSONUnix->spawn(
		'socket_path'   => $self->socket_path,
		'socket_mode'   => $self->{socket_mode},
		'alias'         => 'baphomet_server',
		'auth_required' => $self->{enable_auth} ? 1 : 0,
		defined( $self->{auth_temp_dir} ) ? ( 'auth_temp_dir' => $self->{auth_temp_dir} ) : (),
		# the Neti gate rides JSONUnix's own permission policy now... only
		# passed when auth is on, so with it off the manager spawns exactly as
		# it did before the gate existed. JSONUnix enforces the policy before a
		# handler runs, so the handlers no longer authorize by hand
		$self->{enable_auth} ? ( 'permissions' => $self->_neti_permissions ) : (),
		'on_error' => sub {
			my ( $operation, $errnum, $errstr ) = @_;
			log_drek( 'err', 'socket error during ' . $operation . '... ' . $errstr . ' (' . $errnum . ')' );
		},
		'commands' => \%command_handlers,
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

# the Neti gate, expressed as a JSONUnix permission policy... undef when
# enable_auth is off, so the manager spawns exactly as it did before the gate
# existed. when on, the baseline is one %DEFAULT% rule allowing UID 0 (root
# always passes), the authed_users, and members of the authed_groups, which
# every command without its own rule falls to. the command_perms config lays
# per-command rules over that baseline and may set the default verdict.
# JSONUnix resolves membership through NSS with secondary groups included, and
# an all-digit entry matches by UID or GID, so numeric ids work in the lists
# too. it resolves once per connection rather than per request, which is the
# same thing for the one-shot CLI clients that drive the manager
sub _neti_permissions {
	my ($self) = @_;

	if ( !$self->{enable_auth} ) {
		return undef;
	}

	my $command_perms = $self->{command_perms};

	# the baseline any un-ruled command falls to
	my %commands = (
		'%DEFAULT%' => {
			'users'  => [ 0, @{ $self->{authed_users} } ],
			'groups' => [ @{ $self->{authed_groups} } ],
		},
	);

	# the verdict for a command no rule and no baseline speaks to... deny
	# unless the config says otherwise
	my $default = 'deny';
	if ( defined($command_perms) && defined( $command_perms->{default} ) ) {
		$default = $command_perms->{default};
	}

	# fold the configured per-command rules over the baseline
	if ( defined($command_perms) && ref( $command_perms->{commands} ) eq 'HASH' ) {
		foreach my $name ( keys( %{ $command_perms->{commands} } ) ) {
			$commands{$name} = _neti_command_rule( $command_perms->{commands}{$name} );
		}
	}

	return {
		'default'  => $default,
		'commands' => \%commands,
	};
} ## end sub _neti_permissions

# turns one configured per-command rule into what JSONUnix wants. a bare
# "allow"/"deny" rides through untouched. a table is copied key by key, and
# UID 0 is threaded into its allowed users so root passes a guarded command
# as it passes the baseline... but only when the rule already names allowed
# users or groups. a rule of only denials is left alone, so it still lets
# whoever it does not name fall through to the default verdict rather than
# being narrowed to root
sub _neti_command_rule {
	my ($spec) = @_;

	if ( ref($spec) ne 'HASH' ) {
		return $spec;
	}

	my %rule;
	foreach my $key ( 'users', 'groups', 'deny_users', 'deny_groups' ) {
		if ( defined( $spec->{$key} ) ) {
			$rule{$key} = [ @{ $spec->{$key} } ];
		}
	}

	# root joins the allow set only where there is one to join
	if ( defined( $rule{users} ) || defined( $rule{groups} ) ) {
		$rule{users} = [ 0, @{ $rule{users} || [] } ];
	}

	return \%rule;
} ## end sub _neti_command_rule

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

	# the async galla clients hold aliases that would keep the kernel
	# alive... drop them first, answering any in-flight fan-out per galla
	# with an error, so a deferred reply still resolves
	foreach my $name ( keys( %{ $self->{galla_clients} } ) ) {
		$self->{galla_clients}{$name}->shutdown;
	}
	$self->{galla_clients} = {};

	# one concurrent stop fan out bounded by a single deadline, so shutdown
	# waits on the slowest galla once rather than on each in turn
	my @running = grep { defined( $self->{gallas}{$_}{pid} ) } sort( keys( %{ $self->{gallas} } ) );
	my $answers = $self->_galla_call_many( \@running, 'stop' );
	foreach my $name (@running) {
		my $answer = $answers->{$name};
		if ( ref($answer) eq 'HASH' && exists( $answer->{result} ) ) {
			next;
		}
		my $error = ( ref($answer) eq 'HASH' && defined( $answer->{error} ) ) ? $answer->{error} : 'no answer';
		log_drek( 'err', 'stopping galla "' . $name . '" via it\'s socket failed, sending TERM... ' . $error );
		if ( defined( $self->{gallas}{$name}{wheel} ) ) {
			$self->{gallas}{$name}{wheel}->kill('TERM');
		}
	} ## end foreach my $name (@running)

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
	my $self = $_[OBJECT];

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

# the persistent async client to one galla's socket, made on first use...
# lazy-connecting, every request bounded by the config timeout and answered
# locally past it, so a wedged galla can not stall the manager loop
sub _galla_async_client {
	my ( $self, $name ) = @_;

	if ( !defined( $self->{galla_clients}{$name} ) ) {
		$self->{galla_clients}{$name} = POE::Component::Server::JSONUnix::Client->spawn(
			'socket_path'     => $self->galla_socket_path($name),
			'alias'           => 'baphomet-galla-client-' . $name,
			'auto_connect'    => 0,
			'request_timeout' => $self->{timeout},
			'on_error'        => sub {
				my ( $operation, $errnum, $errstr ) = @_;
				log_drek( 'err',
					'galla client "' . $name . '" error during ' . $operation . '... ' . $errstr . ' (' . $errnum . ')' );
			},
		);
	} ## end if ( !defined( $self->{galla_clients}{$name...}))

	return $self->{galla_clients}{$name};
} ## end sub _galla_async_client

# fires one async call per named galla... each answer folds via
# $fold->($name, $result, $error) (exactly one of the two defined), and
# $finish runs once the last lands, which the per-request timeout
# guarantees. the deferred half of the fan-out commands
sub _galla_fanout_deferred {
	my ( $self, $running, $command, $fold, $finish ) = @_;

	my $outstanding = scalar( @{$running} );
	foreach my $name ( @{$running} ) {
		my $client = $self->_galla_async_client($name);
		$client->connect;
		$client->call(
			'command'  => $command,
			'callback' => sub {
				my ($response) = @_;
				if ( ref($response) eq 'HASH' && defined( $response->{status} ) && $response->{status} eq 'ok' ) {
					$fold->( $name, $response->{result}, undef );
				} else {
					$fold->(
						$name, undef,
						( ref($response) eq 'HASH' && defined( $response->{error} ) )
						? $response->{error}
						: 'no answer'
					);
				}
				$outstanding--;
				if ( !$outstanding ) {
					$finish->();
				}
				return;
			},
		);
	} ## end foreach my $name ( @{$running} )

	return;
} ## end sub _galla_fanout_deferred

# asks every named running galla the one command concurrently... a select
# fan out against a single shared deadline, so the wall time is the slowest
# galla capped at one timeout instead of the sum. galla sockets never
# challenge, which is the case call_many is built for. returns the answers
# hash, each value { result => ... } or { error => ... }
sub _galla_call_many {
	my ( $self, $names, $command ) = @_;

	my %sockets;
	foreach my $name ( @{$names} ) {
		$sockets{$name} = $self->galla_socket_path($name);
	}
	if ( !%sockets ) {
		return {};
	}

	return Ereshkigal::Client->call_many(
		'sockets' => \%sockets,
		'command' => $command,
		'timeout' => $self->{timeout},
	);
} ## end sub _galla_call_many

sub _cmd_status_all {
	my ( $self, $ctx ) = @_;

	my $status = $self->_cmd_status;

	my @running = grep { $status->{gallas}{$_}{running} } keys( %{ $status->{gallas} } );

	if ( !defined($ctx) || !@running ) {
		my $answers = $self->_galla_call_many( \@running, 'status' );
		foreach my $name (@running) {
			my $answer = $answers->{$name};
			if ( ref($answer) eq 'HASH' && exists( $answer->{result} ) ) {
				$status->{gallas}{$name}{status} = $answer->{result};
			} else {
				$status->{gallas}{$name}{error}
					= ( ref($answer) eq 'HASH' && defined( $answer->{error} ) ) ? $answer->{error} : 'no answer';
			}
		}
		return $status;
	} ## end if ( !defined($ctx) || !@running )

	$self->_galla_fanout_deferred(
		\@running, 'status',
		sub {
			my ( $name, $result, $error ) = @_;
			if ( defined($error) ) {
				$status->{gallas}{$name}{error} = $error;
			} else {
				$status->{gallas}{$name}{status} = $result;
			}
			return;
		},
		sub {
			$ctx->respond_result($status);
			return;
		}
	);

	return undef;
} ## end sub _cmd_status_all

sub _cmd_status_galla {
	my ( $self, $request, $ctx ) = @_;

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

	if ( !$status->{running} ) {
		return $status;
	}

	# trapped like the other fan-out handlers, so a dead-but-unreaped
	# galla yields a partial status with a error rather than a raw die...
	# deferred through $ctx when there is one, so even the single ask
	# never blocks the manager loop
	if ( !defined($ctx) ) {
		my $galla_status;
		eval { $galla_status = $self->_galla_client($name)->call_ok('status'); };
		if ($@) {
			$status->{error} = $@;
		} else {
			$status->{status} = $galla_status;
		}
		return $status;
	}

	$self->_galla_fanout_deferred(
		[$name], 'status',
		sub {
			my ( undef, $result, $error ) = @_;
			if ( defined($error) ) {
				$status->{error} = $error;
			} else {
				$status->{status} = $result;
			}
			return;
		},
		sub {
			$ctx->respond_result($status);
			return;
		}
	);

	return undef;
} ## end sub _cmd_status_galla

# the shared shape of the per-galla fan-out commands... one galla when
# args.name says so, else all, asked concurrently with errors held per
# galla so one dead or wedged worker never takes the whole reply down.
# with a $ctx to defer through the reply is chiseled from the answers and
# the manager loop never blocks at all... without one (a direct call in
# the tests) call_many answers synchronously, bounded by one deadline
sub _cmd_fanout {
	my ( $self, $request, $command, $ctx ) = @_;

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
	my @running;
	foreach my $name (@names) {
		if ( !defined( $self->{gallas}{$name}{pid} ) ) {
			$gallas->{$name} = { 'error' => 'not running' };
			next;
		}
		push( @running, $name );
	}

	if ( !defined($ctx) || !@running ) {
		my $answers = $self->_galla_call_many( \@running, $command );
		foreach my $name (@running) {
			my $answer = $answers->{$name};
			if ( ref($answer) eq 'HASH' && exists( $answer->{result} ) ) {
				$gallas->{$name} = $answer->{result};
			} else {
				$gallas->{$name}
					= { 'error' => ( ref($answer) eq 'HASH' && defined( $answer->{error} ) ) ? $answer->{error} : 'no answer' };
			}
		}
		return { 'gallas' => $gallas };
	} ## end if ( !defined($ctx) || !@running )

	$self->_galla_fanout_deferred(
		\@running,
		$command,
		sub {
			my ( $name, $result, $error ) = @_;
			$gallas->{$name} = defined($error) ? { 'error' => $error } : $result;
			return;
		},
		sub {
			$ctx->respond_result( { 'gallas' => $gallas } );
			return;
		}
	);

	return undef;
} ## end sub _cmd_fanout

sub _cmd_accused {
	my ( $self, $request, $ctx ) = @_;

	return $self->_cmd_fanout( $request, 'accused', $ctx );
}

sub _cmd_marked {
	my ( $self, $request, $ctx ) = @_;

	return $self->_cmd_fanout( $request, 'marked', $ctx );
}

sub _cmd_watching {
	my ( $self, $request, $ctx ) = @_;

	return $self->_cmd_fanout( $request, 'watching', $ctx );
}

# the blocking client to Ereshkigal, the source of truth for who Kur holds,
# spun up and through the Neti dance. the JSONUnix dist's own blocking client,
# the same protocol the manager and the gallas speak, so nothing here reaches
# for a foreign dist's client. a bounded ask of the one trusted local daemon
# the whole system leans on... unlike a galla it can not be one of a crowd of
# wedged workers, and a refused socket fails at once, so the brief stall this
# puts on the manager loop is nothing like what a hung galla could do, which is
# why the galla comms alone are kept async
sub _ereshkigal_client {
	my ($self) = @_;

	my $client = POE::Component::Server::JSONUnix::BlockingClient->new(
		'socket_path' => $self->{ereshkigal_socket},
		'timeout'     => $self->{timeout},
	);

	my $auth = $client->authenticate;
	if ( ( $auth->{status} // '' ) ne 'ok' ) {
		die( 'authenticating to Ereshkigal failed... '
				. ( defined( $auth->{error} ) ? $auth->{error} : 'unknown error' )
				. "\n" );
	}

	return $client;
} ## end sub _ereshkigal_client

# one call to Ereshkigal, returning the result or dieing with the fault... the
# call_ok shape over the JSONUnix blocking client, which hands back the whole
# envelope rather than dieing on a non-ok of it's own
sub _ereshkigal_call {
	my ( $client, $command, $args ) = @_;

	my $response = $client->call( 'command' => $command, ( defined($args) ? ( 'args' => $args ) : () ) );
	if ( ref($response) ne 'HASH' || ( $response->{status} // '' ) ne 'ok' ) {
		die( 'Ereshkigal refused "'
				. $command . '"... '
				. ( ref($response) eq 'HASH' && defined( $response->{error} ) ? $response->{error} : 'no answer' )
				. "\n" );
	}

	return $response->{result};
} ## end sub _ereshkigal_call

# the kurs this Baphomet feeds... the watched ones, each with a galla, plus
# the recidive kur banishments are escalated to, which has none. dies on a
# args.name that is not one of them, matching the old CLI-side check
sub _banished_kurs {
	my ( $self, $request ) = @_;

	my @kurs = sort( keys( %{ $self->{gallas} } ) );
	if ( defined( $self->{recidive} ) && !grep { $_ eq $self->{recidive}{kur} } @kurs ) {
		push( @kurs, $self->{recidive}{kur} );
	}

	my $args = defined( $request->{args} ) ? $request->{args} : {};
	if ( defined( $args->{name} ) ) {
		if ( !grep { $_ eq $args->{name} } @kurs ) {
			die( 'the kur "' . $args->{name} . '" is not one this Baphomet feeds' );
		}
		@kurs = ( $args->{name} );
	}

	return @kurs;
} ## end sub _banished_kurs

# one kur's held entry from Ereshkigal's banned lists... its own banned and
# expires when Ereshkigal holds a list for it, else, being a fan_out gate with
# no list of it's own, its member list with each member's holdings. blocking,
# but only against Ereshkigal, and only the gates cost a second call
sub _banished_kur_entry {
	my ( $self, $ereshkigal, $held, $kur ) = @_;

	if ( defined( $held->{$kur} ) ) {
		return {
			'banned'  => $held->{$kur}{banned},
			'expires' => $held->{$kur}{expires},
		};
	}

	my $kur_status;
	eval { $kur_status = _ereshkigal_call( $ereshkigal, 'status_kur', { 'name' => $kur } ); };
	if ($@) {
		my $error = $@;
		$error =~ s/\s+\z//;
		return { 'error' => $error };
	}
	if ( ref( $kur_status->{fan_out} ) ne 'ARRAY' ) {
		return { 'error' => 'no banned list... not running?' };
	}

	my $members = {};
	foreach my $member ( @{ $kur_status->{fan_out} } ) {
		$members->{$member}
			= defined( $held->{$member} )
			? { 'banned' => $held->{$member}{banned}, 'expires' => $held->{$member}{expires} }
			: { 'error'  => 'not among the banned lists' };
	}

	return {
		'fan_out' => $kur_status->{fan_out},
		'members' => $members,
	};
} ## end sub _banished_kur_entry

# folds one galla's pending bans, its banishments spoken but not yet heard,
# into the kur's entry... $answer is the { result => <status> } or
# { error => ... } shape both the sync and the async galla paths hand back
sub _banished_merge_pending {
	my ( $result, $name, $answer ) = @_;

	my $status = ( ref($answer) eq 'HASH' && exists( $answer->{result} ) ) ? $answer->{result} : undef;
	if (   defined($status)
		&& ref($status) eq 'HASH'
		&& ref( $status->{pending_bans} ) eq 'ARRAY'
		&& defined( $result->{kurs}{$name} ) )
	{
		$result->{kurs}{$name}{pending} = $status->{pending_bans};
	}

	return;
} ## end sub _banished_merge_pending

# who Kur holds, seen from the watcher's seat... the held lists from
# Ereshkigal merged with the gallas' pending bans, so a CLI query rides the
# one manager socket rather than reaching around it. the Ereshkigal ask is a
# bounded block, the galla fan-out for pending rides the same async path the
# status commands use, so the wedge-prone workers never stall the loop
sub _cmd_banished {
	my ( $self, $request, $ctx ) = @_;

	my @kurs = $self->_banished_kurs($request);

	# connect, do the Neti dance, and ask for the banned lists... all bounded,
	# all against the one trusted local daemon
	my $ereshkigal;
	my $banned;
	eval {
		$ereshkigal = $self->_ereshkigal_client;
		$banned     = _ereshkigal_call( $ereshkigal, 'banned' );
	};
	if ($@) {
		my $error = 'asking Ereshkigal for the banned lists failed... ' . $@;
		$error =~ s/\s+\z//;
		if ( defined($ctx) ) {
			$ctx->error($error);
			return undef;
		}
		die( $error . "\n" );
	}
	my $held = ref( $banned->{kurs} ) eq 'HASH' ? $banned->{kurs} : {};

	my $result = { 'kurs' => {} };
	foreach my $kur (@kurs) {
		$result->{kurs}{$kur} = $self->_banished_kur_entry( $ereshkigal, $held, $kur );
	}

	# the pending bans ride the async galla fan-out... only the running gallas
	# among the fed kurs are asked, the recidive kur has none
	my @running = grep { defined( $self->{gallas}{$_} ) && defined( $self->{gallas}{$_}{pid} ) } @kurs;

	if ( !defined($ctx) || !@running ) {
		my $answers = $self->_galla_call_many( \@running, 'status' );
		foreach my $name (@running) {
			_banished_merge_pending( $result, $name, $answers->{$name} );
		}
		return $result;
	}

	$self->_galla_fanout_deferred(
		\@running, 'status',
		sub {
			my ( $name, $galla_result, $error ) = @_;
			if ( !defined($error) ) {
				_banished_merge_pending( $result, $name, { 'result' => $galla_result } );
			}
			return;
		},
		sub {
			$ctx->respond_result($result);
			return;
		}
	);

	return undef;
} ## end sub _cmd_banished

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
