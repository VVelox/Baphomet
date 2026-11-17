package App::Baphomet;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util  qw( is_plain_arrayref is_plain_hashref );
use List::Util qw( any min none );
use base 'Error::Helper';
use POE                                              qw( Wheel::Run );
use POE::Component::Server::JSONUnix                 ();
use POE::Component::Server::JSONUnix::Client         ();
use POE::Component::Server::JSONUnix::BlockingClient ();
use IO::Select                                       ();
use IO::Socket::UNIX                                 ();
use JSON::MaybeXS                                    ();
use Path::Tiny                                       qw( path );
use App::Baphomet::Config       qw( load_config check_kur_def kur_split read_digest_key watcher_rules );
use App::Baphomet::Gate::digest qw( digest_of );
use App::Baphomet::Rules        ();
use App::Baphomet::LogDrek      qw( log_drek );

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
    log="/var/log/auth.log"
    parser="bsd_syslog"
    rule="syslog/sshd"

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
	try {
		$config = load_config( $self->{config} );
	} catch ($caught) {
		$self->{perror}      = 1;
		$self->{error}       = 1;
		$self->{errorString} = $caught;
		$self->warn;
	}
	foreach my $item (
		'run_base_dir',  'rules_dir',     'ereshkigal_socket', 'galla_bin',
		'timeout',       'socket_group',  'enable_auth',       'authed_users',
		'authed_groups', 'auth_temp_dir', 'command_perms',     'recidive',
		'digest_key'
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
	try {
		$rules = App::Baphomet::Rules->new(
			'rules_dir'  => $config->{rules_dir},
			'groups_dir' => $config->{groups_dir}
		);
	} catch ($caught) {
		$self->{perror}      = 1;
		$self->{error}       = 3;
		$self->{errorString} = $caught;
		$self->warn;
	}

	foreach my $name ( sort( keys( %{ $config->{kur} } ) ) ) {
		my $def = $config->{kur}{$name};

		try {
			check_kur_def( $name, $def );
		} catch ($caught) {
			$self->{perror}      = 1;
			$self->{error}       = 2;
			$self->{errorString} = $caught;
			$self->warn;
		}

		my ( undef, $watchers ) = kur_split($def);
		foreach my $watcher_name ( sort( keys( %{$watchers} ) ) ) {
			# %group% references expand here the same as in the galla, so a
			# bad group fails the preflight too instead of only at spawn
			my @rule_names;
			try {
				@rule_names = $rules->expand_rules( watcher_rules( $watchers->{$watcher_name} ) );
			} catch ($caught) {
				$self->{perror} = 1;
				$self->{error}  = 3;
				$self->{errorString}
					= 'Failed to expand the rules of the watcher "'
					. $watcher_name
					. '" of the kur "'
					. $name . '"... '
					. $caught;
				$self->warn;
			} ## end catch ($caught)
			foreach my $rule (@rule_names) {
				try {
					$rules->load($rule);
				} catch ($caught) {
					$self->{perror} = 1;
					$self->{error}  = 3;
					$self->{errorString}
						= 'Failed to load the rule "'
						. $rule
						. '" of the watcher "'
						. $watcher_name
						. '" of the kur "'
						. $name . '"... '
						. $caught;
					$self->warn;
				} ## end catch ($caught)
			} ## end foreach my $rule (@rule_names)
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
		# makes any missing parents too, and is a no-op for a existing dir... a
		# failure surfaces via the usability check below
		eval { path($dir)->mkpath; };
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

    - status :: What the manager itself knows, without asking the gallas.

    - status_all :: status with every running galla asked for its own.

    - status_galla :: One galla, summary and status.

    - accused :: The IPs each galla is counting but has not yet banished.

    - marked :: The live marks each galla holds.

    - tracked :: The live tracked records each galla holds.

    - watching :: What each galla's watchers follow right now.

    - banished :: Who Kur holds for the kurs this Baphomet feeds, pending
          bans included.

    - digest :: The hash a value comes to under the config's digest_key.

    - stop :: Stop all the gallas and then the manager.

=head3 status

Takes no args. The result...

    - pid :: The manager's PID.

    - uptime :: Seconds since it started.

    - config :: The path of the loaded config.

    - gallas :: Keyed by galla name, each with running (0 or 1), pid
          (undef when down), restarts (times respawned), and enabled
          (0 or 1).

=head3 status_all

Takes no args. The result is that of status, with each running galla's
entry under gallas gaining status, the galla's own report, or error where
it could not answer. A galla's own report...

    - name :: The galla's kur.

    - pid :: Its PID.

    - uptime :: Seconds since it started.

    - watchers :: Keyed by watcher name, each with its parser, rules, and
          settings, plus logs and following for a file watcher or journal
          and journal_running for a journal one.

    - stats :: The running stats totals.

    - tracked_ips :: How many IPs have live hits.

    - tracked_subnets :: How many subnets have live tallies.

    - pending_bans :: IPs banished but not yet heard by Ereshkigal.

    - pending_cidr_bans :: The subnet twin of pending_bans.

    - recidive :: The kur banishments escalate to, or undef.

=head3 status_galla

Args...

    - name :: The galla to ask. Required.

The result is that galla's gallas entry from status... name, running,
pid, restarts, and enabled... plus, when running, status or error as in
status_all.

=head3 accused, marked, tracked, watching

The four fan-out commands all take the same one arg...

    - name :: One galla instead of all. Optional.

Each answers with a gallas hash keyed by galla name, each entry the
galla's own answer or a hash of just error for one dead, wedged, or not
running, so one bad worker never takes the whole reply down. Each answer
has the galla's name beside its payload.

For accused the payload is accused, keyed by IP...

    - hits :: The raw count of still-live hits.

    - score :: Their weighted sum, what actually races max_score.

    - first :: Epoch of the oldest live hit.

    - last :: Epoch of the newest live hit.

    - rules :: The same four per rule, where per-rule buckets exist.

For marked it is marks, keyed by mark name, each branded key under it
having...

    - expires :: When the brand fades, epoch.

    - hosts :: How many hosts of the fleet set the brand.

    - value :: The harvested value, where the mark stores one.

For tracked it is tracked, keyed by track name, each live record
having...

    - expires :: When the record lapses, epoch.

    - key :: The compound key, split into its parts.

    - fields :: What the transaction has accumulated so far.

For watching it is watchers, keyed by watcher name...

    - globs :: The paths and globs a file watcher hunts by.

    - following :: The concrete files it has a tail wheel on right now.

    - journal :: The journalctl matches, for a journal watcher.

    - journal_running :: Whether the journal wheel is up, for the same.

=head3 banished

Who Kur holds for the kurs this Baphomet feeds, seen from the watcher's
seat. The manager asks Ereshkigal, the source of truth, for its banned
lists, pares them to the fed kurs (the recidive kur included), expands
any fan_out gate to its members, and folds in each galla's pending
bans... banishments spoken but not yet heard. So every CLI query rides
the one manager socket rather than reaching around it to Ereshkigal.

Args...

    - name :: One kur instead of every fed kur. Optional, and refused for
          a kur this Baphomet does not feed.

The result is a kurs hash keyed by kur, each entry...

    - banned :: The IPs Ereshkigal holds for it.

    - expires :: Keyed by IP, when each is released, epoch, 0 meaning
          never.

    - fan_out :: In place of banned and expires for a gate holding no
          list of its own, its member kurs.

    - members :: Alongside fan_out, each member's own banned and expires,
          or error.

    - pending :: The galla's bans not yet heard by Ereshkigal.

    - error :: In place of the above where Ereshkigal could not say.

=head3 digest

Args...

    - value :: The value to hash. Required.

The result is digest, the hash a digest rule gate makes of the value
under the config's digest_key, read afresh on each call, so a operator
can find a name in what marked and tracked answer. It errors with no
digest_key set.

=head3 stop

Takes no args. The result...

    - stopping :: Always 1.

    - pid :: The manager's PID.

It is answered before the death so the caller can wait on the PID...
a restart's start would otherwise race the still-present PID file.
Then the gallas go down, then the manager.

=cut

sub start_server {
	my ($self) = @_;

	$self->errorblank;

	POE::Session->create(
		object_states => [
			$self => {
				'_start'        => '_poe_start',
				'spawn_galla'   => '_poe_spawn_galla',
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
		'banished' => sub {
			my ( undef, $request, $ctx ) = @_;
			return $self->_cmd_banished( $request, $ctx );
		},
		'digest' => sub {
			my ( undef, $request ) = @_;
			return $self->_cmd_digest($request);
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

	# the per-galla fan-out commands share the one handler, told which command
	# it is relaying
	foreach my $fanout_command (qw( accused marked tracked watching )) {
		$command_handlers{$fanout_command} = sub {
			my ( undef, $request, $ctx ) = @_;
			return $self->_cmd_fanout( $request, $fanout_command, $ctx );
		};
	}

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
		# the Neti gate rides JSONUnix's own permission policy... only passed
		# when auth is on, so with it off the manager spawns ungated. JSONUnix
		# enforces the policy before a handler runs, so the handlers never
		# authorize by hand
		$self->{enable_auth} ? ( 'permissions' => $self->_neti_permissions ) : (),
		'on_error' => sub {
			my ( $operation, $errnum, $errstr ) = @_;
			log_drek( 'err',
					  'socket error during '
					. $operation . ' on "'
					. $self->socket_path . '"... '
					. $errstr . ' ('
					. $errnum
					. ')' );
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
# same thing for the one-shot CLI clients that drive the manager.
#
# args:
#   none... it reads enable_auth, authed_users, authed_groups, and
#   command_perms off the object
#
# returns:
#   undef with enable_auth off. otherwise the hash ref JSONUnix takes as its
#   permissions arg...
#     default  :: 'allow' or 'deny', the verdict for a command no rule speaks to
#     commands :: hash ref keyed by command name, plus '%DEFAULT%' for the
#                 baseline, each value a rule as _neti_command_rule returns
#
# example:
#   # authed_users = ['cuthbert'], authed_groups = ['baphomet'], no command_perms
#   my $permissions = $self->_neti_permissions;
#   # { 'default'  => 'deny',
#   #   'commands' => { '%DEFAULT%' => { 'users' => [ 0, 'cuthbert' ], 'groups' => ['baphomet'] } } }
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
	if ( defined($command_perms) && is_plain_hashref( $command_perms->{commands} ) ) {
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
# being narrowed to root. a plain function, not a method.
#
# args:
#   $spec :: one value from command_perms.commands... the string 'allow' or
#            'deny', or a hash ref of any of users, groups, deny_users, and
#            deny_groups, each a array ref of names or numeric ids
#
# returns:
#   a non-hash $spec as it came. otherwise a new hash ref with the same keys,
#   each list copied, and 0 prepended to users when users or groups is set
#
# example:
#   _neti_command_rule('allow');                          # 'allow'
#   _neti_command_rule( { 'groups' => ['wheel'] } );      # { 'groups' => ['wheel'], 'users' => [0] }
#   _neti_command_rule( { 'deny_users' => ['bob'] } );    # { 'deny_users' => ['bob'] }
sub _neti_command_rule {
	my ($spec) = @_;

	if ( !is_plain_hashref($spec) ) {
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

# the argv a galla is spawned with... the configured galla_bin kept in the
# foreground, so POE::Wheel::Run holds its stdio and can reap it, and pointed
# at the same config the manager loaded.
#
# args:
#   $name :: the kur name the galla serves, a key of $self->{gallas}
#
# returns:
#   the argv as a list, the program first
#
# example:
#   my @cmd = $self->_build_galla_cmd('sshd');
#   # ( 'galla', '--foreground', '--name', 'sshd',
#   #   '--config', '/usr/local/etc/baphomet/config.toml' )
sub _build_galla_cmd {
	my ( $self, $name ) = @_;

	return ( $self->{galla_bin}, '--foreground', '--name', $name, '--config', $self->{config} );
}

#
# POE states for the manager session
#

# the manager session's _start state... takes the baphomet_manager alias, so
# the stop command can post stop_all to it, and queues a spawn_galla for
# every kur in the config.
#
# args:
#   none beyond the POE OBJECT and KERNEL
#
# returns:
#   nothing
#
# example:
#   # fired by POE once start_server creates the session
#   POE::Session->create( object_states => [ $self => { '_start' => '_poe_start', ... } ] );
sub _poe_start {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	$kernel->alias_set('baphomet_manager');

	foreach my $name ( sort( keys( %{ $self->{gallas} } ) ) ) {
		$kernel->yield( 'spawn_galla', $name );
	}

	return;
} ## end sub _poe_start

# the spawn_galla state... starts one galla under a POE::Wheel::Run, with its
# stdout and stderr routed to the log and its exit to galla_reaped, and
# indexes the wheel ID and PID back to the galla name. a galla that is
# unknown, disabled, already running, or asked for while the manager is
# shutting down is silently not spawned, which is what makes a delayed
# respawn safe to fire whatever happened meanwhile.
#
# args:
#   ARG0 :: the name of the galla to spawn, a key of $self->{gallas}
#
# returns:
#   nothing. the galla's entry gains wheel, pid, and spawned (epoch)
#
# example:
#   $kernel->yield( 'spawn_galla', 'sshd' );
#   $kernel->delay_set( 'spawn_galla', 4, 'sshd' );
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

# the galla_stdout state... logs one line a galla wrote to stdout at info,
# named by the galla it came from, or 'unknown' for a wheel already
# forgotten.
#
# args:
#   ARG0 :: the line, with out its newline
#   ARG1 :: the POE::Wheel::Run ID it came from
#
# returns:
#   nothing
#
# example:
#   # fired by the wheel... logs 'galla "sshd" stdout... <line>'
sub _poe_galla_stdout {
	my ( $self, $line, $wheel_id ) = @_[ OBJECT, ARG0, ARG1 ];

	my $name = $self->{wheel_to_galla}{$wheel_id};
	$name = 'unknown' if !defined($name);
	log_drek( 'info', 'galla "' . $name . '" stdout... ' . $line );

	return;
}

# the galla_stderr state... the stderr twin of _poe_galla_stdout, logging
# the line at err instead, as stderr from a galla is a death cry or a warn.
#
# args:
#   ARG0 :: the line, with out its newline
#   ARG1 :: the POE::Wheel::Run ID it came from
#
# returns:
#   nothing
#
# example:
#   # fired by the wheel... logs 'galla "sshd" stderr... <line>'
sub _poe_galla_stderr {
	my ( $self, $line, $wheel_id ) = @_[ OBJECT, ARG0, ARG1 ];

	my $name = $self->{wheel_to_galla}{$wheel_id};
	$name = 'unknown' if !defined($name);
	log_drek( 'err', 'galla "' . $name . '" stderr... ' . $line );

	return;
}

# the galla_reaped state, the sig_child handler for a galla... clears the
# dead galla's wheel and PID and, unless the manager is shutting down or the
# galla is disabled, schedules a respawn with backoff. the delay starts at 1
# second, doubles per death up to 60, and resets to 1 when the galla had
# lived past 60 seconds. while shutting down, the last reaping also drops
# the stop_escalate alarm so the manager exits at once.
#
# args:
#   ARG1 :: the PID reaped
#   ARG2 :: its wait status, as $?
#
# returns:
#   nothing. a PID not belonging to a known galla is ignored
#
# example:
#   # registered per spawn in _poe_spawn_galla
#   $kernel->sig_child( $wheel->PID, 'galla_reaped' );
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

	if ( $self->{shutting_down} ) {
		# the last child reaped leaves the stop_escalate alarm as the one
		# thing keeping this session, and so the manager, alive... drop it
		# so stop finishes the moment the reaping does rather than holding
		# the PID file a whole grace period more
		if ( none { defined( $self->{gallas}{$_}{pid} ) } keys( %{ $self->{gallas} } ) ) {
			$kernel->alarm_remove_all;
		}
		return;
	} ## end if ( $self->{shutting_down} )
	if ( !defined($entry) || !$entry->{enabled} ) {
		return;
	}

	# it ran long enough to be considered to have started fine, so reset the backoff
	if ( defined( $entry->{spawned} ) && ( time - $entry->{spawned} ) > 60 ) {
		$entry->{delay} = 1;
	}

	my $delay = $entry->{delay};
	$entry->{delay} = min( $delay * 2, 60 );
	$entry->{restarts}++;

	log_drek( 'err', 'galla "' . $name . '" died, restarting in ' . $delay . ' seconds' );

	# spawn_galla re-checks enabled, a live wheel, and shutting_down when it
	# fires, so a galla disabled or a manager stopping in the meantime is
	# simply not respawned
	$kernel->delay_set( 'spawn_galla', $delay, $name );

	return;
} ## end sub _poe_galla_reaped

# the stop_all state, posted by the stop command... marks the manager as
# shutting down so nothing respawns, shuts the async galla clients, asks
# every running galla to stop over its socket, TERMing any that can not be
# asked, then drops the manager's alarms and alias so the session can end.
# when a galla still runs after that, stop_escalate is set a timeout out.
#
# args:
#   none beyond the POE OBJECT and KERNEL
#
# returns:
#   nothing
#
# example:
#   $poe_kernel->post( 'baphomet_manager', 'stop_all' );
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
		my ( undef, $error ) = _galla_answer( $answers->{$name} );
		if ( !defined($error) ) {
			next;
		}
		log_drek( 'err', 'stopping galla "' . $name . '" via it\'s socket failed, sending TERM... ' . $error );
		if ( defined( $self->{gallas}{$name}{wheel} ) ) {
			$self->{gallas}{$name}{wheel}->kill('TERM');
		}
	} ## end foreach my $name (@running)

	$kernel->alarm_remove_all;
	$kernel->alias_remove('baphomet_manager');

	# a galla that acknowledged the stop but never exits would leave the
	# manager waiting on its sig_child forever... after a grace period any
	# still-running galla is TERMed, and a grace later KILLed. set after the
	# alarm sweep so it survives, and only when something still runs, so a
	# clean stop is not held a whole grace period by a pending alarm
	if ( any { defined( $self->{gallas}{$_}{pid} ) } keys( %{ $self->{gallas} } ) ) {
		$kernel->delay( 'stop_escalate', $self->{timeout}, 'TERM' );
	}

	return;
} ## end sub _poe_stop_all

# the stop escalation... signal whoever is still alive after the grace
# period, TERM the first pass, and when a galla shrugs that off too a
# second grace ends in the unrefusable KILL.
#
# args:
#   ARG0 :: the signal to send, 'TERM' or 'KILL'. undef is read as 'TERM'
#
# returns:
#   nothing. after a TERM pass that found a galla still running, it sets
#   itself again a timeout out with 'KILL'
#
# example:
#   $kernel->delay( 'stop_escalate', $self->{timeout}, 'TERM' );
sub _poe_stop_escalate {
	my ( $self, $kernel, $signal ) = @_[ OBJECT, KERNEL, ARG0 ];
	$signal = 'TERM' if !defined($signal);

	my $still_running;
	foreach my $name ( sort( keys( %{ $self->{gallas} } ) ) ) {
		my $entry = $self->{gallas}{$name};
		if ( !defined( $entry->{pid} ) || !defined( $entry->{wheel} ) ) {
			next;
		}
		log_drek( 'err', 'galla "' . $name . '" is still running past the stop grace period, sending ' . $signal );
		$entry->{wheel}->kill($signal);
		$still_running = 1;
	}

	if ( $still_running && $signal eq 'TERM' ) {
		$kernel->delay( 'stop_escalate', $self->{timeout}, 'KILL' );
	}

	return;
} ## end sub _poe_stop_escalate

#
# JSONUnix command handlers
#

# the manager's own view of one galla, as status and status_galla both
# report it... nothing asked of the galla itself.
#
# args:
#   $entry :: the galla's slot in $self->{gallas}
#
# returns:
#   a hash ref of...
#     running  :: 1 or 0, whether it has a live PID
#     pid      :: its PID, undef when not running
#     restarts :: the count of respawns since the manager started
#     enabled  :: 1 or 0
#
# example:
#   my $view = $self->_galla_entry_status( $self->{gallas}{sshd} );
#   # { 'running' => 1, 'pid' => 4242, 'restarts' => 0, 'enabled' => 1 }
sub _galla_entry_status {
	my ( $self, $entry ) = @_;

	return {
		'running'  => defined( $entry->{pid} ) ? 1 : 0,
		'pid'      => $entry->{pid},
		'restarts' => $entry->{restarts},
		'enabled'  => $entry->{enabled} ? 1 : 0,
	};
} ## end sub _galla_entry_status

# the status command... what the manager itself knows, with out asking any
# galla, so it answers even with every worker wedged. status_all and
# status_galla build on it.
#
# args:
#   none
#
# returns:
#   a hash ref of...
#     pid    :: the manager's PID
#     uptime :: seconds since start_server
#     config :: the path of the loaded config
#     gallas :: hash ref keyed by galla name, each as _galla_entry_status
#               returns
#
# example:
#   my $status = $self->_cmd_status;
#   # { 'pid' => 4100, 'uptime' => 360, 'config' => '/usr/local/etc/baphomet/config.toml',
#   #   'gallas' => { 'sshd' => { 'running' => 1, 'pid' => 4242, 'restarts' => 0, 'enabled' => 1 } } }
sub _cmd_status {
	my ($self) = @_;

	my %gallas;
	foreach my $name ( keys( %{ $self->{gallas} } ) ) {
		$gallas{$name} = $self->_galla_entry_status( $self->{gallas}{$name} );
	}

	return {
		'pid'    => $$,
		'uptime' => time - $self->{started},
		'config' => $self->{config},
		'gallas' => \%gallas,
	};
} ## end sub _cmd_status

# the persistent async client to one galla's socket, made on first use...
# lazy-connecting, every request bounded by the config timeout and answered
# locally past it, so a wedged galla can not stall the manager loop. the
# clients are kept in $self->{galla_clients} till stop_all shuts them.
#
# args:
#   $name :: the galla's name, a key of $self->{gallas}
#
# returns:
#   the POE::Component::Server::JSONUnix::Client for that galla's socket,
#   the same object on every call
#
# example:
#   my $client = $self->_galla_async_client('sshd');
#   $client->connect;
#   $client->call( 'command' => 'status', 'callback' => sub { ... } );
sub _galla_async_client {
	my ( $self, $name ) = @_;

	if ( !defined( $self->{galla_clients}{$name} ) ) {
		my $socket = $self->galla_socket_path($name);
		$self->{galla_clients}{$name} = POE::Component::Server::JSONUnix::Client->spawn(
			'socket_path'     => $socket,
			'alias'           => 'baphomet-galla-client-' . $name,
			'auto_connect'    => 0,
			'request_timeout' => $self->{timeout},
			'on_error'        => sub {
				my ( $operation, $errnum, $errstr ) = @_;
				# name the socket... a connect failure most often means the
				# galla is not up (its socket absent), and the path says which
				log_drek( 'err',
						  'galla client "'
						. $name
						. '" error during '
						. $operation . ' to "'
						. $socket . '"... '
						. $errstr . ' ('
						. $errnum
						. ')' );
			},
		);
	} ## end if ( !defined( $self->{galla_clients}{$name...}))

	return $self->{galla_clients}{$name};
} ## end sub _galla_async_client

# the error a JSONUnix response envelope carries... its own error when it has
# one, else 'no answer', which covers a envelope that is not even a hash.
#
# args:
#   $response :: the envelope as the client handed it back, normally a hash
#                ref of status and result or error, but anything is taken
#
# returns:
#   the error string
#
# example:
#   _envelope_error( { 'status' => 'error', 'error' => 'No such galla' } );    # 'No such galla'
#   _envelope_error(undef);                                                     # 'no answer'
sub _envelope_error {
	my ($response) = @_;

	if ( is_plain_hashref($response) && defined( $response->{error} ) ) {
		return $response->{error};
	}
	return 'no answer';
}

# reads one galla's answer from _galla_call_many as a result and error pair.
#
# args:
#   $answer :: the galla's entry in the _galla_call_many answers, a { result => ... }
#              or { error => ... } hash, or undef when it never answered
#
# returns:
#   the two item list ( $result, $error ), exactly one of them defined for a
#   answer that is either... a missing answer, or one with neither, reads as
#   the error 'no answer'
#
# example:
#   my ( $result, $error ) = _galla_answer( $answers->{sshd} );
#   _galla_answer( { 'result' => { 'name' => 'sshd' } } );    # ( { 'name' => 'sshd' }, undef )
#   _galla_answer(undef);                                     # ( undef, 'no answer' )
sub _galla_answer {
	my ($answer) = @_;

	if ( is_plain_hashref($answer) && exists( $answer->{result} ) ) {
		return ( $answer->{result}, undef );
	}
	return ( undef, _envelope_error($answer) );
}

# asks every named galla the one command concurrently and blocks till all
# have answered or the deadline passes. this is the blocking road, taken when
# there is no JSONUnix context to defer through (the stop at shutdown, direct
# calls in the tests)... the async road goes through _galla_async_client.
#
# it speaks the JSONUnix line protocol by hand, one newline-terminated JSON
# request out and one response line back per socket, because the JSONUnix
# BlockingClient asks one socket at a time and asking N gallas in turn would
# let one wedged galla eat the budget of the rest. so it is a select fan out
# against a single shared deadline, the wall time being the slowest galla
# capped at one timeout instead of the sum. galla sockets never challenge, so
# there is no auth step.
#
# each connect is bounded by a alarm of a even share of what is left of the
# deadline, never under a second... a unix connect to a listener whose
# accept queue has filled blocks, and one alarm can not watch N sockets, so
# the connects are done in turn and only the conversations run together. a
# timeout of 0 means no deadline at all.
#
# args:
#   $names   :: arrayref of galla names to ask, e.g. [ 'sshd', 'postfix' ]
#   $command :: the command string sent to each, e.g. 'stop'
#
# returns:
#   a hashref keyed by galla name, each value either { result => ... } for a
#   response with a ok status, or { error => 'text' } for anything else... a
#   failed connect, a write or read failure, the galla hanging up, a
#   undecodable or non-object line, a non-ok status (its own error, else
#   'unknown error'), or the deadline passing. one galla failing never
#   disturbs the others. a empty $names gives a empty hashref.
#
# example:
#   my $answers = $self->_galla_call_many( [ 'sshd', 'postfix' ], 'stop' );
#   # { sshd => { result => { stopping => 1 } }, postfix => { error => 'timed out after 5 seconds' } }
sub _galla_call_many {
	my ( $self, $names, $command ) = @_;

	my $answers = {};
	if ( !@{$names} ) {
		return $answers;
	}

	# a write to a galla that died would otherwise raise SIGPIPE and kill the
	# manager... ignored, the write fails with EPIPE and lands in that galla's
	# error answer
	local $SIG{PIPE} = 'IGNORE';

	my $timeout      = $self->{timeout};
	my $deadline     = $timeout ? time + $timeout : undef;
	my $request_line = JSON::MaybeXS::encode_json( { 'command' => $command, 'id' => 1 } ) . "\n";

	# each connection is a little state machine... writing till the request
	# line is fully sent, then reading till a newline shows up
	my %conns;
	my $writers     = IO::Select->new;
	my $readers     = IO::Select->new;
	my @sorted      = sort( @{$names} );
	my $left_to_try = scalar(@sorted);
	foreach my $name (@sorted) {
		my $socket_path = $self->galla_socket_path($name);
		my $connect_budget;
		if ( defined($deadline) ) {
			my $time_left = $deadline - time;
			if ( $time_left <= 0 ) {
				$answers->{$name} = { 'error' => 'timed out before connecting to "' . $socket_path . '"' };
				$left_to_try--;
				next;
			}
			$connect_budget = int( $time_left / $left_to_try ) || 1;
		}
		$left_to_try--;

		my $sock;
		my $connect_error;
		eval {
			local $SIG{ALRM} = sub { die("timed out\n"); };
			alarm($connect_budget) if defined($connect_budget);
			$sock = IO::Socket::UNIX->new(
				'Type' => IO::Socket::UNIX::SOCK_STREAM(),
				'Peer' => $socket_path,
			);
			$connect_error = $! if !$sock;
			alarm(0);
			1;
		} or do {
			alarm(0);
			$sock          = undef;
			$connect_error = 'timed out';
		};
		if ( !$sock ) {
			$answers->{$name} = { 'error' => 'failed to connect to "' . $socket_path . '"... ' . $connect_error };
			next;
		}
		$sock->blocking(0);
		$conns{$sock} = { 'name' => $name, 'sock' => $sock, 'sent' => 0, 'buffer' => '' };
		$writers->add($sock);
	} ## end foreach my $name (@sorted)

	my $finish = sub {
		my ( $conn, $answer ) = @_;
		$writers->remove( $conn->{sock} );
		$readers->remove( $conn->{sock} );
		close( $conn->{sock} );
		delete( $conns{ $conn->{sock} } );
		$answers->{ $conn->{name} } = $answer;
	};

	while (%conns) {
		my $time_left;
		if ( defined($deadline) ) {
			$time_left = $deadline - time;
			last if $time_left <= 0;
		}

		my ( $readable, $writable ) = IO::Select->select( $readers, $writers, undef, $time_left );

		foreach my $sock ( @{ $writable // [] } ) {
			my $conn = $conns{$sock} // next;
			my $wrote
				= syswrite( $sock, $request_line, length($request_line) - $conn->{sent}, $conn->{sent} );
			if ( !defined($wrote) ) {
				next if $!{EAGAIN} || $!{EWOULDBLOCK} || $!{EINTR};
				$finish->( $conn, { 'error' => 'failed to write the request... ' . $! } );
				next;
			}
			$conn->{sent} += $wrote;
			if ( $conn->{sent} >= length($request_line) ) {
				$writers->remove($sock);
				$readers->add($sock);
			}
		} ## end foreach my $sock ( @{ $writable // [] } )

		foreach my $sock ( @{ $readable // [] } ) {
			my $conn = $conns{$sock} // next;
			my $read = sysread( $sock, my $chunk, 65536 );
			if ( !defined($read) ) {
				next if $!{EAGAIN} || $!{EWOULDBLOCK} || $!{EINTR};
				$finish->( $conn, { 'error' => 'failed to read the response... ' . $! } );
				next;
			}
			if ( $read == 0 ) {
				$finish->( $conn, { 'error' => 'galla "' . $conn->{name} . '" hung up with out answering' } );
				next;
			}
			$conn->{buffer} .= $chunk;
			next if $conn->{buffer} !~ /\n/;

			my ($line) = split( /\n/, $conn->{buffer}, 2 );
			my $response = eval { JSON::MaybeXS::decode_json($line) };
			if ( !is_plain_hashref($response) ) {
				$finish->( $conn, { 'error' => 'undecodable or non-object response' } );
				next;
			}
			if ( ( $response->{status} // '' ) ne 'ok' ) {
				$finish->( $conn, { 'error' => $response->{error} // 'unknown error' } );
				next;
			}
			$finish->( $conn, { 'result' => $response->{result} } );
		} ## end foreach my $sock ( @{ $readable // [] } )
	} ## end while (%conns)

	# whatever had not answered when the deadline passed
	foreach my $conn ( values(%conns) ) {
		close( $conn->{sock} );
		$answers->{ $conn->{name} } = { 'error' => 'timed out after ' . $timeout . ' seconds' };
	}

	return $answers;
} ## end sub _galla_call_many

# asks the named gallas one command and builds the reply from their answers,
# the shape every galla fan-out handler shares, errors held per galla so one
# dead or wedged worker never takes the whole reply down. with a $ctx the asks
# go out over the async clients and the reply is chiseled once the last lands,
# which the per-request timeout guarantees, so the manager loop never blocks.
# without one (a direct call, as in the tests), or with no one to ask,
# _galla_call_many answers in place, bounded by one deadline.
#
# args:
#   $names   :: arrayref of the names of the gallas to ask, the running ones
#   $command :: the command each is sent, such as 'status' or 'accused'
#   $ctx     :: the JSONUnix context the reply defers through, or undef
#   $fold    :: code ref called per galla as $fold->( $name, $result, $error ),
#               one of result and error defined, to fold its answer into the
#               reply
#   $reply   :: code ref called once every answer is folded, returning the
#               reply
#
# returns:
#   the reply when it was answered in place, else undef, the reply going out
#   through $ctx when the last answer lands
#
# example:
#   my %up;
#   return $self->_galla_ask(
#       [ 'sshd', 'postfix' ], 'status', $ctx,
#       sub { my ( $name, $result, $error ) = @_; $up{$name} = defined($error) ? 0 : 1; return; },
#       sub { return \%up; }
#   );
sub _galla_ask {
	my ( $self, $names, $command, $ctx, $fold, $reply ) = @_;

	if ( !defined($ctx) || !@{$names} ) {
		my $answers = $self->_galla_call_many( $names, $command );
		foreach my $name ( @{$names} ) {
			$fold->( $name, _galla_answer( $answers->{$name} ) );
		}
		return $reply->();
	}

	my $outstanding = scalar( @{$names} );
	foreach my $name ( @{$names} ) {
		my $client = $self->_galla_async_client($name);
		$client->connect;
		$client->call(
			'command'  => $command,
			'callback' => sub {
				my ($response) = @_;
				if ( is_plain_hashref($response) && ( $response->{status} // '' ) eq 'ok' ) {
					$fold->( $name, $response->{result}, undef );
				} else {
					$fold->( $name, undef, _envelope_error($response) );
				}
				$outstanding--;
				if ( !$outstanding ) {
					$ctx->respond_result( $reply->() );
				}
				return;
			},
		);
	} ## end foreach my $name ( @{$names} )

	return undef;
} ## end sub _galla_ask

# the status_all command... status, with every running galla asked for its
# own report via _galla_ask, which lands under that galla's entry as status,
# or as error when it could not answer. a galla not running is not asked.
#
# args:
#   $ctx :: the JSONUnix context to defer the reply through, or undef to
#           answer in place
#
# returns:
#   the status hash ref with the galla entries filled in when answered in
#   place, else undef with the reply sent through $ctx
#
# example:
#   my $status = $self->_cmd_status_all(undef);
#   # { 'pid' => 4100, ..., 'gallas' => { 'sshd' => { 'running' => 1, ..., 'status' => { 'name' => 'sshd', ... } } } }
sub _cmd_status_all {
	my ( $self, $ctx ) = @_;

	my $status  = $self->_cmd_status;
	my @running = grep { $status->{gallas}{$_}{running} } keys( %{ $status->{gallas} } );

	return $self->_galla_ask(
		\@running,
		'status', $ctx,
		sub {
			my ( $name, $result, $error ) = @_;
			if ( defined($error) ) {
				$status->{gallas}{$name}{error} = $error;
			} else {
				$status->{gallas}{$name}{status} = $result;
			}
			return;
		},
		sub { return $status; }
	);
} ## end sub _cmd_status_all

# the hash a value comes to under the config's digest_key, as a digest gate
# makes it, so a operator can look a name up in what the gallas hold. the key
# is read afresh each time, so one rotated on disk is the one asked of.
#
# args:
#   $request :: the JSON request hash ref, whose args.value is the value to
#               hash, a plain string
#
# returns:
#   a hash ref of digest, the hash. dies with no args.value or a non-string
#   one, and with no digest_key set or one that can not be read
#
# example:
#   my $answer = $self->_cmd_digest( { 'args' => { 'value' => 'neti' } } );    # { 'digest' => '6a1f0c2b9e4d7a35' }
sub _cmd_digest {
	my ( $self, $request ) = @_;

	my $args = $request->{args};
	if ( !is_plain_hashref($args) || !defined( $args->{value} ) || ref( $args->{value} ) ne '' ) {
		die('args.value must be the value to hash');
	}
	if ( !defined( $self->{digest_key} ) ) {
		die('no digest_key is set in the config');
	}

	return { 'digest' => digest_of( $args->{value}, read_digest_key( $self->{digest_key} ) ) };
} ## end sub _cmd_digest

# the status_galla command... one galla's manager-side view, and when it is
# running its own report too, asked the same way status_all asks.
#
# args:
#   $request :: the JSON request hash ref, whose args.name is the galla
#   $ctx     :: the JSONUnix context to defer the reply through, or undef to
#               answer in place
#
# returns:
#   a hash ref of name plus the _galla_entry_status fields, and, when
#   running, status (the galla's own report) or error. it is returned at
#   once for a galla not running or answered in place, else undef with the
#   reply sent through $ctx. dies with no args.name, or one naming no galla
#
# example:
#   my $status = $self->_cmd_status_galla( { 'args' => { 'name' => 'sshd' } }, undef );
#   # { 'name' => 'sshd', 'running' => 1, 'pid' => 4242, 'restarts' => 0, 'enabled' => 1,
#   #   'status' => { 'name' => 'sshd', ... } }
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

	my $status = { 'name' => $name, %{ $self->_galla_entry_status($entry) } };

	if ( !$status->{running} ) {
		return $status;
	}

	# asked like the fan-out handlers ask, so a dead-but-unreaped galla
	# yields a partial status with a error rather than a raw die, and even
	# the single ask never blocks the manager loop
	return $self->_galla_ask(
		[$name],
		'status', $ctx,
		sub {
			my ( undef, $result, $error ) = @_;
			if ( defined($error) ) {
				$status->{error} = $error;
			} else {
				$status->{status} = $result;
			}
			return;
		},
		sub { return $status; }
	);
} ## end sub _cmd_status_galla

# the shared shape of the per-galla fan-out commands... one galla when
# args.name says so, else all, each answering into its own entry, a galla
# not running reading as such with out being asked. accused, marked,
# tracked, and watching all ride it, each relaying its own name as the
# command.
#
# args:
#   $request :: the JSON request hash ref, whose optional args.name picks
#               one galla
#   $command :: the command relayed to each galla... 'accused', 'marked',
#               'tracked', or 'watching'
#   $ctx     :: the JSONUnix context to defer the reply through, or undef to
#               answer in place
#
# returns:
#   a hash ref of gallas, keyed by galla name, each value that galla's
#   answer or { error => ... } for one not running or not answering. it is
#   returned when answered in place, else undef with the reply sent through
#   $ctx. dies when args.name names no galla
#
# example:
#   my $reply = $self->_cmd_fanout( { 'args' => { 'name' => 'sshd' } }, 'accused', undef );
#   # { 'gallas' => { 'sshd' => { 'name' => 'sshd', 'accused' => { '192.0.2.7' => { 'hits' => 2, ... } } } } }
sub _cmd_fanout {
	my ( $self, $request, $command, $ctx ) = @_;

	my $args = $request->{args} // {};

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

	return $self->_galla_ask(
		\@running,
		$command, $ctx,
		sub {
			my ( $name, $result, $error ) = @_;
			$gallas->{$name} = defined($error) ? { 'error' => $error } : $result;
			return;
		},
		sub { return { 'gallas' => $gallas }; }
	);
} ## end sub _cmd_fanout

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
		die( 'authenticating to Ereshkigal failed... ' . ( $auth->{error} // 'unknown error' ) . "\n" );
	}

	return $client;
} ## end sub _ereshkigal_client

# one call to Ereshkigal, returning the result or dying with the fault... the
# call_ok shape over the JSONUnix blocking client, which hands back the whole
# envelope rather than dying on a non-ok of its own. a plain function, not a
# method.
#
# args:
#   $client  :: a authenticated JSONUnix BlockingClient, as _ereshkigal_client
#               returns
#   $command :: the Ereshkigal command name, such as 'banned' or 'status_kur'
#   $args    :: hash ref of the command's args, or undef to send none
#
# returns:
#   the result from the envelope, whatever shape that command answers with.
#   dies, the message newline terminated, on a envelope that is not a hash
#   or whose status is not ok
#
# example:
#   my $banned     = _ereshkigal_call( $client, 'banned' );
#   my $kur_status = _ereshkigal_call( $client, 'status_kur', { 'name' => 'all' } );
sub _ereshkigal_call {
	my ( $client, $command, $args ) = @_;

	my $response = $client->call( 'command' => $command, ( defined($args) ? ( 'args' => $args ) : () ) );
	if ( !is_plain_hashref($response) || ( $response->{status} // '' ) ne 'ok' ) {
		die( 'Ereshkigal refused "' . $command . '"... ' . _envelope_error($response) . "\n" );
	}

	return $response->{result};
} ## end sub _ereshkigal_call

# the kurs this Baphomet feeds... the watched ones, each with a galla, plus
# the recidive kur banishments are escalated to, which has none. dies on a
# args.name that is not one of them, matching the old CLI-side check.
#
# args:
#   $request :: the JSON request hash ref, whose optional args.name narrows
#               the answer to one kur
#
# returns:
#   the list of kur names... sorted gallas, with the recidive kur last when
#   it is not already one, or just args.name when given
#
# example:
#   # gallas sshd and postfix, recidive kur recidive
#   my @kurs = $self->_banished_kurs( {} );                                # ( 'postfix', 'sshd', 'recidive' )
#   my @one  = $self->_banished_kurs( { 'args' => { 'name' => 'sshd' } } );  # ( 'sshd' )
sub _banished_kurs {
	my ( $self, $request ) = @_;

	my @kurs = sort( keys( %{ $self->{gallas} } ) );
	if ( defined( $self->{recidive} ) && none { $_ eq $self->{recidive}{kur} } @kurs ) {
		push( @kurs, $self->{recidive}{kur} );
	}

	my $args = $request->{args} // {};
	if ( defined( $args->{name} ) ) {
		if ( none { $_ eq $args->{name} } @kurs ) {
			die( 'the kur "' . $args->{name} . '" is not one this Baphomet feeds' );
		}
		@kurs = ( $args->{name} );
	}

	return @kurs;
} ## end sub _banished_kurs

# one kur's held entry from Ereshkigal's banned lists... its own banned and
# expires when Ereshkigal holds a list for it, else, being a fan_out gate with
# no list of its own, its member list with each member's holdings. blocking,
# but only against Ereshkigal, and only the gates cost a second call.
#
# args:
#   $ereshkigal :: the authenticated client from _ereshkigal_client, used
#                  for a status_kur call on a kur with no held list
#   $held       :: hash ref of Ereshkigal's banned lists, keyed by kur, each
#                  with banned (array ref of IPs) and expires (hash ref of IP
#                  to epoch, 0 meaning never)
#   $kur        :: the kur name to build the entry for
#
# returns:
#   a hash ref, one of...
#     { banned => [...], expires => {...} } for a kur with a held list
#     { fan_out => [ member names ], members => { name => entry } } for a
#       fan_out gate, each member entry banned and expires, or error when
#       it is not among the held lists
#     { error => '...' } when status_kur failed or the kur is neither
#
# example:
#   my $entry = $self->_banished_kur_entry( $client, $held, 'sshd' );
#   # { 'banned' => ['192.0.2.7'], 'expires' => { '192.0.2.7' => 1763300000 } }
sub _banished_kur_entry {
	my ( $self, $ereshkigal, $held, $kur ) = @_;

	if ( defined( $held->{$kur} ) ) {
		return {
			'banned'  => $held->{$kur}{banned},
			'expires' => $held->{$kur}{expires},
		};
	}

	my $kur_status;
	try {
		$kur_status = _ereshkigal_call( $ereshkigal, 'status_kur', { 'name' => $kur } );
	} catch ($caught) {
		my $error = $caught;
		$error =~ s/\s+\z//;
		return { 'error' => $error };
	}
	if ( !is_plain_arrayref( $kur_status->{fan_out} ) ) {
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
# into its kur's entry in the banished reply.
#
# args:
#   $result :: the banished reply being built, { kurs => { name => entry } }
#   $name   :: the galla's name, which is its kur's
#   $status :: the galla's answer to status, a hash ref whose pending_bans
#              array ref of IPs is folded
#
# returns:
#   nothing. $result->{kurs}{$name} gains pending, the pending_bans array
#   ref. a status with no pending_bans list, or a kur with no entry in the
#   reply, adds nothing
#
# example:
#   _banished_merge_pending( $result, 'sshd', { 'pending_bans' => ['192.0.2.7'] } );
#   # $result->{kurs}{sshd}{pending} is now ['192.0.2.7']
sub _banished_merge_pending {
	my ( $result, $name, $status ) = @_;

	if (   is_plain_hashref($status)
		&& is_plain_arrayref( $status->{pending_bans} )
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
# status commands use, so the wedge-prone workers never stall the loop.
#
# args:
#   $request :: the JSON request hash ref, whose optional args.name narrows
#               it to one fed kur
#   $ctx     :: the JSONUnix context to defer the reply through, or undef to
#               answer in place
#
# returns:
#   a hash ref of kurs, keyed by kur, each as _banished_kur_entry returns
#   plus pending where the galla has any. it is returned when answered in
#   place, else undef with the reply sent through $ctx. when Ereshkigal can
#   not be asked, the error goes through $ctx and undef is returned, or with
#   out a $ctx it dies. dies too on a args.name not among the fed kurs
#
# example:
#   my $reply = $self->_cmd_banished( { 'args' => { 'name' => 'sshd' } }, undef );
#   # { 'kurs' => { 'sshd' => { 'banned' => ['192.0.2.7'], 'expires' => { '192.0.2.7' => 0 },
#   #                           'pending' => ['198.51.100.9'] } } }
sub _cmd_banished {
	my ( $self, $request, $ctx ) = @_;

	my @kurs = $self->_banished_kurs($request);

	# connect, do the Neti dance, and ask for the banned lists... all bounded,
	# all against the one trusted local daemon
	my $ereshkigal;
	my $banned;
	try {
		$ereshkigal = $self->_ereshkigal_client;
		$banned     = _ereshkigal_call( $ereshkigal, 'banned' );
	} catch ($caught) {
		my $error = 'asking Ereshkigal for the banned lists failed... ' . $caught;
		$error =~ s/\s+\z//;
		if ( defined($ctx) ) {
			$ctx->error($error);
			return undef;
		}
		die( $error . "\n" );
	}
	my $held = is_plain_hashref( $banned->{kurs} ) ? $banned->{kurs} : {};

	my $result = { 'kurs' => {} };
	foreach my $kur (@kurs) {
		$result->{kurs}{$kur} = $self->_banished_kur_entry( $ereshkigal, $held, $kur );
	}

	# the pending bans ride the async galla fan-out... only the running gallas
	# among the fed kurs are asked, the recidive kur has none, and a galla
	# that does not answer simply adds no pending
	my @running = grep { defined( $self->{gallas}{$_} ) && defined( $self->{gallas}{$_}{pid} ) } @kurs;

	return $self->_galla_ask(
		\@running,
		'status', $ctx,
		sub {
			my ( $name, $galla_status, $error ) = @_;
			if ( !defined($error) ) {
				_banished_merge_pending( $result, $name, $galla_status );
			}
			return;
		},
		sub { return $result; }
	);
} ## end sub _cmd_banished

=head1 ERROR CODES / ERROR FLAGS

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
read/write/traversable.

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

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991, or (at your
  option) any later version, matching fail2ban, which parts of this
  project, most notably the shipped rules, are derived from.

=cut

1;    # End of App::Baphomet
