package App::Baphomet::Galla;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use POE                              qw( Wheel::FollowTail );
use POE::Component::Server::JSONUnix ();
use File::Glob                       qw( bsd_glob );
use Ereshkigal::Client               ();
use App::Baphomet::Config            qw( load_config check_kur_def kur_split resolve_settings watcher_rules watcher_logs );
use App::Baphomet::Parser            ();
use App::Baphomet::Rules             ();
use App::Baphomet::LogDrek           qw( log_drek );

=head1 NAME

App::Baphomet::Galla - Log watching worker for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Galla;

    my $galla = App::Baphomet::Galla->new(
                    'config' => '/usr/local/etc/baphomet/config.toml',
                    'name'   => 'sshd',
                );

    $galla->start_server;

Each galla handles a single kur from the config... it follows the log of
each watcher of that kur, parses the lines, checks them against the rules,
counts matches per IP, and once a IP racks up max_retrys matches with in
find_time seconds, consigns it to Kur via the Ereshkigal manager socket.

Normally spawned and supervised by C<baphomet>, but usable standalone via
the C<galla> bin.

=head1 METHODS

=head2 new

Initiates the object. All errors are considered fatal, meaning if new fails
it will die.

    - config :: Path to the TOML config file. See L<App::Baphomet::Config>
          for the format.
        Default :: /usr/local/etc/baphomet/config.toml

    - name :: The name of the kur under the config this galla is for.
        Default :: undef

All rules referenced by the watchers are loaded, compiled, and their
embedded tests ran, with a failure of any of that being fatal.

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
			all_errors_fatal => 1,
			flags            => {
				1 => 'configLoadFailed',
				2 => 'noSuchKur',
				3 => 'invalidKurDef',
				4 => 'NErunBaseDir',
				5 => 'nonRWrunBaseDir',
				6 => 'rulesLoadFailed',
			},
			fatal_flags      => {},
			perror_not_fatal => 0,
		},
		config       => '/usr/local/etc/baphomet/config.toml',
		name         => undef,
		settings     => undef,
		watchers     => {},
		rules        => undef,
		counters     => {},
		pending_bans => {},
		wheel_to_watcher => {},
		started      => undef,
		stopping     => 0,
		server       => undef,
		stats        => {
			lines      => 0,
			unparsed   => 0,
			matched    => 0,
			bans       => 0,
			ban_errors => 0,
		},
	};
	bless $self;

	if ( defined( $opts{config} ) ) {
		$self->{config} = $opts{config};
	}
	$self->{name} = $opts{name};

	my $config;
	eval { $config = load_config( $self->{config} ); };
	if ($@) {
		$self->{perror}      = 1;
		$self->{error}       = 1;
		$self->{errorString} = $@;
		$self->warn;
	}
	$self->{run_base_dir}      = $config->{run_base_dir};
	$self->{ereshkigal_socket} = $config->{ereshkigal_socket};
	$self->{timeout}           = $config->{timeout};

	if ( !defined( $self->{name} ) || !defined( $config->{kur}{ $self->{name} } ) ) {
		$self->{perror} = 1;
		$self->{error}  = 2;
		$self->{errorString}
			= 'No kur named "'
			. ( defined( $self->{name} ) ? $self->{name} : 'undef' )
			. '" under the config "'
			. $self->{config} . '"';
		$self->warn;
	}

	my $def = $config->{kur}{ $self->{name} };
	eval { check_kur_def( $self->{name}, $def ); };
	if ($@) {
		$self->{perror}      = 1;
		$self->{error}       = 3;
		$self->{errorString} = $@;
		$self->warn;
	}

	my ( $kur_settings, $watchers ) = kur_split($def);
	$self->{settings} = $kur_settings;

	foreach my $dir ( $self->{run_base_dir}, $self->{run_base_dir} . '/galla' ) {
		if ( !-e $dir ) {
			# don't need to check if this worked failed or not here as the next if statement will handle that
			eval { mkdir($dir); };
		}
		if ( !-d $dir ) {
			$self->{perror}      = 1;
			$self->{error}       = 4;
			$self->{errorString} = 'run dir,"' . $dir . '", does not exist or is not a directory';
			$self->warn;
		}
		if ( !-r $dir || !-w $dir ) {
			$self->{perror}      = 1;
			$self->{error}       = 5;
			$self->{errorString} = 'run dir,"' . $dir . '", is either not writable or readable by the current user';
			$self->warn;
		}
	} ## end foreach my $dir ( $self->{run_base_dir}, $self->...)

	eval { $self->{rules} = App::Baphomet::Rules->new( 'rules_dir' => $config->{rules_dir} ); };
	if ($@) {
		$self->{perror}      = 1;
		$self->{error}       = 6;
		$self->{errorString} = $@;
		$self->warn;
	}

	foreach my $watcher_name ( sort( keys( %{$watchers} ) ) ) {
		my $watcher = $watchers->{$watcher_name};

		my @rule_names = watcher_rules($watcher);
		my @rule_objs;
		foreach my $rule_name (@rule_names) {
			my $rule;
			eval { $rule = $self->{rules}->load($rule_name); };
			if ($@) {
				$self->{perror} = 1;
				$self->{error}  = 6;
				$self->{errorString}
					= 'Failed to load the rule "'
					. $rule_name
					. '" for the watcher "'
					. $watcher_name . '"... '
					. $@;
				$self->warn;
			} ## end if ($@)
			push( @rule_objs, $rule );
		} ## end foreach my $rule_name (@rule_names)

		$self->{watchers}{$watcher_name} = {
			'log_spec'  => [ watcher_logs($watcher) ],
			'parser'    => defined( $watcher->{parser} ) ? $watcher->{parser} : 'syslog',
			'rules'     => \@rule_names,
			'rule_objs' => \@rule_objs,
			'settings'  => resolve_settings( $config, $kur_settings, $watcher ),
			'wheels'    => {},
		};
	} ## end foreach my $watcher_name ( sort( keys( %{$watchers...})))

	return $self;
} ## end sub new

=head2 socket_path

Returns the path of the unix socket for this instance.

    my $socket_path = $galla->socket_path;

=cut

sub socket_path {
	my ($self) = @_;

	return $self->{run_base_dir} . '/galla/' . $self->{name} . '.sock';
}

=head2 pid_path

Returns the path of the PID file for this instance.

    my $pid_path = $galla->pid_path;

=cut

sub pid_path {
	my ($self) = @_;

	return $self->{run_base_dir} . '/galla/' . $self->{name} . '.pid';
}

=head2 start_server

Starts following the logs and brings up the
L<POE::Component::Server::JSONUnix> server for this instance, calling
$poe_kernel->run.

This should not be expected to return till the galla is told to stop.

The socket is chmoded to 0600 given only the manager, running as the same
user, talks to it.

A sweeper runs every ten seconds, retrying bans Ereshkigal could not be
reached for, dropping match counts that have aged out of find_time, and
re-expanding any globs in the log specs of the watchers... new matches
get followed and vanished matches get dropped, while literal entries are
never dropped.

The JSON commands handled are as below.

    - status :: Instance status info... watchers with their log specs and
          the files currently being followed, stats, effective settings,
          how many IPs are being counted, and any bans pending retry.

    - stop :: Stop following the logs and exit. Pending bans that could
          not be delivered are lost.

=cut

sub start_server {
	my ($self) = @_;

	$self->errorblank;

	my $ident = 'galla-' . $self->{name};

	my $server = POE::Component::Server::JSONUnix->spawn(
		'socket_path' => $self->socket_path,
		'socket_mode' => oct('0600'),
		'alias'       => $ident,
		'on_error'    => sub {
			my ( $operation, $errnum, $errstr ) = @_;
			log_drek( 'err', 'socket error during ' . $operation . '... ' . $errstr . ' (' . $errnum . ')',
				undef, $ident );
		},
		'commands' => {
			'status' => sub {
				return $self->_cmd_status;
			},
			'stop' => sub {
				my ( undef, undef, $ctx ) = @_;
				return $self->_cmd_stop($ctx);
			},
		},
	);
	$self->{server} = $server;

	POE::Session->create(
		object_states => [
			$self => {
				'_start'     => '_poe_start',
				'got_line'   => '_poe_got_line',
				'tail_error' => '_poe_tail_error',
				'tail_reset' => '_poe_tail_reset',
				'sweep'      => '_poe_sweep',
				'stop_tails' => '_poe_stop_tails',
			},
		],
	);

	$self->{started} = time;

	log_drek(
		'info',
		'started... socket='
			. $self->socket_path
			. ' watchers='
			. join( ',', sort( keys( %{ $self->{watchers} } ) ) ),
		undef, $ident
	);

	$poe_kernel->run;

	log_drek( 'info', 'stopped', undef, $ident );

	return;
} ## end sub start_server

#
# POE states for the tailing session
#

sub _poe_start {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	$kernel->alias_set( 'galla-tails-' . $self->{name} );

	my $ident = 'galla-' . $self->{name};

	foreach my $watcher_name ( sort( keys( %{ $self->{watchers} } ) ) ) {
		my @files = $self->_resolve_watcher_logs( $self->{watchers}{$watcher_name} );

		if ( !@files ) {
			log_drek( 'err',
				'the watcher "' . $watcher_name . '" resolved to no files at all... globs will be rechecked',
				undef, $ident );
		}

		foreach my $file (@files) {
			$self->_start_tail( $watcher_name, $file );
		}
	} ## end foreach my $watcher_name ( sort( keys( %{ $self...})))

	$kernel->delay( 'sweep', 10 );

	return;
} ## end sub _poe_start

# starts following a single file for a watcher... must be called from
# with in the tailing session, as that is who the wheel belongs to
sub _start_tail {
	my ( $self, $watcher_name, $file ) = @_;

	my $ident   = 'galla-' . $self->{name};
	my $watcher = $self->{watchers}{$watcher_name};

	if ( !-e $file ) {
		log_drek( 'err', 'the log "' . $file . '" of the watcher "' . $watcher_name . '" does not exist yet',
			undef, $ident );
	}

	my $wheel = POE::Wheel::FollowTail->new(
		'Filename'   => $file,
		'InputEvent' => 'got_line',
		'ErrorEvent' => 'tail_error',
		'ResetEvent' => 'tail_reset',
	);

	$watcher->{wheels}{$file} = $wheel;
	$self->{wheel_to_watcher}{ $wheel->ID } = $watcher_name;

	log_drek( 'info', 'following "' . $file . '" for the watcher "' . $watcher_name . '"', undef, $ident );

	return;
} ## end sub _start_tail

# expands the log spec of a watcher into the files to follow... entries
# with glob metacharacters are expanded and may match nothing, everything
# else is kept literally even if it does not exist yet... deduped, order
# preserving
sub _resolve_watcher_logs {
	my ( $self, $watcher ) = @_;

	my @files;
	my %seen;
	foreach my $entry ( @{ $watcher->{log_spec} } ) {
		my @matched;
		if ( $entry =~ /[*?\[{]/ ) {
			@matched = bsd_glob($entry);
		} else {
			@matched = ($entry);
		}
		foreach my $file (@matched) {
			if ( !defined( $seen{$file} ) ) {
				$seen{$file} = 1;
				push( @files, $file );
			}
		}
	} ## end foreach my $entry ( @{ $watcher->{log_spec} } )

	return @files;
} ## end sub _resolve_watcher_logs

# re-expands the globs of every watcher, following new matches and
# dropping wheels for vanished ones... literal entries always resolve to
# themselves, so they are never dropped... must be called from with in
# the tailing session
sub _rescan_logs {
	my ($self) = @_;

	my $ident = 'galla-' . $self->{name};

	foreach my $watcher_name ( sort( keys( %{ $self->{watchers} } ) ) ) {
		my $watcher = $self->{watchers}{$watcher_name};

		my %desired = map { $_ => 1 } $self->_resolve_watcher_logs($watcher);

		foreach my $file ( sort( keys(%desired) ) ) {
			if ( !defined( $watcher->{wheels}{$file} ) ) {
				$self->_start_tail( $watcher_name, $file );
			}
		}

		foreach my $file ( sort( keys( %{ $watcher->{wheels} } ) ) ) {
			if ( !defined( $desired{$file} ) ) {
				my $wheel = delete( $watcher->{wheels}{$file} );
				delete( $self->{wheel_to_watcher}{ $wheel->ID } );
				log_drek( 'info',
					'no longer following "' . $file . '" for the watcher "' . $watcher_name . '"... unmatched',
					undef, $ident );
			}
		} ## end foreach my $file ( sort( keys( %{ $watcher->{wheels...}})))
	} ## end foreach my $watcher_name ( sort( keys( %{ $self...})))

	return;
} ## end sub _rescan_logs

sub _poe_got_line {
	my ( $self, $line, $wheel_id ) = @_[ OBJECT, ARG0, ARG1 ];

	my $watcher_name = $self->{wheel_to_watcher}{$wheel_id};
	if ( !defined($watcher_name) ) {
		return;
	}

	$self->_handle_line( $watcher_name, $line );

	return;
} ## end sub _poe_got_line

sub _poe_tail_error {
	my ( $self, $operation, $errnum, $errstr, $wheel_id ) = @_[ OBJECT, ARG0, ARG1, ARG2, ARG3 ];

	my $watcher_name = $self->{wheel_to_watcher}{$wheel_id};
	$watcher_name = 'unknown' if !defined($watcher_name);

	log_drek(
		'err',
		'tail error for the watcher "' . $watcher_name . '" during ' . $operation . '... ' . $errstr . ' (' . $errnum . ')',
		undef,
		'galla-' . $self->{name}
	);

	return;
} ## end sub _poe_tail_error

sub _poe_tail_reset {
	my ( $self, $wheel_id ) = @_[ OBJECT, ARG0 ];

	my $watcher_name = $self->{wheel_to_watcher}{$wheel_id};
	$watcher_name = 'unknown' if !defined($watcher_name);

	log_drek( 'info', 'the log of the watcher "' . $watcher_name . '" was reset... rotated?',
		undef, 'galla-' . $self->{name} );

	return;
} ## end sub _poe_tail_reset

sub _poe_sweep {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	if ( $self->{stopping} ) {
		return;
	}

	$self->_sweep;
	# in the POE state rather than _sweep as wheel handling belongs to
	# this session
	$self->_rescan_logs;

	$kernel->delay( 'sweep', 10 );

	return;
} ## end sub _poe_sweep

# tears the tail wheels down so the session can end and the kernel can exit
sub _poe_stop_tails {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		$self->{watchers}{$watcher_name}{wheels} = {};
	}
	$self->{wheel_to_watcher} = {};

	$kernel->alarm_remove_all;
	$kernel->alias_remove( 'galla-tails-' . $self->{name} );

	return;
} ## end sub _poe_stop_tails

#
# the actual line handling... plain methods so they are testable with out
# the POE side running
#

# handles a single line from the log of the specified watcher
sub _handle_line {
	my ( $self, $watcher_name, $line ) = @_;

	my $watcher = $self->{watchers}{$watcher_name};
	if ( !defined($watcher) ) {
		return;
	}

	$self->{stats}{lines}++;

	my $parsed = App::Baphomet::Parser::parse( $watcher->{parser}, $line );
	if ( !defined($parsed) ) {
		$self->{stats}{unparsed}++;
		return;
	}

	# rules are checked in order and the first to match wins, so a line
	# matching more than one rule only counts once
	foreach my $rule_obj ( @{ $watcher->{rule_objs} } ) {
		my $found = $rule_obj->check($parsed);
		if ( !defined($found) ) {
			next;
		}

		$self->{stats}{matched}++;

		foreach my $ban_var ( $rule_obj->ban_var ) {
			my $ip = $found->{data}{$ban_var};
			if ( defined($ip) ) {
				$self->_register_hit( $watcher_name, $ip );
			}
		}

		last;
	} ## end foreach my $rule_obj ( @{ $watcher->{rule_objs}...})

	return;
} ## end sub _handle_line

# registers a match of a IP, banning it once it has racked up max_retrys
# matches with in find_time seconds
sub _register_hit {
	my ( $self, $watcher_name, $ip ) = @_;

	my $settings = $self->{watchers}{$watcher_name}{settings};
	my $now      = time;

	if ( !defined( $self->{counters}{$ip} ) ) {
		$self->{counters}{$ip} = [];
	}
	push( @{ $self->{counters}{$ip} }, $now );

	# matches older than find_time no longer count
	@{ $self->{counters}{$ip} } = grep { ( $now - $_ ) < $settings->{find_time} } @{ $self->{counters}{$ip} };

	if ( scalar( @{ $self->{counters}{$ip} } ) >= $settings->{max_retrys} ) {
		delete( $self->{counters}{$ip} );
		$self->_ban_ip( $ip, $settings->{ban_time} );
	}

	return;
} ## end sub _register_hit

# consigns a IP to Kur, queueing it for retry by the sweeper if the
# Ereshkigal manager could not be reached
sub _ban_ip {
	my ( $self, $ip, $ban_time ) = @_;

	my $ident = 'galla-' . $self->{name};

	eval { $self->_send_ban( $ip, $ban_time ); };
	if ($@) {
		$self->{stats}{ban_errors}++;
		$self->{pending_bans}{$ip} = $ban_time;
		log_drek( 'err', 'consigning ' . $ip . ' to Kur failed, will retry... ' . $@, undef, $ident );
		return;
	}

	$self->{stats}{bans}++;
	delete( $self->{pending_bans}{$ip} );
	log_drek( 'info',
		'consigned ' . $ip . ' to Kur' . ( defined($ban_time) ? ' ban_time=' . $ban_time : '' ),
		undef, $ident );

	return;
} ## end sub _ban_ip

# the actual ban request to the Ereshkigal manager
sub _send_ban {
	my ( $self, $ip, $ban_time ) = @_;

	my $client = Ereshkigal::Client->new(
		'socket'  => $self->{ereshkigal_socket},
		'timeout' => $self->{timeout},
	);

	$client->call_ok(
		'ban',
		{
			'ips' => [$ip],
			'kur' => $self->{name},
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
		}
	);

	return;
} ## end sub _send_ban

# ran every ten seconds via the sweeper... retries pending bans and drops
# counter entries that have entirely aged out
sub _sweep {
	my ($self) = @_;

	foreach my $ip ( sort( keys( %{ $self->{pending_bans} } ) ) ) {
		$self->_ban_ip( $ip, $self->{pending_bans}{$ip} );
	}

	# so counters for IPs never seen again don't linger forever... any
	# still-relevant entry gets re-pruned properly on its next hit
	my $now = time;
	foreach my $ip ( keys( %{ $self->{counters} } ) ) {
		my $newest = $self->{counters}{$ip}[-1];
		# a day is comfortably past any sane find_time
		if ( !defined($newest) || ( $now - $newest ) > 86400 ) {
			delete( $self->{counters}{$ip} );
		}
	}

	return;
} ## end sub _sweep

#
# JSONUnix command handlers
#

sub _cmd_status {
	my ($self) = @_;

	my $watchers = {};
	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		my $watcher = $self->{watchers}{$watcher_name};
		$watchers->{$watcher_name} = {
			'logs'      => $watcher->{log_spec},
			'following' => [ sort( keys( %{ $watcher->{wheels} } ) ) ],
			'parser'    => $watcher->{parser},
			'rules'     => $watcher->{rules},
			'settings'  => $watcher->{settings},
		};
	}

	return {
		'name'         => $self->{name},
		'pid'          => $$,
		'uptime'       => defined( $self->{started} ) ? time - $self->{started} : 0,
		'watchers'     => $watchers,
		'stats'        => $self->{stats},
		'tracked_ips'  => scalar( keys( %{ $self->{counters} } ) ),
		'pending_bans' => [ sort( keys( %{ $self->{pending_bans} } ) ) ],
	};
} ## end sub _cmd_status

sub _cmd_stop {
	my ( $self, $ctx ) = @_;

	my $ident = 'galla-' . $self->{name};

	log_drek( 'info', 'stop requested', undef, $ident );

	# keeps the sweeper from rescheduling so it's session can end
	$self->{stopping} = 1;

	$poe_kernel->post( 'galla-tails-' . $self->{name}, 'stop_tails' );

	$ctx->respond_result( { 'stopping' => 1 } );
	$ctx->close;

	# the current session is the JSONUnix server session, so this fires its
	# shutdown state after the response has had time to flush
	$poe_kernel->delay( 'shutdown', 1 );

	return undef;
} ## end sub _cmd_stop

=head1 ERRORS CODES / ERROR FLAGS

Error handling is provided by L<Error::Helper>. All errors
are considered fatal.

=head2 1, configLoadFailed

Failed to read or parse the config file.

=head2 2, noSuchKur

The config has no kur of the specified name.

=head2 3, invalidKurDef

The def of the kur is invalid. See L<App::Baphomet::Config>.

=head2 4, NErunBaseDir

The run base dir or the galla dir under it does not exist or is not a
directory.

=head2 5, nonRWrunBaseDir

The run base dir or the galla dir under it is not readable or writable by
the current user.

=head2 6, rulesLoadFailed

Failed to load a rule referenced by a watcher... no such rule, unparsable,
uncompilable, or its embedded tests failing.

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991, or (at your
  option) any later version, matching fail2ban, which parts of this
  project, most notably the shipped rules, are derived from.

=cut

1;
