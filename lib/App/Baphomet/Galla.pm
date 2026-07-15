package App::Baphomet::Galla;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use POE                              qw( Wheel::FollowTail Wheel::Run );
use POE::Component::Server::JSONUnix ();
use File::Glob                       qw( bsd_glob );
use File::Path                       qw( make_path );
use JSON::MaybeXS                    qw( encode_json decode_json );
use POSIX                            qw( strftime );
use Sys::Hostname                    ();
use Ereshkigal::Client               ();
use App::Baphomet::Config
	qw( load_config check_kur_def kur_split resolve_settings resolve_country_codes resolve_namtar_lists resolve_active_time watcher_rules watcher_logs watcher_journal compile_ignore_ips ip_ignored );
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
counts matches per IP, and once a IP racks up max_score matches with in
find_time seconds, banishes it to Kur via the Ereshkigal manager socket.

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
				7 => 'tabletBaseDirError',
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
		rule_counters => {},
		shadow_counters => {},
		shadow_rule_counters => {},
		marks        => {},
		namtar_files => {},
		pending_bans => {},
		wheel_to_watcher => {},
		started      => undef,
		stopping     => 0,
		server       => undef,
		stats        => {
			lines       => 0,
			unparsed    => 0,
			matched     => 0,
			ignored     => 0,
			bans        => 0,
			ban_errors  => 0,
			recidivists => 0,
			per_watcher => {},
			per_rule    => {},
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
	$self->{tablet_base_dir}   = $config->{tablet_base_dir};
	$self->{ledger_keep}       = $config->{ledger_keep};
	$self->{ereshkigal_socket} = $config->{ereshkigal_socket};
	$self->{recidive}          = $config->{recidive};
	$self->{timeout}           = $config->{timeout};
	$self->{checkpoint}        = $config->{checkpoint};
	$self->{journalctl_bin}    = $config->{journalctl_bin};
	$self->{eve_log}           = $config->{eve_log};
	$self->{eve_enable}        = $config->{eve_enable};
	$self->_open_geoip( $config->{geoip_db} );
	$self->{hostname}          = Sys::Hostname::hostname();
	$self->{last_checkpoint}   = 0;
	$self->{positions}         = {};
	$self->{journal_cursors}   = {};
	$self->{wheelid_to_journal} = {};
	$self->{wheel_to_file}     = {};
	$self->{pid_to_journal}     = {};

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

	# the kur's ignore_ips extend the global ones
	my @ignore_entries = (
		@{ $config->{ignore_ips} },
		ref( $kur_settings->{ignore_ips} ) eq 'ARRAY' ? @{ $kur_settings->{ignore_ips} } : ()
	);
	$self->{ignore_ips} = compile_ignore_ips( \@ignore_entries, 'ignore_ips' );

	# internal marks your own hosts, for ban_not_internal rules that banish
	# the other end of a flow... it defaults to the ignore list at each
	# level, so what you ignore is treated as yours
	my @internal_entries = (
		( defined( $config->{internal} ) ? @{ $config->{internal} } : @{ $config->{ignore_ips} } ),
		(
			  defined( $kur_settings->{internal} )     ? @{ $kur_settings->{internal} }
			: ref( $kur_settings->{ignore_ips} ) eq 'ARRAY' ? @{ $kur_settings->{ignore_ips} }
			:                                          ()
		)
	);
	$self->{internal} = compile_ignore_ips( \@internal_entries, 'internal' );

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

	if ( !-e $self->{tablet_base_dir} ) {
		# make_path, as /var/db does not exist on every system... the
		# next check handles a failure here
		eval { make_path( $self->{tablet_base_dir} ); };
	}
	if ( !-d $self->{tablet_base_dir} || !-r $self->{tablet_base_dir} || !-w $self->{tablet_base_dir} ) {
		$self->{perror}      = 1;
		$self->{error}       = 7;
		$self->{errorString}
			= 'tablet_base_dir,"' . $self->{tablet_base_dir} . '", is not a directory or is not read/writable';
		$self->warn;
	}

	# make the EVE log's dir when enabled, so a first write does not fail
	# just for a missing dir... a unwritable one is only logged, as
	# telemetry should never take the galla down
	if ( $self->{eve_enable} ) {
		my $eve_dir = $self->{eve_log};
		$eve_dir =~ s{/[^/]*$}{};
		if ( $eve_dir ne '' && !-e $eve_dir ) {
			eval { mkdir($eve_dir); };
		}
	}

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

		# resolve each rule's country gate against this watcher's country
		# code lists... rule objects are shared across watchers but the lists
		# layer per watcher, so the resolved gate lives on the binding, not
		# the rule. a import of a undefined list is fatal, like a bad rule
		my $watcher_codes = resolve_country_codes( $config, $kur_settings, $watcher );
		my @country_gates;
		for ( my $i = 0; $i < scalar(@rule_objs); $i++ ) {
			my $gate;
			if ( defined( $rule_objs[$i] ) ) {
				eval {
					$gate = $self->_resolve_country_gate( $rule_objs[$i], $watcher_codes,
						'The rule "' . $rule_names[$i] . '" of the watcher "' . $watcher_name . '"' );
				};
				if ($@) {
					$self->{perror}      = 1;
					$self->{error}       = 6;
					$self->{errorString} = $@;
					$self->warn;
				}
			} ## end if ( defined( $rule_objs...))
			push( @country_gates, $gate );
		} ## end for ( my $i = 0; $i < scalar...)

		# and the namtar_list gates the same way... the list names resolve to
		# the watcher's file paths, the files themselves loaded and mtime
		# refreshed on the galla, not frozen here
		my $watcher_namtar = resolve_namtar_lists( $config, $kur_settings, $watcher );
		my @namtar_gates;
		for ( my $i = 0; $i < scalar(@rule_objs); $i++ ) {
			my $gate;
			if ( defined( $rule_objs[$i] ) ) {
				eval {
					$gate = $self->_resolve_namtar_gate( $rule_objs[$i], $watcher_namtar,
						'The rule "' . $rule_names[$i] . '" of the watcher "' . $watcher_name . '"' );
				};
				if ($@) {
					$self->{perror}      = 1;
					$self->{error}       = 6;
					$self->{errorString} = $@;
					$self->warn;
				}
			} ## end if ( defined( $rule_objs...))
			push( @namtar_gates, $gate );
		} ## end for ( my $i = 0; $i < scalar...)

		# and the active_time gates... the window names resolve to the
		# watcher's specs, compiled here as pure config that nothing reloads
		my $watcher_active = resolve_active_time( $config, $kur_settings, $watcher );
		my @active_gates;
		for ( my $i = 0; $i < scalar(@rule_objs); $i++ ) {
			my $gate;
			if ( defined( $rule_objs[$i] ) ) {
				eval {
					$gate = $self->_resolve_active_time_gate( $rule_objs[$i], $watcher_active,
						'The rule "' . $rule_names[$i] . '" of the watcher "' . $watcher_name . '"' );
				};
				if ($@) {
					$self->{perror}      = 1;
					$self->{error}       = 6;
					$self->{errorString} = $@;
					$self->warn;
				}
			} ## end if ( defined( $rule_objs...))
			push( @active_gates, $gate );
		} ## end for ( my $i = 0; $i < scalar...)

		my $is_journal = defined( $watcher->{journal} );
		$self->{watchers}{$watcher_name} = {
			'is_journal'      => $is_journal,
			'log_spec'        => $is_journal ? [] : [ watcher_logs($watcher) ],
			'journal_matches' => $is_journal ? [ watcher_journal($watcher) ] : [],
			'parser'          => defined( $watcher->{parser} ) ? $watcher->{parser} : ( $is_journal ? 'journal' : 'syslog' ),
			'rules'           => \@rule_names,
			'rule_objs'       => \@rule_objs,
			'country_gates'   => \@country_gates,
			'namtar_gates'    => \@namtar_gates,
			'active_gates'    => \@active_gates,
			'settings'        => resolve_settings( $config, $kur_settings, $watcher ),
			'wheels'          => {},
			'journal_wheel'   => undef,
			'journal_delay'   => 1,
			'journal_spawned' => undef,
		};
	} ## end foreach my $watcher_name ( sort( keys( %{$watchers...})))

	# a country gate with no GeoIP database behind it fails closed, so those
	# rules banish nobody... that is a silent hole, so say so loudly. not a
	# perror, the galla runs fine, the gated rules just never fire
	my $country_gated = 0;
	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		foreach my $gate ( @{ $self->{watchers}{$watcher_name}{country_gates} } ) {
			if ( defined($gate) ) {
				$country_gated = 1;
			}
		}
	}
	if ( $country_gated && !defined( $self->{geoip} ) ) {
		log_drek(
			'err',
			'country-gated rules are configured but no GeoIP database is loaded'
				. ( defined( $self->{geoip_error} ) ? '... ' . $self->{geoip_error} : '... geoip_db is unset' )
				. '... those gates fail closed and will banish nobody',
			undef,
			'galla-' . $self->{name}
		);
	} ## end if ( $country_gated && !defined...)

	# load every namtar list slot the gates reference once, up front... the
	# sweeper refreshes them on mtime change from here on. a slot that loads
	# empty or unreadable matches nobody, so those gates banish nobody from
	# it... a silent hole, so name them loudly
	my %namtar_slots;
	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		foreach my $gate ( @{ $self->{watchers}{$watcher_name}{namtar_gates} } ) {
			if ( !defined($gate) ) {
				next;
			}
			foreach my $entry ( @{$gate} ) {
				foreach my $slot ( @{ $entry->{slots} } ) {
					$namtar_slots{ join( "\0", $slot->{type}, $slot->{nocase}, $slot->{path} ) } = $slot;
				}
			}
		} ## end foreach my $gate ( @{ $self...})
	} ## end foreach my $watcher_name ( keys...)
	foreach my $key ( sort( keys(%namtar_slots) ) ) {
		my $slot = $namtar_slots{$key};
		$self->_load_namtar_file( $slot->{type}, $slot->{nocase}, $slot->{path} );
	}
	my @empty = grep {
		my $set = $self->{namtar_files}{$_}{set};
		ref($set) eq 'HASH' ? !%{$set} : !@{$set};
	} sort( keys(%namtar_slots) );
	if (@empty) {
		my @paths = map { $self->{namtar_files}{$_}{path} } @empty;
		log_drek( 'err', 'these namtar list files loaded empty or unreadable, gates matching them banish nobody... '
				. join( ', ', @paths ),
			undef, 'galla-' . $self->{name} );
	} ## end if (@empty)

	# bring back the tablets... counters, pending bans, stats, correlation
	# context, and log positions from the last run
	$self->_load_state;

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

=head2 state_path

Returns the path of a state tablet of the given kind for this instance.

    my $path = $galla->state_path('counters');

=cut

sub state_path {
	my ( $self, $kind ) = @_;

	my $suffix = ( $kind eq 'context' || $kind eq 'stats' ) ? 'jsonl' : 'csv';

	return $self->{tablet_base_dir} . '/galla.' . $self->{name} . '.' . $kind . '.' . $suffix;
}

# writes a tablet atomically via a temp file and rename, calling $writer
# with the open filehandle... logs and swallows errors, as a failed
# checkpoint should not take the galla down
sub _write_tablet {
	my ( $self, $kind, $writer ) = @_;

	my $path = $self->state_path($kind);
	eval {
		my $tmp = $path . '.tmp';
		open( my $fh, '>', $tmp ) || die( 'open failed... ' . $! );
		$writer->($fh);
		close($fh);
		rename( $tmp, $path ) || die( 'rename failed... ' . $! );
	};
	if ($@) {
		log_drek( 'err', 'writing the ' . $kind . ' tablet "' . $path . '" failed... ' . $@,
			undef, 'galla-' . $self->{name} );
	}

	return;
} ## end sub _write_tablet

# reads a tablet's lines, returning them chomped... a missing tablet is
# just a empty list, a unreadable one is logged
sub _read_tablet {
	my ( $self, $kind ) = @_;

	my $path = $self->state_path($kind);
	if ( !-f $path ) {
		return ();
	}

	my @lines;
	eval {
		open( my $fh, '<', $path ) || die( 'open failed... ' . $! );
		@lines = <$fh>;
		close($fh);
	};
	if ($@) {
		log_drek( 'err', 'reading the ' . $kind . ' tablet "' . $path . '" failed... ' . $@,
			undef, 'galla-' . $self->{name} );
		return ();
	}

	chomp(@lines);
	return @lines;
} ## end sub _read_tablet

=head2 checkpoint

Writes the state tablets out now... the counters, the pending bans, the
running stats, the correlation context, the marks, and the log positions.
Called periodically by the sweeper and on stop.

    $galla->checkpoint;

=cut

sub checkpoint {
	my ($self) = @_;

	my $now = time;

	# counters... ip,hit_epoch,weight,rule one row per live hit, rule empty
	# for the shared bucket and the rule name for a per-rule bucket... rule
	# names can not hold a comma, so no quoting is needed. the shadow buckets
	# of observe mode are ephemeral and never chiseled. old three-column rows
	# without a weight restore fine, weighing 1
	$self->_write_tablet(
		'counters',
		sub {
			my ($fh) = @_;
			print $fh "ip,hit,weight,rule\n";
			foreach my $ip ( sort( keys( %{ $self->{counters} } ) ) ) {
				foreach my $entry ( @{ $self->{counters}{$ip} } ) {
					print $fh $ip . ',' . $entry->[0] . ',' . $entry->[1] . ",\n";
				}
			}
			foreach my $rule_name ( sort( keys( %{ $self->{rule_counters} } ) ) ) {
				foreach my $ip ( sort( keys( %{ $self->{rule_counters}{$rule_name} } ) ) ) {
					foreach my $entry ( @{ $self->{rule_counters}{$rule_name}{$ip} } ) {
						print $fh $ip . ',' . $entry->[0] . ',' . $entry->[1] . ',' . $rule_name . "\n";
					}
				}
			}
		}
	);

	# pending bans... ip,ban_time, ban_time empty meaning undef
	$self->_write_tablet(
		'pending',
		sub {
			my ($fh) = @_;
			print $fh "ip,ban_time\n";
			foreach my $ip ( sort( keys( %{ $self->{pending_bans} } ) ) ) {
				print $fh $ip . ',' . ( defined( $self->{pending_bans}{$ip} ) ? $self->{pending_bans}{$ip} : '' ) . "\n";
			}
		}
	);

	# log positions... file,inode,offset
	$self->_write_tablet(
		'positions',
		sub {
			my ($fh) = @_;
			print $fh "file,inode,offset\n";
			$self->_snapshot_positions;
			foreach my $file ( sort( keys( %{ $self->{positions} } ) ) ) {
				my $pos = $self->{positions}{$file};
				print $fh _csv_escape($file) . ',' . $pos->{inode} . ',' . $pos->{offset} . "\n";
			}
		}
	);

	# journal cursors... watcher,cursor, so a restart resumes the journal
	# just after the last line seen rather than from now
	$self->_write_tablet(
		'cursors',
		sub {
			my ($fh) = @_;
			print $fh "watcher,cursor\n";
			foreach my $watcher_name ( sort( keys( %{ $self->{journal_cursors} } ) ) ) {
				my $cursor = $self->{journal_cursors}{$watcher_name};
				if ( defined($cursor) && $cursor ne '' ) {
					print $fh _csv_escape($watcher_name) . ',' . _csv_escape($cursor) . "\n";
				}
			}
		}
	);

	# the running stats, one JSON line, so the totals mean since first
	# loosing rather than since the last respawn
	$self->_write_tablet(
		'stats',
		sub {
			my ($fh) = @_;
			print $fh encode_json( $self->{stats} ) . "\n";
		}
	);

	# correlation context, structured so JSON lines... one rule per line
	$self->_write_tablet(
		'context',
		sub {
			my ($fh) = @_;
			my %seen;
			foreach my $watcher_name ( sort( keys( %{ $self->{watchers} } ) ) ) {
				my $rules = $self->{watchers}{$watcher_name}{rules};
				my $objs  = $self->{watchers}{$watcher_name}{rule_objs};
				for ( my $i = 0; $i < scalar( @{$objs} ); $i++ ) {
					my $rule_obj = $objs->[$i];
					my $rule_name = $rules->[$i];
					if ( !defined($rule_obj) || $seen{$rule_name} ) {
						next;
					}
					$seen{$rule_name} = 1;
					my $state = $rule_obj->dump_state;
					if ( defined($state) ) {
						print $fh encode_json( { 'rule' => $rule_name, 'state' => $state } ) . "\n";
					}
				} ## end for ( my $i = 0; $i < scalar...)
			} ## end foreach my $watcher_name ( sort( keys( %{ $self...})))
		}
	);

	# marks... one JSON line per branded key, name,key,expires and the
	# stored value when there is one. unlike counters and correlation
	# these survive a restart by design, as ttls of a week are legitimate
	$self->_write_tablet(
		'marks',
		sub {
			my ($fh) = @_;
			foreach my $mark_name ( sort( keys( %{ $self->{marks} } ) ) ) {
				my $store = $self->{marks}{$mark_name};
				foreach my $key ( sort( keys( %{$store} ) ) ) {
					print $fh encode_json(
						{
							'name'    => $mark_name,
							'key'     => $key,
							'expires' => $store->{$key}{expires},
							exists( $store->{$key}{value} ) ? ( 'value' => $store->{$key}{value} ) : (),
						}
					) . "\n";
				} ## end foreach my $key ( sort( keys...))
			} ## end foreach my $mark_name ( sort...)
		}
	);

	$self->{last_checkpoint} = $now;

	return;
} ## end sub checkpoint

# records the current tell and inode of every followed file into the
# positions map, so a checkpoint reflects where the wheels actually are
sub _snapshot_positions {
	my ($self) = @_;

	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		my $watcher = $self->{watchers}{$watcher_name};
		foreach my $file ( keys( %{ $watcher->{wheels} } ) ) {
			my $wheel = $watcher->{wheels}{$file};
			my $offset;
			eval { $offset = $wheel->tell; };
			my $inode = ( stat($file) )[1];
			if ( defined($offset) && defined($inode) ) {
				$self->{positions}{$file} = { 'inode' => $inode, 'offset' => $offset };
			}
		} ## end foreach my $file ( keys( %{ $watcher->{wheels...}}))
	} ## end foreach my $watcher_name ( keys( %{ $self->{watchers...}}))

	return;
} ## end sub _snapshot_positions

# loads the tablets back at start... counters and pending bans pruned to
# what is still relevant, correlation context restored into the rules,
# marks restored and pruned of the expired, and log positions kept for
# start_server to seek to
sub _load_state {
	my ($self) = @_;

	my $now = time;

	# counters... a weight column then the per-rule bucket name, both added
	# later. a four-field row is the current ip,hit,weight,rule form; a
	# three-field row is the older ip,hit,rule, its hit weighing 1; rows from
	# before per-rule thresholds land in the shared bucket like they always
	# did. split with a limit so a trailing empty rule field is kept
	my $line_int = 0;
	foreach my $line ( $self->_read_tablet('counters') ) {
		$line_int++;
		if ( ( $line_int == 1 && $line =~ /^ip,/ ) || $line eq '' ) {
			next;
		}
		my @field = split( /,/, $line, 4 );
		my ( $ip, $hit ) = @field[ 0, 1 ];
		my ( $weight, $rule_name );
		if ( scalar(@field) >= 4 ) {
			( $weight, $rule_name ) = @field[ 2, 3 ];
		} else {
			( $weight, $rule_name ) = ( 1, $field[2] );
		}
		if ( !defined($ip) || !defined($hit) || $hit !~ /^[0-9]+$/ ) {
			next;
		}
		if ( !defined($weight) || $weight !~ /^[0-9]+(?:\.[0-9]+)?$/ || $weight + 0 <= 0 ) {
			$weight = 1;
		}
		if ( defined($rule_name) && $rule_name ne '' ) {
			push( @{ $self->{rule_counters}{$rule_name}{$ip} }, [ $hit + 0, $weight + 0 ] );
		} else {
			push( @{ $self->{counters}{$ip} }, [ $hit + 0, $weight + 0 ] );
		}
	} ## end foreach my $line ( $self->_read_tablet...)
	# sort each by epoch and drop entries with nothing recent... the register
	# path re-prunes per the effective find_time on the next hit
	foreach my $bucket ( $self->{counters}, values( %{ $self->{rule_counters} } ) ) {
		foreach my $ip ( keys( %{$bucket} ) ) {
			my @sorted = sort { $a->[0] <=> $b->[0] } @{ $bucket->{$ip} };
			if ( !@sorted || ( $now - $sorted[-1][0] ) > 86400 ) {
				delete( $bucket->{$ip} );
			} else {
				$bucket->{$ip} = \@sorted;
			}
		}
	} ## end foreach my $bucket ( $self->{counters}, values...)
	foreach my $rule_name ( keys( %{ $self->{rule_counters} } ) ) {
		if ( !%{ $self->{rule_counters}{$rule_name} } ) {
			delete( $self->{rule_counters}{$rule_name} );
		}
	}

	# pending bans
	$line_int = 0;
	foreach my $line ( $self->_read_tablet('pending') ) {
		$line_int++;
		if ( ( $line_int == 1 && $line =~ /^ip,/ ) || $line eq '' ) {
			next;
		}
		my ( $ip, $ban_time ) = split( /,/, $line );
		if ( !defined($ip) || $ip eq '' ) {
			next;
		}
		$self->{pending_bans}{$ip} = ( defined($ban_time) && $ban_time =~ /^[0-9]+$/ ) ? $ban_time + 0 : undef;
	} ## end foreach my $line ( $self->_read_tablet...)

	# log positions
	$line_int = 0;
	foreach my $line ( $self->_read_tablet('positions') ) {
		$line_int++;
		if ( ( $line_int == 1 && $line =~ /^file,/ ) || $line eq '' ) {
			next;
		}
		# inode and offset are trailing digit columns, so pull them from
		# the end and leave whatever is left as the file, which may carry
		# a comma inside quotes
		if ( $line !~ /^(.*),([0-9]+),([0-9]+)$/ ) {
			next;
		}
		my ( $file, $inode, $offset ) = ( _csv_unescape($1), $2, $3 );
		if ( !defined($file) || $file eq '' ) {
			next;
		}
		$self->{positions}{$file} = { 'inode' => $inode + 0, 'offset' => $offset + 0 };
	} ## end foreach my $line ( $self->_read_tablet...)

	# journal cursors
	$line_int = 0;
	foreach my $line ( $self->_read_tablet('cursors') ) {
		$line_int++;
		if ( ( $line_int == 1 && $line =~ /^watcher,/ ) || $line eq '' ) {
			next;
		}
		my ( $watcher_name, $cursor ) = split( /,/, $line, 2 );
		$watcher_name = _csv_unescape($watcher_name);
		$cursor       = _csv_unescape($cursor);
		# only for a watcher that still exists and is still a journal one
		if (   defined($watcher_name)
			&& defined($cursor)
			&& defined( $self->{watchers}{$watcher_name} )
			&& $self->{watchers}{$watcher_name}{is_journal} )
		{
			$self->{journal_cursors}{$watcher_name} = $cursor;
		}
	} ## end foreach my $line ( $self->_read_tablet...)

	# stats... take the stored totals, but only shapes and numbers that
	# make sense, as the tablet may be from a older format
	foreach my $line ( $self->_read_tablet('stats') ) {
		if ( $line eq '' ) {
			next;
		}
		my $decoded;
		eval { $decoded = decode_json($line); };
		if ( ref($decoded) ne 'HASH' ) {
			next;
		}
		foreach my $key ( keys( %{ $self->{stats} } ) ) {
			if ( !defined( $decoded->{$key} ) ) {
				next;
			}
			if ( ref( $self->{stats}{$key} ) eq 'HASH' ) {
				if ( ref( $decoded->{$key} ) eq 'HASH' ) {
					$self->{stats}{$key} = $decoded->{$key};
				}
			} elsif ( ref( $decoded->{$key} ) eq '' && $decoded->{$key} =~ /^[0-9]+$/ ) {
				$self->{stats}{$key} = $decoded->{$key} + 0;
			}
		} ## end foreach my $key ( keys( %{ $self->{stats} } ) )
		last;
	} ## end foreach my $line ( $self->_read_tablet...)

	# correlation context
	foreach my $line ( $self->_read_tablet('context') ) {
		if ( $line eq '' ) {
			next;
		}
		my $decoded;
		eval { $decoded = decode_json($line); };
		if ( ref($decoded) ne 'HASH' || !defined( $decoded->{rule} ) ) {
			next;
		}
		my $rule_obj;
		eval { $rule_obj = $self->{rules}->load( $decoded->{rule} ); };
		if ( defined($rule_obj) ) {
			$rule_obj->restore_state( $decoded->{state}, $now );
		}
	} ## end foreach my $line ( $self->_read_tablet...)

	# marks, restored whole and pruned of anything already expired
	foreach my $line ( $self->_read_tablet('marks') ) {
		if ( $line eq '' ) {
			next;
		}
		my $decoded;
		eval { $decoded = decode_json($line); };
		if ( ref($decoded) ne 'HASH'
			|| !defined( $decoded->{name} )
			|| !defined( $decoded->{key} )
			|| !defined( $decoded->{expires} )
			|| $decoded->{expires} !~ /^[0-9]+$/
			|| $decoded->{expires} <= $now )
		{
			next;
		}
		$self->{marks}{ $decoded->{name} }{ $decoded->{key} }
			= { 'expires' => $decoded->{expires} + 0, exists( $decoded->{value} ) ? ( 'value' => $decoded->{value} ) : () };
	} ## end foreach my $line ( $self->_read_tablet...)

	return;
} ## end sub _load_state

# figures out where a fresh wheel on a file should start... the saved
# offset if the file is the same one and has not shrunk, else the top for
# a rotated file, else undef for a file with no saved position
sub _seek_for {
	my ( $self, $file ) = @_;

	my $pos = $self->{positions}{$file};
	if ( !defined($pos) || !-f $file ) {
		return undef;
	}

	my ( $inode, $size ) = ( stat($file) )[ 1, 7 ];
	if ( !defined($inode) ) {
		return undef;
	}

	if ( $inode == $pos->{inode} && $size >= $pos->{offset} ) {
		# same file, lines may have been written while down... resume
		return $pos->{offset};
	}

	# rotated or truncated... start from the top of the new file
	return 0;
} ## end sub _seek_for

sub _csv_escape {
	my ($value) = @_;

	# file paths with a comma or newline would break the simple CSV
	if ( $value =~ /[,"\n]/ ) {
		$value =~ s/"/""/g;
		return '"' . $value . '"';
	}
	return $value;
} ## end sub _csv_escape

sub _csv_unescape {
	my ($value) = @_;

	if ( defined($value) && $value =~ /^"(.*)"$/ ) {
		$value = $1;
		$value =~ s/""/"/g;
	}
	return $value;
} ## end sub _csv_unescape

# emits a event to the EVE log... a no-op unless eve_enable is on... the
# passed fields are merged over the common envelope, and a banish or
# found event_type carries eve_type baphomet for downstream tooling
sub _eve_emit {
	my ( $self, $event_type, $fields ) = @_;

	if ( !$self->{eve_enable} ) {
		return;
	}

	my $record = {
		'eve_type'   => 'baphomet',
		'event_type' => $event_type,
		'timestamp'  => strftime( '%Y-%m-%dT%H:%M:%S%z', localtime(time) ),
		'hostname'   => $self->{hostname},
		'kur'        => $self->{name},
		%{$fields},
	};

	my $line;
	eval { $line = encode_json($record); };
	if ($@) {
		log_drek( 'err', 'encoding a EVE event failed... ' . $@, undef, 'galla-' . $self->{name} );
		return;
	}

	# open, lock, append, close per event... atomic across the gallas
	# sharing the one file and correct under a log rotation
	eval {
		open( my $fh, '>>', $self->{eve_log} ) || die( 'open failed... ' . $! );
		flock( $fh, 2 ) || die( 'lock failed... ' . $! );    # LOCK_EX
		print $fh $line . "\n";
		close($fh);
	};
	if ($@) {
		log_drek( 'err', 'writing to the EVE log "' . $self->{eve_log} . '" failed... ' . $@,
			undef, 'galla-' . $self->{name} );
	}

	return;
} ## end sub _eve_emit

# the parsed representation for a EVE event... the parsed JSON it's self
# for the JSON parsers, the field hash otherwise
sub _eve_parsed {
	my ( $self, $parsed ) = @_;

	if ( ref($parsed) eq 'HASH' && ref( $parsed->{fields} ) eq 'HASH' ) {
		return $parsed->{fields};
	}

	return $parsed;
} ## end sub _eve_parsed

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

    - accused :: The IPs currently accumulating offenses but not yet
          banished... per IP the live hit count and the epochs of the
          first and last hit, across every bucket. A IP counted by a
          rule carrying its own thresholds also gets a rules hash
          breaking those buckets out.

    - marked :: The live marks, per mark name a hash of the branded keys,
          each with its expiry and, when the rule harvested one, the
          stored value.

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
			'accused' => sub {
				return $self->_cmd_accused;
			},
			'marked' => sub {
				return $self->_cmd_marked;
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
				'_start'         => '_poe_start',
				'got_line'       => '_poe_got_line',
				'tail_error'     => '_poe_tail_error',
				'tail_reset'     => '_poe_tail_reset',
				'journal_stdout' => '_poe_journal_stdout',
				'journal_stderr' => '_poe_journal_stderr',
				'journal_reaped' => '_poe_journal_reaped',
				'restart_journal' => '_poe_restart_journal',
				'sweep'          => '_poe_sweep',
				'stop_tails'     => '_poe_stop_tails',
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
		if ( $self->{watchers}{$watcher_name}{is_journal} ) {
			$self->_start_journal($watcher_name);
			next;
		}

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

	# resume from the saved offset if this is the same file it was, so
	# lines written while the galla was down are not missed
	my $seek = $self->_seek_for($file);

	my $wheel = POE::Wheel::FollowTail->new(
		'Filename'   => $file,
		'InputEvent' => 'got_line',
		'ErrorEvent' => 'tail_error',
		'ResetEvent' => 'tail_reset',
		defined($seek) ? ( 'Seek' => $seek ) : (),
	);

	if ( defined($seek) ) {
		log_drek( 'info', 'resuming "' . $file . '" at offset ' . $seek . ' for the watcher "' . $watcher_name . '"',
			undef, $ident );
	}

	$watcher->{wheels}{$file} = $wheel;
	$self->{wheel_to_watcher}{ $wheel->ID } = $watcher_name;
	$self->{wheel_to_file}{ $wheel->ID }    = $file;

	log_drek( 'info', 'following "' . $file . '" for the watcher "' . $watcher_name . '"', undef, $ident );

	return;
} ## end sub _start_tail

# builds the journalctl command for a journal watcher... follow mode, JSON
# output, the saved cursor if there is one, and the watcher's matches
sub _journal_cmd {
	my ( $self, $watcher_name ) = @_;

	my @cmd = ( $self->{journalctl_bin}, '--follow', '--output', 'json' );

	my $cursor = $self->{journal_cursors}{$watcher_name};
	if ( defined($cursor) && $cursor ne '' ) {
		# resume just after where we left off so nothing is re-processed
		push( @cmd, '--after-cursor', $cursor );
	} else {
		# a fresh start reads only from now, not the whole history
		push( @cmd, '--lines', '0' );
	}

	push( @cmd, @{ $self->{watchers}{$watcher_name}{journal_matches} } );

	return @cmd;
} ## end sub _journal_cmd

# starts a journalctl for a journal watcher... must be called from with in
# the tailing session, as the wheel belongs to it
sub _start_journal {
	my ( $self, $watcher_name ) = @_;

	my $ident   = 'galla-' . $self->{name};
	my $watcher = $self->{watchers}{$watcher_name};

	if ( defined( $watcher->{journal_wheel} ) || $self->{stopping} ) {
		return;
	}

	my @cmd = $self->_journal_cmd($watcher_name);

	my $wheel = POE::Wheel::Run->new(
		'Program'     => \@cmd,
		'StdoutEvent' => 'journal_stdout',
		'StderrEvent' => 'journal_stderr',
	);
	$poe_kernel->sig_child( $wheel->PID, 'journal_reaped' );

	$watcher->{journal_wheel}   = $wheel;
	$watcher->{journal_spawned} = time;
	$self->{wheelid_to_journal}{ $wheel->ID }  = $watcher_name;
	$self->{pid_to_journal}{ $wheel->PID }     = $watcher_name;

	log_drek( 'info', 'following the journal for the watcher "' . $watcher_name . '"... ' . join( ' ', @cmd ),
		undef, $ident );

	return;
} ## end sub _start_journal

sub _poe_journal_stdout {
	my ( $self, $line, $wheel_id ) = @_[ OBJECT, ARG0, ARG1 ];

	my $watcher_name = $self->{wheelid_to_journal}{$wheel_id};
	if ( !defined($watcher_name) ) {
		return;
	}

	chomp($line);

	# grab the cursor for a clean resume before handing the line off... a
	# cheap targeted pull rather than a full decode
	if ( $line =~ /"__CURSOR"\s*:\s*"((?:[^"\\]|\\.)*)"/ ) {
		my $cursor = $1;
		$cursor =~ s/\\(["\\])/$1/g;
		$self->{journal_cursors}{$watcher_name} = $cursor;
	}

	# the source for the EVE log... a journal watcher has no file
	my $matches = $self->{watchers}{$watcher_name}{journal_matches};
	my $source = 'journal' . ( @{$matches} ? ':' . join( ',', @{$matches} ) : '' );

	$self->_handle_line( $watcher_name, $line, $source );

	return;
} ## end sub _poe_journal_stdout

sub _poe_journal_stderr {
	my ( $self, $line, $wheel_id ) = @_[ OBJECT, ARG0, ARG1 ];

	my $watcher_name = $self->{wheelid_to_journal}{$wheel_id};
	$watcher_name = 'unknown' if !defined($watcher_name);
	chomp($line);
	log_drek( 'err', 'journalctl for the watcher "' . $watcher_name . '" said... ' . $line,
		undef, 'galla-' . $self->{name} );

	return;
} ## end sub _poe_journal_stderr

sub _poe_journal_reaped {
	my ( $self, $kernel, $pid ) = @_[ OBJECT, KERNEL, ARG1 ];

	my $watcher_name = delete( $self->{pid_to_journal}{$pid} );
	if ( !defined($watcher_name) ) {
		return;
	}

	my $watcher = $self->{watchers}{$watcher_name};
	if ( defined( $watcher->{journal_wheel} ) ) {
		delete( $self->{wheelid_to_journal}{ $watcher->{journal_wheel}->ID } );
		$watcher->{journal_wheel} = undef;
	}

	if ( $self->{stopping} ) {
		return;
	}

	# ran a while so it was working... reset the backoff
	if ( defined( $watcher->{journal_spawned} ) && ( time - $watcher->{journal_spawned} ) > 60 ) {
		$watcher->{journal_delay} = 1;
	}
	my $delay = $watcher->{journal_delay};
	$watcher->{journal_delay} = $delay * 2 > 60 ? 60 : $delay * 2;

	log_drek( 'err',
		'journalctl for the watcher "' . $watcher_name . '" exited, restarting in ' . $delay . ' seconds',
		undef, 'galla-' . $self->{name} );

	$kernel->delay_set( 'restart_journal', $delay, $watcher_name );

	return;
} ## end sub _poe_journal_reaped

sub _poe_restart_journal {
	my ( $self, $watcher_name ) = @_[ OBJECT, ARG0 ];

	$self->_start_journal($watcher_name);

	return;
}

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

		# journal watchers follow no files, so there is nothing to rescan
		if ( $watcher->{is_journal} ) {
			next;
		}

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
				delete( $self->{wheel_to_file}{ $wheel->ID } );
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

	$self->_handle_line( $watcher_name, $line, $self->{wheel_to_file}{$wheel_id} );

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

	# checkpoint the tablets on the configured cadence
	if ( $self->{checkpoint} && ( time - $self->{last_checkpoint} ) >= $self->{checkpoint} ) {
		$self->checkpoint;
	}

	$kernel->delay( 'sweep', 10 );

	return;
} ## end sub _poe_sweep

# tears the tail wheels down so the session can end and the kernel can exit
sub _poe_stop_tails {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		my $watcher = $self->{watchers}{$watcher_name};
		$watcher->{wheels} = {};
		if ( defined( $watcher->{journal_wheel} ) ) {
			$watcher->{journal_wheel}->kill('TERM');
			$watcher->{journal_wheel} = undef;
		}
	}
	$self->{wheel_to_watcher}   = {};
	$self->{wheel_to_file}      = {};
	$self->{wheelid_to_journal} = {};
	$self->{pid_to_journal}     = {};

	$kernel->alarm_remove_all;
	$kernel->alias_remove( 'galla-tails-' . $self->{name} );

	return;
} ## end sub _poe_stop_tails

#
# the actual line handling... plain methods so they are testable with out
# the POE side running
#

# ticks a stat by name... the galla-wide count always, plus the per
# watcher and per rule breakdowns when those are known
sub _tick {
	my ( $self, $key, $watcher_name, $rule_name ) = @_;

	$self->{stats}{$key}++;
	if ( defined($watcher_name) ) {
		$self->{stats}{per_watcher}{$watcher_name}{$key}++;
	}
	if ( defined($rule_name) ) {
		$self->{stats}{per_rule}{$rule_name}{$key}++;
	}

	return;
} ## end sub _tick

# handles a single line from the log of the specified watcher
sub _handle_line {
	my ( $self, $watcher_name, $line, $source ) = @_;

	my $watcher = $self->{watchers}{$watcher_name};
	if ( !defined($watcher) ) {
		return;
	}

	$self->_tick( 'lines', $watcher_name );

	my $parsed = App::Baphomet::Parser::parse( $watcher->{parser}, $line );
	if ( !defined($parsed) ) {
		$self->_tick( 'unparsed', $watcher_name );
		return;
	}

	my $now = time;

	# rules are checked in order and the first to match wins, so a line
	# matching more than one rule only counts once... except a rule whose
	# mark gates veto and a mark_only rule that only brands do not consume
	# the line, so matching falls through to the later rules. the watcher
	# name scopes any correlation state, as keys like conn ids are only
	# unique with in one log
	for ( my $rule_int = 0; $rule_int < scalar( @{ $watcher->{rule_objs} } ); $rule_int++ ) {
		my $rule_obj  = $watcher->{rule_objs}[$rule_int];
		my $rule_name = $watcher->{rules}[$rule_int];
		my $found     = $rule_obj->check( $parsed, $watcher_name );
		if ( !defined($found) ) {
			next;
		}

		my $gates        = $rule_obj->mark_gates;
		my $mark_only    = $rule_obj->mark_only;
		my $country_gate = $watcher->{country_gates}[$rule_int];
		my $namtar_gate  = $watcher->{namtar_gates}[$rule_int];
		my $active_gate  = $watcher->{active_gates}[$rule_int];

		# observe mode... the rule's own eve_only wins over the watcher-resolved
		# one, so a deployment can be set observe at any level and trusted rules
		# opt back in. observe_ignored, a watcher setting, lets observe mode
		# also watch what ignore_ips would drop
		my $rule_eve_only = $rule_obj->eve_only;
		my $eve_only        = defined($rule_eve_only) ? $rule_eve_only : $watcher->{settings}{eve_only};
		my $observe_ignored = $watcher->{settings}{observe_ignored};

		# a capture line may have completed several deferred offenses
		my @all_found = ( $found, ref( $found->{more} ) eq 'ARRAY' ? @{ $found->{more} } : () );
		my $consumed  = 0;
		foreach my $one (@all_found) {
			# the var-keyed mark gates and a vars country gate are data-driven
			# and vet the whole result... a veto means the rule did not really
			# fire, so it neither counts nor consumes the line
			if ( !$self->_mark_gates_pass( $gates, $one->{data}, undef, $now ) ) {
				next;
			}
			if ( !$self->_country_gate_pass( $country_gate, $one->{data}, undef ) ) {
				next;
			}
			if ( !$self->_namtar_gate_pass( $namtar_gate, $one->{data}, undef ) ) {
				next;
			}
			if ( !$self->_active_time_pass( $active_gate, $one->{data}, $now ) ) {
				next;
			}

			$self->_tick( 'matched', $watcher_name, $rule_name );

			# the EVE context for this match, shared by the found event and
			# any banish it triggers... watcher and rule_name ride along
			# for the stats and the ledger. the effective severity is the
			# rule's own or, absent that, the watcher-resolved default_severity
			my $context = {
				'source'    => $source,
				'raw'       => $line,
				'parsed'    => $parsed,
				'found'     => $one->{data},
				'rule'      => $rule_obj,
				'rule_name' => $rule_name,
				'watcher'   => $watcher_name,
				'severity'  => defined( $rule_obj->severity ) ? $rule_obj->severity : $watcher->{settings}{default_severity},
			};

			# a ban_not_internal rule banishes the end of the flow that is
			# not one of ours... the offender may be the src or the dest
			# depending on where the alert fired
			my $not_internal = $rule_obj->ban_not_internal;

			# the offenders this result would banish... the ban_vars that
			# captured a IP that is not one of our own. also who the var-less
			# marks brand and the var-less gates key by
			my @offenders;
			foreach my $ban_var ( $rule_obj->ban_var ) {
				my $ip = $one->{data}{$ban_var};
				if ( !defined($ip) ) {
					next;
				}
				if ( $not_internal && ip_ignored( $self->{internal}, $ip ) ) {
					# ip_ignored is a plain set membership test... here it is
					# the internal set, so this IP is ours, not the offender
					next;
				}
				push( @offenders, $ip );
			} ## end foreach my $ban_var ( $rule_obj...)

			my ( $set, $lifted ) = $self->_apply_marks( $rule_obj, $one->{data}, \@offenders, $now );

			my $score;
			if ( !$mark_only ) {
				# a firing non-mark_only rule consumes the line, same as
				# before marks, whichever offenders the gates then let count
				$consumed = 1;
				foreach my $ip (@offenders) {
					if ( !$self->_mark_gates_pass( $gates, $one->{data}, $ip, $now ) ) {
						next;
					}
					if ( !$self->_country_gate_pass( $country_gate, $one->{data}, $ip ) ) {
						next;
					}
					if ( !$self->_namtar_gate_pass( $namtar_gate, $one->{data}, $ip ) ) {
						next;
					}
					my $registered = $self->_register_hit( $watcher_name, $ip, $context, $eve_only, $observe_ignored );
					if ( !defined($score) && defined($registered) ) {
						$score = $registered;
					}
				}
			} ## end if ( !$mark_only )

			# observe mode colors the match event noted, not found
			$self->_eve_emit( $eve_only ? 'noted' : 'found', $self->_eve_fields( $context, $score, $set, $lifted ) );
		} ## end foreach my $one (@all_found)

		if ($consumed) {
			last;
		}
	} ## end for ( my $rule_int = 0; $rule_int < scalar...)

	return;
} ## end sub _handle_line

# builds the raw/parsed/found/rule/path/score fields of a EVE event from a
# match context... only assembled when the EVE log is on. score is the
# offender's accumulated weighted score, equal to the raw hit tally when no
# weights are in play
sub _eve_fields {
	my ( $self, $context, $score, $set, $lifted ) = @_;

	if ( !$self->{eve_enable} ) {
		return {};
	}

	return {
		defined( $context->{source} ) ? ( 'path' => $context->{source} ) : (),
		'raw'    => $context->{raw},
		'parsed' => $self->_eve_parsed( $context->{parsed} ),
		'found'  => $context->{found},
		'msg'    => $context->{rule}->msg,
		'rule'   => $context->{rule}->info,
		defined( $context->{severity} )     ? ( 'severity'   => $context->{severity} )         : (),
		defined( $context->{rule}->classtype )  ? ( 'classtype'  => $context->{rule}->classtype )  : (),
		defined( $context->{rule}->references ) ? ( 'references' => $context->{rule}->references ) : (),
		defined( $context->{rule}->attack )     ? ( 'attack'     => $context->{rule}->attack )     : (),
		defined($score) ? ( 'score' => $score ) : (),
		( defined($set)    && @{$set} )    ? ( 'marks_set' => $set )    : (),
		( defined($lifted) && @{$lifted} ) ? ( 'unmarked'  => $lifted ) : (),
	};
} ## end sub _eve_fields

# opens the GeoIP database for country gating, if one is configured...
# stores the reader on success, a error string otherwise, both undef when
# no path is set. a missing database is not fatal, the gates fail closed
sub _open_geoip {
	my ( $self, $path ) = @_;

	$self->{geoip}       = undef;
	$self->{geoip_error} = undef;
	if ( !defined($path) ) {
		return;
	}

	eval {
		require IP::Geolocation::MMDB;
		$self->{geoip} = IP::Geolocation::MMDB->new( 'file' => $path );
	};
	if ($@) {
		$self->{geoip_error} = $@;
		$self->{geoip_error} =~ s/\s+at\s+\S+\s+line\s+\d+\.?\s*$//;
	}

	return;
} ## end sub _open_geoip

# the uppercased ISO country code of a IP per the GeoIP database, or undef
# when there is no database, the value is not a locatable address, or it
# carries no country... a country lookup dies on a bad address, so eval it
sub _country_of {
	my ( $self, $ip ) = @_;

	if ( !defined( $self->{geoip} ) || !defined($ip) ) {
		return undef;
	}

	my $record;
	eval { $record = $self->{geoip}->record_for_address($ip); };
	if ( $@ || ref($record) ne 'HASH' || ref( $record->{country} ) ne 'HASH' ) {
		return undef;
	}

	my $iso = $record->{country}{iso_code};

	return defined($iso) ? uc($iso) : undef;
} ## end sub _country_of

# resolves a rule's country gate against a watcher's country code lists into
# a concrete gate, a mode, a set of codes, and the vars... or undef when the
# rule has no gate. a %%%country_codes{name}%%% import of a list this
# watcher does not define is fatal
sub _resolve_country_gate {
	my ( $self, $rule_obj, $codes, $where ) = @_;

	my $country = $rule_obj->country;
	if ( !defined($country) ) {
		return undef;
	}

	my %set;
	foreach my $entry ( @{ $country->{entries} } ) {
		if ( $entry =~ /^%%%country_codes\{([a-zA-Z0-9_\-]+)\}%%%$/ ) {
			my $list = $codes->{$1};
			if ( ref($list) ne 'ARRAY' ) {
				die( $where . ' imports country_codes{' . $1 . '}, which is not a defined list for it' );
			}
			foreach my $code ( @{$list} ) {
				$set{ uc($code) } = 1;
			}
		} else {
			$set{ uc($entry) } = 1;
		}
	} ## end foreach my $entry ( @{ $country...})

	return {
		'mode'  => $country->{mode},
		'codes' => \%set,
		'vars'  => $country->{vars},
	};
} ## end sub _resolve_country_gate

# evaluates a rule's country gate in one of two modes, mirroring the mark
# gates... a vars gate is data-driven and ran once per found result (ip
# undef), a var-less one is offender-keyed and ran per candidate (ip set).
# every checked value's country must satisfy the gate, and a value that
# does not locate fails closed... an unknown country can not be cleared
sub _country_gate_pass {
	my ( $self, $gate, $data, $ip ) = @_;

	if ( !defined($gate) ) {
		return 1;
	}

	my @check;
	if ( defined( $gate->{vars} ) ) {
		# a vars gate belongs to the data pass... let the offender pass by
		if ( defined($ip) ) {
			return 1;
		}
		foreach my $var ( @{ $gate->{vars} } ) {
			push( @check, $data->{$var} );
		}
	} else {
		# a var-less gate belongs to the offender pass... let the data pass by
		if ( !defined($ip) ) {
			return 1;
		}
		@check = ($ip);
	}

	foreach my $value (@check) {
		my $country = $self->_country_of($value);
		if ( !defined($country) ) {
			return 0;
		}
		my $in = $gate->{codes}{$country} ? 1 : 0;
		if ( $gate->{mode} eq 'is' ? !$in : $in ) {
			return 0;
		}
	} ## end foreach my $value (@check)

	return 1;
} ## end sub _country_gate_pass

# loads one namtar list slot into the galla's cache, keyed by (type, nocase,
# path) so a file read as cidr and as strings stay independent... one entry
# per line, # comments and blanks skipped. a cidr slot compiles to a bitmask
# set matched by ip_ignored, a string slot to a hash set matched by lookup,
# nocase folding its keys to lower. a unreadable file or a bad cidr entry
# becomes a empty set matching nobody, rather than taking the galla down... a
# feed is not config
sub _load_namtar_file {
	my ( $self, $type, $nocase, $path ) = @_;

	my $key   = join( "\0", $type, $nocase, $path );
	my $mtime = ( stat($path) )[9];

	my @lines;
	my $fh;
	if ( defined($mtime) && open( $fh, '<', $path ) ) {
		while ( my $line = <$fh> ) {
			chomp($line);
			$line =~ s/#.*$//;
			$line =~ s/^\s+//;
			$line =~ s/\s+$//;
			if ( $line ne '' ) {
				push( @lines, $line );
			}
		}
		close($fh);
	} ## end if ( defined($mtime) &&...)

	my $set;
	if ( $type eq 'string' ) {
		$set = {};
		foreach my $line (@lines) {
			$set->{ $nocase ? lc($line) : $line } = 1;
		}
	} else {
		eval { $set = compile_ignore_ips( \@lines, 'namtar list "' . $path . '"' ); };
		if ($@) {
			log_drek( 'err', 'the namtar list "' . $path . '" has a bad entry, treating it as empty... ' . $@,
				undef, 'galla-' . $self->{name} );
			$set = [];
		}
	} ## end else [ if ( $type eq 'string' )]

	$self->{namtar_files}{$key} = {
		'mtime'  => $mtime,
		'set'    => $set,
		'type'   => $type,
		'nocase' => $nocase,
		'path'   => $path,
	};

	return;
} ## end sub _load_namtar_file

# resolves a rule's namtar_list gate against a watcher's named lists into a
# array of entries, each a set of slots and a var... or undef when the rule
# has no gate. a slot is a {type, nocase, path}, so one entry may union lists
# of different flavors, each matched its own way. a reference to a list this
# watcher does not define is fatal, like a country import
sub _resolve_namtar_gate {
	my ( $self, $rule_obj, $lists, $where ) = @_;

	my $gate = $rule_obj->namtar_list;
	if ( !defined($gate) ) {
		return undef;
	}

	my @entries;
	foreach my $entry ( @{$gate} ) {
		my %slots;
		foreach my $name ( @{ $entry->{lists} } ) {
			my $list = $lists->{$name};
			if ( ref($list) ne 'HASH' ) {
				die( $where . ' references namtar_lists{' . $name . '}, which is not a defined list for it' );
			}
			foreach my $path ( @{ $list->{paths} } ) {
				my $key = join( "\0", $list->{type}, $list->{nocase}, $path );
				$slots{$key} = { 'type' => $list->{type}, 'nocase' => $list->{nocase}, 'path' => $path };
			}
		} ## end foreach my $name ( @{ $entry...})
		push( @entries, { 'slots' => [ map { $slots{$_} } sort( keys(%slots) ) ], 'var' => $entry->{var} } );
	} ## end foreach my $entry ( @{$gate} )

	return \@entries;
} ## end sub _resolve_namtar_gate

# true if the value is on any of the passed slots' sets... a undef value is
# on none, so the gate fails closed. each slot dispatches on its type, a cidr
# set walked by ip_ignored, a string set by a lookup with the slot's fold
sub _namtar_on_any {
	my ( $self, $slots, $value ) = @_;

	if ( !defined($value) ) {
		return 0;
	}
	foreach my $slot ( @{$slots} ) {
		my $file = $self->{namtar_files}{ join( "\0", $slot->{type}, $slot->{nocase}, $slot->{path} ) };
		if ( !defined($file) ) {
			next;
		}
		if ( $slot->{type} eq 'string' ) {
			if ( exists( $file->{set}{ $slot->{nocase} ? lc($value) : $value } ) ) {
				return 1;
			}
		} elsif ( ip_ignored( $file->{set}, $value ) ) {
			return 1;
		}
	} ## end foreach my $slot ( @{$slots} )

	return 0;
} ## end sub _namtar_on_any

# evaluates a rule's namtar_list gate in one of two modes, mirroring the
# country gate... a var entry is data-driven and ran once per result (ip
# undef), a var-less one is offender-keyed and ran per candidate (ip set).
# a entry holds when its value is on any of the entry's lists, and every
# entry must hold... a value on no list fails closed
sub _namtar_gate_pass {
	my ( $self, $gate, $data, $ip ) = @_;

	if ( !defined($gate) ) {
		return 1;
	}

	foreach my $entry ( @{$gate} ) {
		if ( defined( $entry->{var} ) ) {
			# a var entry belongs to the data pass... let the offender pass by
			if ( defined($ip) ) {
				next;
			}
			if ( !$self->_namtar_on_any( $entry->{slots}, $data->{ $entry->{var} } ) ) {
				return 0;
			}
		} else {
			# a var-less entry belongs to the offender pass
			if ( !defined($ip) ) {
				next;
			}
			if ( !$self->_namtar_on_any( $entry->{slots}, $ip ) ) {
				return 0;
			}
		} ## end else [ if ( defined( $entry->{var...}))]
	} ## end foreach my $entry ( @{$gate} )

	return 1;
} ## end sub _namtar_gate_pass

# resolves a rule's active_time gate against a watcher's named windows into
# a mode, a set of compiled specs, and the vars... or undef when the rule
# has no gate. a reference to a window this watcher does not define is
# fatal, like a country import. windows are pure config, so this is frozen,
# nothing reloads it
sub _resolve_active_time_gate {
	my ( $self, $rule_obj, $windows, $where ) = @_;

	my $active = $rule_obj->active_time;
	if ( !defined($active) ) {
		return undef;
	}

	my @specs;
	foreach my $name ( @{ $active->{windows} } ) {
		my $window = $windows->{$name};
		if ( ref($window) ne 'ARRAY' ) {
			die( $where . ' references active_time{' . $name . '}, which is not a defined window for it' );
		}
		foreach my $spec ( @{$window} ) {
			my $days;
			if ( defined( $spec->{days} ) ) {
				$days = {};
				foreach my $day ( @{ $spec->{days} } ) {
					$days->{$day} = 1;
				}
			}
			my $ranges;
			if ( defined( $spec->{hours} ) ) {
				$ranges = [];
				my @hours = ref( $spec->{hours} ) eq 'ARRAY' ? @{ $spec->{hours} } : ( $spec->{hours} );
				foreach my $range (@hours) {
					my ( $start, $end ) = split( /-/, $range );
					push( @{$ranges}, [ $start + 0, $end + 0 ] );
				}
			} ## end if ( defined( $spec->{hours...}))
			push( @specs, { 'days' => $days, 'ranges' => $ranges } );
		} ## end foreach my $spec ( @{$window} )
	} ## end foreach my $name ( @{ $active...})

	return { 'mode' => $active->{mode}, 'specs' => \@specs, 'vars' => $active->{vars} };
} ## end sub _resolve_active_time_gate

# turns a time value into the (wday, hhmm) pair the windows are checked
# against, or a empty list when it does not parse... a all-digits epoch
# (journal micro or millis scaled down) read in local time, or a ISO 8601
# datetime taken at its face-value components. hhmm is hour*100 + minute
sub _time_fields {
	my ( $self, $value ) = @_;

	if ( $value =~ /^[0-9]+$/ ) {
		my $epoch = $value + 0;
		while ( $epoch > 99_999_999_999 ) {
			$epoch = int( $epoch / 1000 );
		}
		my @lt = localtime($epoch);
		return ( $lt[6], $lt[2] * 100 + $lt[1] );
	}

	my $tp;
	eval {
		require Time::Piece;
		my $iso = $value;
		$iso =~ s/[.,][0-9]+//;
		$iso =~ s/(?:Z|[+-][0-9]{2}:?[0-9]{2})$//;
		$iso =~ s/T/ /;
		$tp = Time::Piece->strptime( $iso, '%Y-%m-%d %H:%M:%S' );
	};
	if ( !$@ && defined($tp) ) {
		return ( $tp->day_of_week, $tp->hour * 100 + $tp->minute );
	}

	return ();
} ## end sub _time_fields

# true if the passed (wday, hhmm) falls in any of the compiled specs... a
# spec holds when the day is in its days set (if it has one) and the time
# is in one of its ranges (if it has any), a range with start > end
# wrapping midnight
sub _in_active_windows {
	my ( $self, $specs, $wday, $hhmm ) = @_;

	foreach my $spec ( @{$specs} ) {
		if ( defined( $spec->{days} ) && !$spec->{days}{$wday} ) {
			next;
		}
		if ( defined( $spec->{ranges} ) ) {
			my $hit = 0;
			foreach my $range ( @{ $spec->{ranges} } ) {
				my ( $start, $end ) = @{$range};
				if ( $start <= $end ? ( $hhmm >= $start && $hhmm <= $end ) : ( $hhmm >= $start || $hhmm <= $end ) ) {
					$hit = 1;
					last;
				}
			} ## end foreach my $range ( @{ $spec...})
			if ( !$hit ) {
				next;
			}
		} ## end if ( defined( $spec->{ranges...}))
		return 1;
	} ## end foreach my $spec ( @{$specs} )

	return 0;
} ## end sub _in_active_windows

# evaluates a rule's active_time gate against the passed current epoch, or
# the found vars when it names them... a whole-result gate, time being a
# property of the line not the offender, so ran once per result in the data
# pass. every checked time must satisfy, and a value that does not parse
# fails closed
sub _active_time_pass {
	my ( $self, $gate, $data, $now ) = @_;

	if ( !defined($gate) ) {
		return 1;
	}

	my @sources;
	if ( defined( $gate->{vars} ) ) {
		foreach my $var ( @{ $gate->{vars} } ) {
			push( @sources, $data->{$var} );
		}
	} else {
		@sources = ($now);
	}

	foreach my $value (@sources) {
		my @fields = defined($value) ? $self->_time_fields($value) : ();
		if ( !@fields ) {
			return 0;
		}
		my $in = $self->_in_active_windows( $gate->{specs}, $fields[0], $fields[1] );
		if ( $gate->{mode} eq 'is' ? !$in : $in ) {
			return 0;
		}
	} ## end foreach my $value (@sources)

	return 1;
} ## end sub _active_time_pass

# evaluates a rule's marked/not_marked gates in one of two modes... with a
# undef ip the var-keyed entries, data-driven and ran once per found
# result, with a ip the var-less entries, offender-keyed and ran once per
# candidate. returns true when every applicable gate holds. a marked gate
# with nothing to look up fails, a not_marked one passes, and a value
# compare with either side missing fails... conservative on both counts
sub _mark_gates_pass {
	my ( $self, $gates, $data, $ip, $now ) = @_;

	foreach my $entry ( @{ $gates->{marked} } ) {
		if ( defined( $entry->{var} ) ? defined($ip) : !defined($ip) ) {
			next;
		}
		my $key = defined( $entry->{var} ) ? $data->{ $entry->{var} } : $ip;
		if ( !defined($key) ) {
			return 0;
		}
		my $mark = $self->{marks}{ $entry->{name} }{$key};
		if ( !defined($mark) || $mark->{expires} <= $now ) {
			return 0;
		}
		foreach my $compare ( 'value_is', 'value_not' ) {
			if ( !defined( $entry->{$compare} ) ) {
				next;
			}
			my $against = $data->{ $entry->{$compare} };
			if ( !defined( $mark->{value} ) || !defined($against) ) {
				return 0;
			}
			if ( $compare eq 'value_is' ? $mark->{value} ne $against : $mark->{value} eq $against ) {
				return 0;
			}
		} ## end foreach my $compare ( 'value_is', 'value_not' )
	} ## end foreach my $entry ( @{ $gates->{marked} } )

	foreach my $entry ( @{ $gates->{not_marked} } ) {
		if ( defined( $entry->{var} ) ? defined($ip) : !defined($ip) ) {
			next;
		}
		my $key = defined( $entry->{var} ) ? $data->{ $entry->{var} } : $ip;
		if ( !defined($key) ) {
			next;
		}
		my $mark = $self->{marks}{ $entry->{name} }{$key};
		if ( defined($mark) && $mark->{expires} > $now ) {
			return 0;
		}
	} ## end foreach my $entry ( @{ $gates->{not_marked} } )

	return 1;
} ## end sub _mark_gates_pass

# brands a key into a mark name's store... setting refreshes the expiry,
# and a full store first drops the expired, then the soonest-expiring,
# same bounds as the rules' correlation stores
sub _mark_set {
	my ( $self, $name, $key, $value, $ttl, $now ) = @_;

	my $store = $self->{marks}{$name};
	if ( !defined($store) ) {
		$store = $self->{marks}{$name} = {};
	}

	if ( !defined( $store->{$key} ) && scalar( keys( %{$store} ) ) >= 10000 ) {
		foreach my $held ( keys( %{$store} ) ) {
			if ( $store->{$held}{expires} <= $now ) {
				delete( $store->{$held} );
			}
		}
		if ( scalar( keys( %{$store} ) ) >= 10000 ) {
			my ($soonest) = sort { $store->{$a}{expires} <=> $store->{$b}{expires} } keys( %{$store} );
			delete( $store->{$soonest} );
		}
	} ## end if ( !defined( $store->{$key} ) && scalar...)

	$store->{$key} = { 'expires' => $now + $ttl, defined($value) ? ( 'value' => $value ) : () };

	return;
} ## end sub _mark_set

# applies a rule's mark and unmark entries for one found result... var
# entries key by that capture, var-less ones by each passed offender IP,
# with the ignored never branded. returns the set and lifted lists for
# the EVE event
sub _apply_marks {
	my ( $self, $rule_obj, $data, $offenders, $now ) = @_;

	my @brandable = grep { !ip_ignored( $self->{ignore_ips}, $_ ) } @{$offenders};

	my @set;
	foreach my $entry ( @{ $rule_obj->marks } ) {
		my $value = defined( $entry->{value_var} ) ? $data->{ $entry->{value_var} } : undef;
		my @keys
			= defined( $entry->{var} )
			? ( defined( $data->{ $entry->{var} } ) ? ( $data->{ $entry->{var} } ) : () )
			: @brandable;
		foreach my $key (@keys) {
			$self->_mark_set( $entry->{name}, $key, $value, $entry->{ttl}, $now );
			push( @set, { 'name' => $entry->{name}, 'key' => $key } );
		}
	} ## end foreach my $entry ( @{ $rule_obj->marks } )

	my @lifted;
	foreach my $entry ( @{ $rule_obj->unmarks } ) {
		my @keys
			= defined( $entry->{var} )
			? ( defined( $data->{ $entry->{var} } ) ? ( $data->{ $entry->{var} } ) : () )
			: @brandable;
		foreach my $key (@keys) {
			if ( defined( $self->{marks}{ $entry->{name} } ) && defined( $self->{marks}{ $entry->{name} }{$key} ) ) {
				delete( $self->{marks}{ $entry->{name} }{$key} );
				if ( !%{ $self->{marks}{ $entry->{name} } } ) {
					delete( $self->{marks}{ $entry->{name} } );
				}
				push( @lifted, { 'name' => $entry->{name}, 'key' => $key } );
			}
		} ## end foreach my $key (@keys)
	} ## end foreach my $entry ( @{ $rule_obj->unmarks } )

	return ( \@set, \@lifted );
} ## end sub _apply_marks

# registers a match of a IP, banning it once its accumulated score reaches
# max_score with in find_time seconds... each match deposits the rule's
# weight, so a heavy signature bans faster and several different rules against
# one IP sum toward the one judgment. returns the IP's live score, or undef
# when the IP is ignored and not being observed. in eve_only observe mode it
# counts into a shadow bucket kept wholly apart from the real ones and raises
# a alert instead of banishing, so nothing is sent to Kur
sub _register_hit {
	my ( $self, $watcher_name, $ip, $context, $eve_only, $observe_ignored ) = @_;

	# the ignored never accumulate so much as a counter... unless observe mode
	# is told to watch what ignore_ips would otherwise drop
	if ( ip_ignored( $self->{ignore_ips}, $ip ) ) {
		if ( !( $eve_only && $observe_ignored ) ) {
			$self->_tick( 'ignored', $watcher_name );
			return undef;
		}
	}

	my $settings = $self->{watchers}{$watcher_name}{settings};
	my $now      = time;

	# when the watcher allows it, the rule's own thresholds and weight speak
	# over the watcher's... a rule overriding how counting works gets its own
	# bucket, so its window does not cross-contaminate the shared one, while a
	# ban_time-only override counts in the shared bucket and only bans
	# differently. without the consent every weight is 1, so a shipped rule
	# can not reshape the tuning
	my $allow      = $settings->{allow_per_rule_thresholds};
	my $overrides  = $allow ? $context->{rule}->thresholds : {};
	my $max_score  = defined( $overrides->{max_score} ) ? $overrides->{max_score} : $settings->{max_score};
	my $find_time  = defined( $overrides->{find_time} )  ? $overrides->{find_time}  : $settings->{find_time};
	my $ban_time   = defined( $overrides->{ban_time} )   ? $overrides->{ban_time}   : $settings->{ban_time};
	my $weight     = $allow ? $context->{rule}->weight : 1;

	# observe mode counts into the shadow families, kept apart so a watched
	# rule neither causes nor delays a real ban, nor is polluted by one
	my $counters      = $eve_only ? $self->{shadow_counters}      : $self->{counters};
	my $rule_counters = $eve_only ? $self->{shadow_rule_counters} : $self->{rule_counters};

	my $bucket;
	if ( defined( $overrides->{max_score} ) || defined( $overrides->{find_time} ) ) {
		if ( !defined( $rule_counters->{ $context->{rule_name} } ) ) {
			$rule_counters->{ $context->{rule_name} } = {};
		}
		$bucket = $rule_counters->{ $context->{rule_name} };
	} else {
		$bucket = $counters;
	}

	if ( !defined( $bucket->{$ip} ) ) {
		$bucket->{$ip} = [];
	}
	push( @{ $bucket->{$ip} }, [ $now, $weight ] );

	# matches older than find_time no longer count
	@{ $bucket->{$ip} } = grep { ( $now - $_->[0] ) < $find_time } @{ $bucket->{$ip} };

	my $score = 0;
	foreach my $entry ( @{ $bucket->{$ip} } ) {
		$score += $entry->[1];
	}

	if ( $score >= $max_score ) {
		delete( $bucket->{$ip} );
		if ($eve_only) {
			$self->_alert_ip( $ip, $ban_time, $context, $score );
		} else {
			$self->_ban_ip( $ip, $ban_time, $context, $score );
		}
	}

	return $score;
} ## end sub _register_hit

# banishes a IP to Kur, queueing it for retry by the sweeper if the
# Ereshkigal manager could not be reached
sub _ban_ip {
	my ( $self, $ip, $ban_time, $context, $score ) = @_;

	my $ident = 'galla-' . $self->{name};

	my $watcher_name = defined($context) ? $context->{watcher}   : undef;
	my $rule_name    = defined($context) ? $context->{rule_name} : undef;

	eval { $self->_send_ban( $ip, $ban_time ); };
	if ($@) {
		$self->_tick( 'ban_errors', $watcher_name, $rule_name );
		$self->{pending_bans}{$ip} = $ban_time;
		log_drek( 'err', 'banishing ' . $ip . ' to Kur failed, will retry... ' . $@, undef, $ident );
		return;
	}

	$self->_tick( 'bans', $watcher_name, $rule_name );
	delete( $self->{pending_bans}{$ip} );
	log_drek( 'info',
		'banished ' . $ip . ' to Kur' . ( defined($ban_time) ? ' ban_time=' . $ban_time : '' ),
		undef, $ident );

	# the banish event carries the triggering line's envelope when there
	# was one... a pending retry banish has no context. with a GeoIP
	# database loaded the banished IP's country rides along
	my $country = ( $self->{eve_enable} && defined( $self->{geoip} ) ) ? $self->_country_of($ip) : undef;
	$self->_eve_emit(
		'banish',
		{
			'ip' => $ip,
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
			defined($country)  ? ( 'country'  => $country )  : (),
			defined($context) ? %{ $self->_eve_fields( $context, $score ) } : (),
		}
	);

	# chisel the banishment into the shared ledger and, if this IP has
	# been banished too many times across all kurs, drag it through a
	# further gate to the recidive kur
	my $ledger_count = $self->_ledger_append_and_count( $ip, $context );
	$self->_recidive_check( $ip, $ledger_count );

	return;
} ## end sub _ban_ip

# the observe-mode twin of _ban_ip... an eve_only rule whose shadow score
# reached max_score raises a alert instead of banishing. it writes the EVE
# event a banish would, envelope and country and all, but sends nothing to
# Kur, chisels no ledger, escalates no recidive, and ticks alerts not bans.
# the shadow bucket was already cleared by the caller, so it re-arms
sub _alert_ip {
	my ( $self, $ip, $ban_time, $context, $score ) = @_;

	my $watcher_name = defined($context) ? $context->{watcher}   : undef;
	my $rule_name    = defined($context) ? $context->{rule_name} : undef;

	$self->_tick( 'alerts', $watcher_name, $rule_name );
	log_drek( 'info',
		'would banish ' . $ip . ' to Kur (observe mode)' . ( defined($ban_time) ? ' ban_time=' . $ban_time : '' ),
		undef, 'galla-' . $self->{name} );

	my $country = ( $self->{eve_enable} && defined( $self->{geoip} ) ) ? $self->_country_of($ip) : undef;
	$self->_eve_emit(
		'alert',
		{
			'ip' => $ip,
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
			defined($country)  ? ( 'country'  => $country )  : (),
			defined($context) ? %{ $self->_eve_fields( $context, $score ) } : (),
		}
	);

	return;
} ## end sub _alert_ip

# the actual ban request to the Ereshkigal manager, to this galla's kur by
# default or the passed one for a recidive escalation
sub _send_ban {
	my ( $self, $ip, $ban_time, $kur ) = @_;

	my $client = Ereshkigal::Client->new(
		'socket'  => $self->{ereshkigal_socket},
		'timeout' => $self->{timeout},
	);

	$client->call_ok(
		'ban',
		{
			'ips' => [$ip],
			'kur' => defined($kur) ? $kur : $self->{name},
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
		}
	);

	return;
} ## end sub _send_ban

# returns the path of the shared banishment ledger, under the tablet dir,
# not per galla as every galla writes to the one ledger
sub ledger_path {
	my ($self) = @_;

	return $self->{tablet_base_dir} . '/banishments.csv';
}

# escalates to the recidive kur if the IP has now been banished
# max_score times with in find_time across all kurs, per the ledger count
# from _ledger_append_and_count... a no-op when recidive is off, and never
# re-counts a recidive escalation it's self
sub _recidive_check {
	my ( $self, $ip, $count ) = @_;

	if ( !defined( $self->{recidive} ) ) {
		return;
	}
	# a escalation to the recidive kur is not it's self a offense to count
	if ( $self->{name} eq $self->{recidive}{kur} ) {
		return;
	}

	my $max_score = defined( $self->{recidive}{max_score} ) ? $self->{recidive}{max_score} : 5;
	my $ban_time   = defined( $self->{recidive}{ban_time} ) ? $self->{recidive}{ban_time} : 0;

	if ( !defined($count) || $count < $max_score ) {
		return;
	}

	$self->_tick('recidivists');
	log_drek(
		'info',
		'recidivist '
			. $ip
			. ' banished '
			. $count
			. ' times, dragging through to the recidive kur "'
			. $self->{recidive}{kur} . '"',
		undef,
		'galla-' . $self->{name}
	);

	eval { $self->_send_ban( $ip, $ban_time, $self->{recidive}{kur} ); };
	if ($@) {
		$self->{stats}{ban_errors}++;
		log_drek( 'err', 'banishing recidivist ' . $ip . ' failed... ' . $@, undef, 'galla-' . $self->{name} );
		return;
	}

	# a recidive escalation is its own banish event, to the recidive kur,
	# with the ledger count and no single triggering line
	my $country = ( $self->{eve_enable} && defined( $self->{geoip} ) ) ? $self->_country_of($ip) : undef;
	$self->_eve_emit(
		'banish',
		{
			'ip'       => $ip,
			'kur'      => $self->{recidive}{kur},
			'ban_time' => $ban_time,
			'count'    => $count,
			defined($country) ? ( 'country' => $country ) : (),
			'recidive' => \1,
		}
	);

	return;
} ## end sub _recidive_check

# chisels a banishment row into the shared ledger under a exclusive lock
# and returns how many times this IP appears with in the recidive window...
# the lock serializes the several gallas sharing the one ledger. Rows are
# epoch,kur,ip,rule,watcher, pruned to ledger_keep but never inside the
# recidive window, and rows landing on the recidive kur it's self are never
# counted, as a escalation's landing is not a offense
sub _ledger_append_and_count {
	my ( $self, $ip, $context ) = @_;

	my $now = time;
	my $find_time =
		defined( $self->{recidive} )
		? ( defined( $self->{recidive}{find_time} ) ? $self->{recidive}{find_time} : 604800 )
		: 0;
	my $recidive_kur = defined( $self->{recidive} ) ? $self->{recidive}{kur} : '';

	# rows still inside the recidive window must survive whatever
	# ledger_keep says... 0 means keep forever
	my $keep = $self->{ledger_keep};
	if ( $keep && $keep < $find_time ) {
		$keep = $find_time;
	}

	my $rule    = defined($context) && defined( $context->{rule_name} ) ? $context->{rule_name} : '';
	my $watcher = defined($context) && defined( $context->{watcher} )   ? $context->{watcher}   : '';

	my $path  = $self->ledger_path;
	my $count = 0;
	eval {
		open( my $fh, '+>>', $path ) || die( 'open failed... ' . $! );
		flock( $fh, 2 ) || die( 'lock failed... ' . $! );    # LOCK_EX

		print $fh $now . ','
			. $self->{name} . ','
			. $ip . ','
			. _csv_escape($rule) . ','
			. _csv_escape($watcher) . "\n";

		# read the whole ledger back and count this IP with in the window,
		# rewriting it pruned so it does not grow past ledger_keep... the
		# header is skipped by the epoch check and rewritten fresh
		seek( $fh, 0, 0 );
		my @kept;
		while ( my $line = <$fh> ) {
			chomp($line);
			my ( $epoch, $kur, $row_ip ) = split( /,/, $line, 4 );
			if ( !defined($epoch) || $epoch !~ /^[0-9]+$/ || !defined($row_ip) || $row_ip eq '' ) {
				next;
			}
			if ( $keep && ( $now - $epoch ) >= $keep ) {
				next;
			}
			push( @kept, $line );
			if ( $row_ip eq $ip && $find_time && ( $now - $epoch ) < $find_time && $kur ne $recidive_kur ) {
				$count++;
			}
		} ## end while ( my $line = <$fh> )

		# rewrite pruned
		seek( $fh, 0, 0 );
		truncate( $fh, 0 );
		print $fh "epoch,kur,ip,rule,watcher\n";
		print $fh join( "\n", @kept ) . ( @kept ? "\n" : '' );

		close($fh);
	};
	if ($@) {
		log_drek( 'err', 'the banishment ledger "' . $path . '" could not be updated... ' . $@,
			undef, 'galla-' . $self->{name} );
		return undef;
	}

	return $count;
} ## end sub _ledger_append_and_count

# ran every ten seconds via the sweeper... retries pending bans and drops
# counter entries that have entirely aged out
sub _sweep {
	my ($self) = @_;

	foreach my $ip ( sort( keys( %{ $self->{pending_bans} } ) ) ) {
		$self->_ban_ip( $ip, $self->{pending_bans}{$ip} );
	}

	# so counters for IPs never seen again don't linger forever... any
	# still-relevant entry gets re-pruned properly on its next hit. the
	# shadow families of observe mode are swept the same way
	my $now = time;
	foreach my $bucket (
		$self->{counters},        values( %{ $self->{rule_counters} } ),
		$self->{shadow_counters}, values( %{ $self->{shadow_rule_counters} } )
		)
	{
		foreach my $ip ( keys( %{$bucket} ) ) {
			my $newest = $bucket->{$ip}[-1];
			# a day is comfortably past any sane find_time
			if ( !defined($newest) || ( $now - $newest->[0] ) > 86400 ) {
				delete( $bucket->{$ip} );
			}
		}
	} ## end foreach my $bucket ( $self->...)
	foreach my $rule_counters ( $self->{rule_counters}, $self->{shadow_rule_counters} ) {
		foreach my $rule_name ( keys( %{$rule_counters} ) ) {
			if ( !%{ $rule_counters->{$rule_name} } ) {
				delete( $rule_counters->{$rule_name} );
			}
		}
	}

	# reload any namtar list slot whose file mtime changed, appeared, or
	# vanished, so a updated feed takes effect with in a sweep... _load keys
	# by the same slot, so it overwrites in place
	foreach my $key ( keys( %{ $self->{namtar_files} } ) ) {
		my $rec    = $self->{namtar_files}{$key};
		my $mtime  = ( stat( $rec->{path} ) )[9];
		my $cached = $rec->{mtime};
		if ( ( defined($mtime) ? $mtime : -1 ) != ( defined($cached) ? $cached : -1 ) ) {
			$self->_load_namtar_file( $rec->{type}, $rec->{nocase}, $rec->{path} );
		}
	} ## end foreach my $key ( keys( %{ ...}))

	# expire marks whose ttl has run out, so a ttl elapses on time rather
	# than waiting on the next line that would key it
	foreach my $mark_name ( keys( %{ $self->{marks} } ) ) {
		my $store = $self->{marks}{$mark_name};
		foreach my $key ( keys( %{$store} ) ) {
			if ( $store->{$key}{expires} <= $now ) {
				delete( $store->{$key} );
			}
		}
		if ( !%{$store} ) {
			delete( $self->{marks}{$mark_name} );
		}
	} ## end foreach my $mark_name ( keys...)

	# expire the correlation state of the rules... rule objects are shared
	# across watchers, so sweep each once
	my %swept;
	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		foreach my $rule_obj ( @{ $self->{watchers}{$watcher_name}{rule_objs} } ) {
			if ( !$swept{$rule_obj} ) {
				$swept{$rule_obj} = 1;
				$rule_obj->sweep_state($now);
			}
		}
	} ## end foreach my $watcher_name ( keys( %{ $self->{watchers...}}))

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
			'parser'   => $watcher->{parser},
			'rules'    => $watcher->{rules},
			'settings' => $watcher->{settings},
			$watcher->{is_journal}
			? (
				'journal'         => $watcher->{journal_matches},
				'journal_running' => defined( $watcher->{journal_wheel} ) ? 1 : 0,
				)
			: (
				'logs'      => $watcher->{log_spec},
				'following' => [ sort( keys( %{ $watcher->{wheels} } ) ) ],
			),
		};
	}

	# a IP may live in the shared bucket and per-rule buckets at once...
	# count each defendant once
	my %tracked = %{ $self->{counters} };
	foreach my $rule_name ( keys( %{ $self->{rule_counters} } ) ) {
		foreach my $ip ( keys( %{ $self->{rule_counters}{$rule_name} } ) ) {
			$tracked{$ip} = 1;
		}
	}

	return {
		'name'         => $self->{name},
		'pid'          => $$,
		'uptime'       => defined( $self->{started} ) ? time - $self->{started} : 0,
		'watchers'     => $watchers,
		'stats'        => $self->{stats},
		'tracked_ips'  => scalar( keys(%tracked) ),
		'pending_bans' => [ sort( keys( %{ $self->{pending_bans} } ) ) ],
		'recidive'     => defined( $self->{recidive} ) ? $self->{recidive}{kur} : undef,
	};
} ## end sub _cmd_status

# sums the weights of a bucket's [epoch, weight] entries into its score
sub _score_of {
	my ($entries) = @_;

	my $score = 0;
	foreach my $entry ( @{$entries} ) {
		$score += $entry->[1];
	}

	return $score;
}

sub _cmd_accused {
	my ($self) = @_;

	# every live hit per IP, the shared bucket and any per-rule buckets
	# together... the per-rule buckets also broken out under rules, as each
	# is racing its own thresholds. each hit is a [epoch, weight] pair, so a
	# defendant carries both a raw hit count and the weighted score that is
	# what actually races max_score
	my %all;
	my %by_rule;
	foreach my $ip ( keys( %{ $self->{counters} } ) ) {
		push( @{ $all{$ip} }, @{ $self->{counters}{$ip} } );
	}
	foreach my $rule_name ( keys( %{ $self->{rule_counters} } ) ) {
		foreach my $ip ( keys( %{ $self->{rule_counters}{$rule_name} } ) ) {
			my $hits = $self->{rule_counters}{$rule_name}{$ip};
			if ( !@{$hits} ) {
				next;
			}
			push( @{ $all{$ip} }, @{$hits} );
			$by_rule{$ip}{$rule_name} = {
				'hits'  => scalar( @{$hits} ),
				'score' => _score_of($hits),
				'first' => $hits->[0][0],
				'last'  => $hits->[-1][0],
			};
		} ## end foreach my $ip ( keys( %{ $self->{rule_counters...}}))
	} ## end foreach my $rule_name ( keys( %{ $self->{rule_counters...}}))

	my $accused = {};
	foreach my $ip ( keys(%all) ) {
		my @hits = sort { $a->[0] <=> $b->[0] } @{ $all{$ip} };
		if ( !@hits ) {
			next;
		}
		$accused->{$ip} = {
			'hits'  => scalar(@hits),
			'score' => _score_of( \@hits ),
			'first' => $hits[0][0],
			'last'  => $hits[-1][0],
			defined( $by_rule{$ip} ) ? ( 'rules' => $by_rule{$ip} ) : (),
		};
	} ## end foreach my $ip ( keys(%all) )

	return {
		'name'    => $self->{name},
		'accused' => $accused,
	};
} ## end sub _cmd_accused

sub _cmd_marked {
	my ($self) = @_;

	# the live marks store, per name a hash of branded keys, each with its
	# expiry and the harvested value when there is one
	my $now   = time;
	my $marks = {};
	foreach my $mark_name ( keys( %{ $self->{marks} } ) ) {
		my $store = $self->{marks}{$mark_name};
		foreach my $key ( keys( %{$store} ) ) {
			if ( $store->{$key}{expires} <= $now ) {
				next;
			}
			$marks->{$mark_name}{$key} = {
				'expires' => $store->{$key}{expires},
				exists( $store->{$key}{value} ) ? ( 'value' => $store->{$key}{value} ) : (),
			};
		} ## end foreach my $key ( keys( %{$store} ) )
	} ## end foreach my $mark_name ( keys...)

	return {
		'name'  => $self->{name},
		'marks' => $marks,
	};
} ## end sub _cmd_marked

sub _cmd_stop {
	my ( $self, $ctx ) = @_;

	my $ident = 'galla-' . $self->{name};

	log_drek( 'info', 'stop requested', undef, $ident );

	# keeps the sweeper from rescheduling so it's session can end
	$self->{stopping} = 1;

	# leave fresh tablets behind, while the wheels still exist to snapshot
	# their positions from
	$self->checkpoint;

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

=head2 7, tabletBaseDirError

The tablet base dir could not be created or is not read/writable.

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
