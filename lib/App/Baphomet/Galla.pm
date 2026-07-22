package App::Baphomet::Galla;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use POE                                      qw( Wheel::FollowTail Wheel::Run );
use POE::Component::Server::JSONUnix         ();
use POE::Component::Server::JSONUnix::Client ();
use File::Glob                       qw( bsd_glob );
use JSON::MaybeXS                    qw( encode_json decode_json );
use POSIX                            qw( strftime );
use Socket                           qw( AF_INET AF_INET6 inet_pton );
use Sys::Hostname                    ();
use Ereshkigal::Client               ();
use App::Baphomet::Config
	qw( load_config check_kur_def kur_split resolve_settings resolve_country_codes resolve_namtar_lists resolve_active_time watcher_rules watcher_logs watcher_journal watcher_is_journal watcher_join compile_ignore_ips ip_ignored ip_network ip_family );
use App::Baphomet::Parser     ();
use App::Baphomet::Rules      ();
use App::Baphomet::ClayTablet ();
use App::Baphomet::LogDrek    qw( log_drek );

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
			# the installed Error::Helper reads all_fatal where its POD says
			# all_errors_fatal... both are set so the contract holds either way
			all_errors_fatal => 1,
			all_fatal        => 1,
			flags            => {
				1 => 'configLoadFailed',
				2 => 'noSuchKur',
				3 => 'invalidKurDef',
				4 => 'NErunBaseDir',
				5 => 'nonRWrunBaseDir',
				6 => 'rulesLoadFailed',
				7 => 'tabletStoreError',
			},
			fatal_flags      => {},
			perror_not_fatal => 0,
		},
		config                   => '/usr/local/etc/baphomet/config.toml',
		name                     => undef,
		settings                 => undef,
		watchers                 => {},
		rules                    => undef,
		counters                 => {},
		rule_counters            => {},
		shadow_counters          => {},
		shadow_rule_counters     => {},
		distinct_counters        => {},
		shadow_distinct_counters => {},
		subnet_counters          => { v4 => {}, v6 => {} },
		shadow_subnet_counters   => { v4 => {}, v6 => {} },
		marks                    => {},
		mark_sync                => 0,
		mark_stream_id           => undef,
		namtar_files             => {},
		pending_bans             => {},
		pending_cidr_bans        => {},
		kur_client               => undef,
		inflight_bans            => {},
		dns_async                => 0,
		dns_inflight             => {},
		dns_bg                   => undef,
		wheel_to_watcher         => {},
		started                  => undef,
		stopping                 => 0,
		server                   => undef,
		stats                    => {
			lines            => 0,
			unparsed         => 0,
			matched          => 0,
			ignored          => 0,
			joined           => 0,
			bans             => 0,
			ban_errors       => 0,
			recidivists      => 0,
			sightings        => 0,
			alerts           => 0,
			subnet_bans      => 0,
			subnet_alerts    => 0,
			hostname_dropped => 0,
			dns_failures     => 0,
			rdns_failures    => 0,
			per_watcher      => {},
			per_rule         => {},
		},
	};
	bless( $self, ref($blank) || $blank );

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
	$self->{enable_dns}       = $config->{enable_dns};
	$self->{usedns_timeout}   = $config->{usedns_timeout};
	$self->{usedns_max_addrs} = $config->{usedns_max_addrs};
	$self->{dns_cache}        = {};
	$self->{dns_resolve}      = undef;

	if ( $self->{enable_dns} ) {
		$self->_open_dns;
	}
	$self->{enable_rdns}        = $config->{enable_rdns};
	$self->{rdns_timeout}       = $config->{rdns_timeout};
	$self->{rdns_cache}         = {};
	$self->{country_cache}      = {};
	$self->{dns_reverse}        = undef;
	$self->{dns_forward}        = undef;
	$self->{hostname}           = Sys::Hostname::hostname();
	$self->{last_checkpoint}    = 0;
	$self->{positions}          = {};
	$self->{join_buffers}       = {};
	$self->{line_seqs}          = {};
	$self->{journal_cursors}    = {};
	$self->{wheelid_to_journal} = {};
	$self->{wheel_to_file}      = {};
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
	} ## end if ( !defined( $self->{name} ) || !defined...)

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
			  defined( $kur_settings->{internal} )          ? @{ $kur_settings->{internal} }
			: ref( $kur_settings->{ignore_ips} ) eq 'ARRAY' ? @{ $kur_settings->{ignore_ips} }
			:                                                 ()
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

	# the state tablets go through a pluggable backend under the global
	# ClayTablet config... the file backend, the default, is the current
	# on-disk system and defaults its base dir to tablet_base_dir. an
	# unusable backend or store is a fatal startup error, like a bad run dir
	eval {
		$self->{tablet} = App::Baphomet::ClayTablet->new(
			'config'          => $config->{ClayTablet},
			'name'            => $self->{name},
			'tablet_base_dir' => $self->{tablet_base_dir},
		);
	};
	if ($@) {
		$self->{perror}      = 1;
		$self->{error}       = 7;
		$self->{errorString} = $@;
		$self->warn;
	} else {
		my $tablet_error = $self->{tablet}->verify;
		if ( defined($tablet_error) ) {
			$self->{perror}      = 1;
			$self->{error}       = 7;
			$self->{errorString} = $tablet_error;
			$self->warn;
		}
		# whether the store carries a fleet mark sync bus... the galla then
		# publishes brands to it and drains the fleet's into its own marks
		$self->{mark_sync} = $self->{tablet}->mark_sync;
	} ## end else [ if ($@) ]

	# make the EVE log's dir when enabled, so a first write does not fail
	# just for a missing dir... a unwritable one is only logged, as
	# telemetry should never take the galla down
	if ( $self->{eve_enable} ) {
		$self->_ensure_eve_dir;
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
					= 'Failed to load the rule "' . $rule_name . '" for the watcher "' . $watcher_name . '"... ' . $@;
				$self->warn;
			}
			push( @rule_objs, $rule );
		} ## end foreach my $rule_name (@rule_names)

		# resolve each rule's country gate against this watcher's country
		# code lists... rule objects are shared across watchers but the lists
		# layer per watcher, so each resolved gate lives on the binding, not
		# the rule. a import of a undefined list is fatal, like a bad rule.
		# country, namtar_list, and active_time resolve identically, so one
		# loop over a dispatch list covers all three... the namtar files
		# themselves are loaded and mtime refreshed on the galla, not frozen
		# here, while active_time compiles to pure config nothing reloads
		my @gate_families = (
			[ '_resolve_country_gate',     resolve_country_codes( $config, $kur_settings, $watcher ) ],
			[ '_resolve_namtar_gate',      resolve_namtar_lists( $config, $kur_settings, $watcher ) ],
			[ '_resolve_active_time_gate', resolve_active_time( $config, $kur_settings, $watcher ) ],
		);
		my @resolved_gate_lists;
		foreach my $family (@gate_families) {
			my ( $resolver, $watcher_layered ) = @{$family};
			my @gates;
			for ( my $i = 0; $i < scalar(@rule_objs); $i++ ) {
				my $gate;
				if ( defined( $rule_objs[$i] ) ) {
					eval {
						$gate = $self->$resolver( $rule_objs[$i], $watcher_layered,
							'The rule "' . $rule_names[$i] . '" of the watcher "' . $watcher_name . '"' );
					};
					if ($@) {
						$self->{perror}      = 1;
						$self->{error}       = 6;
						$self->{errorString} = $@;
						$self->warn;
					}
				} ## end if ( defined( $rule_objs[$i] ) )
				push( @gates, $gate );
			} ## end for ( my $i = 0; $i < scalar(@rule_objs); $i...)
			push( @resolved_gate_lists, \@gates );
		} ## end foreach my $family (@gate_families)
		my ( $country_gates, $namtar_gates, $active_gates ) = @resolved_gate_lists;

		# the joiner, compiled... check_kur_def already vetted it, so a die
		# here is the same config error it already flagged
		my $join_compiled;
		eval { $join_compiled = watcher_join($watcher); };
		if ($@) {
			$self->{perror}      = 1;
			$self->{error}       = 3;
			$self->{errorString} = $@;
			$self->warn;
		}

		my $is_journal = watcher_is_journal($watcher);
		$self->{watchers}{$watcher_name} = {
			'is_journal'      => $is_journal,
			'log_spec'        => $is_journal          ? []                            : [ watcher_logs($watcher) ],
			'journal_matches' => $is_journal          ? [ watcher_journal($watcher) ] : [],
			'parser' => defined( $watcher->{parser} ) ? $watcher->{parser} : ( $is_journal ? 'journal' : 'syslog' ),
			'join'            => $join_compiled,
			'rules'           => \@rule_names,
			'rule_objs'       => \@rule_objs,
			'country_gates'   => $country_gates,
			'namtar_gates'    => $namtar_gates,
			'active_gates'    => $active_gates,
			'settings'        => resolve_settings( $config, $kur_settings, $watcher ),
			'wheels'          => {},
			'journal_wheel'   => undef,
			'journal_delay'   => 1,
			'journal_spawned' => undef,
		};
	} ## end foreach my $watcher_name ( sort( keys( %{$watchers...})))

	# a detection rule writes only to EVE, so it is a silent no-op with the log
	# off... force it on when any is loaded, make the dir a first write needs,
	# and say so, rather than leave the operator wondering why nothing lands
	if ( !$self->{eve_enable} ) {
		my $has_detection = 0;
		foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
			foreach my $rule_obj ( @{ $self->{watchers}{$watcher_name}{rule_objs} } ) {
				if ( defined($rule_obj) && $rule_obj->is_detection ) {
					$has_detection = 1;
				}
			}
		}
		if ($has_detection) {
			$self->{eve_enable} = 1;
			$self->_ensure_eve_dir;
			log_drek( 'info', 'a detection rule is loaded... EVE output enabled to ' . $self->{eve_log},
				undef, 'galla-' . $self->{name} );
		}
	} ## end if ( !$self->{eve_enable} )

	# a resolve usedns with out the machinery behind it behaves as no...
	# say so loudly rather than silently never banishing a hostname
	my @dns_wanting;
	foreach my $watcher_name ( sort( keys( %{ $self->{watchers} } ) ) ) {
		my $watcher_settings = $self->{watchers}{$watcher_name}{settings};
		if ( $watcher_settings->{usedns} ne 'no' && !defined( $self->{dns_resolve} ) ) {
			push( @dns_wanting, $watcher_name );
			$watcher_settings->{usedns} = 'no';
		}
	}
	if (@dns_wanting) {
		log_drek(
			'err',
			'usedns is configured on '
				. join( ', ', @dns_wanting ) . ' but '
				. (
					$self->{enable_dns}
					? 'Net::DNS is not loadable... ' . ( defined( $self->{dns_error} ) ? $self->{dns_error} : '' )
					: 'enable_dns is off'
				)
				. '... treated as no, hostname offenders banish nobody',
			undef,
			'galla-' . $self->{name}
		);
	} ## end if (@dns_wanting)

	# reverse_dns gates fail closed with out the machinery behind them, so
	# those rules count nothing... a silent hole, so say so loudly. the
	# resolver only stands up at all when some rule wants it
	my $rdns_gated = 0;
	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		foreach my $rule_obj ( @{ $self->{watchers}{$watcher_name}{rule_objs} } ) {
			if ( defined($rule_obj) && defined( $rule_obj->reverse_dns ) ) {
				$rdns_gated = 1;
			}
		}
	}
	if ($rdns_gated) {
		if ( !$self->{enable_rdns} ) {
			log_drek(
				'err',
				'reverse_dns-gated rules are configured but enable_rdns is off...'
					. ' those gates fail closed and will count nothing',
				undef,
				'galla-' . $self->{name}
			);
		} else {
			$self->_open_rdns;
			if ( defined( $self->{rdns_error} ) ) {
				log_drek(
					'err',
					'reverse_dns-gated rules are configured but Net::DNS is not loadable...'
						. ' those gates fail closed and will count nothing... '
						. $self->{rdns_error},
					undef,
					'galla-' . $self->{name}
				);
			} ## end if ( defined( $self->{rdns_error} ) )
		} ## end else [ if ( !$self->{enable_rdns} ) ]
	} ## end if ($rdns_gated)

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
	} ## end if ( $country_gated && !defined( $self->{geoip...}))

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
		} ## end foreach my $gate ( @{ $self->{watchers}{$watcher_name...}})
	} ## end foreach my $watcher_name ( keys( %{ $self->{watchers...}}))
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
		log_drek(
			'err',
			'these namtar list files loaded empty or unreadable, gates matching them banish nobody... '
				. join( ', ', @paths ),
			undef,
			'galla-' . $self->{name}
		);
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

Returns the locator of a state tablet of the given kind for this instance...
a path for the file backend, a store key for others.

    my $path = $galla->state_path('counters');

=cut

sub state_path {
	my ( $self, $kind ) = @_;

	return $self->{tablet}->locator($kind);
}

# builds a tablet's lines by handing $writer a in-memory filehandle to print
# into, exactly as the old on-disk writer did, then hands the lines to the
# configured backend... the backend logs and swallows a storage failure, as a
# failed checkpoint should not take the galla down
sub _write_tablet {
	my ( $self, $kind, $writer ) = @_;

	my @lines;
	eval {
		my $buf = '';
		open( my $fh, '>', \$buf ) || die( 'in-memory open failed... ' . $! );
		$writer->($fh);
		close($fh);
		@lines = split( /\n/, $buf );
	};
	if ($@) {
		log_drek( 'err', 'building the ' . $kind . ' tablet failed... ' . $@, undef, 'galla-' . $self->{name} );
		return;
	}

	$self->{tablet}->write( $kind, \@lines );

	return;
} ## end sub _write_tablet

# reads a tablet's lines from the backend, returning them chomped... a missing
# tablet is just a empty list
sub _read_tablet {
	my ( $self, $kind ) = @_;

	return $self->{tablet}->read($kind);
}

=head2 checkpoint

Writes the state tablets out now... the counters, the distinct-cardinality
sets, the pending bans, the log positions, the journal cursors, the running
stats, the correlation context, the marks, and the mark-stream cursor. Called
periodically by the sweeper and on stop.

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

	# subnet buckets... family,net,hit_epoch,weight,member one row per live
	# deposit, so a restart resumes a partial subnet count and remembers who
	# fed it. the family is v4 or v6, the two kept apart. the shadow buckets of
	# observe mode are ephemeral and never chiseled. the member is last, as a
	# IPv6 holds no comma but is the one field worth putting at the end anyway
	$self->_write_tablet(
		'subnet',
		sub {
			my ($fh) = @_;
			print $fh "family,net,hit,weight,member\n";
			foreach my $family ( sort( keys( %{ $self->{subnet_counters} } ) ) ) {
				my $store = $self->{subnet_counters}{$family};
				foreach my $network ( sort( keys( %{$store} ) ) ) {
					foreach my $entry ( @{ $store->{$network} } ) {
						print $fh $family . ','
							. $network . ','
							. $entry->[0] . ','
							. $entry->[1] . ','
							. ( defined( $entry->[2] ) ? $entry->[2] : '' ) . "\n";
					}
				}
			} ## end foreach my $family ( sort( keys( %{ $self->{subnet_counters...}})))
		}
	);

	# distinct-cardinality sets... one JSON line per (rule, ip, distinct value)
	# with the value's newest epoch, so a restart resumes a partial count
	$self->_write_tablet(
		'distinct',
		sub {
			my ($fh) = @_;
			foreach my $rule_name ( sort( keys( %{ $self->{distinct_counters} } ) ) ) {
				foreach my $ip ( sort( keys( %{ $self->{distinct_counters}{$rule_name} } ) ) ) {
					my $set = $self->{distinct_counters}{$rule_name}{$ip};
					foreach my $value ( sort( keys( %{$set} ) ) ) {
						print $fh encode_json(
							{ 'rule' => $rule_name, 'ip' => $ip, 'value' => $value, 'epoch' => $set->{$value} } )
							. "\n";
					}
				}
			} ## end foreach my $rule_name ( sort( keys( %{ $self->{...}})))
		}
	);

	# pending bans... ip,ban_time, and its CIDR twin net,ban_time, ban_time
	# empty meaning undef, for bans the manager could not be reached for
	$self->_write_pending_tablet( 'pending',      'ip',  $self->{pending_bans} );
	$self->_write_pending_tablet( 'pending_cidr', 'net', $self->{pending_cidr_bans} );

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
					my $rule_obj  = $objs->[$i];
					my $rule_name = $rules->[$i];
					if ( !defined($rule_obj) || $seen{$rule_name} ) {
						next;
					}
					$seen{$rule_name} = 1;
					my $state = $rule_obj->dump_state;
					if ( defined($state) ) {
						print $fh encode_json( { 'rule' => $rule_name, 'state' => $state } ) . "\n";
					}
				} ## end for ( my $i = 0; $i < scalar( @{$objs} ); $i...)
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
							defined( $store->{$key}{set} )  ? ( 'set'   => $store->{$key}{set} )   : (),
							exists( $store->{$key}{value} ) ? ( 'value' => $store->{$key}{value} ) : (),
						}
					) . "\n";
				} ## end foreach my $key ( sort( keys( %{$store} ) ) )
			} ## end foreach my $mark_name ( sort( keys( %{ $self->{...}})))
		}
	);

	# the mark stream cursor... where the fleet mark bus was last drained to,
	# so a restart resumes the tail rather than replaying the whole stream.
	# host-local, like the journal cursors
	if ( $self->{mark_sync} ) {
		$self->_write_tablet(
			'mark_stream',
			sub {
				my ($fh) = @_;
				if ( defined( $self->{mark_stream_id} ) && $self->{mark_stream_id} ne '' ) {
					print $fh $self->{mark_stream_id} . "\n";
				}
			}
		);
	} ## end if ( $self->{mark_sync} )

	# the shared ledger is pruned here rather than per ban, so a busy galla
	# never pays O(ledger) on the ban path
	$self->_ledger_compact;

	$self->{last_checkpoint} = $now;

	return;
} ## end sub checkpoint

# records the current tell and inode of every followed file into the
# positions map, so a checkpoint reflects where the wheels actually are
sub _snapshot_positions {
	my ($self) = @_;

	my %wheeled;
	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		my $watcher = $self->{watchers}{$watcher_name};
		foreach my $file ( keys( %{ $watcher->{wheels} } ) ) {
			$wheeled{$file} = 1;
			my $wheel = $watcher->{wheels}{$file};
			my $offset;
			eval { $offset = $wheel->tell; };
			my $inode = ( stat($file) )[1];
			if ( defined($offset) && defined($inode) ) {
				$self->{positions}{$file} = { 'inode' => $inode, 'offset' => $offset };
			}
		}
	} ## end foreach my $watcher_name ( keys( %{ $self->{watchers...}}))

	# a position for a file gone from disk and no longer followed is dead
	# weight... dated glob logs would otherwise pile up in the tablet forever
	foreach my $file ( keys( %{ $self->{positions} } ) ) {
		if ( !$wheeled{$file} && !-e $file ) {
			delete( $self->{positions}{$file} );
		}
	}

	return;
} ## end sub _snapshot_positions

# loads the tablets back at start... counters, distinct sets, and pending bans
# pruned to what is still relevant, log positions kept for start_server to seek
# to, journal cursors restored, the running stats carried forward, correlation
# context restored into the rules, marks restored and pruned of the expired,
# and the mark stream drained to catch up on what the fleet branded while down
sub _load_state {
	my ($self) = @_;

	my $now = time;

	$self->_load_subnet($now);
	$self->_load_counters($now);
	$self->_load_distinct($now);
	$self->_load_pending_tablet( 'pending',      'ip',  $self->{pending_bans} );
	$self->_load_pending_tablet( 'pending_cidr', 'net', $self->{pending_cidr_bans} );
	$self->_load_positions;
	$self->_load_cursors;
	$self->_load_stats;
	$self->_load_context($now);
	$self->_load_marks($now);

	if ( $self->{mark_sync} ) {
		$self->_load_mark_stream;
	}

	return;
} ## end sub _load_state

# restores the accumulated per-ip and per-rule hit counters, then sorts each
# bucket by epoch and drops anything with nothing recent... the register path
# re-prunes per the effective find_time on the next hit
sub _load_counters {
	my ( $self, $now ) = @_;

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
	} ## end foreach my $line ( $self->_read_tablet('counters'...))

	$self->_prune_restored_counters($now);

	return;
} ## end sub _load_counters

# restores the subnet buckets, per family, remembering each deposit's member
# IP... loaded before the counters so their shared prune sorts and ages these
# too. a row for a family other than v4 or v6, or with a unusable epoch, is
# skipped. a missing weight restores as 1, like the per-IP counters
sub _load_subnet {
	my ( $self, $now ) = @_;

	my $line_int = 0;
	foreach my $line ( $self->_read_tablet('subnet') ) {
		$line_int++;
		if ( ( $line_int == 1 && $line =~ /^family,/ ) || $line eq '' ) {
			next;
		}
		my ( $family, $network, $hit, $weight, $member ) = split( /,/, $line, 5 );
		if ( !defined($family) || ( $family ne 'v4' && $family ne 'v6' ) ) {
			next;
		}
		if ( !defined($network) || $network eq '' || !defined($hit) || $hit !~ /^[0-9]+$/ ) {
			next;
		}
		if ( !defined($weight) || $weight !~ /^[0-9]+(?:\.[0-9]+)?$/ || $weight + 0 <= 0 ) {
			$weight = 1;
		}
		push(
			@{ $self->{subnet_counters}{$family}{$network} },
			[ $hit + 0, $weight + 0, ( defined($member) && $member ne '' ? $member : undef ) ]
		);
	} ## end foreach my $line ( $self->_read_tablet('subnet'...))

	return;
} ## end sub _load_subnet

# sort each restored counter bucket by epoch, per-IP and subnet stores
# alike, and drop entries with nothing recent, then drop any per-rule
# bucket left empty... the register path re-prunes per the effective
# find_time on the next hit, and relies on the time-ordering settled here
sub _prune_restored_counters {
	my ( $self, $now ) = @_;

	foreach my $bucket ( $self->{counters}, values( %{ $self->{rule_counters} } ) ) {
		foreach my $ip ( keys( %{$bucket} ) ) {
			my @sorted = sort { $a->[0] <=> $b->[0] } @{ $bucket->{$ip} };
			if ( !@sorted || ( $now - $sorted[-1][0] ) > 86400 ) {
				delete( $bucket->{$ip} );
			} else {
				$bucket->{$ip} = \@sorted;
			}
		}
	} ## end foreach my $bucket ( $self->{counters}, values(...))
	foreach my $rule_name ( keys( %{ $self->{rule_counters} } ) ) {
		if ( !%{ $self->{rule_counters}{$rule_name} } ) {
			delete( $self->{rule_counters}{$rule_name} );
		}
	}

	# the restored subnet buckets, per family... sort each network's deposits
	# and drop any with nothing recent, the same as the per-IP buckets
	foreach my $family ( keys( %{ $self->{subnet_counters} } ) ) {
		my $store = $self->{subnet_counters}{$family};
		foreach my $network ( keys( %{$store} ) ) {
			my @sorted = sort { $a->[0] <=> $b->[0] } @{ $store->{$network} };
			if ( !@sorted || ( $now - $sorted[-1][0] ) > 86400 ) {
				delete( $store->{$network} );
			} else {
				$store->{$network} = \@sorted;
			}
		}
	} ## end foreach my $family ( keys( %{ $self->{subnet_counters...}}))

	return;
} ## end sub _prune_restored_counters

# distinct-cardinality sets, restored per (rule, ip, value) and pruned of
# anything more than a day stale... the register path re-prunes to the
# effective find_time on the next hit
sub _load_distinct {
	my ( $self, $now ) = @_;

	foreach my $line ( $self->_read_tablet('distinct') ) {
		if ( $line eq '' ) {
			next;
		}
		my $decoded;
		eval { $decoded = decode_json($line); };
		if (   ref($decoded) ne 'HASH'
			|| !defined( $decoded->{rule} )
			|| !defined( $decoded->{ip} )
			|| !defined( $decoded->{value} )
			|| !defined( $decoded->{epoch} )
			|| $decoded->{epoch} !~ /^[0-9]+$/
			|| ( $now - $decoded->{epoch} ) > 86400 )
		{
			next;
		} ## end if ( ref($decoded) ne 'HASH' || !defined( ...))
		$self->{distinct_counters}{ $decoded->{rule} }{ $decoded->{ip} }{ $decoded->{value} } = $decoded->{epoch} + 0;
	} ## end foreach my $line ( $self->_read_tablet('distinct'...))

	return;
} ## end sub _load_distinct

# pending bans, the ip and cidr flavors alike... a subject and, optionally,
# the ban_time it is owed
sub _load_pending_tablet {
	my ( $self, $kind, $key_column, $store ) = @_;

	my $line_int = 0;
	foreach my $line ( $self->_read_tablet($kind) ) {
		$line_int++;
		if ( ( $line_int == 1 && $line =~ /^\Q$key_column\E,/ ) || $line eq '' ) {
			next;
		}
		my ( $subject, $ban_time ) = split( /,/, $line );
		if ( !defined($subject) || $subject eq '' ) {
			next;
		}
		$store->{$subject} = ( defined($ban_time) && $ban_time =~ /^[0-9]+$/ ) ? $ban_time + 0 : undef;
	} ## end foreach my $line ( $self->_read_tablet($kind) )

	return;
} ## end sub _load_pending_tablet

# the writer twin... subject,ban_time with a empty ban_time meaning undef
sub _write_pending_tablet {
	my ( $self, $kind, $key_column, $store ) = @_;

	$self->_write_tablet(
		$kind,
		sub {
			my ($fh) = @_;
			print $fh $key_column . ",ban_time\n";
			foreach my $subject ( sort( keys( %{$store} ) ) ) {
				print $fh $subject . ',' . ( defined( $store->{$subject} ) ? $store->{$subject} : '' ) . "\n";
			}
		}
	);

	return;
} ## end sub _write_pending_tablet

# log positions... the saved inode and offset a file was last read to
sub _load_positions {
	my ($self) = @_;

	my $line_int = 0;
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
	} ## end foreach my $line ( $self->_read_tablet('positions'...))

	return;
} ## end sub _load_positions

# journal cursors, kept only for a watcher that still exists and is still a
# journal one
sub _load_cursors {
	my ($self) = @_;

	my $line_int = 0;
	foreach my $line ( $self->_read_tablet('cursors') ) {
		$line_int++;
		if ( ( $line_int == 1 && $line =~ /^watcher,/ ) || $line eq '' ) {
			next;
		}
		# the watcher column may carry a comma inside quotes, so a plain
		# first-comma split would shear a quoted name in half
		if ( $line !~ /^("(?:[^"]|"")*"|[^,]*),(.*)$/ ) {
			next;
		}
		my ( $watcher_name, $cursor ) = ( _csv_unescape($1), _csv_unescape($2) );
		# only for a watcher that still exists and is still a journal one
		if (   defined($watcher_name)
			&& defined($cursor)
			&& defined( $self->{watchers}{$watcher_name} )
			&& $self->{watchers}{$watcher_name}{is_journal} )
		{
			$self->{journal_cursors}{$watcher_name} = $cursor;
		}
	} ## end foreach my $line ( $self->_read_tablet('cursors'...))

	return;
} ## end sub _load_cursors

# stats... take the stored totals, but only shapes and numbers that make
# sense, as the tablet may be from a older format
sub _load_stats {
	my ($self) = @_;

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
	} ## end foreach my $line ( $self->_read_tablet('stats'))

	return;
} ## end sub _load_stats

# correlation context, handed back to each rule to restore its own state
sub _load_context {
	my ( $self, $now ) = @_;

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
	} ## end foreach my $line ( $self->_read_tablet('context'...))

	return;
} ## end sub _load_context

# marks, restored whole and pruned of anything already expired
sub _load_marks {
	my ( $self, $now ) = @_;

	foreach my $line ( $self->_read_tablet('marks') ) {
		if ( $line eq '' ) {
			next;
		}
		my $decoded;
		eval { $decoded = decode_json($line); };
		if (   ref($decoded) ne 'HASH'
			|| !defined( $decoded->{name} )
			|| !defined( $decoded->{key} )
			|| !defined( $decoded->{expires} )
			|| $decoded->{expires} !~ /^[0-9]+$/
			|| $decoded->{expires} <= $now )
		{
			next;
		}
		$self->{marks}{ $decoded->{name} }{ $decoded->{key} } = {
			'expires' => $decoded->{expires} + 0,
			( defined( $decoded->{set} ) && $decoded->{set} =~ /^[0-9]+$/ ) ? ( 'set'   => $decoded->{set} + 0 ) : (),
			exists( $decoded->{value} )                                     ? ( 'value' => $decoded->{value} )   : ()
		};
	} ## end foreach my $line ( $self->_read_tablet('marks'))

	return;
} ## end sub _load_marks

# the mark stream cursor, then a first drain to catch up on whatever the
# fleet branded while this galla was down... over the local marks just
# restored above, so the two converge before the socket opens. a missing
# or trimmed-away cursor just replays the retained stream, which is safe
sub _load_mark_stream {
	my ($self) = @_;

	foreach my $line ( $self->_read_tablet('mark_stream') ) {
		if ( $line ne '' ) {
			$self->{mark_stream_id} = $line;
			last;
		}
	}
	$self->_sync_marks;

	return;
} ## end sub _load_mark_stream

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

	# a newline can not survive the line-based tablets no matter the
	# quoting, as the writer splits the buffer on them and the loaders
	# read line-wise, so it is dropped rather than chiseled broken
	$value =~ s/[\r\n]//g;
	# file paths with a comma or quote would break the simple CSV
	if ( $value =~ /[,"]/ ) {
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
}

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
		flock( $fh, 2 )                        || die( 'lock failed... ' . $! );    # LOCK_EX
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
}

# the raw match line for a EVE event... normally the log line verbatim,
# but when that line is itself a JSON object or array it rides along
# decoded, so the eve stream carries the structure and not a escaped
# string blob. anything that does not decode stays the line as received
sub _eve_raw {
	my ( $self, $raw ) = @_;

	if ( defined($raw) && $raw =~ /^\s*[\{\[]/ ) {
		my $decoded;
		eval { $decoded = decode_json($raw); };
		if ( !$@ && ref($decoded) ) {
			return $decoded;
		}
	}

	return $raw;
} ## end sub _eve_raw

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

    - watching :: Per watcher, what it is set to watch and what it is
          watching now... for a file watcher the log specs (literal paths
          and globs) under globs and the concrete files currently followed
          under following, and for a journal watcher the journalctl matches
          under journal with journal_running saying whether the wheel is up.

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
			'watching' => sub {
				return $self->_cmd_watching;
			},
			'stop' => sub {
				my ( undef, undef, $ctx ) = @_;
				return $self->_cmd_stop($ctx);
			},
		},
	);
	$self->{server} = $server;

	# the persistent async client bans ride, so the event loop never blocks
	# on Kur... a down Ereshkigal at start is a normal state, hence lazy
	$self->_spawn_kur_client;

	# under POE the DNS work goes through the background engine... the
	# blocking closures stay the transport everywhere else
	$self->{dns_async} = 1;

	POE::Session->create(
		object_states => [
			$self => {
				'_start'          => '_poe_start',
				'got_line'        => '_poe_got_line',
				'tail_error'      => '_poe_tail_error',
				'tail_reset'      => '_poe_tail_reset',
				'journal_stdout'  => '_poe_journal_stdout',
				'journal_stderr'  => '_poe_journal_stderr',
				'journal_reaped'  => '_poe_journal_reaped',
				'restart_journal' => '_poe_restart_journal',
				'sweep'           => '_poe_sweep',
				'join_flush'      => '_poe_join_flush',
				'stop_tails'      => '_poe_stop_tails',
				'dns_start'       => '_poe_dns_start',
				'dns_answered'    => '_poe_dns_answered',
				'dns_timed_out'   => '_poe_dns_timed_out',
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
		undef,
		$ident
	);

	$poe_kernel->run;

	# a final checkpoint... anything an in-flight ban answered into the
	# pending queues while the loop was winding down persists too
	$self->checkpoint;

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

	# the joiner tick only runs when a watcher carries a joiner... a second
	# is the flush_after resolution, far finer than the sweep's ten
	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		if ( defined( $self->{watchers}{$watcher_name}{join} ) ) {
			$kernel->delay( 'join_flush', 1 );
			last;
		}
	}

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

	$watcher->{wheels}{$file}               = $wheel;
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

	$watcher->{journal_wheel}                 = $wheel;
	$watcher->{journal_spawned}               = time;
	$self->{wheelid_to_journal}{ $wheel->ID } = $watcher_name;
	$self->{pid_to_journal}{ $wheel->PID }    = $watcher_name;

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
	my $source  = 'journal' . ( @{$matches} ? ':' . join( ',', @{$matches} ) : '' );

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

	log_drek( 'err', 'journalctl for the watcher "' . $watcher_name . '" exited, restarting in ' . $delay . ' seconds',
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
		'tail error for the watcher "'
			. $watcher_name
			. '" during '
			. $operation . '... '
			. $errstr . ' ('
			. $errnum . ')',
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

sub _poe_join_flush {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	if ( $self->{stopping} ) {
		return;
	}

	$self->_flush_stale_join_buffers;
	$kernel->delay( 'join_flush', 1 );

	return;
} ## end sub _poe_join_flush

# tears the tail wheels down so the session can end and the kernel can exit
sub _poe_stop_tails {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	# whatever record a joiner is midway through gathering goes through the
	# pipeline whole, so a clean stop drops nothing buffered
	$self->_flush_stale_join_buffers(1);

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

	# in-flight DNS queries would hold this session alive... their alarms
	# fall to the remove_all below, the selects are dropped here
	foreach my $handle_key ( keys( %{ $self->{dns_inflight} } ) ) {
		my $query = delete( $self->{dns_inflight}{$handle_key} );
		if ( defined( $query->{handle} ) ) {
			$kernel->select_read( $query->{handle} );
		}
	}

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

# handles a single physical line from the log of the specified watcher...
# a watcher with a joiner glues continuation lines onto their head line
# ahead of the parser, so what the rules judge is one logical record
sub _handle_line {
	my ( $self, $watcher_name, $line, $source ) = @_;

	my $watcher = $self->{watchers}{$watcher_name};
	if ( !defined($watcher) ) {
		return;
	}

	$self->_tick( 'lines', $watcher_name );

	my $join = $watcher->{join};
	if ( !defined($join) ) {
		return $self->_process_record( $watcher_name, $line, $source );
	}

	# buffers are per source as continuation only means adjacency with in
	# one file, and several files may feed one watcher interleaved
	my $source_key = defined($source) ? $source : '';
	my $buffer     = $self->{join_buffers}{$watcher_name}{$source_key};

	if ( defined($buffer) && $line =~ $join->{continuation} ) {
		push( @{ $buffer->{lines} }, $line );
		$buffer->{last_seen} = time;
		if ( scalar( @{ $buffer->{lines} } ) >= $join->{max_lines} ) {
			$self->_flush_join_buffer( $watcher_name, $source_key );
		}
		return;
	}

	# a head line... the record before it is whole, so flush it, then
	# buffer this one awaiting its continuations... a continuation with
	# no head to glue to, like starting mid record, heads its own
	$self->_flush_join_buffer( $watcher_name, $source_key );
	$self->{join_buffers}{$watcher_name}{$source_key}
		= { 'lines' => [$line], 'source' => $source, 'last_seen' => time };

	return;
} ## end sub _handle_line

# flushes one join buffer through the pipeline as a single record, the
# physical lines glued with newlines
sub _flush_join_buffer {
	my ( $self, $watcher_name, $source_key ) = @_;

	my $buffer = delete( $self->{join_buffers}{$watcher_name}{$source_key} );
	if ( !defined($buffer) ) {
		return;
	}
	if ( scalar( @{ $buffer->{lines} } ) > 1 ) {
		$self->_tick( 'joined', $watcher_name );
	}

	return $self->_process_record( $watcher_name, join( "\n", @{ $buffer->{lines} } ), $buffer->{source} );
} ## end sub _flush_join_buffer

# flushes every join buffer not fed since its watcher's flush_after ago...
# ran on the joiner tick, and forced by the stop path so nothing buffered
# is dropped on a clean stop
sub _flush_stale_join_buffers {
	my ( $self, $force ) = @_;

	my $now = time;
	foreach my $watcher_name ( sort( keys( %{ $self->{join_buffers} } ) ) ) {
		my $join = $self->{watchers}{$watcher_name}{join};
		foreach my $source_key ( sort( keys( %{ $self->{join_buffers}{$watcher_name} } ) ) ) {
			my $buffer = $self->{join_buffers}{$watcher_name}{$source_key};
			if ( $force || !defined($join) || ( $now - $buffer->{last_seen} ) >= $join->{flush_after} ) {
				$self->_flush_join_buffer( $watcher_name, $source_key );
			}
		}
	}

	return;
} ## end sub _flush_stale_join_buffers

# handles a single logical record... the whole line for most watchers, the
# joined lines for one with a joiner
sub _process_record {
	my ( $self, $watcher_name, $line, $source ) = @_;

	my $watcher = $self->{watchers}{$watcher_name};
	if ( !defined($watcher) ) {
		return;
	}

	my $parsed = App::Baphomet::Parser::parse( $watcher->{parser}, $line );
	if ( !defined($parsed) ) {
		$self->_tick( 'unparsed', $watcher_name );
		return;
	}

	my $now = time;

	# the record's position in its own file, for the staged rules whose
	# skip bound counts intervening lines... keyless staging slots by the
	# source too
	my $seq_source = defined($source) ? $source : '';
	my $line_ctx   = {
		'seq'    => ++$self->{line_seqs}{$watcher_name}{$seq_source},
		'source' => $seq_source,
		# carried so the rules do not each call time per line
		'now'    => $now,
	};

	# rules are checked in order and the first to match wins, so a line
	# matching more than one rule only counts once... except a rule whose
	# mark gates veto and a mark_only rule that only brands do not consume
	# the line, so matching falls through to the later rules. the watcher
	# name scopes any correlation state, as keys like conn ids are only
	# unique with in one log
	for ( my $rule_int = 0; $rule_int < scalar( @{ $watcher->{rule_objs} } ); $rule_int++ ) {
		my $rule_obj  = $watcher->{rule_objs}[$rule_int];
		my $rule_name = $watcher->{rules}[$rule_int];
		my $found     = $rule_obj->check( $parsed, $watcher_name, $line_ctx );
		if ( !defined($found) ) {
			next;
		}

		my $gates        = $rule_obj->mark_gates;
		my $mark_only    = $rule_obj->mark_only;
		my $is_detection = $rule_obj->is_detection;
		my $country_gate = $watcher->{country_gates}[$rule_int];
		my $namtar_gate  = $watcher->{namtar_gates}[$rule_int];
		my $active_gate  = $watcher->{active_gates}[$rule_int];

		# observe mode... the rule's own eve_only wins over the watcher-resolved
		# one, so a deployment can be set observe at any level and trusted rules
		# opt back in. observe_ignored, a watcher setting, lets observe mode
		# also watch what ignore_ips would drop
		my $rule_eve_only   = $rule_obj->eve_only;
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
			if ( !$self->_reverse_dns_gate_pass( $rule_obj->reverse_dns, $one->{data}, undef ) ) {
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
				'stages'    => $one->{stages},
				'rule'      => $rule_obj,
				'rule_name' => $rule_name,
				'watcher'   => $watcher_name,
				'severity'  => defined( $rule_obj->severity )
				? $rule_obj->severity
				: $watcher->{settings}{default_severity},
			};

			# a ban_not_internal rule banishes the end of the flow that is
			# not one of ours... the offender may be the src or the dest
			# depending on where the alert fired. a detection rule banishes
			# nobody, so it has no offenders, only detection_var subjects
			my $not_internal = $is_detection ? 0 : $rule_obj->ban_not_internal;

			# the offenders this result would banish... the ban_vars that
			# captured a IP that is not one of our own. also who the var-less
			# marks brand and the var-less gates key by
			my @offenders;
			if ( !$is_detection ) {
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
				} ## end foreach my $ban_var ( $rule_obj->ban_var )
			} ## end if ( !$is_detection )

			# usedns... a ban_var value that is not a IP is a hostname the
			# daemon logged, hostile input. under no it is dropped, under
			# resolve_seen it becomes the addresses it resolves to, and
			# under resolve_ban it counts by name, resolving at the
			# threshold over in _ban_ip
			if (@offenders) {
				@offenders = $self->_usedns_offenders( $watcher_name, \@offenders );
			}

			my ( $set, $lifted ) = $self->_apply_marks( $rule_obj, $one->{data}, \@offenders, $now );

			my $score;
			if ($is_detection) {
				# detection-only... count each detection_var subject into the
				# shadow buckets and never banish. a subject crossing threshold
				# raises a sighted, a match itself is a sighting. it consumes
				# the line the same as any firing non-mark_only rule
				$consumed = 1;
				foreach my $detection_var ( $rule_obj->detection_var ) {
					my $subject = $one->{data}{$detection_var};
					if ( !defined($subject) || $subject eq '' ) {
						next;
					}
					my $registered
						= $self->_register_hit( $watcher_name, $subject, $context, $eve_only, $observe_ignored, 1 );
					if ( !defined($score) && defined($registered) ) {
						$score = $registered;
					}
				} ## end foreach my $detection_var ( $rule_obj->detection_var)
				$self->_eve_emit( 'sighting', $self->_eve_fields( $context, $score, $set, $lifted ) );
			} else {
				# the offender this match would pass for banning, the first to
				# survive the per-IP gates and reach the ban path... promoted to
				# the match event's top-level ip, the way a banish carries it,
				# undef and so absent when nothing was passed for banning
				my $ban_ip;
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
						if ( !$self->_reverse_dns_gate_pass( $rule_obj->reverse_dns, $one->{data}, $ip ) ) {
							next;
						}
						if ( !defined($ban_ip) ) {
							$ban_ip = $ip;
						}
						my $registered
							= $self->_register_hit( $watcher_name, $ip, $context, $eve_only, $observe_ignored );
						if ( !defined($score) && defined($registered) ) {
							$score = $registered;
						}
					} ## end foreach my $ip (@offenders)
				} ## end if ( !$mark_only )

				# observe mode colors the match event noted, not found
				my $fields = $self->_eve_fields( $context, $score, $set, $lifted );
				if ( defined($ban_ip) ) {
					$fields->{ip} = $ban_ip;
				}
				$self->_eve_emit( $eve_only ? 'noted' : 'found', $fields );
			} ## end else [ if ($is_detection) ]
		} ## end foreach my $one (@all_found)

		if ($consumed) {
			last;
		}
	} ## end for ( my $rule_int = 0; $rule_int < scalar(...))

	return;
} ## end sub _process_record

# builds the raw/parsed/found/rule/path/score fields of a EVE event from a
# match context... only assembled when the EVE log is on. score is the
# offender's accumulated weighted score, equal to the raw hit tally when no
# weights are in play
sub _eve_fields {
	my ( $self, $context, $score, $set, $lifted ) = @_;

	if ( !$self->{eve_enable} ) {
		return {};
	}

	# the flow's src and dest addresses lifted to the top level from the found
	# data, under the vars the rule names or the src_ip / dest_ip defaults...
	# always emitted, null when the named var is absent, so a consumer can
	# lean on them being there
	my $found   = ref( $context->{found} ) eq 'HASH' ? $context->{found} : {};
	my $src_ip  = $found->{ $context->{rule}->src_ip_var };
	my $dest_ip = $found->{ $context->{rule}->dest_ip_var };

	return {
		defined( $context->{source} ) ? ( 'path' => $context->{source} ) : (),
		'raw'    => $self->_eve_raw( $context->{raw} ),
		'parsed' => $self->_eve_parsed( $context->{parsed} ),
		'found'  => $context->{found},
		# a staged rule's whole story... each stage hit's index, epoch, and
		# line, the raw above being only the final one
		defined( $context->{stages} ) ? ( 'stages' => $context->{stages} ) : (),
		'src_ip'  => $src_ip,
		'dest_ip' => $dest_ip,
		'msg'     => $context->{rule}->msg,
		'rule'    => $context->{rule}->info,
		defined( $context->{severity} )         ? ( 'severity'   => $context->{severity} )         : (),
		defined( $context->{rule}->classtype )  ? ( 'classtype'  => $context->{rule}->classtype )  : (),
		defined( $context->{rule}->references ) ? ( 'references' => $context->{rule}->references ) : (),
		defined( $context->{rule}->attack )     ? ( 'attack'     => $context->{rule}->attack )     : (),
		defined($score)                         ? ( 'score'      => $score )                       : (),
		( defined($set) && @{$set} )            ? ( 'marks_set'  => $set )                         : (),
		( defined($lifted) && @{$lifted} )      ? ( 'unmarked'   => $lifted )                      : (),
	};
} ## end sub _eve_fields

# stands the optional DNS resolver up for usedns, if enable_dns consents...
# stores a resolving closure on success, a error string otherwise. a set
# enable_dns with no loadable Net::DNS leaves usedns behaving as no, which
# the watcher build says loudly. the closure is the seam the tests inject
# a mock resolver through
sub _open_dns {
	my ($self) = @_;

	$self->{dns_error} = undef;
	eval {
		require Net::DNS::Resolver;
		my $resolver = Net::DNS::Resolver->new(
			'udp_timeout' => $self->{usedns_timeout},
			'tcp_timeout' => $self->{usedns_timeout},
			'retry'       => 1,
		);
		# kept for the background query engine, which bgsends on the same
		# resolver the blocking closure wraps... one config, one behavior
		$self->{dns_resolver} = $resolver;
		$self->{dns_resolve}  = sub {
			my ($hostname) = @_;
			my @addrs;
			foreach my $type ( 'A', 'AAAA' ) {
				my $reply = $resolver->query( $hostname, $type );
				if ( defined($reply) ) {
					foreach my $rr ( $reply->answer ) {
						if ( $rr->type eq $type ) {
							push( @addrs, $rr->address );
						}
					}
				}
			} ## end foreach my $type ( 'A', 'AAAA' )
			if ( !@addrs ) {
				return undef;
			}
			return \@addrs;
		}; ## end sub
	};
	if ($@) {
		$self->{dns_error} = $@;
	}

	return;
} ## end sub _open_dns

# stands the reverse DNS machinery up for the reverse_dns gates... the PTR
# and forward closures return a array ref (possibly empty... authoritative
# absence is an answer) or undef (failure), the distinction the gate's
# fail-closed logic leans on. only called when some rule carries the gate,
# so Net::DNS stays optional for everyone else. the closures are the seam
# the tests inject mocks through
sub _open_rdns {
	my ($self) = @_;

	$self->{rdns_error} = undef;
	eval {
		require Net::DNS::Resolver;
		my $resolver = Net::DNS::Resolver->new(
			'udp_timeout' => $self->{rdns_timeout},
			'tcp_timeout' => $self->{rdns_timeout},
			'retry'       => 1,
		);
		# kept for the background query engine, as with dns_resolver
		$self->{rdns_resolver} = $resolver;
		my $ask = sub {
			my ( $query_name, @types ) = @_;
			my @found;
			foreach my $type (@types) {
				my $packet = $resolver->send( $query_name, $type );
				if ( !defined($packet) ) {
					return undef;
				}
				my $rcode = $packet->header->rcode;
				if ( $rcode ne 'NOERROR' && $rcode ne 'NXDOMAIN' ) {
					return undef;
				}
				foreach my $rr ( $packet->answer ) {
					if ( $type eq 'PTR' && $rr->type eq 'PTR' ) {
						push( @found, $rr->ptrdname );
					} elsif ( $rr->type eq $type ) {
						push( @found, $rr->address );
					}
				}
			} ## end foreach my $type (@types)
			return \@found;
		}; ## end $ask = sub
		$self->{dns_reverse} = sub {
			my ($address) = @_;
			return $ask->( $address, 'PTR' );
		};
		$self->{dns_forward} = sub {
			my ($hostname) = @_;
			return $ask->( $hostname, 'A', 'AAAA' );
		};
	};
	if ($@) {
		$self->{rdns_error} = $@;
	}

	return;
} ## end sub _open_rdns

# folds a reply packet into the tri-valued outcome the blocking closures
# return... an arrayref of extracted values for NOERROR/NXDOMAIN (possibly
# empty, authoritative absence being an answer), undef for a failure
sub _dns_fold {
	my ( $packet, $qtype ) = @_;

	if ( !defined($packet) ) {
		return undef;
	}
	my $rcode = eval { $packet->header->rcode };
	if ( !defined($rcode) || ( $rcode ne 'NOERROR' && $rcode ne 'NXDOMAIN' ) ) {
		return undef;
	}

	my @found;
	foreach my $rr ( $packet->answer ) {
		if ( $qtype eq 'PTR' && $rr->type eq 'PTR' ) {
			push( @found, $rr->ptrdname );
		} elsif ( $rr->type eq $qtype ) {
			push( @found, $rr->address );
		}
	}

	return \@found;
} ## end sub _dns_fold

# whether background queries of the given kind can actually fly... the
# galla must be under POE (dns_async, set by start_server) and hold either
# the injectable seam or the kind's resolver. without this the blocking
# closures stay the transport, which is what keeps run_tests and a galla
# driven directly by the tests working with out an event loop
sub _dns_async_ready {
	my ( $self, $kind ) = @_;

	if ( !$self->{dns_async} ) {
		return 0;
	}
	if ( defined( $self->{dns_bg} ) ) {
		return 1;
	}
	return defined( $kind eq 'rdns' ? $self->{rdns_resolver} : $self->{dns_resolver} ) ? 1 : 0;
} ## end sub _dns_async_ready

# fires one background query, $done receiving the folded tri-value...
# routed through the tails session so the select and the timeout alarm
# live there no matter which session initiated (a kur client completion,
# say). the dns_bg closure is the test seam, standing in for the whole
# wire engine when injected
sub _dns_query_bg {
	my ( $self, $kind, $qname, $qtype, $done ) = @_;

	if ( defined( $self->{dns_bg} ) ) {
		$self->{dns_bg}->( $kind, $qname, $qtype, $done );
		return;
	}

	$poe_kernel->post(
		'galla-tails-' . $self->{name},
		'dns_start',
		{
			'kind'  => $kind,
			'qname' => $qname,
			'qtype' => $qtype,
			'done'  => $done,
		}
	);

	return;
} ## end sub _dns_query_bg

# the wire half of the engine... bgsend on the same resolver the blocking
# closure wraps, the returned handle watched by the kernel and bounded by
# the kind's configured timeout
sub _poe_dns_start {
	my ( $self, $kernel, $query ) = @_[ OBJECT, KERNEL, ARG0 ];

	my $resolver = $query->{kind} eq 'rdns' ? $self->{rdns_resolver} : $self->{dns_resolver};
	my $timeout  = $query->{kind} eq 'rdns' ? $self->{rdns_timeout}  : $self->{usedns_timeout};
	if ( !defined($resolver) ) {
		$query->{done}->(undef);
		return;
	}

	my $handle = eval { $resolver->bgsend( $query->{qname}, $query->{qtype} ); };
	if ( !defined($handle) ) {
		$query->{done}->(undef);
		return;
	}

	$query->{handle}                    = $handle;
	$self->{dns_inflight}{"$handle"}    = $query;
	$kernel->select_read( $handle, 'dns_answered' );
	$query->{alarm_id} = $kernel->delay_set( 'dns_timed_out', $timeout, "$handle" );

	return;
} ## end sub _poe_dns_start

sub _poe_dns_answered {
	my ( $self, $kernel, $handle ) = @_[ OBJECT, KERNEL, ARG0 ];

	$kernel->select_read($handle);
	my $query = delete( $self->{dns_inflight}{"$handle"} );
	if ( !defined($query) ) {
		return;
	}
	if ( defined( $query->{alarm_id} ) ) {
		$kernel->alarm_remove( $query->{alarm_id} );
	}

	my $resolver = $query->{kind} eq 'rdns' ? $self->{rdns_resolver} : $self->{dns_resolver};
	my $packet   = eval { $resolver->bgread($handle); };
	$query->{done}->( _dns_fold( $packet, $query->{qtype} ) );

	return;
} ## end sub _poe_dns_answered

# a query past its deadline completes as a failure, the fail-closed
# posture every DNS consumer already promises... the answer showing up
# later is simply discarded, its select gone
sub _poe_dns_timed_out {
	my ( $self, $kernel, $handle_key ) = @_[ OBJECT, KERNEL, ARG0 ];

	my $query = delete( $self->{dns_inflight}{$handle_key} );
	if ( !defined($query) ) {
		return;
	}
	$kernel->select_read( $query->{handle} );
	$query->{done}->(undef);

	return;
} ## end sub _poe_dns_timed_out

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
# carries no country... a country lookup dies on a bad address, so eval it.
# answers are cached 60 seconds like the DNS ones, as this was the one
# uncached per-line gate lookup
sub _country_of {
	my ( $self, $ip ) = @_;

	if ( !defined( $self->{geoip} ) || !defined($ip) ) {
		return undef;
	}

	my $now    = time;
	my $cached = $self->{country_cache}{$ip};
	if ( defined($cached) && $cached->{expires} > $now ) {
		return $cached->{iso};
	}

	my $record;
	eval { $record = $self->{geoip}->record_for_address($ip); };
	my $iso;
	if ( !$@ && ref($record) eq 'HASH' && ref( $record->{country} ) eq 'HASH' ) {
		$iso = defined( $record->{country}{iso_code} ) ? uc( $record->{country}{iso_code} ) : undef;
	}

	$self->_bound_expiring_store( $self->{country_cache}, $ip, $now );
	$self->{country_cache}{$ip} = { 'iso' => $iso, 'expires' => $now + 60 };

	return $iso;
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
	} ## end foreach my $entry ( @{ $country->{entries} } )

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

# the reverse_dns gate... a var entry is data-driven and ran once per found
# result (ip undef), a var-less one is offender-keyed and ran per candidate
# (ip set). every entry checked must hold
sub _reverse_dns_gate_pass {
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
			my $value = $data->{ $entry->{var} };
			if ( !defined($value) || !$self->_rdns_entry_pass( $entry, $value, $data ) ) {
				return 0;
			}
		} else {
			# a var-less entry belongs to the offender pass... let the data
			# pass by
			if ( !defined($ip) ) {
				next;
			}
			if ( !$self->_rdns_entry_pass( $entry, $ip, $data ) ) {
				return 0;
			}
		} ## end else [ if ( defined( $entry->{var} ) ) ]
	} ## end foreach my $entry ( @{$gate} )

	return 1;
} ## end sub _reverse_dns_gate_pass

# runs one reverse_dns entry against one address... the PTR names, forward
# confirmed unless refused, compared against the regexp or the named found
# value, negated when asked. by default authoritative absence is data...
# no names means the comparison is false and negate makes it count...
# while inability to ask is not... a lookup failure vetoes regardless of
# negate, so an outage can never get anyone counted by a negated gate.
# the entry's on_nxdomain and on_servfail knobs override those defaults
# per rule. always fails closed with out a resolver, on a non-address
# value, and on a missing matches_var
sub _rdns_entry_pass {
	my ( $self, $entry, $address, $data ) = @_;

	if ( !$self->{enable_rdns} || !defined( $self->{dns_reverse} ) ) {
		return 0;
	}
	if ( !defined( ip_family($address) ) ) {
		return 0;
	}

	# the lookup outcome knobs... pass and fail are terminal verdicts the
	# comparison and negate never touch, compare proceeds over whatever
	# names there are
	my $names = $self->_rdns_names($address);
	if ( !defined($names) ) {
		if ( $entry->{on_servfail} eq 'pass' ) {
			return 1;
		}
		if ( $entry->{on_servfail} eq 'fail' ) {
			return 0;
		}
		$names = [];
	} elsif ( !@{$names} ) {
		if ( $entry->{on_nxdomain} eq 'pass' ) {
			return 1;
		}
		if ( $entry->{on_nxdomain} eq 'fail' ) {
			return 0;
		}
	}

	# forward confirmation... a name only participates when it resolves
	# back to the address, a spoofed PTR being as good as absent
	my @confirmed;
	if ( !$entry->{forward_confirm} ) {
		@confirmed = @{$names};
	} else {
		foreach my $ptr_name ( @{$names} ) {
			my $addrs = $self->_rdns_forward($ptr_name);
			if ( !defined($addrs) ) {
				if ( $entry->{on_servfail} eq 'pass' ) {
					return 1;
				}
				if ( $entry->{on_servfail} eq 'fail' ) {
					return 0;
				}
				# compare... this name is simply unconfirmed
				next;
			} ## end if ( !defined($addrs) )
			if ( grep { $self->_rdns_addr_eq( $_, $address ) } @{$addrs} ) {
				push( @confirmed, $ptr_name );
			}
		} ## end foreach my $ptr_name ( @{$names} )
	} ## end else [ if ( !$entry->{forward_confirm} ) ]

	my $hit = 0;
	if ( defined( $entry->{regexp} ) ) {
		foreach my $ptr_name (@confirmed) {
			if ( $ptr_name =~ $entry->{regexp} ) {
				$hit = 1;
				last;
			}
		}
	} else {
		my $expected = $data->{ $entry->{matches_var} };
		if ( !defined($expected) || $expected eq '' ) {
			return 0;
		}
		$expected = lc($expected);
		$expected =~ s/\.+$//;
		foreach my $ptr_name (@confirmed) {
			my $folded = lc($ptr_name);
			$folded =~ s/\.+$//;
			if ( $folded eq $expected ) {
				$hit = 1;
				last;
			}
		}
	} ## end else [ if ( defined( $entry->{regexp} ) ) ]

	if ( $entry->{negate} ) {
		$hit = $hit ? 0 : 1;
	}

	return $hit;
} ## end sub _rdns_entry_pass

# the cached tri-state lookups behind the reverse_dns gate... a array ref
# (possibly empty, authoritative absence) or undef (failure), both
# remembered, so a hostile flood of matches asks each question once a
# minute at most. under the background engine a cold key fires its query
# and answers undef for THIS line — a lookup failure, judged by the
# entry's on_servfail knob like any other — the real answer warm in the
# cache for the next line, and a flood on one cold key fires one query
sub _rdns_cached {
	my ( $self, $cache_key, $ask ) = @_;

	my $now    = time;
	my $cached = $self->{rdns_cache}{$cache_key};
	if ( defined($cached) && $cached->{expires} > $now ) {
		return $cached->{inflight} ? undef : $cached->{answer};
	}

	if ( $self->_dns_async_ready('rdns') ) {
		$self->_rdns_fire( $cache_key, $now );
		return undef;
	}

	my $answer = eval { $ask->(); };
	if ( $@ || ( defined($answer) && ref($answer) ne 'ARRAY' ) ) {
		$answer = undef;
	}
	if ( !defined($answer) ) {
		$self->_tick('rdns_failures');
	}

	# bound the cache the way the other stores are bounded
	$self->_bound_expiring_store( $self->{rdns_cache}, $cache_key, $now );
	$self->{rdns_cache}{$cache_key} = { 'answer' => $answer, 'expires' => $now + 60 };

	return $answer;
} ## end sub _rdns_cached

# fires the background lookup a cold rdns cache key names... ptr: keys ask
# PTR of the address, fwd: keys ask A and AAAA of the name, either failing
# whole if a family fails, matching the blocking $ask. a landed PTR answer
# proactively warms the forward confirmations of its names, so the usual
# cold-name cost is one line, not one per chain hop
sub _rdns_fire {
	my ( $self, $cache_key, $now ) = @_;

	my ( $kind_prefix, $subject ) = split( /:/, $cache_key, 2 );

	$self->_bound_expiring_store( $self->{rdns_cache}, $cache_key, $now );
	$self->{rdns_cache}{$cache_key} = {
		'inflight' => 1,
		'expires'  => $now + ( $self->{rdns_timeout} * 2 ) + 1,
	};

	my $settle = sub {
		my ($answer) = @_;
		if ( !defined($answer) ) {
			$self->_tick('rdns_failures');
		}
		$self->{rdns_cache}{$cache_key} = { 'answer' => $answer, 'expires' => time + 60 };
		if ( $kind_prefix eq 'ptr' && defined($answer) ) {
			# warm the forward confirmations... PTR sets are small, but a
			# hostile one is capped rather than trusted
			my $warmed = 0;
			foreach my $ptr_name ( @{$answer} ) {
				last if ++$warmed > 10;
				my $fwd_key    = 'fwd:' . $ptr_name;
				my $fwd_cached = $self->{rdns_cache}{$fwd_key};
				if ( defined($fwd_cached) && $fwd_cached->{expires} > time ) {
					next;
				}
				$self->_rdns_fire( $fwd_key, time );
			}
		} ## end if ( $kind_prefix eq 'ptr' && defined($answer...))
		return;
	};

	if ( $kind_prefix eq 'ptr' ) {
		$self->_dns_query_bg( 'rdns', $subject, 'PTR', $settle );
		return;
	}

	# fwd... both families must answer, either failing fails the whole,
	# exactly as the blocking $ask treats it
	my @found;
	my $failed;
	my $outstanding = 2;
	my $one_family  = sub {
		my ($answer) = @_;
		if ( !defined($answer) ) {
			$failed = 1;
		} else {
			push( @found, @{$answer} );
		}
		$outstanding--;
		if ( !$outstanding ) {
			$settle->( $failed ? undef : \@found );
		}
		return;
	};
	foreach my $qtype ( 'A', 'AAAA' ) {
		$self->_dns_query_bg( 'rdns', $subject, $qtype, $one_family );
	}

	return;
} ## end sub _rdns_fire

sub _rdns_names {
	my ( $self, $address ) = @_;

	return $self->_rdns_cached( 'ptr:' . $address, sub { $self->{dns_reverse}->($address); } );
}

sub _rdns_forward {
	my ( $self, $hostname ) = @_;

	return $self->_rdns_cached( 'fwd:' . $hostname, sub { $self->{dns_forward}->($hostname); } );
}

# compares two addresses by packed value, so IPv6 spelling differences do
# not defeat forward confirmation
sub _rdns_addr_eq {
	my ( $self, $left, $right ) = @_;

	foreach my $family ( AF_INET, AF_INET6 ) {
		my $left_packed  = inet_pton( $family, $left );
		my $right_packed = inet_pton( $family, $right );
		if ( defined($left_packed) && defined($right_packed) ) {
			return $left_packed eq $right_packed ? 1 : 0;
		}
	}

	return 0;
} ## end sub _rdns_addr_eq

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
	} ## end if ( defined($mtime) && open( $fh, '<', $path...))

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
	}

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
		} ## end foreach my $name ( @{ $entry->{lists} } )
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
		}
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
			}
			push( @specs, { 'days' => $days, 'ranges' => $ranges } );
		} ## end foreach my $spec ( @{$window} )
	} ## end foreach my $name ( @{ $active->{windows} } )

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
			}
			if ( !$hit ) {
				next;
			}
		} ## end if ( defined( $spec->{ranges} ) )
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

	# the sequence gate... ordered temporal correlation. every named mark must
	# be live for the key and their first-seen times non-decreasing in the
	# listed order, so "stage a then b then c" only holds when a fired no later
	# than b and b no later than c. keyed like the marked gate, by a var's
	# capture or, var-less, by the offender
	foreach my $entry ( @{ $gates->{sequence} } ) {
		if ( defined( $entry->{var} ) ? defined($ip) : !defined($ip) ) {
			next;
		}
		my $key = defined( $entry->{var} ) ? $data->{ $entry->{var} } : $ip;
		if ( !defined($key) ) {
			return 0;
		}
		my $prev_set;
		foreach my $mark_name ( @{ $entry->{marks} } ) {
			my $mark = $self->{marks}{$mark_name}{$key};
			if ( !defined($mark) || $mark->{expires} <= $now ) {
				return 0;
			}
			my $set = $mark->{set};
			# order only enforced between marks that both carry a set time... a
			# mark from before set times existed simply is not ordered against
			if ( defined($set) && defined($prev_set) && $set < $prev_set ) {
				return 0;
			}
			if ( defined($set) ) {
				$prev_set = $set;
			}
		} ## end foreach my $mark_name ( @{ $entry->{marks} } )
	} ## end foreach my $entry ( @{ $gates->{sequence} } )

	return 1;
} ## end sub _mark_gates_pass

# bounds a store of expiring entries at the shared 10000 cap ahead of
# inserting a new key... expired entries are pruned first, then the soonest
# to expire is evicted, found by a linear min-scan rather than a sort, as
# this can run per line under a deliberate key flood. the twin of the
# rules-side store bound in App::Baphomet::Rules::Base
sub _bound_expiring_store {
	my ( $self, $store, $key_value, $now ) = @_;

	if ( defined( $store->{$key_value} ) || scalar( keys( %{$store} ) ) < 10000 ) {
		return;
	}

	foreach my $key ( keys( %{$store} ) ) {
		if ( $store->{$key}{expires} <= $now ) {
			delete( $store->{$key} );
		}
	}
	if ( scalar( keys( %{$store} ) ) >= 10000 ) {
		my $soonest;
		foreach my $key ( keys( %{$store} ) ) {
			if ( !defined($soonest) || $store->{$key}{expires} < $store->{$soonest}{expires} ) {
				$soonest = $key;
			}
		}
		delete( $store->{$soonest} );
	}

	return;
} ## end sub _bound_expiring_store

# brands a key into a mark name's store... setting refreshes the expiry,
# and a full store first drops the expired, then the soonest-expiring,
# same bounds as the rules' correlation stores
sub _mark_set {
	my ( $self, $name, $key, $value, $ttl, $now ) = @_;

	my $store = $self->{marks}{$name};
	if ( !defined($store) ) {
		$store = $self->{marks}{$name} = {};
	}

	$self->_bound_expiring_store( $store, $key, $now );

	# the set time is first-seen... a re-brand refreshes the expiry but keeps
	# when the mark first appeared, so the sequence gate orders by when each
	# stage first fired rather than when it was last touched
	my $set
		= ( defined( $store->{$key} ) && defined( $store->{$key}{set} ) && $store->{$key}{expires} > $now )
		? $store->{$key}{set}
		: $now;
	$store->{$key} = { 'expires' => $now + $ttl, 'set' => $set, defined($value) ? ( 'value' => $value ) : () };

	# gossip the brand to the fleet, best-effort, after the local set... a
	# failed publish never unmakes the brand that just happened
	if ( $self->{mark_sync} ) {
		$self->{tablet}->mark_publish( 'set', $name, $key, $value, $now + $ttl, $set );
	}

	return;
} ## end sub _mark_set

# applies a rule's mark and unmark entries for one found result... var
# entries key by that capture, var-less ones by each passed offender IP,
# with the ignored never branded. returns the set and lifted lists for
# the EVE event
sub _apply_marks {
	my ( $self, $rule_obj, $data, $offenders, $now ) = @_;

	my $marks   = $rule_obj->marks;
	my $unmarks = $rule_obj->unmarks;

	# the overwhelmingly common rule carries neither, so it skips the
	# per-offender ignore_ips walk entirely
	if ( !@{$marks} && !@{$unmarks} ) {
		return ( [], [] );
	}

	my @brandable = grep { !ip_ignored( $self->{ignore_ips}, $_ ) } @{$offenders};

	my @set;
	foreach my $entry ( @{$marks} ) {
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
	foreach my $entry ( @{$unmarks} ) {
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
				if ( $self->{mark_sync} ) {
					$self->{tablet}->mark_publish( 'unset', $entry->{name}, $key, undef, undef );
				}
			} ## end if ( defined( $self->{marks}{ $entry->{name...}}))
		} ## end foreach my $key (@keys)
	} ## end foreach my $entry ( @{ $rule_obj->unmarks } )

	return ( \@set, \@lifted );
} ## end sub _apply_marks

# drains the fleet mark bus and folds the new deltas into the live marks,
# advancing the stream cursor... a no-op unless the store carries a bus. the
# read path never touches it, so a bus that is down just yields nothing and the
# gates keep deciding on the local marks
sub _sync_marks {
	my ($self) = @_;

	if ( !$self->{mark_sync} ) {
		return;
	}

	my $now = time;
	my ( $events, $new_id ) = $self->{tablet}->mark_drain( $self->{mark_stream_id} );
	foreach my $event ( @{$events} ) {
		$self->_ingest_mark_event( $event, $now );
	}
	$self->{mark_stream_id} = $new_id;

	return;
} ## end sub _sync_marks

# applies one drained mark delta to the live marks. events fold in stream
# order, which is a single total order every galla agrees on, so this converges
# without any locking. a set is extend-only on the expiry, so a re-brand from
# anywhere never shortens a mark, and takes the delta's value; an unset lifts.
# already-expired sets are dropped, the local sweeper handles the rest
sub _ingest_mark_event {
	my ( $self, $event, $now ) = @_;

	my ( $op, $name, $key ) = ( $event->{op}, $event->{name}, $event->{key} );
	if ( !defined($op) || !defined($name) || !defined($key) ) {
		return;
	}

	if ( $op eq 'unset' ) {
		if ( defined( $self->{marks}{$name} ) && defined( $self->{marks}{$name}{$key} ) ) {
			delete( $self->{marks}{$name}{$key} );
			if ( !%{ $self->{marks}{$name} } ) {
				delete( $self->{marks}{$name} );
			}
		}
		return;
	}

	if ( $op eq 'set' ) {
		my $event_expires = $event->{expires};
		if ( !defined($event_expires) || $event_expires !~ /^[0-9]+$/ || $event_expires <= $now ) {
			return;
		}
		$event_expires += 0;
		my $held    = $self->{marks}{$name}{$key};
		my $expires = $event_expires;
		if ( defined($held) && $held->{expires} > $expires ) {
			$expires = $held->{expires};
		}
		# the set time folds to the earliest, so the whole fleet agrees on when
		# a stage first fired regardless of drain order... expires max, set min,
		# and the value rides with whichever expiry won (ties folding to the
		# lexically greater value), all order-independent so the fold converges
		my $set = ( defined( $event->{set} ) && $event->{set} =~ /^[0-9]+$/ ) ? $event->{set} + 0 : undef;
		if ( defined($held) && defined( $held->{set} ) && ( !defined($set) || $held->{set} < $set ) ) {
			$set = $held->{set};
		}
		my $value_source = $event;
		if ( defined($held) ) {
			if ( $held->{expires} > $event_expires ) {
				$value_source = $held;
			} elsif ( $held->{expires} == $event_expires ) {
				my $held_value  = defined( $held->{value} )  ? $held->{value}  : '';
				my $event_value = defined( $event->{value} ) ? $event->{value} : '';
				if ( $held_value gt $event_value ) {
					$value_source = $held;
				}
			}
		}
		$self->{marks}{$name}{$key} = {
			'expires' => $expires,
			defined($set)                    ? ( 'set'   => $set )                   : (),
			exists( $value_source->{value} ) ? ( 'value' => $value_source->{value} ) : ()
		};
	} ## end if ( $op eq 'set' )

	return;
} ## end sub _ingest_mark_event

# registers a match of a IP, banning it once its accumulated score reaches
# max_score with in find_time seconds... each match deposits the rule's
# weight, so a heavy signature bans faster and several different rules against
# one IP sum toward the one judgment. returns the IP's live score, or undef
# when the IP is ignored and not being observed. in eve_only observe mode it
# counts into a shadow bucket kept wholly apart from the real ones and raises
# a alert instead of banishing, so nothing is sent to Kur
sub _register_hit {
	my ( $self, $watcher_name, $ip, $context, $eve_only, $observe_ignored, $detection ) = @_;

	# the ignored never accumulate so much as a counter... unless observe mode
	# is told to watch what ignore_ips would otherwise drop. a detection subject
	# is not necessarily a IP and never banishes, so ignore_ips does not apply
	if ( !$detection && ip_ignored( $self->{ignore_ips}, $ip ) ) {
		if ( !( $eve_only && $observe_ignored ) ) {
			$self->_tick( 'ignored', $watcher_name );
			return undef;
		}
	}

	my $settings = $self->{watchers}{$watcher_name}{settings};
	my $now      = time;

	# detection rules, like observe mode, count into the shadow families so
	# they can never cause or delay a real ban
	my $use_shadow = ( $eve_only || $detection );

	# when the watcher allows it, the rule's own thresholds and weight speak
	# over the watcher's... a rule overriding how counting works gets its own
	# bucket, so its window does not cross-contaminate the shared one, while a
	# ban_time-only override counts in the shared bucket and only bans
	# differently. without the consent every weight is 1, so a shipped rule
	# can not reshape the tuning
	my $allow     = $settings->{allow_per_rule_thresholds};
	my $overrides = $allow                             ? $context->{rule}->thresholds : {};
	my $max_score = defined( $overrides->{max_score} ) ? $overrides->{max_score}      : $settings->{max_score};
	my $find_time = defined( $overrides->{find_time} ) ? $overrides->{find_time}      : $settings->{find_time};
	my $ban_time  = defined( $overrides->{ban_time} )  ? $overrides->{ban_time}       : $settings->{ban_time};
	my $weight    = $allow                             ? $context->{rule}->weight     : 1;

	# distinct-cardinality counting... instead of summing hits, the bucket is
	# the set of distinct values of the rule's `of` field, keyed by the grouping
	# key, and the score is the set size. bans when the key has produced
	# max_score distinct values with in find_time. the grouping key is the `by`
	# field when set (value_count, count of one field grouped by another, N
	# sources against one account), else the offender (plain distinct-
	# cardinality, N users from one source), and the ban always lands on the
	# current offender, so a non-bannable key like a username still banishes the
	# source that tipped it over
	my $distinct = defined( $context->{rule} ) ? $context->{rule}->distinct : undef;
	if ( defined($distinct) ) {
		my $dcounters = $use_shadow ? $self->{shadow_distinct_counters} : $self->{distinct_counters};
		my $rule_name = $context->{rule_name};
		my $of_value  = $context->{found}{ $distinct->{of} };
		my $key       = defined( $distinct->{by} ) ? $context->{found}{ $distinct->{by} } : $ip;
		if ( !defined($key) || $key eq '' ) {
			return undef;
		}

		my $set = $dcounters->{$rule_name}{$key};
		if ( !defined($set) ) {
			$set = $dcounters->{$rule_name}{$key} = {};
		}
		if ( defined($of_value) && $of_value ne '' ) {
			# bound the set per key... prune the expired first, then evict the
			# oldest, so a flood of distinct values can not grow it without limit
			if ( !defined( $set->{$of_value} ) && scalar( keys( %{$set} ) ) >= 10000 ) {
				foreach my $held ( keys( %{$set} ) ) {
					if ( ( $now - $set->{$held} ) >= $find_time ) {
						delete( $set->{$held} );
					}
				}
				if ( scalar( keys( %{$set} ) ) >= 10000 ) {
					# a linear min-scan, not a sort... this is the per-line
					# path under a deliberate value flood
					my $oldest;
					foreach my $held ( keys( %{$set} ) ) {
						if ( !defined($oldest) || $set->{$held} < $set->{$oldest} ) {
							$oldest = $held;
						}
					}
					delete( $set->{$oldest} );
				}
			} ## end if ( !defined( $set->{$of_value} ) && scalar...)
			$set->{$of_value} = $now;
		} ## end if ( defined($of_value) && $of_value ne '')
		# distinct values older than find_time no longer count
		foreach my $value ( keys( %{$set} ) ) {
			if ( ( $now - $set->{$value} ) >= $find_time ) {
				delete( $set->{$value} );
			}
		}

		my $score = scalar( keys( %{$set} ) );
		if ( $score >= $max_score ) {
			# offender-keyed... the key is the banished IP, clear its set like a
			# counter. by-keyed value_count... the key is not the ban target, so
			# keep the set and banish the current offender, catching every
			# further source while the group stays over threshold
			if ( $key eq $ip ) {
				delete( $dcounters->{$rule_name}{$key} );
			}
			if ($detection) {
				$self->_sighted( $ip, $context, $score );
			} elsif ($eve_only) {
				$self->_alert_ip( $ip, $ban_time, $context, $score );
			} else {
				$self->_ban_ip( $ip, $ban_time, $context, $score );
			}
		} ## end if ( $score >= $max_score )

		# a distinct-counted offender still feeds its subnet bucket... the
		# subnet family is its own per-hit tally with its own threshold,
		# regardless of how the per-IP judgment is scored
		if ( !$detection ) {
			$self->_register_subnet_hit( $watcher_name, $ip, $context, $eve_only, $weight, $now );
		}

		return $score;
	} ## end if ( defined($distinct) )

	# observe mode and detection count into the shadow families, kept apart so
	# a watched or detection rule neither causes nor delays a real ban, nor is
	# polluted by one
	my $counters      = $use_shadow ? $self->{shadow_counters}      : $self->{counters};
	my $rule_counters = $use_shadow ? $self->{shadow_rule_counters} : $self->{rule_counters};

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

	# matches older than find_time no longer count... entries arrive in time
	# order, so shifting the expired off the front beats rebuilding the array
	while ( @{ $bucket->{$ip} } && ( $now - $bucket->{$ip}[0][0] ) >= $find_time ) {
		shift( @{ $bucket->{$ip} } );
	}

	my $score = _score_of( $bucket->{$ip} );

	if ( $score >= $max_score ) {
		delete( $bucket->{$ip} );
		if ($detection) {
			$self->_sighted( $ip, $context, $score );
		} elsif ($eve_only) {
			$self->_alert_ip( $ip, $ban_time, $context, $score );
		} else {
			$self->_ban_ip( $ip, $ban_time, $context, $score );
		}
	} ## end if ( $score >= $max_score )

	# alongside the per-IP tally the offender also feeds a subnet bucket, when
	# the watcher names a prefix for this IP's family... its own threshold, its
	# own window, and a crossing banishes the whole CIDR. a detection subject
	# never banishes, so it never buckets
	if ( !$detection ) {
		$self->_register_subnet_hit( $watcher_name, $ip, $context, $eve_only, $weight, $now );
	}

	return $score;
} ## end sub _register_hit

# feeds the subnet bucket for a offender, when its family has a configured
# prefix... v4 and v6 keep wholly separate stores, and only a family named in
# the settings buckets at all. each deposit remembers the member IP so a
# crossing can name who tipped it. crossing subnet_max_score with in
# subnet_find_time banishes the CIDR, or in observe mode alerts on it. counts
# into the shadow store for observe mode, kept apart from the real one
sub _register_subnet_hit {
	my ( $self, $watcher_name, $ip, $context, $eve_only, $weight, $now ) = @_;

	my $settings = $self->{watchers}{$watcher_name}{settings};

	# never bucket, let alone banish, our own space
	if ( ip_ignored( $self->{internal}, $ip ) ) {
		return;
	}

	my $family = ip_family($ip);
	if ( !defined($family) ) {
		return;
	}
	my $prefix = $family eq 'v4' ? $settings->{ban_subnet_v4} : $settings->{ban_subnet_v6};
	if ( !defined($prefix) ) {
		return;
	}
	my $network = ip_network( $ip, $prefix );
	if ( !defined($network) ) {
		return;
	}

	# the subnet threshold and window fall back to the per-IP ones when the
	# watcher sets none of their own. the ban_time is the watcher's
	my $max_score = defined( $settings->{subnet_max_score} ) ? $settings->{subnet_max_score} : $settings->{max_score};
	my $find_time = defined( $settings->{subnet_find_time} ) ? $settings->{subnet_find_time} : $settings->{find_time};
	my $ban_time  = $settings->{ban_time};

	my $bucket = ( $eve_only ? $self->{shadow_subnet_counters} : $self->{subnet_counters} )->{$family};
	if ( !defined( $bucket->{$network} ) ) {
		$bucket->{$network} = [];
	}
	push( @{ $bucket->{$network} }, [ $now, $weight, $ip ] );

	# deposits older than the subnet find_time no longer count... time
	# ordered, so the expired shift off the front
	while ( @{ $bucket->{$network} } && ( $now - $bucket->{$network}[0][0] ) >= $find_time ) {
		shift( @{ $bucket->{$network} } );
	}

	my $score = _score_of( $bucket->{$network} );
	if ( $score < $max_score ) {
		return;
	}

	# the members that fed the CIDR, distinct and in first-seen order, with the
	# window they spanned, for the eve bucket
	my %seen;
	my @members;
	my ( $first, $last );
	foreach my $entry ( @{ $bucket->{$network} } ) {
		if ( !$seen{ $entry->[2] } ) {
			$seen{ $entry->[2] } = 1;
			push( @members, $entry->[2] );
		}
		if ( !defined($first) || $entry->[0] < $first ) { $first = $entry->[0]; }
		if ( !defined($last)  || $entry->[0] > $last )  { $last  = $entry->[0]; }
	}
	my $info = {
		'family'  => $family,
		'cidr'    => $network,
		'prefix'  => $prefix + 0,
		'members' => \@members,
		'hits'    => scalar( @{ $bucket->{$network} } ),
		'score'   => $score,
		defined($first) ? ( 'first' => $first ) : (),
		defined($last)  ? ( 'last'  => $last )  : (),
	};

	# clear on firing, like a per-IP bucket, so it re-arms rather than banishing
	# every further hit
	delete( $bucket->{$network} );

	if ($eve_only) {
		$self->_alert_subnet( $network, $ban_time, $context, $score, $info );
	} else {
		$self->_ban_subnet( $network, $ban_time, $context, $score, $info );
	}

	return;
} ## end sub _register_subnet_hit

# filters and transforms a offender list per the watcher's usedns... IPs
# pass untouched, hostnames are dropped (no), resolved into their
# addresses (resolve_seen), or passed through to count by name
# (resolve_ban)
sub _usedns_offenders {
	my ( $self, $watcher_name, $offenders ) = @_;

	my $mode = $self->{watchers}{$watcher_name}{settings}{usedns};
	my @kept;
	foreach my $offender ( @{$offenders} ) {
		if ( defined( ip_family($offender) ) || $mode eq 'resolve_ban' ) {
			push( @kept, $offender );
			next;
		}
		if ( $mode eq 'resolve_seen' ) {
			my $addrs = $self->_resolve_hostname_seen($offender);
			if ( defined($addrs) ) {
				push( @kept, @{$addrs} );
			}
			next;
		}
		# no... a hostname names nobody banishable, though the match still
		# wrote to EVE
		$self->_tick( 'hostname_dropped', $watcher_name );
	} ## end foreach my $offender ( @{$offenders} )

	return @kept;
} ## end sub _usedns_offenders

# resolves a hostname to its addresses through the optional resolver,
# cached both ways, capped, and fenced... the ignored and the internal are
# dropped post-resolution absolutely, since the name was hostile input and
# must never aim Kur at your own, and a name resolving past
# usedns_max_addrs is refused whole rather than trimmed. failing closed
# every way... the failure mode is no ban, never a wrong one. returns a
# array ref of addresses, possibly empty, or undef for unresolvable or
# refused
sub _resolve_hostname {
	my ( $self, $hostname ) = @_;

	my $now    = time;
	my $cached = $self->{dns_cache}{$hostname};
	if ( defined($cached) && !$cached->{inflight} && $cached->{expires} > $now ) {
		return $cached->{addrs};
	}

	my $addrs;
	if ( defined( $self->{dns_resolve} ) ) {
		$addrs = eval { $self->{dns_resolve}->($hostname); };
		if ( $@ || ref($addrs) ne 'ARRAY' ) {
			$addrs = undef;
		}
	}

	return $self->_resolve_hostname_fence( $hostname, $addrs, $now );
} ## end sub _resolve_hostname

# the fences and the cache write shared by the blocking and background
# resolutions... max_addrs refusal, the absolute ignore/internal drops,
# the failure tick, and the answered cache entry
sub _resolve_hostname_fence {
	my ( $self, $hostname, $addrs, $now ) = @_;

	if ( defined($addrs) && scalar( @{$addrs} ) > $self->{usedns_max_addrs} ) {
		log_drek(
			'err',
			'"'
				. $hostname
				. '" resolves to '
				. scalar( @{$addrs} )
				. ' addresses, past usedns_max_addrs... refused whole, banishing nobody',
			undef,
			'galla-' . $self->{name}
		);
		$addrs = undef;
	} ## end if ( defined($addrs) && scalar( @{$addrs} ...))

	if ( defined($addrs) ) {
		my @kept;
		foreach my $addr ( @{$addrs} ) {
			if ( !defined( ip_family($addr) ) ) {
				next;
			}
			if ( ip_ignored( $self->{ignore_ips}, $addr ) || ip_ignored( $self->{internal}, $addr ) ) {
				next;
			}
			push( @kept, $addr );
		}
		$addrs = \@kept;
	} else {
		$self->_tick('dns_failures');
	}

	# bound the cache the way the other stores are bounded
	$self->_bound_expiring_store( $self->{dns_cache}, $hostname, $now );
	$self->{dns_cache}{$hostname} = { 'addrs' => $addrs, 'expires' => $now + 60 };

	return $addrs;
} ## end sub _resolve_hostname_fence

# the background form... a cache hit answers at once, a resolution already
# in flight is joined as a waiter rather than re-asked, and a cold name
# fires A and AAAA concurrently (the blocking closure asks them in turn),
# every waiter answered from the one fenced fold. falls back to the
# blocking path when the engine can not fly
sub _resolve_hostname_async {
	my ( $self, $hostname, $done ) = @_;

	if ( !$self->_dns_async_ready('dns') ) {
		$done->( $self->_resolve_hostname($hostname) );
		return;
	}

	my $now    = time;
	my $cached = $self->{dns_cache}{$hostname};
	if ( defined($cached) && $cached->{expires} > $now ) {
		if ( $cached->{inflight} ) {
			push( @{ $cached->{waiters} }, $done );
			return;
		}
		$done->( $cached->{addrs} );
		return;
	}

	$self->_bound_expiring_store( $self->{dns_cache}, $hostname, $now );
	my $entry = $self->{dns_cache}{$hostname} = {
		'inflight' => 1,
		'waiters'  => [$done],
		# past the query deadline plus grace the entry is just stale
		'expires' => $now + ( $self->{usedns_timeout} * 2 ) + 1,
	};

	my @addrs;
	my $outstanding = 2;
	my $one_family  = sub {
		my ($found) = @_;
		if ( defined($found) ) {
			push( @addrs, @{$found} );
		}
		$outstanding--;
		if ($outstanding) {
			return;
		}
		# no addresses at all reads as a failure, matching the blocking
		# closure... the fence ticks, caches, and drops the fences' share
		my $fenced  = $self->_resolve_hostname_fence( $hostname, ( @addrs ? \@addrs : undef ), time );
		my $waiters = $entry->{waiters};
		foreach my $waiter ( @{$waiters} ) {
			$waiter->($fenced);
		}
		return;
	};
	foreach my $qtype ( 'A', 'AAAA' ) {
		$self->_dns_query_bg( 'dns', $hostname, $qtype, $one_family );
	}

	return;
} ## end sub _resolve_hostname_async

# the per-line form resolve_seen counts through... never blocks and never
# waits. an answered cache is used, a cold name fires the background
# resolution and counts nobody THIS line (the fail-closed posture the
# feature already promises), the answer warm for the next line. without
# the engine the blocking path stands, as it always did
sub _resolve_hostname_seen {
	my ( $self, $hostname ) = @_;

	if ( !$self->_dns_async_ready('dns') ) {
		return $self->_resolve_hostname($hostname);
	}

	my $cached = $self->{dns_cache}{$hostname};
	if ( defined($cached) && $cached->{expires} > time ) {
		return $cached->{inflight} ? undef : $cached->{addrs};
	}

	$self->_resolve_hostname_async( $hostname, sub { return; } );

	return undef;
} ## end sub _resolve_hostname_seen

# banishes what a hostname names... the resolve_ban terminal. resolution
# failing or refusing means no ban at all, said loudly... a hostname is
# never queued for retry, since what a name means changes with whoever
# controls it
sub _ban_hostname {
	my ( $self, $hostname, $ban_time, $context, $score ) = @_;

	delete( $self->{pending_bans}{$hostname} );

	# a resolution already underway for this name will banish on its own
	if ( $self->{inflight_bans}{ 'host:' . $hostname } ) {
		return;
	}
	$self->{inflight_bans}{ 'host:' . $hostname } = 1;

	$self->_resolve_hostname_async(
		$hostname,
		sub {
			my ($addrs) = @_;
			delete( $self->{inflight_bans}{ 'host:' . $hostname } );
			if ( !defined($addrs) || !@{$addrs} ) {
				log_drek( 'err',
					'"' . $hostname . '" crossed the threshold but resolved to nothing banishable... banishing nobody',
					undef, 'galla-' . $self->{name} );
				return;
			}
			foreach my $addr ( @{$addrs} ) {
				my $addr_context = ref($context) eq 'HASH' ? { %{$context}, 'hostname' => $hostname } : undef;
				$self->_ban_ip( $addr, $ban_time, $addr_context, $score );
			}
			return;
		}
	);

	return;
} ## end sub _ban_hostname

# banishes a IP to Kur, queueing it for retry by the sweeper if the
# Ereshkigal manager could not be reached... the send completes async under
# POE, so the judgment tail runs from the answer, not from here
sub _ban_ip {
	my ( $self, $ip, $ban_time, $context, $score ) = @_;

	# a target that is not a IP is a hostname a resolve_ban rule counted
	# by... resolve it now, at the threshold, and banish what survives
	if ( !defined( ip_family($ip) ) ) {
		return $self->_ban_hostname( $ip, $ban_time, $context, $score );
	}

	# a decision already in flight absorbs this crossing... it will either
	# deliver or pend on its own
	if ( $self->{inflight_bans}{ 'ip:' . $ip } ) {
		return;
	}
	$self->{inflight_bans}{ 'ip:' . $ip } = 1;

	my $watcher_name = defined($context) ? $context->{watcher}   : undef;
	my $rule_name    = defined($context) ? $context->{rule_name} : undef;

	$self->_kur_ban(
		$ip, $ban_time, undef,
		sub {
			my ($error) = @_;
			delete( $self->{inflight_bans}{ 'ip:' . $ip } );
			if ( defined($error) ) {
				$self->_tick( 'ban_errors', $watcher_name, $rule_name );
				$self->{pending_bans}{$ip} = $ban_time;
				log_drek( 'err', 'banishing ' . $ip . ' to Kur failed, will retry... ' . $error,
					undef, 'galla-' . $self->{name} );
				return;
			}
			$self->_ban_delivered( $ip, $ban_time, $context, $score );
			return;
		}
	);

	return;
} ## end sub _ban_ip

# the tail of a landed IP ban... the tick, the log, the EVE banish, the
# ledger chisel, and the recidive gate. split from the send so the batched
# sweep drain (and one day an async completion) can run it per subject
sub _ban_delivered {
	my ( $self, $ip, $ban_time, $context, $score ) = @_;

	my $watcher_name = defined($context) ? $context->{watcher}   : undef;
	my $rule_name    = defined($context) ? $context->{rule_name} : undef;

	$self->_tick( 'bans', $watcher_name, $rule_name );
	delete( $self->{pending_bans}{$ip} );
	log_drek( 'info', 'banished ' . $ip . ' to Kur' . ( defined($ban_time) ? ' ban_time=' . $ban_time : '' ),
		undef, 'galla-' . $self->{name} );

	# the banish event carries the triggering line's envelope when there
	# was one... a pending retry banish has no context. with a GeoIP
	# database loaded the banished IP's country rides along
	my $country = ( $self->{eve_enable} && defined( $self->{geoip} ) ) ? $self->_country_of($ip) : undef;
	$self->_eve_emit(
		'banish',
		{
			'ip' => $ip,
			( defined($context) && defined( $context->{hostname} ) )
			? ( 'hostname' => $context->{hostname} )
			: (),
			defined($ban_time) ? ( 'ban_time' => $ban_time )                 : (),
			defined($country)  ? ( 'country' => $country )                   : (),
			defined($context)  ? %{ $self->_eve_fields( $context, $score ) } : (),
		}
	);

	# chisel the banishment into the shared ledger and, if this IP has
	# been banished too many times across all kurs, drag it through a
	# further gate to the recidive kur
	my $ledger_count = $self->_ledger_append_and_count( $ip, $context );
	$self->_recidive_check( $ip, $ledger_count );

	return;
} ## end sub _ban_delivered

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
			defined($context)  ? %{ $self->_eve_fields( $context, $score ) } : (),
		}
	);

	return;
} ## end sub _alert_ip

# the detection twin of _ban_ip and _alert_ip... a detection rule whose shadow
# score reached max_score records a sighted for the subject that crossed it. it
# writes the EVE event with the same match envelope, but the subject is whatever
# the detection_var named, not necessarily a IP, so there is no country lookup
# and no ban_time. it sends nothing to Kur, chisels no ledger, escalates no
# recidive, and ticks sightings. the shadow bucket was already cleared, so it
# re-arms
sub _sighted {
	my ( $self, $subject, $context, $score ) = @_;

	my $watcher_name = defined($context) ? $context->{watcher}   : undef;
	my $rule_name    = defined($context) ? $context->{rule_name} : undef;

	$self->_tick( 'sightings', $watcher_name, $rule_name );
	log_drek( 'info', 'sighted ' . $subject . ' (detection)', undef, 'galla-' . $self->{name} );

	$self->_eve_emit(
		'sighted',
		{
			'subject' => $subject,
			defined($context) ? %{ $self->_eve_fields( $context, $score ) } : (),
		}
	);

	return;
} ## end sub _sighted

# banishes a whole CIDR to Kur when its subnet bucket crossed... the twin of
# _ban_ip for the network case. queues the CIDR for the sweeper to retry if
# the manager could not be reached. the banish event lists the CIDR as its ip,
# the last triggering line as its raw, and a bucket field naming the members
# that fed it. no country lookup, a CIDR has no single one. the CIDR is chiseled
# into the shared ledger under its own key, so a subnet banished too many times
# escalates to the recidive kur just as a IP would, as a cidr_ban
sub _ban_subnet {
	my ( $self, $network, $ban_time, $context, $score, $info ) = @_;

	if ( $self->{inflight_bans}{ 'net:' . $network } ) {
		return;
	}
	$self->{inflight_bans}{ 'net:' . $network } = 1;

	my $watcher_name = defined($context) ? $context->{watcher}   : undef;
	my $rule_name    = defined($context) ? $context->{rule_name} : undef;

	$self->_kur_cidr_ban(
		$network, $ban_time, undef,
		sub {
			my ($error) = @_;
			delete( $self->{inflight_bans}{ 'net:' . $network } );
			if ( defined($error) ) {
				$self->_tick( 'ban_errors', $watcher_name, $rule_name );
				$self->{pending_cidr_bans}{$network} = $ban_time;
				log_drek( 'err', 'banishing ' . $network . ' to Kur failed, will retry... ' . $error,
					undef, 'galla-' . $self->{name} );
				return;
			}
			$self->_subnet_ban_delivered( $network, $ban_time, $context, $score, $info );
			return;
		}
	);

	return;
} ## end sub _ban_subnet

# the tail of a landed CIDR ban, the twin of _ban_delivered
sub _subnet_ban_delivered {
	my ( $self, $network, $ban_time, $context, $score, $info ) = @_;

	my $watcher_name = defined($context) ? $context->{watcher}   : undef;
	my $rule_name    = defined($context) ? $context->{rule_name} : undef;

	$self->_tick( 'subnet_bans', $watcher_name, $rule_name );
	delete( $self->{pending_cidr_bans}{$network} );
	log_drek( 'info', 'banished ' . $network . ' to Kur' . ( defined($ban_time) ? ' ban_time=' . $ban_time : '' ),
		undef, 'galla-' . $self->{name} );

	$self->_eve_emit(
		'banish',
		{
			'ip' => $network,
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
			defined($info)     ? ( 'bucket'   => $info )     : (),
			defined($context)  ? %{ $self->_eve_fields( $context, $score ) } : (),
		}
	);

	# chisel the CIDR into the shared ledger, keyed on its own network string,
	# and escalate to the recidive kur when it has been banished too often
	my $ledger_count = $self->_ledger_append_and_count( $network, $context );
	$self->_recidive_check( $network, $ledger_count, 1 );

	return;
} ## end sub _subnet_ban_delivered

# the observe-mode twin of _ban_subnet... a crossed shadow subnet bucket raises
# a alert instead of banishing, sending nothing to Kur
sub _alert_subnet {
	my ( $self, $network, $ban_time, $context, $score, $info ) = @_;

	my $watcher_name = defined($context) ? $context->{watcher}   : undef;
	my $rule_name    = defined($context) ? $context->{rule_name} : undef;

	$self->_tick( 'subnet_alerts', $watcher_name, $rule_name );
	log_drek(
		'info',
		'would banish '
			. $network
			. ' to Kur (observe mode)'
			. ( defined($ban_time) ? ' ban_time=' . $ban_time : '' ),
		undef,
		'galla-' . $self->{name}
	);

	$self->_eve_emit(
		'alert',
		{
			'ip' => $network,
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
			defined($info)     ? ( 'bucket'   => $info )     : (),
			defined($context)  ? %{ $self->_eve_fields( $context, $score ) } : (),
		}
	);

	return;
} ## end sub _alert_subnet

# spawns the persistent async client to the Ereshkigal manager socket...
# lazy-connecting, every request bounded by the config timeout and answered
# locally past it, so the galla's event loop never waits on Kur. only under
# POE... without it (run_tests, a galla driven directly by the tests) the
# blocking client stays the transport, via the _kur_ban fallbacks
sub _spawn_kur_client {
	my ($self) = @_;

	my $ident = 'galla-' . $self->{name};
	$self->{kur_client} = POE::Component::Server::JSONUnix::Client->spawn(
		'socket_path'     => $self->{ereshkigal_socket},
		'alias'           => $ident . '-kur-client',
		'auto_connect'    => 0,
		'request_timeout' => $self->{timeout},
		'on_error'        => sub {
			my ( $operation, $errnum, $errstr ) = @_;
			log_drek( 'err', 'kur client error during ' . $operation . '... ' . $errstr . ' (' . $errnum . ')',
				undef, $ident );
		},
		'on_disconnect' => sub {
			my ( undef, $reason ) = @_;
			log_drek( 'info', 'kur client disconnected... ' . $reason, undef, $ident );
		},
	);

	return;
} ## end sub _spawn_kur_client

# one command over the async client, $done->($error) when answered, $error
# undef on ok. reconnects lazily (calls made while connecting are queued by
# the client) and, if the manager demands authentication, completes the
# ownership challenge once on this connection and resends... the same dance
# the blocking client does
sub _kur_call {
	my ( $self, $command, $args, $done ) = @_;

	my $client = $self->{kur_client};
	$client->connect;

	my $answered = sub {
		my ($response) = @_;
		if ( ref($response) eq 'HASH' && defined( $response->{status} ) && $response->{status} eq 'ok' ) {
			$done->(undef);
			return 1;
		}
		return 0;
	};

	$client->call(
		'command'  => $command,
		'args'     => $args,
		'callback' => sub {
			my ($response) = @_;
			if ( $answered->($response) ) {
				return;
			}
			my $error
				= ( ref($response) eq 'HASH' && defined( $response->{error} ) ) ? $response->{error} : 'unknown error';
			if ( $error !~ /^authentication required/ ) {
				$done->($error);
				return;
			}
			# auth state lives on the connection, so challenge and resend
			$client->authenticate(
				'callback' => sub {
					my ($verdict) = @_;
					if ( !( ref($verdict) eq 'HASH' && defined( $verdict->{status} ) && $verdict->{status} eq 'ok' ) )
					{
						$done->( 'authentication failed... '
								. ( ( ref($verdict) eq 'HASH' && defined( $verdict->{error} ) ) ? $verdict->{error} : 'unknown error' ) );
						return;
					}
					$client->call(
						'command'  => $command,
						'args'     => $args,
						'callback' => sub {
							my ($again) = @_;
							if ( $answered->($again) ) {
								return;
							}
							$done->(
								( ref($again) eq 'HASH' && defined( $again->{error} ) )
								? $again->{error}
								: 'unknown error'
							);
							return;
						},
					);
					return;
				},
			);
			return;
		},
	);

	return;
} ## end sub _kur_call

# a ban to the Ereshkigal manager, one ip or an arrayref, $done->($error)
# when answered... async over the kur client when it is up, else the
# blocking _send_ban with $done called before this returns, which is what
# keeps a galla usable without a event loop
sub _kur_ban {
	my ( $self, $ips, $ban_time, $kur, $done ) = @_;

	if ( !defined( $self->{kur_client} ) ) {
		eval { $self->_send_ban( $ips, $ban_time, $kur ); };
		$done->( $@ ? $@ : undef );
		return;
	}

	$self->_kur_call(
		'ban',
		{
			'ips' => ref($ips) eq 'ARRAY' ? $ips : [$ips],
			'kur' => defined($kur)        ? $kur : $self->{name},
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
		},
		$done
	);

	return;
} ## end sub _kur_ban

# the CIDR twin of _kur_ban
sub _kur_cidr_ban {
	my ( $self, $networks, $ban_time, $kur, $done ) = @_;

	if ( !defined( $self->{kur_client} ) ) {
		eval { $self->_send_cidr_ban( $networks, $ban_time, $kur ); };
		$done->( $@ ? $@ : undef );
		return;
	}

	$self->_kur_call(
		'cidr_ban',
		{
			'cidrs' => ref($networks) eq 'ARRAY' ? $networks : [$networks],
			'kur'   => defined($kur)             ? $kur      : $self->{name},
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
		},
		$done
	);

	return;
} ## end sub _kur_cidr_ban

# the CIDR ban request to the Ereshkigal manager, its cidr_ban command... the
# manager masks the host bits, dedupes, and drops it on a kur that can not do
# CIDR per its cidr_silent_drop. to this galla's kur by default. takes one
# network or an arrayref of them, so the sweep drain sends a batch as one
# request
sub _send_cidr_ban {
	my ( $self, $network, $ban_time, $kur ) = @_;

	my $client = Ereshkigal::Client->new(
		'socket'  => $self->{ereshkigal_socket},
		'timeout' => $self->{timeout},
	);

	$client->call_ok(
		'cidr_ban',
		{
			'cidrs' => ref($network) eq 'ARRAY' ? $network : [$network],
			'kur'   => defined($kur)            ? $kur     : $self->{name},
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
		}
	);

	return;
} ## end sub _send_cidr_ban

# the actual ban request to the Ereshkigal manager, to this galla's kur by
# default or the passed one for a recidive escalation. takes one ip or an
# arrayref of them, so the sweep drain sends a batch as one request
sub _send_ban {
	my ( $self, $ip, $ban_time, $kur ) = @_;

	my $client = Ereshkigal::Client->new(
		'socket'  => $self->{ereshkigal_socket},
		'timeout' => $self->{timeout},
	);

	$client->call_ok(
		'ban',
		{
			'ips' => ref($ip) eq 'ARRAY' ? $ip  : [$ip],
			'kur' => defined($kur)       ? $kur : $self->{name},
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
		}
	);

	return;
} ## end sub _send_ban

# drains the pending ban queues, IP and CIDR alike... the pendings are
# grouped by owed ban_time and each group goes out as one batched request,
# so a down Ereshkigal costs the sweep one timeout per group rather than
# one per subject. a non-IP subject restored off an old tablet falls back
# through _ban_ip, which resolves-or-drops it as always
sub _drain_pending_bans {
	my ($self) = @_;

	$self->_drain_pending_group( $self->{pending_bans},      0 );
	$self->_drain_pending_group( $self->{pending_cidr_bans}, 1 );

	return;
}

sub _drain_pending_group {
	my ( $self, $pending, $subnet ) = @_;

	my $inflight_prefix = $subnet ? 'net:' : 'ip:';

	my %groups;
	foreach my $subject ( sort( keys( %{$pending} ) ) ) {
		if ( !$subnet && !defined( ip_family($subject) ) ) {
			$self->_ban_ip( $subject, $pending->{$subject} );
			next;
		}
		# a subject already being answered for is left alone... the answer
		# will deliver it or leave it pending for the next sweep
		if ( $self->{inflight_bans}{ $inflight_prefix . $subject } ) {
			next;
		}
		my $group_key = defined( $pending->{$subject} ) ? $pending->{$subject} : '';
		push( @{ $groups{$group_key} }, $subject );
	}

	my $ident = 'galla-' . $self->{name};
	foreach my $group_key ( sort( keys(%groups) ) ) {
		my $subjects = $groups{$group_key};
		my $ban_time = $group_key eq '' ? undef : $group_key + 0;
		foreach my $subject ( @{$subjects} ) {
			$self->{inflight_bans}{ $inflight_prefix . $subject } = 1;
		}
		my $answered = sub {
			my ($error) = @_;
			foreach my $subject ( @{$subjects} ) {
				delete( $self->{inflight_bans}{ $inflight_prefix . $subject } );
			}
			if ( defined($error) ) {
				$self->_tick('ban_errors');
				log_drek( 'err',
					'retrying ' . scalar( @{$subjects} ) . ' pending ban(s) failed, will retry again... ' . $error,
					undef, $ident );
				return;
			}
			foreach my $subject ( @{$subjects} ) {
				if ($subnet) {
					$self->_subnet_ban_delivered( $subject, $ban_time, undef, undef, undef );
				} else {
					$self->_ban_delivered( $subject, $ban_time, undef, undef );
				}
			}
			return;
		};
		if ($subnet) {
			$self->_kur_cidr_ban( $subjects, $ban_time, undef, $answered );
		} else {
			$self->_kur_ban( $subjects, $ban_time, undef, $answered );
		}
	} ## end foreach my $group_key ( sort( keys(%groups) ) )

	return;
} ## end sub _drain_pending_group

# returns the path of the shared banishment ledger, under the tablet dir,
# not per galla as every galla writes to the one ledger
sub ledger_path {
	my ($self) = @_;

	return $self->{tablet_base_dir} . '/banishments.csv';
}

# escalates to the recidive kur if the subject has now been banished
# max_score times with in find_time across all kurs, per the ledger count
# from _ledger_append_and_count... a no-op when recidive is off, and never
# re-counts a recidive escalation it's self. the subject is a IP normally, or
# a CIDR when $subnet is set, in which case the escalation goes out as a
# cidr_ban and no country is looked up, a CIDR having no single one
sub _recidive_check {
	my ( $self, $subject, $count, $subnet ) = @_;

	if ( !defined( $self->{recidive} ) ) {
		return;
	}
	# a escalation to the recidive kur is not it's self a offense to count
	if ( $self->{name} eq $self->{recidive}{kur} ) {
		return;
	}

	my $max_score = defined( $self->{recidive}{max_score} ) ? $self->{recidive}{max_score} : 5;
	my $ban_time  = defined( $self->{recidive}{ban_time} )  ? $self->{recidive}{ban_time}  : 0;

	if ( !defined($count) || $count < $max_score ) {
		return;
	}

	$self->_tick('recidivists');
	log_drek(
		'info',
		'recidivist '
			. $subject
			. ' banished '
			. $count
			. ' times, dragging through to the recidive kur "'
			. $self->{recidive}{kur} . '"',
		undef,
		'galla-' . $self->{name}
	);

	my $escalated = sub {
		my ($error) = @_;
		if ( defined($error) ) {
			$self->_tick('ban_errors');
			log_drek( 'err', 'banishing recidivist ' . $subject . ' failed... ' . $error,
				undef, 'galla-' . $self->{name} );
			return;
		}
		# a recidive escalation is its own banish event, to the recidive kur,
		# with the ledger count and no single triggering line
		my $country
			= ( !$subnet && $self->{eve_enable} && defined( $self->{geoip} ) ) ? $self->_country_of($subject) : undef;
		$self->_eve_emit(
			'banish',
			{
				'ip'       => $subject,
				'kur'      => $self->{recidive}{kur},
				'ban_time' => $ban_time,
				'count'    => $count,
				defined($country) ? ( 'country' => $country ) : (),
				'recidive' => \1,
			}
		);
		return;
	};

	if ($subnet) {
		$self->_kur_cidr_ban( $subject, $ban_time, $self->{recidive}{kur}, $escalated );
	} else {
		$self->_kur_ban( $subject, $ban_time, $self->{recidive}{kur}, $escalated );
	}

	return;
} ## end sub _recidive_check

# the recidive window in seconds, 0 when recidive is off
sub _recidive_find_time {
	my ($self) = @_;

	if ( !defined( $self->{recidive} ) ) {
		return 0;
	}
	return defined( $self->{recidive}{find_time} ) ? $self->{recidive}{find_time} : 604800;
}

# folds ledger rows from the folded-to offset onward into the in-memory
# recidive tally, subject => [epochs]... rows landing on the recidive kur
# it's self are never counted, as a escalation's landing is not a offense.
# expects the caller to hold the ledger lock
sub _ledger_fold {
	my ( $self, $fh, $now, $find_time, $recidive_kur ) = @_;

	# a ledger smaller than the folded-to offset was compacted by somebody,
	# so the tally starts over from the top
	my $size = ( stat($fh) )[7];
	if ( !defined( $self->{ledger_offset} ) || $size < $self->{ledger_offset} ) {
		$self->{ledger_offset} = 0;
		$self->{ledger_tally}  = {};
	}

	seek( $fh, $self->{ledger_offset}, 0 ) || die( 'seek failed... ' . $! );
	while ( my $line = <$fh> ) {
		chomp($line);
		my ( $epoch, $kur, $row_ip ) = split( /,/, $line, 4 );
		if ( !defined($epoch) || $epoch !~ /^[0-9]+$/ || !defined($row_ip) || $row_ip eq '' ) {
			next;
		}
		if ( $kur eq $recidive_kur || ( $now - $epoch ) >= $find_time ) {
			next;
		}
		push( @{ $self->{ledger_tally}{$row_ip} }, $epoch + 0 );
	} ## end while ( my $line = <$fh> )
	$self->{ledger_offset} = tell($fh);

	return;
} ## end sub _ledger_fold

# chisels a banishment row into the shared ledger under a exclusive lock
# and returns how many times this IP appears with in the recidive window.
# Rows are epoch,kur,ip,rule,watcher. only rows appended since the last
# look are read, folded into a live tally, so a ban costs O(new rows)
# rather than O(ledger)... the whole-ledger pruning to ledger_keep lives in
# _ledger_compact, off the ban path, on the checkpoint cadence
sub _ledger_append_and_count {
	my ( $self, $ip, $context ) = @_;

	my $now          = time;
	my $find_time    = $self->_recidive_find_time;
	my $recidive_kur = defined( $self->{recidive} ) ? $self->{recidive}{kur} : '';

	my $rule    = defined($context) && defined( $context->{rule_name} ) ? $context->{rule_name} : '';
	my $watcher = defined($context) && defined( $context->{watcher} )   ? $context->{watcher}   : '';

	my $path = $self->ledger_path;
	eval {
		open( my $fh, '+>>', $path ) || die( 'open failed... ' . $! );
		flock( $fh, 2 )              || die( 'lock failed... ' . $! );    # LOCK_EX

		# with recidive off nothing ever reads the tally, so the row is
		# purely appended and the ledger is never even read here
		if ($find_time) {
			$self->_ledger_fold( $fh, $now, $find_time, $recidive_kur );
		}

		# a fresh ledger gets its header ahead of the first row... the
		# append mode writes land at EOF regardless of the read position
		if ( ( stat($fh) )[7] == 0 ) {
			print( $fh "epoch,kur,ip,rule,watcher\n" ) || die( 'write failed... ' . $! );
		}
		print( $fh $now . ','
				. $self->{name} . ','
				. $ip . ','
				. _csv_escape($rule) . ','
				. _csv_escape($watcher)
				. "\n" )
			|| die( 'write failed... ' . $! );
		if ($find_time) {
			$self->{ledger_offset} = tell($fh);
		}

		close($fh) || die( 'close failed... ' . $! );
	};
	if ($@) {
		log_drek( 'err', 'the banishment ledger "' . $path . '" could not be updated... ' . $@,
			undef, 'galla-' . $self->{name} );
		return undef;
	}

	if ( !$find_time ) {
		return 0;
	}

	# the just-chiseled row counts too, folded straight into the tally...
	# unless this galla is the recidive kur, whose rows never count
	if ( $self->{name} ne $recidive_kur ) {
		push( @{ $self->{ledger_tally}{$ip} }, $now );
	}

	my $count = 0;
	if ( defined( $self->{ledger_tally}{$ip} ) ) {
		@{ $self->{ledger_tally}{$ip} } = grep { ( $now - $_ ) < $find_time } @{ $self->{ledger_tally}{$ip} };
		$count = scalar( @{ $self->{ledger_tally}{$ip} } );
		if ( !$count ) {
			delete( $self->{ledger_tally}{$ip} );
		}
	}

	return $count;
} ## end sub _ledger_append_and_count

# prunes the shared ledger to ledger_keep under the exclusive lock, rows
# inside the recidive window surviving whatever ledger_keep says... ran on
# the checkpoint cadence rather than per ban, and a no-op when ledger_keep
# is 0, keep forever. unfolded rows are folded first so the offset landing
# at the rewritten EOF loses nothing
sub _ledger_compact {
	my ($self) = @_;

	if ( !$self->{ledger_keep} ) {
		return;
	}

	my $now          = time;
	my $find_time    = $self->_recidive_find_time;
	my $recidive_kur = defined( $self->{recidive} ) ? $self->{recidive}{kur} : '';

	my $keep = $self->{ledger_keep};
	if ( $keep < $find_time ) {
		$keep = $find_time;
	}

	my $path = $self->ledger_path;
	if ( !-f $path ) {
		return;
	}
	eval {
		open( my $fh, '+<', $path ) || die( 'open failed... ' . $! );
		flock( $fh, 2 )             || die( 'lock failed... ' . $! );    # LOCK_EX

		if ($find_time) {
			$self->_ledger_fold( $fh, $now, $find_time, $recidive_kur );
		}

		seek( $fh, 0, 0 ) || die( 'seek failed... ' . $! );
		my @kept;
		while ( my $line = <$fh> ) {
			chomp($line);
			my ( $epoch, $kur, $row_ip ) = split( /,/, $line, 4 );
			if ( !defined($epoch) || $epoch !~ /^[0-9]+$/ || !defined($row_ip) || $row_ip eq '' ) {
				next;
			}
			if ( ( $now - $epoch ) >= $keep ) {
				next;
			}
			push( @kept, $line );
		} ## end while ( my $line = <$fh> )

		seek( $fh, 0, 0 )  || die( 'seek failed... ' . $! );
		truncate( $fh, 0 ) || die( 'truncate failed... ' . $! );
		print( $fh "epoch,kur,ip,rule,watcher\n" )                   || die( 'write failed... ' . $! );
		print( $fh join( "\n", @kept ) . ( @kept ? "\n" : '' ) )     || die( 'write failed... ' . $! );
		if ($find_time) {
			$self->{ledger_offset} = tell($fh);
		}

		close($fh) || die( 'close failed... ' . $! );
	};
	if ($@) {
		log_drek( 'err', 'compacting the banishment ledger "' . $path . '" failed... ' . $@,
			undef, 'galla-' . $self->{name} );
	}

	return;
} ## end sub _ledger_compact

# ran every ten seconds via the sweeper... retries pending bans and drops
# counter entries that have entirely aged out
sub _sweep {
	my ($self) = @_;

	$self->_drain_pending_bans;

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
	} ## end foreach my $bucket ( $self->{counters}, values(...))
	foreach my $rule_counters ( $self->{rule_counters}, $self->{shadow_rule_counters} ) {
		foreach my $rule_name ( keys( %{$rule_counters} ) ) {
			if ( !%{ $rule_counters->{$rule_name} } ) {
				delete( $rule_counters->{$rule_name} );
			}
		}
	}

	# the subnet buckets the same way, per family, real and shadow... a network
	# with no recent deposit is dropped so a quiet CIDR does not linger
	foreach my $store ( $self->{subnet_counters}, $self->{shadow_subnet_counters} ) {
		foreach my $family ( keys( %{$store} ) ) {
			foreach my $network ( keys( %{ $store->{$family} } ) ) {
				my $newest = $store->{$family}{$network}[-1];
				if ( !defined($newest) || ( $now - $newest->[0] ) > 86400 ) {
					delete( $store->{$family}{$network} );
				}
			}
		}
	} ## end foreach my $store ( $self->{subnet_counters}, $self...)

	# the distinct-cardinality sets the same way... drop values past a day, a
	# coarse cleanup, the register path re-prunes per the effective find_time
	foreach my $dcounters ( $self->{distinct_counters}, $self->{shadow_distinct_counters} ) {
		foreach my $rule_name ( keys( %{$dcounters} ) ) {
			foreach my $ip ( keys( %{ $dcounters->{$rule_name} } ) ) {
				my $set = $dcounters->{$rule_name}{$ip};
				foreach my $value ( keys( %{$set} ) ) {
					if ( ( $now - $set->{$value} ) > 86400 ) {
						delete( $set->{$value} );
					}
				}
				if ( !%{$set} ) {
					delete( $dcounters->{$rule_name}{$ip} );
				}
			} ## end foreach my $ip ( keys( %{ $dcounters->{$rule_name...}}))
			if ( !%{ $dcounters->{$rule_name} } ) {
				delete( $dcounters->{$rule_name} );
			}
		} ## end foreach my $rule_name ( keys( %{$dcounters} ) )
	} ## end foreach my $dcounters ( $self->{distinct_counters...})

	# the recidive tally the same way... a subject whose banishments have
	# all aged past the window is dropped rather than lingering
	if ( defined( $self->{recidive} ) && ref( $self->{ledger_tally} ) eq 'HASH' ) {
		my $find_time = $self->_recidive_find_time;
		foreach my $subject ( keys( %{ $self->{ledger_tally} } ) ) {
			@{ $self->{ledger_tally}{$subject} }
				= grep { ( $now - $_ ) < $find_time } @{ $self->{ledger_tally}{$subject} };
			if ( !@{ $self->{ledger_tally}{$subject} } ) {
				delete( $self->{ledger_tally}{$subject} );
			}
		}
	} ## end if ( defined( $self->{recidive} ) && ref( $self...))

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
	}

	# drain the fleet mark bus into the live marks before expiring, so a
	# freshly gossiped brand is present and then aged by the same pass
	$self->_sync_marks;

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
	} ## end foreach my $mark_name ( keys( %{ $self->{marks}...}))

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
	}

	return;
} ## end sub _sweep

#
# JSONUnix command handlers
#

# the per-watcher journal-or-files rendering shared by status and
# watching... status names the file specs logs where watching names them
# globs, a wire shape kept as chiseled, so the key is the caller's
sub _watcher_following {
	my ( $self, $watcher, $spec_key ) = @_;

	if ( $watcher->{is_journal} ) {
		return (
			'journal'         => $watcher->{journal_matches},
			'journal_running' => defined( $watcher->{journal_wheel} ) ? 1 : 0,
		);
	}
	return (
		$spec_key   => $watcher->{log_spec},
		'following' => [ sort( keys( %{ $watcher->{wheels} } ) ) ],
	);
} ## end sub _watcher_following

sub _cmd_status {
	my ($self) = @_;

	my $watchers = {};
	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		my $watcher = $self->{watchers}{$watcher_name};
		$watchers->{$watcher_name} = {
			'parser'   => $watcher->{parser},
			'rules'    => $watcher->{rules},
			'settings' => $watcher->{settings},
			$self->_watcher_following( $watcher, 'logs' ),
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
		'name'            => $self->{name},
		'pid'             => $$,
		'uptime'          => defined( $self->{started} ) ? time - $self->{started} : 0,
		'watchers'        => $watchers,
		'stats'           => $self->{stats},
		'tracked_ips'     => scalar( keys(%tracked) ),
		'tracked_subnets' => scalar( keys( %{ $self->{subnet_counters}{v4} } ) )
			+ scalar( keys( %{ $self->{subnet_counters}{v6} } ) ),
		'pending_bans'      => [ sort( keys( %{ $self->{pending_bans} } ) ) ],
		'pending_cidr_bans' => [ sort( keys( %{ $self->{pending_cidr_bans} } ) ) ],
		'recidive'          => defined( $self->{recidive} ) ? $self->{recidive}{kur} : undef,
	};
} ## end sub _cmd_status

# makes the EVE log's dir if it is missing, best effort... telemetry
# should never take the galla down
sub _ensure_eve_dir {
	my ($self) = @_;

	my $eve_dir = $self->{eve_log};
	$eve_dir =~ s{/[^/]*$}{};
	if ( $eve_dir ne '' && !-e $eve_dir ) {
		mkdir($eve_dir);
	}

	return;
} ## end sub _ensure_eve_dir

# sums the weights of a bucket's [epoch, weight] entries into its score
sub _score_of {
	my ($entries) = @_;

	my $score = 0;
	foreach my $entry ( @{$entries} ) {
		$score += $entry->[1];
	}

	return $score;
} ## end sub _score_of

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
		}
	} ## end foreach my $mark_name ( keys( %{ $self->{marks}...}))

	return {
		'name'  => $self->{name},
		'marks' => $marks,
	};
} ## end sub _cmd_marked

sub _cmd_watching {
	my ($self) = @_;

	# per watcher, what it was set to watch versus what it is watching now...
	# for file watchers the log specs are the literal paths and globs it hunts
	# by, while following is the concrete files a spec has resolved to and has
	# a tail wheel on right now. for journal watchers the journalctl matches
	# stand in for the specs, with journal_running saying whether the wheel is up
	my $watchers = {};
	foreach my $watcher_name ( keys( %{ $self->{watchers} } ) ) {
		my $watcher = $self->{watchers}{$watcher_name};
		$watchers->{$watcher_name} = { $self->_watcher_following( $watcher, 'globs' ) };
	}

	return {
		'name'     => $self->{name},
		'watchers' => $watchers,
	};
} ## end sub _cmd_watching

sub _cmd_stop {
	my ( $self, $ctx ) = @_;

	my $ident = 'galla-' . $self->{name};

	log_drek( 'info', 'stop requested', undef, $ident );

	# keeps the sweeper from rescheduling so it's session can end
	$self->{stopping} = 1;

	# drop the kur client... every in-flight ban is answered with an error,
	# landing back in the pending queues for the final checkpoint to persist
	if ( defined( $self->{kur_client} ) ) {
		$self->{kur_client}->shutdown;
		$self->{kur_client} = undef;
	}

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

=head2 7, tabletStoreError

The state tablet store could not be set up... the file backend's base dir is
not read/writable, a configured backend would not load, or a store such as the
redis backend's could not be reached. See L<App::Baphomet::ClayTablet>.

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
