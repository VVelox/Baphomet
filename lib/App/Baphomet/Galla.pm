package App::Baphomet::Galla;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use POE                              qw( Wheel::FollowTail Wheel::Run );
use POE::Component::Server::JSONUnix ();
use File::Glob                       qw( bsd_glob );
use JSON::MaybeXS                    qw( encode_json decode_json );
use POSIX                            qw( strftime );
use Sys::Hostname                    ();
use Ereshkigal::Client               ();
use App::Baphomet::Config
	qw( load_config check_kur_def kur_split resolve_settings watcher_rules watcher_logs watcher_journal compile_ignore_ips ip_ignored );
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
				7 => 'cacheBaseDirError',
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
			lines       => 0,
			unparsed    => 0,
			matched     => 0,
			ignored     => 0,
			bans        => 0,
			ban_errors  => 0,
			recidivists => 0,
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
	$self->{cache_base_dir}    = $config->{cache_base_dir};
	$self->{ereshkigal_socket} = $config->{ereshkigal_socket};
	$self->{recidive}          = $config->{recidive};
	$self->{timeout}           = $config->{timeout};
	$self->{checkpoint}        = $config->{checkpoint};
	$self->{journalctl_bin}    = $config->{journalctl_bin};
	$self->{eve_log}           = $config->{eve_log};
	$self->{eve_enable}        = $config->{eve_enable};
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

	# internal marks your own hosts, for ban_not_internal rules that consign
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

	if ( !-e $self->{cache_base_dir} ) {
		# the next check handles a failure here
		eval { mkdir( $self->{cache_base_dir} ); };
	}
	if ( !-d $self->{cache_base_dir} || !-r $self->{cache_base_dir} || !-w $self->{cache_base_dir} ) {
		$self->{perror}      = 1;
		$self->{error}       = 7;
		$self->{errorString}
			= 'cache_base_dir,"' . $self->{cache_base_dir} . '", is not a directory or is not read/writable';
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

		my $is_journal = defined( $watcher->{journal} );
		$self->{watchers}{$watcher_name} = {
			'is_journal'      => $is_journal,
			'log_spec'        => $is_journal ? [] : [ watcher_logs($watcher) ],
			'journal_matches' => $is_journal ? [ watcher_journal($watcher) ] : [],
			'parser'          => defined( $watcher->{parser} ) ? $watcher->{parser} : ( $is_journal ? 'journal' : 'syslog' ),
			'rules'           => \@rule_names,
			'rule_objs'       => \@rule_objs,
			'settings'        => resolve_settings( $config, $kur_settings, $watcher ),
			'wheels'          => {},
			'journal_wheel'   => undef,
			'journal_delay'   => 1,
			'journal_spawned' => undef,
		};
	} ## end foreach my $watcher_name ( sort( keys( %{$watchers...})))

	# bring back the tablets... counters, pending bans, correlation
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

	my $suffix = $kind eq 'context' ? 'jsonl' : 'csv';

	return $self->{cache_base_dir} . '/galla.' . $self->{name} . '.' . $kind . '.' . $suffix;
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
correlation context, and the log positions. Called periodically by the
sweeper and on stop.

    $galla->checkpoint;

=cut

sub checkpoint {
	my ($self) = @_;

	my $now = time;

	# counters... ip,hit_epoch one row per live hit
	$self->_write_tablet(
		'counters',
		sub {
			my ($fh) = @_;
			print $fh "ip,hit\n";
			foreach my $ip ( sort( keys( %{ $self->{counters} } ) ) ) {
				foreach my $hit ( @{ $self->{counters}{$ip} } ) {
					print $fh $ip . ',' . $hit . "\n";
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
# and log positions kept for start_server to seek to
sub _load_state {
	my ($self) = @_;

	my $now = time;

	# counters
	my $line_int = 0;
	foreach my $line ( $self->_read_tablet('counters') ) {
		$line_int++;
		if ( ( $line_int == 1 && $line =~ /^ip,/ ) || $line eq '' ) {
			next;
		}
		my ( $ip, $hit ) = split( /,/, $line );
		if ( !defined($ip) || !defined($hit) || $hit !~ /^[0-9]+$/ ) {
			next;
		}
		# only keep hits still inside the widest find_time in play
		push( @{ $self->{counters}{$ip} }, $hit + 0 );
	} ## end foreach my $line ( $self->_read_tablet...)
	# sort each and drop entries with nothing recent... the register path
	# re-prunes per watcher find_time on the next hit
	foreach my $ip ( keys( %{ $self->{counters} } ) ) {
		my @sorted = sort { $a <=> $b } @{ $self->{counters}{$ip} };
		if ( !@sorted || ( $now - $sorted[-1] ) > 86400 ) {
			delete( $self->{counters}{$ip} );
		} else {
			$self->{counters}{$ip} = \@sorted;
		}
	} ## end foreach my $ip ( keys( %{ $self->{counters} } ) )

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
# passed fields are merged over the common envelope, and a consign or
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

# handles a single line from the log of the specified watcher
sub _handle_line {
	my ( $self, $watcher_name, $line, $source ) = @_;

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
	# matching more than one rule only counts once... the watcher name
	# scopes any correlation state, as keys like conn ids are only unique
	# with in one log
	foreach my $rule_obj ( @{ $watcher->{rule_objs} } ) {
		my $found = $rule_obj->check( $parsed, $watcher_name );
		if ( !defined($found) ) {
			next;
		}

		# a capture line may have completed several deferred offenses
		my @all_found = ( $found, ref( $found->{more} ) eq 'ARRAY' ? @{ $found->{more} } : () );
		foreach my $one (@all_found) {
			$self->{stats}{matched}++;

			# the EVE context for this match, shared by the found event and
			# any consign it triggers
			my $context = {
				'source' => $source,
				'raw'    => $line,
				'parsed' => $parsed,
				'found'  => $one->{data},
				'rule'   => $rule_obj,
			};

			# a ban_not_internal rule consigns the end of the flow that is
			# not one of ours... the offender may be the src or the dest
			# depending on where the alert fired
			my $not_internal = $rule_obj->ban_not_internal;

			my $count;
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
				my $registered = $self->_register_hit( $watcher_name, $ip, $context );
				if ( !defined($count) && defined($registered) ) {
					$count = $registered;
				}
			} ## end foreach my $ban_var ( $rule_obj...)

			$self->_eve_emit( 'found', $self->_eve_fields( $context, $count ) );
		} ## end foreach my $one (@all_found)

		last;
	} ## end foreach my $rule_obj ( @{ $watcher->{rule_objs}...})

	return;
} ## end sub _handle_line

# builds the raw/parsed/found/rule/path/count fields of a EVE event from a
# match context... only assembled when the EVE log is on
sub _eve_fields {
	my ( $self, $context, $count ) = @_;

	if ( !$self->{eve_enable} ) {
		return {};
	}

	return {
		defined( $context->{source} ) ? ( 'path' => $context->{source} ) : (),
		'raw'    => $context->{raw},
		'parsed' => $self->_eve_parsed( $context->{parsed} ),
		'found'  => $context->{found},
		'rule'   => $context->{rule}->info,
		defined($count) ? ( 'count' => $count ) : (),
	};
} ## end sub _eve_fields

# registers a match of a IP, banning it once it has racked up max_retrys
# matches with in find_time seconds... returns the IP's live count, or
# undef when the IP is ignored
sub _register_hit {
	my ( $self, $watcher_name, $ip, $context ) = @_;

	# the ignored never accumulate so much as a counter
	if ( ip_ignored( $self->{ignore_ips}, $ip ) ) {
		$self->{stats}{ignored}++;
		return undef;
	}

	my $settings = $self->{watchers}{$watcher_name}{settings};
	my $now      = time;

	if ( !defined( $self->{counters}{$ip} ) ) {
		$self->{counters}{$ip} = [];
	}
	push( @{ $self->{counters}{$ip} }, $now );

	# matches older than find_time no longer count
	@{ $self->{counters}{$ip} } = grep { ( $now - $_ ) < $settings->{find_time} } @{ $self->{counters}{$ip} };

	my $count = scalar( @{ $self->{counters}{$ip} } );

	if ( $count >= $settings->{max_retrys} ) {
		delete( $self->{counters}{$ip} );
		$self->_ban_ip( $ip, $settings->{ban_time}, $context, $count );
	}

	return $count;
} ## end sub _register_hit

# consigns a IP to Kur, queueing it for retry by the sweeper if the
# Ereshkigal manager could not be reached
sub _ban_ip {
	my ( $self, $ip, $ban_time, $context, $count ) = @_;

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

	# the consign event carries the triggering line's envelope when there
	# was one... a pending retry consign has no context
	$self->_eve_emit(
		'consign',
		{
			'ip' => $ip,
			defined($ban_time) ? ( 'ban_time' => $ban_time ) : (),
			defined($context) ? %{ $self->_eve_fields( $context, $count ) } : (),
		}
	);

	# record the consignment to the shared ledger and, if this IP has been
	# consigned too many times across all kurs, drag it through a further
	# gate to the recidive kur
	$self->_recidive_check($ip);

	return;
} ## end sub _ban_ip

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

# returns the path of the shared consignment ledger, under the cache dir,
# not per galla as every galla writes to the one ledger
sub recidive_ledger_path {
	my ($self) = @_;

	return $self->{cache_base_dir} . '/consignments.csv';
}

# records a consignment to the shared ledger and escalates to the recidive
# kur if the IP has now been consigned max_retrys times with in find_time
# across all kurs... a no-op when recidive is off, and never re-counts a
# recidive escalation it's self
sub _recidive_check {
	my ( $self, $ip ) = @_;

	if ( !defined( $self->{recidive} ) ) {
		return;
	}
	# a escalation to the recidive kur is not it's self a offense to count
	if ( $self->{name} eq $self->{recidive}{kur} ) {
		return;
	}

	my $now        = time;
	my $find_time  = defined( $self->{recidive}{find_time} ) ? $self->{recidive}{find_time} : 604800;
	my $max_retrys = defined( $self->{recidive}{max_retrys} ) ? $self->{recidive}{max_retrys} : 5;
	my $ban_time   = defined( $self->{recidive}{ban_time} ) ? $self->{recidive}{ban_time} : 0;

	my $count = $self->_ledger_append_and_count( $ip, $now, $find_time );
	if ( !defined($count) || $count < $max_retrys ) {
		return;
	}

	$self->{stats}{recidivists}++;
	log_drek(
		'info',
		'recidivist '
			. $ip
			. ' consigned '
			. $count
			. ' times, dragging through to the recidive kur "'
			. $self->{recidive}{kur} . '"',
		undef,
		'galla-' . $self->{name}
	);

	eval { $self->_send_ban( $ip, $ban_time, $self->{recidive}{kur} ); };
	if ($@) {
		$self->{stats}{ban_errors}++;
		log_drek( 'err', 'consigning recidivist ' . $ip . ' failed... ' . $@, undef, 'galla-' . $self->{name} );
		return;
	}

	# a recidive escalation is its own consign event, to the recidive kur,
	# with the ledger count and no single triggering line
	$self->_eve_emit(
		'consign',
		{
			'ip'       => $ip,
			'kur'      => $self->{recidive}{kur},
			'ban_time' => $ban_time,
			'count'    => $count,
			'recidive' => \1,
		}
	);

	return;
} ## end sub _recidive_check

# appends a consignment row under a exclusive lock and returns how many
# times this IP appears with in find_time... the lock serializes the
# several gallas sharing the one ledger
sub _ledger_append_and_count {
	my ( $self, $ip, $now, $find_time ) = @_;

	my $path  = $self->recidive_ledger_path;
	my $count = 0;
	eval {
		open( my $fh, '+>>', $path ) || die( 'open failed... ' . $! );
		flock( $fh, 2 ) || die( 'lock failed... ' . $! );    # LOCK_EX

		print $fh $now . ',' . $self->{name} . ',' . $ip . "\n";

		# read the whole ledger back and count this IP with in the window,
		# rewriting it pruned so it does not grow without bound
		seek( $fh, 0, 0 );
		my @kept;
		while ( my $line = <$fh> ) {
			chomp($line);
			my ( $epoch, $kur, $row_ip ) = split( /,/, $line, 3 );
			if ( !defined($epoch) || $epoch !~ /^[0-9]+$/ || !defined($row_ip) ) {
				next;
			}
			if ( ( $now - $epoch ) >= $find_time ) {
				next;
			}
			push( @kept, $epoch . ',' . $kur . ',' . $row_ip );
			if ( $row_ip eq $ip ) {
				$count++;
			}
		} ## end while ( my $line = <$fh> )

		# rewrite pruned
		seek( $fh, 0, 0 );
		truncate( $fh, 0 );
		print $fh join( "\n", @kept ) . ( @kept ? "\n" : '' );

		close($fh);
	};
	if ($@) {
		log_drek( 'err', 'the recidive ledger "' . $path . '" could not be updated... ' . $@,
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
	# still-relevant entry gets re-pruned properly on its next hit
	my $now = time;
	foreach my $ip ( keys( %{ $self->{counters} } ) ) {
		my $newest = $self->{counters}{$ip}[-1];
		# a day is comfortably past any sane find_time
		if ( !defined($newest) || ( $now - $newest ) > 86400 ) {
			delete( $self->{counters}{$ip} );
		}
	}

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

	return {
		'name'         => $self->{name},
		'pid'          => $$,
		'uptime'       => defined( $self->{started} ) ? time - $self->{started} : 0,
		'watchers'     => $watchers,
		'stats'        => $self->{stats},
		'tracked_ips'  => scalar( keys( %{ $self->{counters} } ) ),
		'pending_bans' => [ sort( keys( %{ $self->{pending_bans} } ) ) ],
		'recidive'     => defined( $self->{recidive} ) ? $self->{recidive}{kur} : undef,
	};
} ## end sub _cmd_status

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

=head2 7, cacheBaseDirError

The cache base dir could not be created or is not read/writable.

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
