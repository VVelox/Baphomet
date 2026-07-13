package App::Baphomet::Config;

use 5.006;
use strict;
use warnings;
use Exporter   qw( import );
use Socket     qw( AF_INET AF_INET6 inet_pton );
use TOML::Tiny qw( from_toml );

=pod

=head1 NAME

App::Baphomet::Config - Config loading and checking shared by the baphomet manager and galla workers.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

our @EXPORT_OK
	= qw( load_config kur_split check_kur_def resolve_settings watcher_rules watcher_logs watcher_journal compile_ignore_ips ip_ignored );

=head1 SYNOPSIS

    use App::Baphomet::Config qw( load_config kur_split check_kur_def resolve_settings );

    my $config = load_config('/usr/local/etc/baphomet/config.toml');

    foreach my $name ( keys( %{ $config->{kur} } ) ) {
        check_kur_def( $name, $config->{kur}{$name} );
        my ( $settings, $watchers ) = kur_split( $config->{kur}{$name} );
    }

=head1 DESCRIPTION

Both the C<baphomet> manager and the C<galla> workers read the same TOML
config file, so the loading, defaulting, and checking live here instead of
each carrying their own copy.

The config file is TOML. Hashes under C<kur> define kurs, with the name of
the hash being the kur name, which must match a kur name over on the
Ereshkigal side as it is what ban requests are targeted at. Scalar keys
inside a kur hash are settings for that kur while hash keys inside it are
watchers, each binding a log file to a parser and a rule.

    # the base kur config for sshd
    [kur.sshd]
    max_retrys=5
    ban_time=300
    # read authlog
    # the key for the hash under sshd is just a freeform name
    [kur.sshd.authlog]
    log=/var/log/auth.log
    parser=bsd_syslog
    rule=syslog/sshd

Top level keys are as below.

    - run_base_dir :: Base dir for run files.
        Default :: /var/run/baphomet

    - tablet_base_dir :: Base dir for the state tablets a galla writes so
          its counters, pending bans, correlation context, and log
          positions survive a restart.
        Default :: /var/db/baphomet

    - checkpoint :: Seconds between periodic rewrites of the state
          tablets. 0 disables the periodic rewrite... a checkpoint on stop
          still happens.
        Default :: 60

    - rules_dir :: The dir holding the matching rules. A rule of
          C<syslog/sshd> is the file C<syslog/sshd.yaml> under here.
        Default :: /usr/local/etc/baphomet/rules

    - ereshkigal_socket :: The Ereshkigal manager socket bans are sent to.
        Default :: /var/run/ereshkigal/socket

    - galla_bin :: The galla bin to spawn workers with.
        Default :: galla

    - journalctl_bin :: The journalctl to read journal watchers with.
        Default :: journalctl

    - timeout :: Timeout in seconds used when talking to sockets, both
          galla ones and the Ereshkigal one.
        Default :: 30

    - max_retrys :: How many matches with in find_time seconds it takes
          for a IP to be banned. May be overridden per kur and per watcher.
        Default :: 5

    - find_time :: The window in seconds matches are counted across.
          Matches older than this no longer count towards max_retrys.
          May be overridden per kur and per watcher.
        Default :: 600

    - ban_time :: Ban time in seconds forwarded with ban requests, with 0
          meaning never time out. If not set anywhere, it is left out of
          the request and the Ereshkigal side default applies. May be
          overridden per kur and per watcher.
        Default :: undef

    - ignore_ips :: A array of IPv4/IPv6 addresses and CIDRs that are
          never consigned, no matter what the rules say. A kur may carry
          its own ignore_ips, which extends this list for that kur rather
          than replacing it. Hostnames are not accepted... resolving
          config at load time is a trust decision this declines to make.
        Default :: []

    - internal :: A array of IPv4/IPv6 addresses and CIDRs that are your
          own hosts. Rules with the C<ban_not_internal> option consign the
          end of a flow that is not internal, for cases like Suricata
          alerts where the offender may be the src or the dest depending
          on where in the stream it fired. A kur may carry its own
          internal, extending this. Where not set it defaults to the
          ignore_ips, so what you ignore is also treated as yours... and
          since a ignored IP is never consigned anyway, the consigned end
          is by extension not ignored either.
        Default :: undef, meaning the same as ignore_ips

    - socket_group :: Group ownership of the manager socket.
        Default :: the default group of the root user

    - socket_mode :: Perms for the manager socket. A octal string such as
          "0660", processed via oct. Galla sockets are always 0600 and not
          configurable.
        Default :: 0660

    - enable_auth :: Opens the Neti gate... the
          L<POE::Component::Server::JSONUnix> unix ownership auth challenge
          on the manager socket, so who may drive the manager, ask its
          status, or stop it is gated by authed_users and authed_groups.
          UID 0 always passes. With it off, the socket perms alone gate
          access.
        Default :: 0

    - authed_users :: A array of users allowed past the Neti gate.
        Default :: []

    - authed_groups :: A array of groups whose members are allowed past
          the Neti gate. Membership is resolved at request time.
        Default :: []

    - auth_temp_dir :: Dir used for the ownership challenge cookie files,
          passed to L<POE::Component::Server::JSONUnix>.
        Default :: undef

    - recidive :: A table turning on repeat offender escalation. When set,
          every consignment is recorded to a shared ledger, and a IP
          consigned across any kurs max_retrys times with in find_time is
          dragged through a further gate... consigned to the recidive
          C<kur> for ban_time seconds, which should be long. Keys...

              kur :: The kur recidivists are consigned to. Required.
                  There must be a matching kur on the Ereshkigal side
                  covering everything worth protecting.

              max_retrys :: Consignments before a IP is a recidivist.
                  Default :: 5

              find_time :: The window the consignments are counted over.
                  Default :: 604800, a week

              ban_time :: How long a recidivist is held, 0 being eternal.
                  Default :: 0
        Default :: undef, off

    - eve_log :: Path of the EVE event log, the NDJSON record of what the
          gallas do... found and consign events, in the Suricata eve.json
          shape. Shared by all the gallas.
        Default :: /var/log/baphomet/eve.json

    - eve_enable :: Whether to actually write the EVE log. The path is set
          by default but nothing is written unless this is turned on.
        Default :: 0

Watcher hashes take the keys below.

    - log :: The log file, or a array of them, to follow. Entries
          containing glob metacharacters are expanded, and re-expanded
          every ten seconds while running, so new matches get picked up
          and vanished ones dropped. Literal entries are kept even if the
          file does not exist yet.

          log = "/var/log/auth.log"
          log = "/jails/*/var/log/auth.log"
          log = [ "/var/log/maillog", "/var/log/mail/*.log" ]

    - parser :: The parser for lines of that log. See
          L<App::Baphomet::Parser> for the known parsers.
        Default :: syslog

    - rule :: The rule, or a array of rules, to match parsed lines
          against, relative to rules_dir, in the form C<type/name>. With a
          array, rules are checked in order and the first to match a line
          wins, which suits logs carrying several daemons, like a maillog.
          See L<App::Baphomet::Rules>.

    - max_retrys / find_time / ban_time :: Optional per watcher overrides.

The effective settings for a watcher are watcher over kur over global over
default.

=head1 EXPORTS

Nothing is exported by default. Everything below is available via
C<@EXPORT_OK>.

=head1 FUNCTIONS

=head2 load_config

Reads and parses the config file, merging in defaults. Will die on read or
parse failure or on invalid top level settings. Does not check the kur
defs... that is what L</check_kur_def> is for.

    my $config = load_config($path);

=cut

sub load_config {
	my ($path) = @_;

	if ( !defined($path) ) {
		die('No config path specified');
	}

	my $raw_config;
	{
		local $/ = undef;
		open( my $fh, '<', $path ) || die( 'Failed to open the config, "' . $path . '"... ' . $! );
		$raw_config = <$fh>;
		close($fh);
	}

	my ( $parsed, $parse_error ) = from_toml($raw_config);
	if ( !defined($parsed) || ref($parsed) ne 'HASH' ) {
		die(      'Failed to parse the config, "'
				. $path . '"... '
				. ( defined($parse_error) ? $parse_error : 'parsing did not return a hash' ) );
	}

	my $config = {
		'run_base_dir'      => '/var/run/baphomet',
		'tablet_base_dir'   => '/var/db/baphomet',
		'rules_dir'         => '/usr/local/etc/baphomet/rules',
		'ereshkigal_socket' => '/var/run/ereshkigal/socket',
		'galla_bin'         => 'galla',
		'journalctl_bin'    => 'journalctl',
		'timeout'           => 30,
		'checkpoint'        => 60,
		'max_retrys'        => 5,
		'find_time'         => 600,
		'ban_time'          => undef,
		'ignore_ips'        => [],
		'internal'          => undef,
		'socket_group'      => undef,
		'socket_mode'       => '0660',
		'enable_auth'       => 0,
		'authed_users'      => [],
		'authed_groups'     => [],
		'auth_temp_dir'     => undef,
		'recidive'          => undef,
		'eve_log'           => '/var/log/baphomet/eve.json',
		'eve_enable'        => 0,
		'kur'               => {},
	};

	foreach my $item ( keys( %{$parsed} ) ) {
		if ( !exists( $config->{$item} ) ) {
			die( 'Unknown setting "' . $item . '" in the config "' . $path . '"' );
		}
		if ( defined( $parsed->{$item} ) ) {
			$config->{$item} = $parsed->{$item};
		}
	}

	if ( ref( $config->{kur} ) ne 'HASH' ) {
		die('kur in the config is defined but not a hash');
	}

	my $times_error = _times_error($config);
	if ( defined($times_error) ) {
		die($times_error);
	}

	if ( $config->{timeout} !~ /^[0-9]+$/ || !$config->{timeout} ) {
		die( 'timeout, "' . $config->{timeout} . '", is not a positive int of seconds' );
	}

	if ( $config->{checkpoint} !~ /^[0-9]+$/ ) {
		die( 'checkpoint, "' . $config->{checkpoint} . '", is not a non-negative int of seconds' );
	}

	if ( ref( $config->{socket_mode} ) ne '' || $config->{socket_mode} !~ /^[0-7]{3,4}$/ ) {
		die( 'socket_mode, "' . $config->{socket_mode} . '", is not a octal perms string such as "0660"' );
	}
	if ( defined( $config->{socket_group} ) && ( ref( $config->{socket_group} ) ne '' || $config->{socket_group} eq '' ) )
	{
		die('socket_group is not a group name');
	}

	# the Neti gate... the auth challenge on the manager socket
	$config->{enable_auth} = $config->{enable_auth} ? 1 : 0;
	foreach my $item ( 'authed_users', 'authed_groups' ) {
		my $list_error = _authed_list_error( $config->{$item} );
		if ( defined($list_error) ) {
			die( $item . ' is ' . $list_error );
		}
	}
	if ( defined( $config->{auth_temp_dir} ) && ( ref( $config->{auth_temp_dir} ) ne '' || $config->{auth_temp_dir} eq '' ) )
	{
		die('auth_temp_dir is not a path');
	}

	# dies on anything unusable
	compile_ignore_ips( $config->{ignore_ips}, 'The top level ignore_ips' );
	if ( defined( $config->{internal} ) ) {
		compile_ignore_ips( $config->{internal}, 'The top level internal' );
	}

	if ( defined( $config->{recidive} ) ) {
		_check_recidive( $config->{recidive} );
	}

	# normalize eve_enable to a plain 0 or 1
	$config->{eve_enable} = $config->{eve_enable} ? 1 : 0;
	if ( !defined( $config->{eve_log} ) || ref( $config->{eve_log} ) ne '' || $config->{eve_log} eq '' ) {
		die('eve_log is not a path');
	}

	return $config;
} ## end sub load_config

# checks the recidive table, dieing on anything unusable
sub _check_recidive {
	my ($recidive) = @_;

	if ( ref($recidive) ne 'HASH' ) {
		die('recidive is not a table');
	}
	foreach my $key ( keys( %{$recidive} ) ) {
		if ( $key !~ /^(?:kur|max_retrys|find_time|ban_time)$/ ) {
			die( 'recidive has the unknown key "' . $key . '"' );
		}
	}
	if ( !defined( $recidive->{kur} ) || ref( $recidive->{kur} ) ne '' || $recidive->{kur} !~ /^[a-zA-Z0-9\-]+$/ ) {
		die('recidive lacks a kur naming where recidivists are consigned, matching /^[a-zA-Z0-9\-]+$/');
	}
	if ( defined( $recidive->{max_retrys} ) && ( $recidive->{max_retrys} !~ /^[0-9]+$/ || !$recidive->{max_retrys} ) )
	{
		die('recidive max_retrys is not a positive int');
	}
	if ( defined( $recidive->{find_time} ) && ( $recidive->{find_time} !~ /^[0-9]+$/ || !$recidive->{find_time} ) ) {
		die('recidive find_time is not a positive int of seconds');
	}
	if ( defined( $recidive->{ban_time} ) && $recidive->{ban_time} !~ /^[0-9]+$/ ) {
		die('recidive ban_time is not a non-negative int of seconds');
	}

	return;
} ## end sub _check_recidive

=head2 kur_split

Splits a kur def hash into its settings and its watchers. Hash values are
watchers, everything else is a setting.

    my ( $settings, $watchers ) = kur_split($def);

=cut

sub kur_split {
	my ($def) = @_;

	my $settings = {};
	my $watchers = {};
	foreach my $key ( keys( %{$def} ) ) {
		if ( ref( $def->{$key} ) eq 'HASH' ) {
			$watchers->{$key} = $def->{$key};
		} else {
			$settings->{$key} = $def->{$key};
		}
	}

	return ( $settings, $watchers );
} ## end sub kur_split

=head2 check_kur_def

Checks a kur def, dieing with a description of the problem if it is not
usable... bad name, no watchers, a watcher lacking log/parser/rule, a
unknown parser or rule type, or a unknown or invalid setting.

    check_kur_def( $name, $def );

=cut

sub check_kur_def {
	my ( $name, $def ) = @_;

	if ( !defined($name) || $name !~ /^[a-zA-Z0-9\-]+$/ ) {
		die( 'The kur name, "' . ( defined($name) ? $name : 'undef' ) . '", does not match /^[a-zA-Z0-9\-]+$/' );
	}
	if ( ref($def) ne 'HASH' ) {
		die( 'The def for the kur "' . $name . '" is not a hash' );
	}

	my ( $settings, $watchers ) = kur_split($def);

	my $settings_error = _settings_error($settings);
	if ( defined($settings_error) ) {
		die( 'The kur "' . $name . '" has ' . $settings_error );
	}

	if ( defined( $settings->{ignore_ips} ) ) {
		compile_ignore_ips( $settings->{ignore_ips}, 'The ignore_ips of the kur "' . $name . '"' );
	}
	if ( defined( $settings->{internal} ) ) {
		compile_ignore_ips( $settings->{internal}, 'The internal of the kur "' . $name . '"' );
	}

	if ( !keys( %{$watchers} ) ) {
		die( 'The kur "' . $name . '" has no watchers' );
	}

	require App::Baphomet::Parser;
	require App::Baphomet::Rules;

	foreach my $watcher_name ( sort( keys( %{$watchers} ) ) ) {
		my $watcher = $watchers->{$watcher_name};
		my $where   = 'The watcher "' . $watcher_name . '" of the kur "' . $name . '" ';

		foreach my $key ( keys( %{$watcher} ) ) {
			if ( $key !~ /^(?:log|journal|parser|rule|max_retrys|find_time|ban_time)$/ ) {
				die( $where . 'has the unknown key "' . $key . '"' );
			}
			# rule, log, and journal may be arrays... everything else is a scalar
			if ( ref( $watcher->{$key} ) ne ''
				&& !( $key =~ /^(?:rule|log|journal)$/ && ref( $watcher->{$key} ) eq 'ARRAY' ) )
			{
				die( $where . 'key "' . $key . '" is not a scalar' );
			}
		}

		my $watcher_settings_error = _settings_error($watcher);
		if ( defined($watcher_settings_error) ) {
			die( $where . 'has ' . $watcher_settings_error );
		}

		# a watcher follows either a log, one or more files, or the
		# journal, a set of journalctl matches... exactly one of the two
		my $is_journal = defined( $watcher->{journal} );
		if ( defined( $watcher->{log} ) && $is_journal ) {
			die( $where . 'has both a log and a journal, which are mutually exclusive' );
		}
		if ( !defined( $watcher->{log} ) && !$is_journal ) {
			die( $where . 'lacks a log or a journal' );
		}

		if ($is_journal) {
			my @matches = watcher_journal($watcher);
			foreach my $match (@matches) {
				if ( !defined($match) || ref($match) ne '' ) {
					die( $where . 'has a non-string journal match' );
				}
			}
		} else {
			my @logs = watcher_logs($watcher);
			if ( !@logs ) {
				die( $where . 'has a empty log array' );
			}
			foreach my $log (@logs) {
				if ( !defined($log) || ref($log) ne '' || $log eq '' ) {
					die( $where . 'has a empty or non-string log entry' );
				}
			}
		} ## end else [ if ($is_journal) ]

		if ( defined( $watcher->{parser} ) && !App::Baphomet::Parser::is_known( $watcher->{parser} ) ) {
			die( $where . 'has the unknown parser "' . $watcher->{parser} . '"' );
		}
		if ( !defined( $watcher->{rule} ) ) {
			die( $where . 'lacks a rule' );
		}
		my @rules = watcher_rules($watcher);
		if ( !@rules ) {
			die( $where . 'has a empty rule array' );
		}
		my $parser
			= defined( $watcher->{parser} ) ? $watcher->{parser}
			: $is_journal                   ? 'journal'
			:                                 'syslog';
		foreach my $rule (@rules) {
			if ( !defined($rule) || ref($rule) ne '' ) {
				die( $where . 'has a non-string rule entry' );
			}
			if ( $rule !~ /^[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+$/ ) {
				die( $where . 'has a invalid rule, "' . $rule . '"... should be like "syslog/sshd"' );
			}
			my ($rule_type) = split( /\//, $rule );
			if ( !App::Baphomet::Rules::known_type($rule_type) ) {
				die( $where . 'has a rule of the unknown type "' . $rule_type . '"' );
			}
			# a mismatched pairing would parse fine and then match nothing, forever
			if ( !App::Baphomet::Rules::type_accepts_parser( $rule_type, $parser ) ) {
				die(      $where
						. 'pairs the rule "'
						. $rule
						. '" of the type "'
						. $rule_type
						. '" with the parser "'
						. $parser
						. '", whose lines that type can not consume' );
			}
		} ## end foreach my $rule (@rules)
	} ## end foreach my $watcher_name ( sort( keys( %{$watchers...})))

	return;
} ## end sub check_kur_def

=head2 resolve_settings

Resolves the effective max_retrys, find_time, and ban_time for a watcher...
watcher over kur over global.

    my $settings = resolve_settings( $config, $kur_settings, $watcher );

=cut

sub resolve_settings {
	my ( $config, $kur_settings, $watcher ) = @_;

	my $resolved = {};
	foreach my $item ( 'max_retrys', 'find_time', 'ban_time' ) {
		if ( defined($watcher) && defined( $watcher->{$item} ) ) {
			$resolved->{$item} = $watcher->{$item};
		} elsif ( defined($kur_settings) && defined( $kur_settings->{$item} ) ) {
			$resolved->{$item} = $kur_settings->{$item};
		} else {
			$resolved->{$item} = $config->{$item};
		}
	}

	return $resolved;
} ## end sub resolve_settings

=head2 watcher_rules

Returns the rules of a watcher as a list, regardless of if its rule key is
a single rule or a array of them.

    my @rules = watcher_rules($watcher);

=cut

sub watcher_rules {
	my ($watcher) = @_;

	if ( ref( $watcher->{rule} ) eq 'ARRAY' ) {
		return @{ $watcher->{rule} };
	}

	return ( $watcher->{rule} );
} ## end sub watcher_rules

=head2 watcher_logs

Returns the log entries of a watcher as a list, regardless of if its log
key is a single entry or a array of them. Does not expand globs... that is
the galla's business, as it has to redo it while running.

    my @logs = watcher_logs($watcher);

=cut

sub watcher_logs {
	my ($watcher) = @_;

	if ( ref( $watcher->{log} ) eq 'ARRAY' ) {
		return @{ $watcher->{log} };
	}

	return ( $watcher->{log} );
} ## end sub watcher_logs

=head2 compile_ignore_ips

Compiles a ignore_ips list, a array of IPv4/IPv6 addresses and CIDRs,
into the form L</ip_ignored> takes. Will die on anything unusable, with
the passed $where leading the error message.

    my $compiled = compile_ignore_ips( $list, $where );

=cut

sub compile_ignore_ips {
	my ( $list, $where ) = @_;

	if ( !defined($where) ) {
		$where = 'ignore_ips';
	}
	if ( ref($list) ne 'ARRAY' ) {
		die( $where . ' is not a array' );
	}

	my @compiled;
	foreach my $entry ( @{$list} ) {
		if ( !defined($entry) || ref($entry) ne '' || $entry eq '' ) {
			die( $where . ' contains a empty or non-string entry' );
		}

		my ( $addr, $prefix ) = split( /\//, $entry, 2 );

		my $packed = inet_pton( AF_INET, $addr );
		my $bits   = 32;
		if ( !defined($packed) ) {
			$packed = inet_pton( AF_INET6, $addr );
			$bits   = 128;
		}
		if ( !defined($packed) ) {
			die( $where . ' entry "' . $entry . '" is not a IPv4 or IPv6 address or CIDR' );
		}

		if ( !defined($prefix) ) {
			$prefix = $bits;
		}
		if ( $prefix !~ /^[0-9]+$/ || $prefix > $bits ) {
			die( $where . ' entry "' . $entry . '" has a invalid prefix length' );
		}

		push( @compiled, { 'packed' => $packed, 'prefix' => $prefix, 'bits' => $bits } );
	} ## end foreach my $entry ( @{$list} )

	return \@compiled;
} ## end sub compile_ignore_ips

=head2 ip_ignored

Checks a IP against a compiled ignore_ips list. IPv4 mapped IPv6, the
::ffff: form, is checked as its IPv4 self. Anything that is not a IP,
like a hostname a rule captured, is never regarded as ignored.

    if ( ip_ignored( $compiled, $ip ) ) { ... }

=cut

sub ip_ignored {
	my ( $compiled, $ip ) = @_;

	if ( !defined($ip) || ref($compiled) ne 'ARRAY' || !@{$compiled} ) {
		return 0;
	}

	my $packed = inet_pton( AF_INET, $ip );
	my $bits   = 32;
	if ( !defined($packed) ) {
		my $packed6 = inet_pton( AF_INET6, $ip );
		if ( !defined($packed6) ) {
			return 0;
		}
		# IPv4 mapped IPv6 is really IPv4
		if ( substr( $packed6, 0, 12 ) eq ( "\0" x 10 ) . "\xff\xff" ) {
			$packed = substr( $packed6, 12 );
		} else {
			$packed = $packed6;
			$bits   = 128;
		}
	} ## end if ( !defined($packed) )

	foreach my $net ( @{$compiled} ) {
		if ( $net->{bits} != $bits ) {
			next;
		}

		my $whole_bytes = int( $net->{prefix} / 8 );
		my $spare_bits  = $net->{prefix} % 8;

		if ( substr( $packed, 0, $whole_bytes ) ne substr( $net->{packed}, 0, $whole_bytes ) ) {
			next;
		}
		if ($spare_bits) {
			my $mask = chr( 0xFF << ( 8 - $spare_bits ) & 0xFF );
			if ( ( substr( $packed, $whole_bytes, 1 ) & $mask ) ne ( substr( $net->{packed}, $whole_bytes, 1 ) & $mask ) )
			{
				next;
			}
		}

		return 1;
	} ## end foreach my $net ( @{$compiled} )

	return 0;
} ## end sub ip_ignored

=head2 watcher_journal

Returns the journalctl matches of a watcher as a list, regardless of if
its journal key is a single match or a array of them. A empty list means
follow the whole journal.

    my @matches = watcher_journal($watcher);

=cut

sub watcher_journal {
	my ($watcher) = @_;

	if ( ref( $watcher->{journal} ) eq 'ARRAY' ) {
		return @{ $watcher->{journal} };
	}
	if ( defined( $watcher->{journal} ) && $watcher->{journal} ne '' && $watcher->{journal} ne '1' ) {
		return ( $watcher->{journal} );
	}

	return ();
} ## end sub watcher_journal

# returns a error string if the passed value is not a array of strings,
# undef otherwise... for the authed_users/authed_groups lists
sub _authed_list_error {
	my ($list) = @_;

	if ( ref($list) ne 'ARRAY' ) {
		return 'not a array';
	}
	foreach my $item ( @{$list} ) {
		if ( !defined($item) || ref($item) ne '' ) {
			return 'not a array of just strings';
		}
	}

	return undef;
} ## end sub _authed_list_error

# returns a error string if any of max_retrys/find_time/ban_time present in
# the passed hash is invalid, undef otherwise
sub _settings_error {
	my ($settings) = @_;

	foreach my $key ( keys( %{$settings} ) ) {
		if ( $key !~ /^(?:log|journal|parser|rule|max_retrys|find_time|ban_time|ignore_ips|internal)$/ ) {
			return 'the unknown setting "' . $key . '"';
		}
	}

	return _times_error($settings);
} ## end sub _settings_error

# returns a error string if any time-ish setting in the passed hash is
# invalid, undef otherwise
sub _times_error {
	my ($settings) = @_;

	if ( defined( $settings->{max_retrys} ) && ( $settings->{max_retrys} !~ /^[0-9]+$/ || !$settings->{max_retrys} ) )
	{
		return 'a max_retrys, "' . $settings->{max_retrys} . '", that is not a positive int';
	}
	if ( defined( $settings->{find_time} ) && ( $settings->{find_time} !~ /^[0-9]+$/ || !$settings->{find_time} ) ) {
		return 'a find_time, "' . $settings->{find_time} . '", that is not a positive int of seconds';
	}
	if ( defined( $settings->{ban_time} ) && $settings->{ban_time} !~ /^[0-9]+$/ ) {
		return 'a ban_time, "' . $settings->{ban_time} . '", that is not a non-negative int of seconds';
	}

	return undef;
} ## end sub _times_error

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
