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
	= qw( load_config kur_split check_kur_def resolve_settings resolve_country_codes resolve_namtar_lists resolve_active_time watcher_rules watcher_logs watcher_journal compile_ignore_ips ip_ignored );

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
    max_score=5
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

    - ledger_keep :: How long rows are kept in the shared banishment
          ledger, in seconds, read by the recidive gate and the ledger
          command. 0 means keep forever. Rows still inside the recidive
          find_time are always kept, whatever this says.
        Default :: 2592000

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

    - max_score :: How many matches with in find_time seconds it takes
          for a IP to be banned. May be overridden per kur and per watcher.
        Default :: 5

    - find_time :: The window in seconds matches are counted across.
          Matches older than this no longer count towards max_score.
          May be overridden per kur and per watcher.
        Default :: 600

    - ban_time :: Ban time in seconds forwarded with ban requests, with 0
          meaning never time out. If not set anywhere, it is left out of
          the request and the Ereshkigal side default applies. May be
          overridden per kur and per watcher.
        Default :: undef

    - ignore_ips :: A array of IPv4/IPv6 addresses and CIDRs that are
          never banished, no matter what the rules say. A kur may carry
          its own ignore_ips, which extends this list for that kur rather
          than replacing it. Hostnames are not accepted... resolving
          config at load time is a trust decision this declines to make.
        Default :: []

    - internal :: A array of IPv4/IPv6 addresses and CIDRs that are your
          own hosts. Rules with the C<ban_not_internal> option banish the
          end of a flow that is not internal, for cases like Suricata
          alerts where the offender may be the src or the dest depending
          on where in the stream it fired. A kur may carry its own
          internal, extending this. Where not set it defaults to the
          ignore_ips, so what you ignore is also treated as yours... and
          since a ignored IP is never banished anyway, the banished end
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
          every banishment is recorded to a shared ledger, and a IP
          banished across any kurs max_score times with in find_time is
          dragged through a further gate... banished to the recidive
          C<kur> for ban_time seconds, which should be long. Keys...

              kur :: The kur recidivists are banished to. Required.
                  There must be a matching kur on the Ereshkigal side
                  covering everything worth protecting.

              max_score :: Banishments before a IP is a recidivist.
                  Default :: 5

              find_time :: The window the banishments are counted over.
                  Default :: 604800, a week

              ban_time :: How long a recidivist is held, 0 being eternal.
                  Default :: 0
        Default :: undef, off

    - eve_log :: Path of the EVE event log, the NDJSON record of what the
          gallas do... found and banish events, in the Suricata eve.json
          shape. Shared by all the gallas.
        Default :: /var/log/baphomet/eve.json

    - eve_enable :: Whether to actually write the EVE log. The path is set
          by default but nothing is written unless this is turned on.
        Default :: 0

    - geoip_db :: Path to a MaxMind GeoIP2/GeoLite2 country database, for
          rules with a country gate. Read via the optional
          IP::Geolocation::MMDB module. Unset or unloadable, and every
          country gate fails closed.
        Default :: undef

    - country_codes :: A hash of named ISO 3166 code lists a rule's country
          gate can import. Global here, and also per kur and per watcher,
          merged per name.
        Default :: {}

    - namtar_lists :: A hash of named lists a rule's namtar_list gate can
          check against, each a path or array of paths (a cidr list) or a
          {type, files, nocase} table (cidr, or a string list). Global,
          per kur, and per watcher, merged per name.
        Default :: {}

    - active_time :: A hash of named time windows a rule's active_time gate
          can reference, each a {days, hours} spec or a array of them.
          Global, per kur, and per watcher, merged per name.
        Default :: {}

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

    - max_score / find_time / ban_time :: Optional per watcher overrides.

    - allow_per_rule_thresholds :: Whether this watcher honors thresholds a
          rule carries. Per watcher, kur, and global.

    - country_codes :: Named country-code lists overriding the kur's and
          global's for this watcher's rules.

    - namtar_lists :: Named lists (cidr or string) overriding the kur's and
          global's for this watcher's rules.

    - active_time :: Named time windows overriding the kur's and global's
          for this watcher's rules.

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
		'ledger_keep'       => 2592000,
		'max_score'        => 5,
		'find_time'         => 600,
		'ban_time'          => undef,
		'allow_per_rule_thresholds' => 0,
		'eve_only'          => 0,
		'observe_ignored'   => 0,
		'default_severity'  => undef,
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
		'geoip_db'          => undef,
		'country_codes'     => {},
		'namtar_lists'      => {},
		'active_time'       => {},
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

	if ( $config->{ledger_keep} !~ /^[0-9]+$/ ) {
		die( 'ledger_keep, "' . $config->{ledger_keep} . '", is not a non-negative int of seconds' );
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

	# normalize the booleans to a plain 0 or 1
	$config->{eve_enable}                = $config->{eve_enable}                ? 1 : 0;
	$config->{allow_per_rule_thresholds} = $config->{allow_per_rule_thresholds} ? 1 : 0;
	$config->{eve_only}                  = $config->{eve_only}                  ? 1 : 0;
	$config->{observe_ignored}           = $config->{observe_ignored}           ? 1 : 0;
	my $severity_error = _severity_error( $config->{default_severity} );
	if ( defined($severity_error) ) {
		die( 'The top level ' . $severity_error );
	}
	if ( !defined( $config->{eve_log} ) || ref( $config->{eve_log} ) ne '' || $config->{eve_log} eq '' ) {
		die('eve_log is not a path');
	}

	if ( defined( $config->{geoip_db} ) && ( ref( $config->{geoip_db} ) ne '' || $config->{geoip_db} eq '' ) ) {
		die('geoip_db is not a path');
	}
	my $codes_error = _country_codes_error( $config->{country_codes}, 'The top level country_codes' );
	if ( defined($codes_error) ) {
		die($codes_error);
	}
	my $namtar_error = _namtar_lists_error( $config->{namtar_lists}, 'The top level namtar_lists' );
	if ( defined($namtar_error) ) {
		die($namtar_error);
	}
	my $active_error = _active_time_error( $config->{active_time}, 'The top level active_time' );
	if ( defined($active_error) ) {
		die($active_error);
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
		if ( $key !~ /^(?:kur|max_score|find_time|ban_time)$/ ) {
			die( 'recidive has the unknown key "' . $key . '"' );
		}
	}
	if ( !defined( $recidive->{kur} ) || ref( $recidive->{kur} ) ne '' || $recidive->{kur} !~ /^[a-zA-Z0-9\-]+$/ ) {
		die('recidive lacks a kur naming where recidivists are banished, matching /^[a-zA-Z0-9\-]+$/');
	}
	if ( defined( $recidive->{max_score} ) && ( $recidive->{max_score} !~ /^[0-9]+$/ || !$recidive->{max_score} ) )
	{
		die('recidive max_score is not a positive int');
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

# settings that are hashes rather than scalars, so kur_split does not
# mistake them for watchers... country_codes, namtar_lists, and active_time
# are hashes of named things
my %hash_settings = ( 'country_codes' => 1, 'namtar_lists' => 1, 'active_time' => 1 );

# the severity levels a default_severity may name... matches the rule-side
# set in App::Baphomet::Rules::Base, kept local to avoid a load-order coupling
my %valid_severity = map { $_ => 1 } qw( info low medium high critical );

# returns a bare error string if the passed default_severity is set and not a
# valid level, undef otherwise... the caller supplies its own context lead
sub _severity_error {
	my ($value) = @_;

	if ( defined($value) && ( ref($value) ne '' || !$valid_severity{$value} ) ) {
		return 'default_severity is not one of info/low/medium/high/critical';
	}

	return undef;
}

sub kur_split {
	my ($def) = @_;

	my $settings = {};
	my $watchers = {};
	foreach my $key ( keys( %{$def} ) ) {
		if ( ref( $def->{$key} ) eq 'HASH' && !$hash_settings{$key} ) {
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
			if ( $key
				!~ /^(?:log|journal|parser|rule|max_score|find_time|ban_time|allow_per_rule_thresholds|eve_only|observe_ignored|default_severity|country_codes|namtar_lists|active_time)$/
				)
			{
				die( $where . 'has the unknown key "' . $key . '"' );
			}
			# rule, log, and journal may be arrays, country_codes,
			# namtar_lists, and active_time hashes, TOML booleans are
			# blessed... else a scalar
			if ( ref( $watcher->{$key} ) ne ''
				&& !( $key =~ /^(?:rule|log|journal)$/                      && ref( $watcher->{$key} ) eq 'ARRAY' )
				&& !( $key =~ /^(?:country_codes|namtar_lists|active_time)$/ && ref( $watcher->{$key} ) eq 'HASH' )
				&& !( $key =~ /^(?:allow_per_rule_thresholds|eve_only|observe_ignored)$/
					&& ref( $watcher->{$key} ) eq 'JSON::PP::Boolean' ) )
			{
				die( $where . 'key "' . $key . '" is not a scalar' );
			}
		} ## end foreach my $key ( keys( %{$watcher} ) )

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

Resolves the effective max_score, find_time, ban_time,
allow_per_rule_thresholds, eve_only, observe_ignored, and default_severity for
a watcher... watcher over kur over global. The three booleans are normalized
to a plain 0 or 1. default_severity is the level a rule's EVE events carry
when the rule sets no severity of its own (undef when unset). eve_only puts
the watcher's rules in observe mode (matches to EVE, no
real ban); observe_ignored lets that observe mode also process IPs ignore_ips
would otherwise drop. A rule's own eve_only, when set, layers over this.

    my $settings = resolve_settings( $config, $kur_settings, $watcher );

=cut

sub resolve_settings {
	my ( $config, $kur_settings, $watcher ) = @_;

	my $resolved = {};
	foreach my $item (
		'max_score',        'find_time',       'ban_time', 'allow_per_rule_thresholds',
		'eve_only',         'observe_ignored', 'default_severity'
		)
	{
		if ( defined($watcher) && defined( $watcher->{$item} ) ) {
			$resolved->{$item} = $watcher->{$item};
		} elsif ( defined($kur_settings) && defined( $kur_settings->{$item} ) ) {
			$resolved->{$item} = $kur_settings->{$item};
		} else {
			$resolved->{$item} = $config->{$item};
		}
	}
	foreach my $flag ( 'allow_per_rule_thresholds', 'eve_only', 'observe_ignored' ) {
		$resolved->{$flag} = $resolved->{$flag} ? 1 : 0;
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

# returns a error string if any of max_score/find_time/ban_time present in
# the passed hash is invalid, undef otherwise
sub _settings_error {
	my ($settings) = @_;

	foreach my $key ( keys( %{$settings} ) ) {
		if ( $key
			!~ /^(?:log|journal|parser|rule|max_score|find_time|ban_time|allow_per_rule_thresholds|eve_only|observe_ignored|default_severity|ignore_ips|internal|country_codes|namtar_lists|active_time)$/
			)
		{
			return 'the unknown setting "' . $key . '"';
		}
	}

	if ( defined( $settings->{country_codes} ) ) {
		my $codes_error = _country_codes_error( $settings->{country_codes}, 'country_codes' );
		if ( defined($codes_error) ) {
			return $codes_error;
		}
	}
	if ( defined( $settings->{namtar_lists} ) ) {
		my $namtar_error = _namtar_lists_error( $settings->{namtar_lists}, 'namtar_lists' );
		if ( defined($namtar_error) ) {
			return $namtar_error;
		}
	}
	if ( defined( $settings->{active_time} ) ) {
		my $active_error = _active_time_error( $settings->{active_time}, 'active_time' );
		if ( defined($active_error) ) {
			return $active_error;
		}
	}
	my $severity_error = _severity_error( $settings->{default_severity} );
	if ( defined($severity_error) ) {
		return $severity_error;
	}

	return _times_error($settings);
} ## end sub _settings_error

=head2 resolve_country_codes

Resolves the effective named country-code lists for a watcher... the global
country_codes overlaid by the kur's, then the watcher's, merged per name so
a deeper level replaces a same-named list while names it does not mention
stay inherited. Codes are uppercased.

    my $lists = resolve_country_codes( $config, $kur_settings, $watcher );

=cut

sub resolve_country_codes {
	my ( $config, $kur_settings, $watcher ) = @_;

	my $resolved = {};
	foreach my $level ( $config, $kur_settings, $watcher ) {
		if ( defined($level) && ref( $level->{country_codes} ) eq 'HASH' ) {
			foreach my $name ( keys( %{ $level->{country_codes} } ) ) {
				$resolved->{$name} = [ map { uc($_) } @{ $level->{country_codes}{$name} } ];
			}
		}
	}

	return $resolved;
} ## end sub resolve_country_codes

# returns a error string if the passed country_codes is not a hash of
# non-empty arrays of 2-letter codes, undef otherwise... $where leads the
# message
sub _country_codes_error {
	my ( $codes, $where ) = @_;

	if ( ref($codes) ne 'HASH' ) {
		return $where . ' is not a hash of named code lists';
	}
	foreach my $name ( keys( %{$codes} ) ) {
		if ( ref( $codes->{$name} ) ne 'ARRAY' || !@{ $codes->{$name} } ) {
			return $where . ' list "' . $name . '" is not a non-empty array';
		}
		foreach my $code ( @{ $codes->{$name} } ) {
			if ( !defined($code) || ref($code) ne '' || $code !~ /^[A-Za-z]{2}$/ ) {
				return $where . ' list "' . $name . '" has a entry that is not a 2-letter country code';
			}
		}
	} ## end foreach my $name ( keys( %{$codes} ) )

	return undef;
} ## end sub _country_codes_error

=head2 resolve_namtar_lists

Resolves the effective named namtar lists for a watcher... the global
namtar_lists overlaid by the kur's, then the watcher's, merged per name so
a deeper level replaces a same-named list. Each name resolves to a
C<{type, nocase, paths}> spec, the paths a array with scalars normalized to
one element. The bare path or array form is a cidr list, the typed table
form C<{type, files, nocase}> may also be a string list.

    my $lists = resolve_namtar_lists( $config, $kur_settings, $watcher );

=cut

sub resolve_namtar_lists {
	my ( $config, $kur_settings, $watcher ) = @_;

	my $resolved = {};
	foreach my $level ( $config, $kur_settings, $watcher ) {
		if ( defined($level) && ref( $level->{namtar_lists} ) eq 'HASH' ) {
			foreach my $name ( keys( %{ $level->{namtar_lists} } ) ) {
				$resolved->{$name} = _namtar_list_spec( $level->{namtar_lists}{$name} );
			}
		}
	}

	return $resolved;
} ## end sub resolve_namtar_lists

# normalizes one named namtar list, in either the bare cidr form (a path or
# array of paths) or the typed table form ({type, files, nocase}), into a
# {type, nocase, paths} spec. defaults type to cidr and nocase off, the
# shape already vetted by _namtar_lists_error
sub _namtar_list_spec {
	my ($value) = @_;

	if ( ref($value) eq 'HASH' ) {
		my $type  = defined( $value->{type} ) ? $value->{type} : 'cidr';
		my $files = $value->{files};
		return {
			'type'   => $type,
			'nocase' => ( $type eq 'string' && $value->{nocase} ) ? 1 : 0,
			'paths'  => [ ref($files) eq 'ARRAY' ? @{$files} : ($files) ],
		};
	}

	return {
		'type'   => 'cidr',
		'nocase' => 0,
		'paths'  => [ ref($value) eq 'ARRAY' ? @{$value} : ($value) ],
	};
} ## end sub _namtar_list_spec

# returns a error string if the passed namtar_lists is not a hash of named
# lists, each a path, a non-empty array of paths, or a typed table
# ({type: cidr|string, files: path or array, nocase: bool, string only}),
# undef otherwise... $where leads the message
sub _namtar_lists_error {
	my ( $lists, $where ) = @_;

	if ( ref($lists) ne 'HASH' ) {
		return $where . ' is not a hash of named lists';
	}
	foreach my $name ( keys( %{$lists} ) ) {
		my $value = $lists->{$name};
		my $paths;
		if ( ref($value) eq 'HASH' ) {
			foreach my $key ( keys( %{$value} ) ) {
				if ( $key !~ /^(?:type|files|nocase)$/ ) {
					return $where . ' list "' . $name . '" has the unknown key "' . $key . '"';
				}
			}
			if ( defined( $value->{type} ) && $value->{type} ne 'cidr' && $value->{type} ne 'string' ) {
				return $where . ' list "' . $name . '" has a type that is not "cidr" or "string"';
			}
			if ( defined( $value->{nocase} ) ) {
				if ( ref( $value->{nocase} ) ne '' && ref( $value->{nocase} ) ne 'JSON::PP::Boolean' ) {
					return $where . ' list "' . $name . '" has a nocase that is not a boolean';
				}
				if ( !defined( $value->{type} ) || $value->{type} ne 'string' ) {
					return $where . ' list "' . $name . '" sets nocase on a non-string list';
				}
			} ## end if ( defined( $value->{nocase...}))
			$paths = $value->{files};
			if ( !defined($paths) ) {
				return $where . ' list "' . $name . '" is missing files';
			}
		} elsif ( ref($value) ne '' && ref($value) ne 'ARRAY' ) {
			return $where . ' list "' . $name . '" is not a path, a array of paths, or a typed table';
		} else {
			$paths = $value;
		} ## end else [ if ( ref($value) eq 'HASH')]

		my @paths = ref($paths) eq 'ARRAY' ? @{$paths} : ($paths);
		if ( !@paths ) {
			return $where . ' list "' . $name . '" is a empty array';
		}
		foreach my $path (@paths) {
			if ( !defined($path) || ref($path) ne '' || $path eq '' ) {
				return $where . ' list "' . $name . '" has a entry that is not a non-empty path';
			}
		}
	} ## end foreach my $name ( keys( %{$lists} ) )

	return undef;
} ## end sub _namtar_lists_error

=head2 resolve_active_time

Resolves the effective named time windows for a watcher... the global
active_time overlaid by the kur's, then the watcher's, merged per name so a
deeper level replaces a same-named window. Each name resolves to a array of
specs, a single spec normalized to a one element array.

    my $windows = resolve_active_time( $config, $kur_settings, $watcher );

=cut

sub resolve_active_time {
	my ( $config, $kur_settings, $watcher ) = @_;

	my $resolved = {};
	foreach my $level ( $config, $kur_settings, $watcher ) {
		if ( defined($level) && ref( $level->{active_time} ) eq 'HASH' ) {
			foreach my $name ( keys( %{ $level->{active_time} } ) ) {
				my $window = $level->{active_time}{$name};
				$resolved->{$name} = [ ref($window) eq 'ARRAY' ? @{$window} : ($window) ];
			}
		}
	}

	return $resolved;
} ## end sub resolve_active_time

# returns a error string if the passed active_time is not a hash of named
# windows, each a spec or a array of specs of {days?, hours?}, undef
# otherwise... $where leads the message
sub _active_time_error {
	my ( $windows, $where ) = @_;

	if ( ref($windows) ne 'HASH' ) {
		return $where . ' is not a hash of named windows';
	}
	foreach my $name ( keys( %{$windows} ) ) {
		my $window = $windows->{$name};
		if ( ref($window) ne 'HASH' && ref($window) ne 'ARRAY' ) {
			return $where . ' window "' . $name . '" is not a spec or a array of specs';
		}
		my @specs = ref($window) eq 'ARRAY' ? @{$window} : ($window);
		if ( !@specs ) {
			return $where . ' window "' . $name . '" is a empty array';
		}
		foreach my $spec (@specs) {
			my $spec_error = _active_time_spec_error( $spec, $where . ' window "' . $name . '"' );
			if ( defined($spec_error) ) {
				return $spec_error;
			}
		}
	} ## end foreach my $name ( keys( %{$windows...}))

	return undef;
} ## end sub _active_time_error

# returns a error string if a single active_time spec is malformed, undef
# otherwise... a hash of optional days (0..6) and hours ("HHMM-HHMM" or a
# array of them), at least one of the two present
sub _active_time_spec_error {
	my ( $spec, $where ) = @_;

	if ( ref($spec) ne 'HASH' ) {
		return $where . ' has a spec that is not a hash';
	}
	foreach my $key ( keys( %{$spec} ) ) {
		if ( $key !~ /^(?:days|hours)$/ ) {
			return $where . ' has a spec with the unknown key "' . $key . '"';
		}
	}
	if ( !defined( $spec->{days} ) && !defined( $spec->{hours} ) ) {
		return $where . ' has a spec setting neither days nor hours';
	}

	if ( defined( $spec->{days} ) ) {
		if ( ref( $spec->{days} ) ne 'ARRAY' || !@{ $spec->{days} } ) {
			return $where . ' has a days that is not a non-empty array';
		}
		foreach my $day ( @{ $spec->{days} } ) {
			if ( !defined($day) || ref($day) ne '' || $day !~ /^[0-6]$/ ) {
				return $where . ' has a day that is not 0..6';
			}
		}
	} ## end if ( defined( $spec->{days...}))

	if ( defined( $spec->{hours} ) ) {
		if ( ref( $spec->{hours} ) ne '' && ref( $spec->{hours} ) ne 'ARRAY' ) {
			return $where . ' has a hours that is not a range or a array of ranges';
		}
		my @ranges = ref( $spec->{hours} ) eq 'ARRAY' ? @{ $spec->{hours} } : ( $spec->{hours} );
		if ( !@ranges ) {
			return $where . ' has a empty hours array';
		}
		foreach my $range (@ranges) {
			if ( !defined($range) || ref($range) ne '' || $range !~ /^(?:[01][0-9]|2[0-3])[0-5][0-9]-(?:[01][0-9]|2[0-3])[0-5][0-9]$/ )
			{
				return $where . ' has a hours range that is not HHMM-HHMM';
			}
		}
	} ## end if ( defined( $spec->{hours...}))

	return undef;
} ## end sub _active_time_spec_error

# returns a error string if any time-ish setting in the passed hash is
# invalid, undef otherwise
sub _times_error {
	my ($settings) = @_;

	if ( defined( $settings->{max_score} ) && ( $settings->{max_score} !~ /^[0-9]+$/ || !$settings->{max_score} ) )
	{
		return 'a max_score, "' . $settings->{max_score} . '", that is not a positive int';
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
