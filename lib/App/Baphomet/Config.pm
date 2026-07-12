package App::Baphomet::Config;

use 5.006;
use strict;
use warnings;
use Exporter   qw( import );
use TOML::Tiny qw( from_toml );

=pod

=head1 NAME

App::Baphomet::Config - Config loading and checking shared by the baphomet manager and galla workers.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

our @EXPORT_OK = qw( load_config kur_split check_kur_def resolve_settings watcher_rules );

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

    - rules_dir :: The dir holding the matching rules. A rule of
          C<syslog/sshd> is the file C<syslog/sshd.yaml> under here.
        Default :: /usr/local/etc/baphomet/rules

    - ereshkigal_socket :: The Ereshkigal manager socket bans are sent to.
        Default :: /var/run/ereshkigal/socket

    - galla_bin :: The galla bin to spawn workers with.
        Default :: galla

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

    - socket_group :: Group ownership of the manager socket.
        Default :: the default group of the root user

    - socket_mode :: Perms for the manager socket. Processed via oct, so
          should be specified as a string such as "0660". Galla sockets
          are always 0600 and not configurable.
        Default :: 0660

Watcher hashes take the keys below.

    - log :: The log file to follow.

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
		'rules_dir'         => '/usr/local/etc/baphomet/rules',
		'ereshkigal_socket' => '/var/run/ereshkigal/socket',
		'galla_bin'         => 'galla',
		'timeout'           => 30,
		'max_retrys'        => 5,
		'find_time'         => 600,
		'ban_time'          => undef,
		'socket_group'      => undef,
		'socket_mode'       => '0660',
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

	return $config;
} ## end sub load_config

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

	if ( !keys( %{$watchers} ) ) {
		die( 'The kur "' . $name . '" has no watchers' );
	}

	require App::Baphomet::Parser;
	require App::Baphomet::Rules;

	foreach my $watcher_name ( sort( keys( %{$watchers} ) ) ) {
		my $watcher = $watchers->{$watcher_name};
		my $where   = 'The watcher "' . $watcher_name . '" of the kur "' . $name . '" ';

		foreach my $key ( keys( %{$watcher} ) ) {
			if ( $key !~ /^(?:log|parser|rule|max_retrys|find_time|ban_time)$/ ) {
				die( $where . 'has the unknown key "' . $key . '"' );
			}
			# rule may be a array of rules... everything else is a scalar
			if ( ref( $watcher->{$key} ) ne '' && !( $key eq 'rule' && ref( $watcher->{$key} ) eq 'ARRAY' ) ) {
				die( $where . 'key "' . $key . '" is not a scalar' );
			}
		}

		my $watcher_settings_error = _settings_error($watcher);
		if ( defined($watcher_settings_error) ) {
			die( $where . 'has ' . $watcher_settings_error );
		}

		if ( !defined( $watcher->{log} ) || $watcher->{log} eq '' ) {
			die( $where . 'lacks a log' );
		}
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
		my $parser = defined( $watcher->{parser} ) ? $watcher->{parser} : 'syslog';
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

# returns a error string if any of max_retrys/find_time/ban_time present in
# the passed hash is invalid, undef otherwise
sub _settings_error {
	my ($settings) = @_;

	foreach my $key ( keys( %{$settings} ) ) {
		if ( $key !~ /^(?:log|parser|rule|max_retrys|find_time|ban_time)$/ ) {
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
