#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
	eval { require App::Cmd; };
	if ($@) {
		plan skip_all => 'App::Cmd not available';
	}
}

use App::Baphomet::App::Command::ledger         ();
use App::Baphomet::App::Command::banished       ();
use App::Baphomet::App::Command::lnms_f2b_extend ();

#
# the ledger row parser
#

my $entry = App::Baphomet::App::Command::ledger::_parse_row('1784067000,sshd,1.2.3.4,syslog/sshd,authlog');
is( $entry->{epoch},   1784067000,    'epoch parsed' );
is( $entry->{kur},     'sshd',        'kur parsed' );
is( $entry->{ip},      '1.2.3.4',     'ip parsed' );
is( $entry->{rule},    'syslog/sshd', 'rule parsed' );
is( $entry->{watcher}, 'authlog',     'watcher parsed' );
ok( defined( $entry->{date} ), 'the date rides along' );

# a row from before the ledger carried rule and watcher
$entry = App::Baphomet::App::Command::ledger::_parse_row('1784067000,sshd,1.2.3.4');
is( $entry->{ip}, '1.2.3.4', 'a old three column row still parses' );
ok( !defined( $entry->{rule} ), 'with out a rule' );

# a quoted watcher carrying a comma
$entry = App::Baphomet::App::Command::ledger::_parse_row('1784067000,sshd,1.2.3.4,syslog/sshd,"auth,log"');
is( $entry->{watcher}, 'auth,log', 'a quoted watcher unquotes' );

# the header and mangled rows are nothing
ok( !defined( App::Baphomet::App::Command::ledger::_parse_row('epoch,kur,ip,rule,watcher') ),
	'the header parses to nothing' );
ok( !defined( App::Baphomet::App::Command::ledger::_parse_row('not a row') ), 'a mangled row parses to nothing' );

#
# the --since spec
#

is( App::Baphomet::App::Command::ledger::_since_epoch('1784067000'), 1784067000, "a bare epoch is it's self" );
my $week_ago = App::Baphomet::App::Command::ledger::_since_epoch('1w');
ok( abs( ( time - 604800 ) - $week_ago ) < 5, 'a relative span counts back from now' );

#
# paring banished down to a IP
#

my $result = {
	'kurs' => {
		'sshd' => {
			'banned'  => [ '1.2.3.4', '5.6.7.8' ],
			'expires' => { '1.2.3.4' => 1784070000, '5.6.7.8' => 1784071000 },
			'pending' => [],
		},
		'web' => {
			'fan_out' => [ 'nginx', 'apache' ],
			'members' => {
				'nginx'  => { 'banned' => ['1.2.3.4'], 'expires' => { '1.2.3.4' => 1784072000 } },
				'apache' => { 'banned' => [],          'expires' => {} },
			},
		},
		'smtp' => {
			'banned'  => [],
			'expires' => {},
			'pending' => ['1.2.3.4'],
		},
		'irc' => {
			'banned'  => [],
			'expires' => {},
			'pending' => [],
		},
	},
};

my $pared = App::Baphomet::App::Command::banished::_pare_to_ip( $result, '1.2.3.4' );
is( $pared->{ip}, '1.2.3.4', 'the IP rides along' );
is( $pared->{kurs}{sshd}{banned},  1,          'held on the real kur' );
is( $pared->{kurs}{sshd}{expires}, 1784070000, 'with its expiry' );
is( $pared->{kurs}{web}{members}{nginx}{banned}, 1, 'held on a fan_out member' );
ok( !defined( $pared->{kurs}{web}{members}{apache} ), 'not on the other member' );
is( $pared->{kurs}{smtp}{pending}, 1, 'pending counts as held' );
ok( !defined( $pared->{kurs}{irc} ), 'a kur not holding it is dropped' );

#
# the lnms-f2b-extend structure builder
#

my $extend = App::Baphomet::App::Command::lnms_f2b_extend::_extend_structure( { 'sshd' => 4, 'smtp' => 1 }, 0, '' );
is( $extend->{data}{total},        5, 'total sums the jails' );
is( $extend->{data}{jails}{sshd},  4, 'the sshd jail count' );
is( $extend->{data}{jails}{smtp},  1, 'the smtp jail count' );
is( $extend->{error},              0, 'no error' );
is( $extend->{errorString},        '', 'and no error string' );
is( $extend->{version},            '1', 'the format version' );

$extend = App::Baphomet::App::Command::lnms_f2b_extend::_extend_structure( {}, 1, 'Ereshkigal is down' );
is( $extend->{data}{total},   0, 'a failed run tallies zero' );
is_deeply( $extend->{data}{jails}, {}, 'with no jails' );
is( $extend->{error},         1, 'the error rides out' );
is( $extend->{errorString},   'Ereshkigal is down', 'and its string' );

#
# the per-jail tallies from the manager's banished answer... pure, no client
#

my %tallies = App::Baphomet::App::Command::lnms_f2b_extend::_tallies_from_banished(
	{
		'kurs' => {
			# a real kur tallies its own banned count
			'sshd' => { 'banned' => [ '1.2.3.4', '5.6.7.8' ], 'expires' => {} },
			# an empty but present real kur is a zero jail
			'smtp' => { 'banned' => [], 'expires' => {} },
			# a fan_out gate tallies the union of its members, an IP on both once
			'web' => {
				'fan_out' => [ 'nginx', 'apache' ],
				'members' => {
					'nginx'  => { 'banned' => [ '1.1.1.1', '2.2.2.2' ] },
					'apache' => { 'banned' => [ '2.2.2.2', '3.3.3.3' ] },
				},
			},
			# a kur the manager could not read still shows as a zero jail
			'broken' => { 'error' => 'no banned list... not running?' },
		},
	}
);
is( $tallies{sshd},   2, 'a real kur tallies its banned count' );
is( $tallies{smtp},   0, 'an empty real kur tallies zero' );
is( $tallies{web},    3, 'a fan_out gate tallies the union of its members' );
is( $tallies{broken}, 0, 'a kur the manager could not read tallies zero' );

# a banished answer with no kurs is simply no jails
my %empty = App::Baphomet::App::Command::lnms_f2b_extend::_tallies_from_banished( { 'kurs' => {} } );
is_deeply( \%empty, {}, 'no kurs, no jails' );

done_testing;
