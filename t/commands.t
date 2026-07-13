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

use App::Baphomet::App::Command::ledger    ();
use App::Baphomet::App::Command::consigned ();

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
# paring consigned down to a IP
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

my $pared = App::Baphomet::App::Command::consigned::_pare_to_ip( $result, '1.2.3.4' );
is( $pared->{ip}, '1.2.3.4', 'the IP rides along' );
is( $pared->{kurs}{sshd}{banned},  1,          'held on the real kur' );
is( $pared->{kurs}{sshd}{expires}, 1784070000, 'with its expiry' );
is( $pared->{kurs}{web}{members}{nginx}{banned}, 1, 'held on a fan_out member' );
ok( !defined( $pared->{kurs}{web}{members}{apache} ), 'not on the other member' );
is( $pared->{kurs}{smtp}{pending}, 1, 'pending counts as held' );
ok( !defined( $pared->{kurs}{irc} ), 'a kur not holding it is dropped' );

done_testing;
