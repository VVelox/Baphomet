#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp    qw( tempdir );
use File::Path    qw( make_path );
use JSON::MaybeXS qw( decode_json );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();
use App::Baphomet::Rules ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/raw', $dir . '/rules/json', $dir . '/run' );

# a regexp rule captures under its own names, so it has to say which is
# which... the five promoted vars named explicitly
open( my $fh, '>', $dir . '/rules/raw/flow.yaml' ) || die($!);
print $fh <<'EOR';
---
message_regexp:
  - '^conn %%%%SRC%%%%:(?<SPORT>\d+) -> %%%%DEST%%%%:(?<DPORT>\d+) user (?<USER>\S+)$'
ban_var:
  - SRC
src_ip_var: SRC
dest_ip_var: DEST
src_port_var: SPORT
dest_port_var: DPORT
user_var: USER
tests:
  positive:
    - message: "conn 192.0.2.5:4444 -> 198.51.100.9:22 user alice"
      found: 1
      data:
        SRC: "192.0.2.5"
        SPORT: "4444"
        DEST: "198.51.100.9"
        DPORT: "22"
        USER: "alice"
EOR
close($fh);

# a rule naming none of them leans on the defaults, and a raw line carries no
# field called src_ip... every one of the five comes out null
open( $fh, '>', $dir . '/rules/raw/bare.yaml' ) || die($!);
print $fh <<'EOR';
---
message_regexp:
  - '^bare thing from %%%%SRC%%%%$'
ban_var:
  - SRC
tests:
  positive:
    - message: "bare thing from 192.0.2.6"
      found: 1
      data:
        SRC: "192.0.2.6"
EOR
close($fh);

# a JSON schema names the fields the way the defaults expect already, so the
# rule sets nothing and the ports arrive as native integers
open( $fh, '>', $dir . '/rules/json/flow.yaml' ) || die($!);
print $fh <<'EOR';
---
gate:
  - field: event_type
    values: [ alert ]
ban_var:
  - src_ip
tests:
  positive:
    - message: '{"event_type":"alert","src_ip":"203.0.113.8","src_port":51000,"dest_ip":"198.51.100.9","dest_port":443,"user":"bob"}'
      found: 1
      data:
        src_ip: "203.0.113.8"
EOR
close($fh);

foreach my $log ( 'log', 'jlog' ) {
	open( $fh, '>', $dir . '/' . $log ) || die($!);
	close($fh);
}

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
eve_log = "$dir/eve/eve.json"
eve_enable = true
max_score = 10
find_time = 600

[kur.app]
ban_time = 300

[kur.app.w]
log = "$dir/log"
parser = "raw"
rule = [ "raw/flow", "raw/bare" ]

[kur.app.j]
log = "$dir/jlog"
parser = "json"
rule = "json/flow"
EOC
close($fh);

# the events as text as well as decoded... a port has to be a JSON number and
# not the string the capture handed over, which only the raw line can show
sub read_lines {
	my $path = $dir . '/eve/eve.json';
	return () if !-f $path;
	open( my $efh, '<', $path ) || die($!);
	my @lines = <$efh>;
	close($efh);
	return @lines;
}

sub read_events {
	return map { decode_json($_) } read_lines();
}

my $galla = App::Baphomet::Galla->new( 'config' => $dir . '/config.toml', 'name' => 'app' );
ok( !$galla->{perror}, 'galla built' ) || diag( $galla->{errorString} );

#
# a regexp rule naming all five
#

$galla->_handle_line( 'w', 'conn 192.0.2.5:4444 -> 198.51.100.9:22 user alice' );
my ($event) = read_events();
is( $event->{src_ip},    '192.0.2.5',    'src_ip lifted from the named var' );
is( $event->{dest_ip},   '198.51.100.9', 'dest_ip lifted from the named var' );
is( $event->{src_port},  4444,           'src_port lifted from the named var' );
is( $event->{dest_port}, 22,             'dest_port lifted from the named var' );
is( $event->{user},      'alice',        'user lifted from the named var' );

# the capture handed over the string "4444"... it has to reach the log as a
# number, or a dynamic mapping meeting it first makes the field a keyword and
# every range query over the port is lost
my ($line) = read_lines();
like( $line, qr/"src_port":4444[,}]/, 'a captured port is written as a JSON number, not a string' );
like( $line, qr/"dest_port":22[,}]/,  'and so is the other end' );
like( $line, qr/"user":"alice"[,}]/,  'while user stays the string it is' );

#
# a rule naming none of them, on a line carrying none of them... all five are
# still there, so a consumer can lean on the fields being present
#

$galla->_handle_line( 'w', 'bare thing from 192.0.2.6' );
my @events = read_events();
my $bare   = $events[-1];
foreach my $field ( 'src_ip', 'dest_ip', 'src_port', 'dest_port', 'user' ) {
	ok( exists( $bare->{$field} ),   'a rule naming nothing still emits ' . $field );
	ok( !defined( $bare->{$field} ), 'and it is null' );
}

#
# the defaults suit a JSON schema outright... the rule names nothing and every
# one of the five still lands
#

$galla->_handle_line( 'j',
	'{"event_type":"alert","src_ip":"203.0.113.8","src_port":51000,"dest_ip":"198.51.100.9","dest_port":443,"user":"bob"}'
);
@events = read_events();
my $json_event = $events[-1];
is( $json_event->{src_ip},    '203.0.113.8',  'the src_ip default reads a JSON schema untouched' );
is( $json_event->{dest_ip},   '198.51.100.9', 'and dest_ip' );
is( $json_event->{src_port},  51000,          'and src_port' );
is( $json_event->{dest_port}, 443,            'and dest_port' );
is( $json_event->{user},      'bob',          'and user' );

#
# a var pointed at something that is not a port is written as it is rather
# than dropped, so the mistake surfaces instead of hiding
#

is( App::Baphomet::Galla::_eve_port('22'),    22,      'a numeric string becomes a number' );
is( App::Baphomet::Galla::_eve_port(22),      22,      'a number stays one' );
is( App::Baphomet::Galla::_eve_port('imaps'), 'imaps', 'a non-numeric value is written as it is' );
is( App::Baphomet::Galla::_eve_port(undef),   undef,   'and undef stays undef' );

#
# each of the five refuses anything but a non-empty string, at load
#

my $vdir = tempdir( CLEANUP => 1 );
make_path( $vdir . '/raw' );
my $vrules = App::Baphomet::Rules->new( rules_dir => $vdir, shipped => 0 );

foreach my $key ( 'src_ip_var', 'dest_ip_var', 'src_port_var', 'dest_port_var', 'user_var' ) {
	open( my $vfh, '>', $vdir . '/raw/bad.yaml' ) || die($!);
	print $vfh "---\nmessage_regexp:\n  - 'from %%%%SRC%%%%'\nban_var:\n  - SRC\n" . $key . ": ''\n";
	close($vfh);
	ok( !eval { $vrules->load('raw/bad'); 1 }, 'an empty ' . $key . ' refuses to load' );
	like( $@, qr/\Q$key\E/, 'and the error names it' );
}

#
# the shipped regexp rules capture the account as USER, so each of them has to
# say so... the defaults suit the JSON schemas, not a named capture
#

my $rules_dir = 'share/rules';
SKIP: {
	if ( !-d $rules_dir ) {
		skip( 'no rules dir found... not running from the dist root?', 1 );
	}
	my @unnamed;
	foreach my $path ( glob( $rules_dir . '/*/*.yaml' ) ) {
		open( my $rfh, '<', $path ) || die($!);
		my $body = do { local $/; <$rfh> };
		close($rfh);
		if ( $body =~ /\(\?<USER>/ && $body !~ /^user_var:/m ) {
			push( @unnamed, $path );
		}
	}
	is_deeply( \@unnamed, [], 'every shipped rule capturing USER names it as its user_var' );

	#
	# and the same for the address... the SRC token only ever matches an
	# address, so a rule capturing it has an offender to promote
	#
	my @unpromoted;
	foreach my $path ( glob( $rules_dir . '/*/*.yaml' ) ) {
		open( my $rfh, '<', $path ) || die($!);
		my $body = do { local $/; <$rfh> };
		close($rfh);
		if ( $body =~ /%%%%SRC%%%%|\(\?<SRC>/ && $body !~ /^src_ip_var:/m ) {
			push( @unpromoted, $path );
		}
	}
	is_deeply( \@unpromoted, [], 'every shipped rule capturing SRC names it as its src_ip_var' );
} ## end SKIP:

#
# the whole chain over a shipped rule... the sshd rule captures no account of
# its own, so .user can only come from the munger, and the port has no other
# source at all. this is the enrichment actually reaching the log rather than
# the wiring being merely well formed
#

SKIP: {
	if ( !-d 'share/rules' ) {
		skip( 'no rules dir found... not running from the dist root?', 4 );
	}
	if ( !eval { require Log::Munger; 1 } ) {
		skip( 'Log::Munger not available', 4 );
	}

	my $shipped = tempdir( CLEANUP => 1 );
	make_path( $shipped . '/run' );
	open( my $sfh, '>', $shipped . '/log' ) || die($!);
	close($sfh);

	open( $sfh, '>', $shipped . '/config.toml' ) || die($!);
	print $sfh <<"EOC";
run_base_dir = "$shipped/run"
tablet_base_dir = "$shipped/cache"
rules_dir = "share/rules"
ereshkigal_socket = "$shipped/nonexistent.sock"
eve_log = "$shipped/eve/eve.json"
eve_enable = true
max_score = 10
find_time = 600

[kur.app]
ban_time = 300

[kur.app.w]
log = "$shipped/log"
parser = "bsd_syslog"
rule = "syslog/sshd"
EOC
	close($sfh);

	my $shipped_galla = App::Baphomet::Galla->new( 'config' => $shipped . '/config.toml', 'name' => 'app' );
	if ( $shipped_galla->{perror} ) {
		skip( 'the shipped galla would not build... ' . $shipped_galla->{errorString}, 4 );
	}

	$shipped_galla->_handle_line( 'w',
		'Jul 12 08:15:50 gate sshd[2278]: Failed password for invalid user admin from 192.0.2.7 port 4711 ssh2' );

	open( my $efh, '<', $shipped . '/eve/eve.json' ) || die($!);
	my @shipped_lines = <$efh>;
	close($efh);

	my $shipped_event = decode_json( $shipped_lines[0] );
	is( $shipped_event->{src_ip},   '192.0.2.7', 'the shipped sshd rule promotes its own SRC capture' );
	is( $shipped_event->{src_port}, 4711,        'and the port, which only the munger holds' );
	is( $shipped_event->{user},     'admin',     'and the account, which the rule itself never captures' );
	like( $shipped_lines[0], qr/"src_port":4711[,}]/, 'the munger port reaches the log as a JSON number' );
} ## end SKIP:

done_testing;
