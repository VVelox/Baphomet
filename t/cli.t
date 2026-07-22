#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );

BEGIN {
	eval { require App::Cmd::Tester; require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'App::Cmd::Tester or Ereshkigal::Client not available';
	}
}

use App::Baphomet::App ();
use JSON::MaybeXS      ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog' );

open( my $fh, '>', $dir . '/rules/syslog/good.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
EOR
close($fh);

open( $fh, '>', $dir . '/rules/syslog/bad.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: something else"
      found: 1
EOR
close($fh);

#
# commands list
#

my $result = App::Cmd::Tester->test_app( 'App::Baphomet::App', ['commands'] );
is( $result->exit_code, 0, 'commands exits 0' );
foreach my $command (
	'start',    'stop',     'status', 'check_rules',
	'test_line', 'accused', 'banished', 'ledger', 'lnms-f2b-extend'
	)
{
	like( $result->stdout, qr/$command/, 'commands lists ' . $command );
}

#
# check_rules
#

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App',
	[ 'check_rules', '--rules-dir', $dir . '/rules', 'syslog/good' ] );
is( $result->exit_code, 0, 'check_rules on a good rule exits 0' );
like( $result->stdout, qr/syslog\/good \.\.\. ok/, 'check_rules reports the good rule ok' );

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App', [ 'check_rules', '--rules-dir', $dir . '/rules' ] );
isnt( $result->exit_code, 0, 'check_rules with a bad rule present exits non-zero' );
like( $result->stdout, qr/syslog\/good \.\.\. ok/, 'the good rule still reported ok' );
like( $result->stdout, qr/syslog\/bad \.\.\. /,    'the bad rule reported' );

#
# test_line
#

$result = App::Cmd::Tester->test_app(
	'App::Baphomet::App',
	[
		'test_line',           '--rules-dir', $dir . '/rules', '--rule',
		'syslog/good',         'Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4'
	]
);
is( $result->exit_code, 0, 'test_line on a matching line exits 0' );
like( $result->stdout, qr/"found"\s*:\s*1/,         'test_line reports found' );
like( $result->stdout, qr/"SRC"\s*:\s*"1\.2\.3\.4"/, 'test_line reports the capture' );

$result = App::Cmd::Tester->test_app(
	'App::Baphomet::App',
	[
		'test_line',   '--rules-dir', $dir . '/rules', '--rule',
		'syslog/good', 'Jul 12 08:15:50 vixen42 sshd[1]: nothing of note'
	]
);
is( $result->exit_code, 0, 'test_line on a non-matching line exits 0' );
like( $result->stdout, qr/"found"\s*:\s*0/, 'test_line reports not found' );

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App',
	[ 'test_line', '--rules-dir', $dir . '/rules', '--rule', 'syslog/good', 'complete garbage' ] );
isnt( $result->exit_code, 0, 'test_line on a unparsable line exits non-zero' );

#
# ledger... read straight from the file, no manager needed
#

make_path( $dir . '/tablets' );
open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
tablet_base_dir = "$dir/tablets"
rules_dir = "$dir/rules"
EOC
close($fh);

my $now = time;
open( $fh, '>', $dir . '/tablets/banishments.csv' ) || die($!);
print $fh "epoch,kur,ip,rule,watcher\n";
print $fh ( $now - 172800 ) . ",sshd,1.2.3.4,syslog/good,authlog\n";
print $fh ( $now - 60 ) . ",sshd,1.2.3.4,syslog/good,authlog\n";
print $fh ( $now - 30 ) . ",smtp,5.6.7.8,syslog/good,maillog\n";
close($fh);

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App', [ 'ledger', '--config', $dir . '/config.toml' ] );
is( $result->exit_code, 0, 'ledger exits 0' );
like( $result->stdout, qr/"1\.2\.3\.4"/, 'ledger carries the first IP' );
like( $result->stdout, qr/"5\.6\.7\.8"/, 'ledger carries the second IP' );

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App',
	[ 'ledger', '--config', $dir . '/config.toml', '--ip', '5.6.7.8' ] );
unlike( $result->stdout, qr/"1\.2\.3\.4"/, '--ip drops the other IP' );
like( $result->stdout, qr/"5\.6\.7\.8"/, 'and keeps the named one' );

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App',
	[ 'ledger', '--config', $dir . '/config.toml', 'smtp' ] );
unlike( $result->stdout, qr/"sshd"/, 'a kur arg drops the other kurs' );

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App',
	[ 'ledger', '--config', $dir . '/config.toml', '--since', '1d' ] );
my $decoded = JSON::MaybeXS::decode_json( $result->stdout );
is( scalar( @{ $decoded->{entries} } ), 2, '--since drops the old entry and keeps the fresh' );

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App',
	[ 'ledger', '--config', $dir . '/config.toml', '--tail', '1' ] );
$decoded = JSON::MaybeXS::decode_json( $result->stdout );
is( scalar( @{ $decoded->{entries} } ), 1,         '--tail keeps just the last' );
is( $decoded->{entries}[0]{ip},         '5.6.7.8', 'and it is the newest' );

#
# lnms-f2b-extend... the manager is not up here, so the error path is
# exercised, but the emitted shape and its -b compression still hold. it
# rides the manager socket now, not Ereshkigal, so a dead --socket stands in
#

require IO::Uncompress::Gunzip;
require MIME::Base64;

my @dead_socket = ( '--socket', $dir . '/nope.sock' );

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App', [ @dead_socket, 'lnms-f2b-extend' ] );
is( $result->exit_code, 0, 'lnms-f2b-extend exits 0 even with the manager down' );
my $extend = JSON::MaybeXS::decode_json( $result->stdout );
is( $extend->{version},     '1', 'the extend format version' );
is( $extend->{error},       1,   'a down manager is a non-zero error' );
like( $extend->{errorString}, qr/manager/, 'and the error string names it' );
is_deeply( $extend->{data}, { 'total' => 0, 'jails' => {} }, 'with an empty jail set' );

$result = App::Cmd::Tester->test_app( 'App::Baphomet::App', [ @dead_socket, 'lnms-f2b-extend', '-b' ] );
is( $result->exit_code, 0, 'lnms-f2b-extend -b exits 0' );
like( $result->stdout, qr/^[A-Za-z0-9+\/=]+\n\z/, '-b emits one line of Base64' );
my $raw       = MIME::Base64::decode_base64( $result->stdout );
my $inflated  = '';
IO::Uncompress::Gunzip::gunzip( \$raw => \$inflated ) || die( 'gunzip failed' );
my $roundtrip = JSON::MaybeXS::decode_json($inflated);
is_deeply( $roundtrip, $extend, '-b GZip+Base64 round-trips to the same structure' );

done_testing;
