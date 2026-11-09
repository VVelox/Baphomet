#!perl
# the manager's own status handlers... status reports every galla, and
# status_galla one by name, both with the same running/pid/restarts/enabled
# view of it. the gallas are never spawned, so every one reads as not
# running and status_galla answers without asking a socket anything
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run' );

open( my $fh, '>', $dir . '/rules/syslog/sshd.yaml' ) || die($!);
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
    - message: "Jul 12 08:15:50 mail01 sshd[1]: bad thing from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
EOR
close($fh);

my $group = getgrgid( ( split( /\s+/, $) ) )[0] );
open( my $config_fh, '>', $dir . '/config.toml' ) || die($!);
print $config_fh <<"EOC";
run_base_dir = "$dir/run"
rules_dir = "$dir/rules"
socket_group = "$group"

[kur.one]
ban_time = 300

[kur.one.authlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"

[kur.two]
ban_time = 300

[kur.two.authlog]
log = "$dir/log2"
parser = "bsd_syslog"
rule = "syslog/sshd"
EOC
close($config_fh);

my $baphomet = App::Baphomet->new( 'config' => $dir . '/config.toml' );
ok( defined($baphomet), 'manager built' );

# start_server stamps this, and the server is never started here
$baphomet->{started} = time - 5;

my @galla_names = sort( keys( %{ $baphomet->{gallas} } ) );
is( scalar(@galla_names), 2, 'one galla per kur' );

my $idle = { 'running' => 0, 'pid' => undef, 'restarts' => 0, 'enabled' => 1 };

#
# status, every galla at once
#
my $status = $baphomet->_cmd_status;
is( $status->{pid},    $$,                    'status carries the manager PID' );
is( $status->{config}, $dir . '/config.toml', 'status carries the config path' );
ok( $status->{uptime} >= 5 && $status->{uptime} < 60, 'status carries the uptime since start' );
is_deeply( [ sort( keys( %{ $status->{gallas} } ) ) ], \@galla_names, 'status lists every galla' );
foreach my $name (@galla_names) {
	is_deeply( $status->{gallas}{$name}, $idle, 'status reports galla "' . $name . '" as idle' );
}

#
# status_galla, one galla by name
#
my $one = $baphomet->_cmd_status_galla( { 'args' => { 'name' => $galla_names[0] } }, undef );
is_deeply( $one, { 'name' => $galla_names[0], %{$idle} }, 'status_galla reports the galla named, without asking it' );

# the counters are read live, not cached at build time
$baphomet->{gallas}{ $galla_names[1] }{restarts} = 3;
$baphomet->{gallas}{ $galla_names[1] }{enabled}  = 0;
is_deeply(
	$baphomet->_cmd_status->{gallas}{ $galla_names[1] },
	{ %{$idle}, 'restarts' => 3, 'enabled' => 0 },
	'status reads restarts and enabled as they stand'
);
is_deeply(
	$baphomet->_cmd_status_galla( { 'args' => { 'name' => $galla_names[1] } }, undef ),
	{ 'name' => $galla_names[1], %{$idle}, 'restarts' => 3, 'enabled' => 0 },
	'status_galla reads them the same way'
);

eval { $baphomet->_cmd_status_galla( { 'args' => { 'name' => 'nope' } }, undef ); };
like( $@, qr/No such galla, "nope"/, 'status_galla refuses a unknown galla' );

eval { $baphomet->_cmd_status_galla( { 'args' => {} }, undef ); };
like( $@, qr/args\.name must be the name of a galla/, 'status_galla requires a name' );

done_testing;
