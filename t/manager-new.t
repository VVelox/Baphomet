#!perl
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
make_path( $dir . '/rules/syslog' );
make_path( $dir . '/run' );

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
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
EOR
close($fh);

# the group of the current user, so socket_group resolves with out root
my $group = getgrgid( ( split( /\s+/, $) ) )[0] );

sub write_config {
	my ( $extra, $toplevel ) = @_;
	$toplevel = '' if !defined($toplevel);
	open( my $config_fh, '>', $dir . '/config.toml' ) || die($!);
	print $config_fh <<"EOC";
run_base_dir = "$dir/run"
rules_dir = "$dir/rules"
socket_group = "$group"
$toplevel

[kur.sshd]
ban_time = 300

[kur.sshd.authlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"
$extra
EOC
	close($config_fh);
	return;
} ## end sub write_config

write_config('');

my $baphomet = App::Baphomet->new( 'config' => $dir . '/config.toml' );
ok( defined($baphomet), 'new worked' );
is( $baphomet->socket_path, $dir . '/run/socket', 'socket_path' );
is( $baphomet->pid_path,    $dir . '/run/pid',    'pid_path' );
is( $baphomet->galla_socket_path('sshd'), $dir . '/run/galla/sshd.sock', 'galla_socket_path' );
ok( -d $dir . '/run/galla', 'run galla dir created' );
ok( defined( $baphomet->{gallas}{sshd} ), 'galla registered for the kur' );
ok( defined( $baphomet->{socket_gid} ),   'socket group resolved' );

my @cmd = $baphomet->_build_galla_cmd('sshd');
is_deeply(
	\@cmd,
	[ 'galla', '--foreground', '--name', 'sshd', '--config', $dir . '/config.toml' ],
	'galla cmd built as expected'
);

# no config at all
ok( !eval { App::Baphomet->new( 'config' => $dir . '/nonexistent.toml' ); 1 }, 'new dies on a missing config' );

# a kur missing its rule
write_config( "\n[kur.sshd.badwatcher]\nlog = \"$dir/log\"\nparser = \"bsd_syslog\"\nrule = \"syslog/missing\"\n" );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'new dies on a missing rule' );
like( $@, qr/missing/, 'error mentions the rule' );

# a kur with a unknown parser
write_config( "\n[kur.sshd.badwatcher]\nlog = \"$dir/log\"\nparser = \"cuneiform\"\nrule = \"syslog/sshd\"\n" );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'new dies on a unknown parser' );

# a kur with no watchers
write_config("\n[kur.empty]\nban_time = 300\n");
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'new dies on a watcherless kur' );

# a watcher with a log array and a glob passes validation
write_config(
	"\n[kur.sshd.globwatcher]\nlog = [ \"$dir/log\", \"$dir/jails/*/auth.log\" ]\nparser = \"bsd_syslog\"\nrule = \"syslog/sshd\"\n"
);
ok( eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'log arrays with globs check out' )
	|| diag($@);

# but a empty log array does not
write_config("\n[kur.sshd.badwatcher]\nlog = [ ]\nparser = \"bsd_syslog\"\nrule = \"syslog/sshd\"\n");
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'new dies on a empty log array' );

#
# the Neti gate... auth config
#

write_config( '', "enable_auth = true\nauthed_users = [ \"alice\" ]\nauthed_groups = [ \"wheel\" ]" );
my $authed = App::Baphomet->new( 'config' => $dir . '/config.toml' );
is( $authed->{enable_auth}, 1, 'enable_auth read as 1' );
is_deeply( $authed->{authed_users},  ['alice'], 'authed_users read' );
is_deeply( $authed->{authed_groups}, ['wheel'], 'authed_groups read' );

# the Neti gate is now a JSONUnix permission policy... no policy when auth is
# off, so the manager spawns as it always did
write_config('');
my $plain = App::Baphomet->new( 'config' => $dir . '/config.toml' );
is( $plain->{enable_auth}, 0, 'enable_auth defaults off' );
is( $plain->_neti_permissions, undef, 'auth off... no permission policy' );

# with auth on... a single %DEFAULT% rule denying by default and allowing UID
# 0 (root), the authed users, and the authed groups. JSONUnix does the actual
# membership resolution and enforcement, tested in its own dist
my $policy = $authed->_neti_permissions;
is( $policy->{default}, 'deny', 'the policy denies by default' );
is_deeply(
	$policy->{commands}{'%DEFAULT%'},
	{ 'users' => [ 0, 'alice' ], 'groups' => ['wheel'] },
	'the %DEFAULT% rule allows root, the authed users, and the authed groups'
);

# a bad authed list is a config error
write_config( '', "enable_auth = true\nauthed_users = \"notanarray\"" );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'a non-array authed_users is a error' );

#
# command_perms... per command rules laid over the baseline
#

my $perms_toplevel = <<'EOT';
enable_auth = true
authed_users = [ "nanni" ]
authed_groups = [ "ops" ]

[command_perms]
default = "deny"

[command_perms.commands.status]
users = [ "nanni" ]

[command_perms.commands.stop]
users = [ "nanni" ]
groups = [ "ops" ]
deny_users = [ "ea-nasir" ]

[command_perms.commands.watching]
deny_users = [ "ea-nasir" ]
EOT
write_config( '', $perms_toplevel );
my $cperms = App::Baphomet->new( 'config' => $dir . '/config.toml' );
ok( defined($cperms), 'a config with command_perms builds' ) || diag($@);
my $cpolicy = $cperms->_neti_permissions;

is( $cpolicy->{default}, 'deny', 'command_perms carries the default verdict through' );
is_deeply(
	$cpolicy->{commands}{'%DEFAULT%'},
	{ 'users' => [ 0, 'nanni' ], 'groups' => ['ops'] },
	'the %DEFAULT% baseline still allows root, authed users, and authed groups'
);
is_deeply(
	$cpolicy->{commands}{status},
	{ 'users' => [ 0, 'nanni' ] },
	'a per-command allow-list gets root threaded in beside nanni'
);
is_deeply(
	$cpolicy->{commands}{stop},
	{ 'users' => [ 0, 'nanni' ], 'groups' => ['ops'], 'deny_users' => ['ea-nasir'] },
	'stop allows root, nanni, and ops, and turns ea-nasir away'
);
is_deeply(
	$cpolicy->{commands}{watching},
	{ 'deny_users' => ['ea-nasir'] },
	'a deny-only rule is left as written, no root threaded in, so it still falls through'
);

# the default verdict may open up, and a whole command may be a bare
# allow/deny shorthand
write_config( '',
	"enable_auth = true\n\n[command_perms]\ndefault = \"allow\"\n\n[command_perms.commands]\nstatus = \"allow\"\nstop = \"deny\"\n"
);
my $cshort  = App::Baphomet->new( 'config' => $dir . '/config.toml' );
my $spolicy = $cshort->_neti_permissions;
is( $spolicy->{default},           'allow', 'command_perms default may be allow' );
is( $spolicy->{commands}{status},  'allow', 'a bare allow shorthand rides through' );
is( $spolicy->{commands}{stop},    'deny',  'a bare deny shorthand rides through' );
ok( defined( $spolicy->{commands}{'%DEFAULT%'} ), 'the baseline rule is still present alongside the shorthands' );

# command_perms is validated even with auth off, but yields no policy then
write_config( '', "enable_auth = false\n\n[command_perms]\ndefault = \"deny\"\n\n[command_perms.commands.status]\nusers = [ \"nanni\" ]\n" );
my $coff = App::Baphomet->new( 'config' => $dir . '/config.toml' );
ok( defined($coff), 'command_perms validates with auth off' ) || diag($@);
is( $coff->_neti_permissions, undef, 'auth off... command_perms yields no policy' );

# command_perms config errors
write_config( '', "enable_auth = true\n\n[command_perms.commands.frobnicate]\nusers = [ \"nanni\" ]\n" );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'a rule naming an unknown command is a error' );

write_config( '', "enable_auth = true\n\n[command_perms]\ndefault = \"maybe\"\n" );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'a default that is not allow/deny is a error' );

write_config( '', "enable_auth = true\n\n[command_perms.commands.stop]\nfolks = [ \"nanni\" ]\n" );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'an unknown rule key is a error' );

write_config( '', "enable_auth = true\n\n[command_perms.commands.stop]\nusers = \"nanni\"\n" );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'a non-array rule list is a error' );

write_config( '', "enable_auth = true\n\n[command_perms.commands]\nstop = 5\n" );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'a rule that is neither string nor table is a error' );

#
# banished... the manager now gathers who Kur holds, so the CLI rides the
# one socket. the kur set it answers over is testable without a live Ereshkigal
#

ok( App::Baphomet::Config::known_command('banished'), 'banished is a nameable, gateable command' );

write_config( '', "[recidive]\nkur = \"recidive\"" );
my $withrec = App::Baphomet->new( 'config' => $dir . '/config.toml' );
ok( defined($withrec), 'a manager with a recidive kur builds' ) || diag($@);

# the watched kurs plus the recidive kur, which has no galla of it's own
is_deeply(
	[ sort( $withrec->_banished_kurs( {} ) ) ],
	[ 'recidive', 'sshd' ],
	'the fed kurs are the watched ones plus the recidive kur'
);

# a name narrows to the one kur
is_deeply( [ $withrec->_banished_kurs( { 'args' => { 'name' => 'sshd' } } ) ], ['sshd'], 'a name narrows the set' );
is_deeply(
	[ $withrec->_banished_kurs( { 'args' => { 'name' => 'recidive' } } ) ],
	['recidive'],
	'the recidive kur may be named too'
);

# a name that is not one this Baphomet feeds is refused
ok(
	!eval { $withrec->_banished_kurs( { 'args' => { 'name' => 'nope' } } ); 1 },
	'a kur this Baphomet does not feed is refused'
);

# with no recidive, just the watched kurs
write_config('');
my $norec = App::Baphomet->new( 'config' => $dir . '/config.toml' );
is_deeply( [ $norec->_banished_kurs( {} ) ], ['sshd'], 'no recidive, just the watched kurs' );

#
# socket_mode / socket_group
#

write_config( '', 'socket_mode = "0640"' );
ok( eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'a valid socket_mode checks out' ) || diag($@);

write_config( '', 'socket_mode = "garbage"' );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'a non-octal socket_mode is a error' );

write_config( '', 'socket_mode = "999"' );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'a non-octal-digit socket_mode is a error' );

done_testing;
