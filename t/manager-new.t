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

# _authorize is a no-op when auth is off
write_config('');
my $plain = App::Baphomet->new( 'config' => $dir . '/config.toml' );
is( $plain->{enable_auth}, 0, 'enable_auth defaults off' );
ok( eval { $plain->_authorize( FakeCtx->new( 1000, 'nobody' ) ); 1 }, 'auth off... anyone passes' );

# with auth on... UID 0 always passes, a listed user passes, others are refused
ok( eval { $authed->_authorize( FakeCtx->new( 0,    'root' ) );   1 }, 'UID 0 passes the Neti gate' );
ok( eval { $authed->_authorize( FakeCtx->new( 1001, 'alice' ) );  1 }, 'a authed user passes' );
ok( !eval { $authed->_authorize( FakeCtx->new( 1002, 'mallory' ) ); 1 }, 'an unlisted user is refused' );
like( $@, qr/Neti gate/, 'refusal names the Neti gate' );

# a bad authed list is a config error
write_config( '', "enable_auth = true\nauthed_users = \"notanarray\"" );
ok( !eval { App::Baphomet->new( 'config' => $dir . '/config.toml' ); 1 }, 'a non-array authed_users is a error' );

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

# a stand in for the JSONUnix auth context, giving _authorize a uid and username
package FakeCtx;

sub new {
	my ( $class, $uid, $username ) = @_;
	return bless { uid => $uid, username => $username }, $class;
}
sub uid      { return $_[0]->{uid} }
sub username { return $_[0]->{username} }
