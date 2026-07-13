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

use App::Baphomet::Galla  ();
use App::Baphomet::Config qw( check_kur_def watcher_journal );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run', $dir . '/cache' );

open( my $fh, '>', $dir . '/rules/syslog/sshd.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
message_regexp:
  - 'Invalid user \S+ from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: Invalid user x from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
EOR
close($fh);

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
cache_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
journalctl_bin = "$dir/fake-journalctl"

[kur.sshd]
ban_time = 300

[kur.sshd.journal]
journal = [ "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session" ]
rule = "syslog/sshd"
EOC
close($fh);

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );
ok( defined($galla), 'galla with a journal watcher built' );
ok( $galla->{watchers}{journal}{is_journal}, 'the watcher is a journal one' );
is( $galla->{watchers}{journal}{parser}, 'journal', 'parser defaults to journal for a journal watcher' );
is_deeply(
	$galla->{watchers}{journal}{journal_matches},
	[ 'SYSLOG_IDENTIFIER=sshd', 'SYSLOG_IDENTIFIER=sshd-session' ],
	'journal matches captured'
);

# the journalctl command, fresh start... follow, json, lines 0, then matches
my @cmd = $galla->_journal_cmd('journal');
is_deeply(
	\@cmd,
	[
		$dir . '/fake-journalctl', '--follow', '--output', 'json', '--lines', '0',
		'SYSLOG_IDENTIFIER=sshd', 'SYSLOG_IDENTIFIER=sshd-session'
	],
	'fresh journalctl command'
);

# with a saved cursor... resume after it, no --lines
$galla->{journal_cursors}{journal} = 's=abc;i=1';
@cmd = $galla->_journal_cmd('journal');
is( $cmd[4], '--after-cursor', 'resume uses --after-cursor' );
is( $cmd[5], 's=abc;i=1',      'with the saved cursor' );
ok( !( grep { $_ eq '--lines' } @cmd ), 'no --lines when resuming' );

# feeding a journal line the normal way bans and stashes the cursor
my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}
# the stdout handler pulls the cursor... exercise the same extraction
my $jline
	= '{"__CURSOR":"s=xyz;i=9;b=2;m=3;t=4;x=5","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Invalid user bob from 9.9.9.9 port 1"}';
if ( $jline =~ /"__CURSOR"\s*:\s*"((?:[^"\\]|\\.)*)"/ ) {
	$galla->{journal_cursors}{journal} = $1;
}
$galla->_handle_line( 'journal', $jline );
is( $galla->{journal_cursors}{journal}, 's=xyz;i=9;b=2;m=3;t=4;x=5', 'cursor stashed from the line' );
is( $galla->{stats}{matched}, 1, 'the journal line matched the sshd rule' );

# the cursor survives a checkpoint and restore
$galla->checkpoint;
ok( -f $dir . '/cache/galla.sshd.cursors.csv', 'cursors tablet written' );
my $reborn = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );
is( $reborn->{journal_cursors}{journal}, 's=xyz;i=9;b=2;m=3;t=4;x=5', 'cursor restored on a fresh galla' );
like( join( ' ', $reborn->_journal_cmd('journal') ), qr/--after-cursor/, 'the reborn galla resumes from it' );

#
# config validation
#

my $good = { 'j' => { 'journal' => [ 'SYSLOG_IDENTIFIER=sshd' ], 'rule' => 'syslog/sshd' } };
ok( eval { check_kur_def( 'sshd', $good ); 1 }, 'journal watcher validates' ) || diag($@);

my $both = { 'j' => { 'journal' => ['X=y'], 'log' => '/var/log/x', 'rule' => 'syslog/sshd' } };
ok( !eval { check_kur_def( 'sshd', $both ); 1 }, 'log and journal together is a error' );

my $neither = { 'j' => { 'rule' => 'syslog/sshd' } };
ok( !eval { check_kur_def( 'sshd', $neither ); 1 }, 'neither log nor journal is a error' );

# a http rule can not pair with the journal (journal is a syslog parser)
my $mismatch = { 'j' => { 'journal' => ['X=y'], 'rule' => 'http/badbots' } };
ok( !eval { check_kur_def( 'sshd', $mismatch ); 1 }, 'a non-syslog rule on the journal is a error' );

done_testing;
