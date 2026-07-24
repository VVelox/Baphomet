#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp            qw( tempdir );
use File::Path            qw( make_path );
use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();

my $rules_dir = tempdir( CLEANUP => 1 );
make_path( $rules_dir . '/raw' );
make_path( $rules_dir . '/syslog' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $rules_dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

sub syslog_line {
	my ($line) = @_;
	return App::Baphomet::Parser::parse( 'bsd_syslog', $line );
}

sub raw_line {
	my ($line) = @_;
	return App::Baphomet::Parser::parse( 'raw', $line );
}

#
# the brute-force-that-worked shape... counted failures, then the success
#

write_rule( 'syslog/worked', <<'EOR' );
---
daemons:
  - sshd
stages:
  - message_regexp:
      - '^Failed password for (?<USER>\S+) from %%%%SRC%%%%'
    count: 2
  - message_regexp:
      - '^Accepted \w+ for \S+ from %%%%SRC%%%%'
per: [ SRC ]
ban_var:
  - SRC
tests:
  positive:
    - messages:
        - "Jul 12 08:15:50 host sshd[100]: Failed password for root from 192.0.2.5 port 1 ssh2"
        - "Jul 12 08:15:51 host sshd[101]: Failed password for root from 192.0.2.5 port 2 ssh2"
        - "Jul 12 08:15:52 host sshd[102]: Accepted password for root from 192.0.2.5 port 3 ssh2"
      found: 1
      data:
        SRC: "192.0.2.5"
        USER: "root"
  negative:
    # one failure is a typo, not a break-in
    - messages:
        - "Jul 12 08:15:50 host sshd[100]: Failed password for root from 192.0.2.6 port 1 ssh2"
        - "Jul 12 08:15:52 host sshd[102]: Accepted password for root from 192.0.2.6 port 3 ssh2"
      found: 0
    # a success with no failures at all
    - message: "Jul 12 08:15:52 host sshd[102]: Accepted password for root from 192.0.2.7 port 3 ssh2"
      found: 0
    # another source's success does not complete this source's failures
    - messages:
        - "Jul 12 08:15:50 host sshd[100]: Failed password for root from 192.0.2.8 port 1 ssh2"
        - "Jul 12 08:15:51 host sshd[101]: Failed password for root from 192.0.2.8 port 2 ssh2"
        - "Jul 12 08:15:52 host sshd[102]: Accepted password for root from 192.0.2.9 port 3 ssh2"
      found: 0
EOR

my $rules  = App::Baphomet::Rules->new( rules_dir => $rules_dir, shipped => 0 );
my $worked = $rules->load('syslog/worked');
ok( defined($worked), 'staged rule loaded, embedded sequence tests passed' );

my $seq = 0;

sub ctx {
	my ($source) = @_;
	return { 'seq' => ++$seq, 'source' => defined($source) ? $source : '' };
}

# interleaved keys advance their own slots only
my $found;
$worked->check( syslog_line('Jul 12 08:15:50 host sshd[1]: Failed password for a from 192.0.2.10 port 1 ssh2'),
	's', ctx() );
$worked->check( syslog_line('Jul 12 08:15:50 host sshd[2]: Failed password for b from 192.0.2.11 port 1 ssh2'),
	's', ctx() );
$worked->check( syslog_line('Jul 12 08:15:51 host sshd[3]: Failed password for a from 192.0.2.10 port 2 ssh2'),
	's', ctx() );
$found
	= $worked->check( syslog_line('Jul 12 08:15:52 host sshd[4]: Accepted password for a from 192.0.2.10 port 3 ssh2'),
		's', ctx() );
ok( defined($found), 'the completed source fired' );
is( $found->{data}{SRC},             '192.0.2.10', 'with its own address' );
is( $found->{data}{USER},            'a',          'and the captures merged from the failure stage' );
is( scalar( @{ $found->{stages} } ), 3,            'the found carries all three stage hits' );
is( $found->{stages}[0]{stage},      0,            'the first hit is stage zero' );
$found
	= $worked->check( syslog_line('Jul 12 08:15:53 host sshd[5]: Accepted password for b from 192.0.2.11 port 3 ssh2'),
		's', ctx() );
ok( !defined($found), 'the one-failure source did not fire on its success' );

# extra first-stage hits mid-sequence never trample a sequence in flight
$worked->check( syslog_line('Jul 12 08:16:00 host sshd[6]: Failed password for c from 192.0.2.12 port 1 ssh2'),
	's', ctx() );
$worked->check( syslog_line('Jul 12 08:16:01 host sshd[7]: Failed password for c from 192.0.2.12 port 2 ssh2'),
	's', ctx() );
$worked->check( syslog_line('Jul 12 08:16:02 host sshd[8]: Failed password for c from 192.0.2.12 port 3 ssh2'),
	's', ctx() );
$found
	= $worked->check( syslog_line('Jul 12 08:16:03 host sshd[9]: Accepted password for c from 192.0.2.12 port 4 ssh2'),
		's', ctx() );
ok( defined($found), 'failures past the count did not reset the sequence' );

# scope isolation
$worked->check( syslog_line('Jul 12 08:16:10 host sshd[10]: Failed password for d from 192.0.2.13 port 1 ssh2'),
	's', ctx() );
$worked->check( syslog_line('Jul 12 08:16:11 host sshd[11]: Failed password for d from 192.0.2.13 port 2 ssh2'),
	's', ctx() );
$found
	= $worked->check( syslog_line('Jul 12 08:16:12 host sshd[12]: Accepted password for d from 192.0.2.13 port 3 ssh2'),
		'other-scope', ctx() );
ok( !defined($found), 'another scope knows nothing of the sequence' );

#
# within... a stale sequence dies, and the killing line may head a new one
#

write_rule( 'raw/timed', <<'EOR' );
---
stages:
  - message_regexp:
      - '^open (?<KEY>\S+)'
  - message_regexp:
      - '^boom (?<KEY>\S+) from %%%%SRC%%%%'
    within: 60
per: [ KEY ]
ban_var:
  - SRC
tests:
  positive:
    - messages:
        - "open k1"
        - "boom k1 from 192.0.2.20"
      found: 1
      data:
        SRC: "192.0.2.20"
EOR
my $timed = $rules->load('raw/timed');
ok( defined($timed), 'within rule loaded' );

$timed->check( raw_line('open k2'), 't', ctx() );
$timed->{stage_state}{t}{k2}{last_time} = time - 120;
$found = $timed->check( raw_line('boom k2 from 192.0.2.21'), 't', ctx() );
ok( !defined($found),                         'a hit past within did not fire' );
ok( !defined( $timed->{stage_state}{t}{k2} ), 'and the stale sequence is dead' );
$timed->check( raw_line('open k2'), 't', ctx() );
$found = $timed->check( raw_line('boom k2 from 192.0.2.21'), 't', ctx() );
ok( defined($found), 'a fresh sequence fires normally after the reset' );

# a slot past its expires is dead at read, even before any sweep... the
# same judged-at-read rule the context and pending stores follow
$timed->check( raw_line('open k3'), 't', ctx() );
$timed->{stage_state}{t}{k3}{expires} = time - 1;
$found = $timed->check( raw_line('boom k3 from 192.0.2.22'), 't', ctx() );
ok( !defined($found),                         'a hit on an expired slot did not fire' );
ok( !defined( $timed->{stage_state}{t}{k3} ), 'and the expired slot is dropped' );

#
# skip... too many intervening lines kills the sequence
#

write_rule( 'raw/near', <<'EOR' );
---
stages:
  - message_regexp:
      - '^head (?<KEY>\S+)'
  - message_regexp:
      - '^tail (?<KEY>\S+) from %%%%SRC%%%%'
    skip: 1
per: [ KEY ]
ban_var:
  - SRC
tests:
  positive:
    # one intervening line is with in the skip
    - messages:
        - "head k1"
        - "noise"
        - "tail k1 from 192.0.2.30"
      found: 1
      data:
        SRC: "192.0.2.30"
  negative:
    # two intervening lines is past it
    - messages:
        - "head k2"
        - "noise"
        - "noise"
        - "tail k2 from 192.0.2.31"
      found: 0
EOR
my $near = $rules->load('raw/near');
ok( defined($near), 'skip rule loaded, embedded tests proved the bound' );

#
# a single counted stage... per-session repetition, the family 2 shape
#

write_rule( 'raw/repeat', <<'EOR' );
---
stages:
  - message_regexp:
      - '^auth failure on (?<CONN>\S+) from %%%%SRC%%%%'
    count: 3
per: [ CONN ]
ban_var:
  - SRC
tests:
  positive:
    - messages:
        - "auth failure on conn1 from 192.0.2.40"
        - "auth failure on conn1 from 192.0.2.40"
        - "auth failure on conn1 from 192.0.2.40"
      found: 1
      data:
        SRC: "192.0.2.40"
  negative:
    # spread over three connections, never three on one
    - messages:
        - "auth failure on conn1 from 192.0.2.41"
        - "auth failure on conn2 from 192.0.2.41"
        - "auth failure on conn3 from 192.0.2.41"
      found: 0
EOR
my $repeat = $rules->load('raw/repeat');
ok( defined($repeat), 'single counted stage rule loaded' );

#
# a per keyed on the envelope... repetition with in one daemon session
#

write_rule( 'syslog/persession', <<'EOR' );
---
daemons:
  - imapd
stages:
  - message_regexp:
      - '^LOGIN FAILED.* host=%%%%SRC%%%%'
    count: 3
per: [ syslog.host, syslog.daemon, syslog.pid ]
ban_var:
  - SRC
tests:
  positive:
    - messages:
        - "Jul 12 08:15:50 host imapd[500]: LOGIN FAILED, user=a, host=192.0.2.45"
        - "Jul 12 08:15:51 host imapd[500]: LOGIN FAILED, user=b, host=192.0.2.45"
        - "Jul 12 08:15:52 host imapd[500]: LOGIN FAILED, user=c, host=192.0.2.45"
      found: 1
      data:
        SRC: "192.0.2.45"
  negative:
    # three failures across three sessions is not three on one
    - messages:
        - "Jul 12 08:15:50 host imapd[501]: LOGIN FAILED, user=a, host=192.0.2.46"
        - "Jul 12 08:15:51 host imapd[502]: LOGIN FAILED, user=b, host=192.0.2.46"
        - "Jul 12 08:15:52 host imapd[503]: LOGIN FAILED, user=c, host=192.0.2.46"
      found: 0
EOR
my $persession = $rules->load('syslog/persession');
ok( defined($persession), 'envelope keyed per rule loaded, embedded tests proved the session scoping' );

#
# keyless adjacency... one slot per source
#

write_rule( 'raw/adjacent', <<'EOR' );
---
stages:
  - message_regexp:
      - '^PANIC in auth layer'
  - message_regexp:
      - '^client %%%%SRC%%%% disconnected'
ban_var:
  - SRC
tests:
  positive:
    - messages:
        - "PANIC in auth layer"
        - "client 192.0.2.50 disconnected"
      found: 1
      data:
        SRC: "192.0.2.50"
EOR
my $adjacent = $rules->load('raw/adjacent');
ok( defined($adjacent), 'keyless staged rule loaded' );

$adjacent->check( raw_line('PANIC in auth layer'), 'k', ctx('file-a') );
$found = $adjacent->check( raw_line('client 192.0.2.51 disconnected'), 'k', ctx('file-b') );
ok( !defined($found), 'another source does not complete a keyless sequence' );
$found = $adjacent->check( raw_line('client 192.0.2.51 disconnected'), 'k', ctx('file-a') );
ok( defined($found), 'the same source does' );
is( $found->{data}{SRC}, '192.0.2.51', 'with the address of the completing line' );

#
# ignore_regexp vetoes a line from the stages entirely
#

write_rule( 'raw/ignoring', <<'EOR' );
---
ignore_regexp:
  - 'from the health checker'
stages:
  - message_regexp:
      - '^bad thing (?<KEY>\S+)'
    count: 2
  - message_regexp:
      - '^worse thing (?<KEY>\S+) from %%%%SRC%%%%'
per: [ KEY ]
ban_var:
  - SRC
tests:
  positive:
    - messages:
        - "bad thing k1"
        - "bad thing k1"
        - "worse thing k1 from 192.0.2.60"
      found: 1
      data:
        SRC: "192.0.2.60"
  negative:
    # the ignored line does not count as a stage hit
    - messages:
        - "bad thing k2"
        - "bad thing k2 from the health checker"
        - "worse thing k2 from 192.0.2.61"
      found: 0
EOR
my $ignoring = $rules->load('raw/ignoring');
ok( defined($ignoring), 'ignore_regexp on a staged rule proved by embedded tests' );

#
# sweep_state expiry
#

$timed->check( raw_line('open k9'), 't', ctx() );
$timed->sweep_state( time + 3600 );
ok( !defined( $timed->{stage_state}{t} ), 'a swept slot is gone' );

#
# invalid defs
#

write_rule( 'raw/bothmatchers',
	"---\nmessage_regexp:\n  - 'x'\nstages:\n  - message_regexp: [ 'y' ]\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/bothmatchers'); 1 }, 'stages beside message_regexp refuses to load' );

write_rule( 'raw/orphanper', "---\nmessage_regexp:\n  - 'x'\nper: [ SRC ]\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/orphanper'); 1 }, 'a per with out stages refuses to load' );

write_rule( 'raw/emptystages', "---\nstages: []\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/emptystages'); 1 }, 'empty stages refuses to load' );

write_rule( 'raw/badstagekey', "---\nstages:\n  - message_regexp: [ 'x' ]\n    derp: 1\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/badstagekey'); 1 }, 'a unknown stage key refuses to load' );

write_rule( 'raw/badcount', "---\nstages:\n  - message_regexp: [ 'x' ]\n    count: 0\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/badcount'); 1 }, 'a zero count refuses to load' );

write_rule( 'raw/badper', "---\nstages:\n  - message_regexp: [ 'x' ]\nper: [ syslog.pid ]\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/badper'); 1 }, 'a raw per keying on the envelope refuses to load' );

done_testing;
