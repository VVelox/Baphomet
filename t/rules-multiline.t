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

sub raw_line {
	my ($line) = @_;
	return App::Baphomet::Parser::parse( 'raw', $line );
}

#
# offense first, address later... the mongodb shape, with defer
#

write_rule( 'raw/defer', <<'EOR' );
---
capture_regexp:
  - regexp: '^\[conn(?<KEY>\d+)\] end connection %%%%SRC%%%%:\d+'
    key: KEY
    ttl: 60
message_regexp:
  - regexp: '^\[conn(?<KEY>\d+)\] auth failed'
    key: KEY
    defer: 60
ban_var:
  - SRC
tests:
  positive:
    - messages:
        - "[conn7] auth failed"
        - "[conn7] end connection 192.0.2.35:53276"
      found: 1
      data:
        SRC: "192.0.2.35"
    # several offenses on one connection all complete at once
    - messages:
        - "[conn8] auth failed"
        - "[conn8] auth failed"
        - "[conn8] end connection 192.0.2.36:53277"
      found: 2
      data:
        SRC: "192.0.2.36"
  negative:
    - message: "[conn9] auth failed"
      found: 0
    # key mismatch never completes
    - messages:
        - "[conn10] auth failed"
        - "[conn11] end connection 192.0.2.37:53278"
      found: 0
EOR

my $rules = App::Baphomet::Rules->new( rules_dir => $rules_dir );
my $defer = $rules->load('raw/defer');
ok( defined($defer), 'defer rule loaded, embedded sequence tests passed' );

# the same by hand, checking the found shapes and the more array
my $found = $defer->check( raw_line('[conn1] auth failed'), 'scope-a' );
ok( !defined($found), 'deferred offense not found yet' );
$found = $defer->check( raw_line('[conn1] auth failed'), 'scope-a' );
ok( !defined($found), 'second deferred offense not found yet' );
$found = $defer->check( raw_line('[conn1] end connection 192.0.2.5:1234'), 'scope-a' );
ok( defined($found), 'capture line completes' );
is( $found->{data}{SRC},           '192.0.2.5', 'completion carries the address' );
is( scalar( @{ $found->{more} } ), 1,           'second completion in more' );
is( $found->{more}[0]{data}{SRC},  '192.0.2.5', 'more completion carries the address too' );

# scope isolation... conn1 in another scope knows nothing
$found = $defer->check( raw_line('[conn1] end connection 192.0.2.9:1234'), 'scope-b' );
ok( !defined($found), 'a different scope has no pendings for the same key' );

# TTL expiry via sweep_state
$found = $defer->check( raw_line('[conn2] auth failed'), 'scope-a' );
$defer->sweep_state( time + 120 );
$found = $defer->check( raw_line('[conn2] end connection 192.0.2.6:1234'), 'scope-a' );
ok( !defined($found), 'a swept pending does not complete' );

#
# address first, offense later... the sendmail shape, no defer needed
#

write_rule( 'raw/lookup', <<'EOR' );
---
capture_regexp:
  - regexp: '^(?<QID>\w+): from someone relay \[%%%%SRC%%%%\]'
    key: QID
    ttl: 60
message_regexp:
  - regexp: '^(?<QID>\w+): user unknown'
    key: QID
ban_var:
  - SRC
tests:
  positive:
    - messages:
        - "q123AB: from someone relay [192.0.2.44]"
        - "q123AB: user unknown"
      found: 1
      data:
        SRC: "192.0.2.44"
  negative:
    # the offense with out the earlier context is unresolvable
    - message: "q999ZZ: user unknown"
      found: 0
EOR

my $lookup = $rules->load('raw/lookup');
ok( defined($lookup), 'lookup rule loaded, embedded sequence tests passed' );

$lookup->check( raw_line('qAAA: from someone relay [192.0.2.50]'), 's' );
$found = $lookup->check( raw_line('qAAA: user unknown'), 's' );
ok( defined($found), 'keyed offense resolves through stored context' );
is( $found->{data}{SRC}, '192.0.2.50', 'address from the stored captures' );
is( $found->{regexp},    0,            'offense entry index reported' );

# context expiry
$lookup->check( raw_line('qBBB: from someone relay [192.0.2.51]'), 's' );
$lookup->sweep_state( time + 120 );
$found = $lookup->check( raw_line('qBBB: user unknown'), 's' );
ok( !defined($found), 'expired context does not resolve' );

# plain string entries still work alongside keyed ones
write_rule( 'raw/mixed', <<'EOR' );
---
message_regexp:
  - 'plain bad thing from %%%%SRC%%%%'
  - regexp: '^(?<QID>\w+): keyed bad thing'
    key: QID
ban_var:
  - SRC
tests:
  positive:
    - message: "plain bad thing from 192.0.2.60"
      found: 1
      data:
        SRC: "192.0.2.60"
EOR
my $mixed = $rules->load('raw/mixed');
ok( defined($mixed), 'mixed string and hash entries load' );

#
# envelope keys... correlation by the session, no key in the message at all
#

sub syslog_line {
	my ($line) = @_;
	return App::Baphomet::Parser::parse( 'bsd_syslog', $line );
}

write_rule( 'syslog/session', <<'EOR' );
---
daemons:
  - sshd
capture_regexp:
  - regexp: '^Connection from %%%%SRC%%%% port \d+'
    key: [ syslog.host, syslog.daemon, syslog.pid ]
    ttl: 120
message_regexp:
  - regexp: '^Too many authentication failures'
    key: [ syslog.host, syslog.daemon, syslog.pid ]
    defer: 60
ban_var:
  - SRC
tests:
  positive:
    # address first, the sshd shape
    - messages:
        - "Jul 12 08:15:50 vixen42 sshd[100]: Connection from 192.0.2.70 port 40000"
        - "Jul 12 08:15:52 vixen42 sshd[100]: Too many authentication failures"
      found: 1
      data:
        SRC: "192.0.2.70"
  negative:
    # a different pid is a different session
    - messages:
        - "Jul 12 08:15:50 vixen42 sshd[100]: Connection from 192.0.2.70 port 40000"
        - "Jul 12 08:15:52 vixen42 sshd[200]: Too many authentication failures"
      found: 0
EOR

my $session = $rules->load('syslog/session');
ok( defined($session), 'envelope keyed rule loaded, embedded sequence tests passed' );

# offense first resolves through defer when the capture line lands
$found = $session->check( syslog_line('Jul 12 08:15:52 vixen42 sshd[300]: Too many authentication failures'), 'e' );
ok( !defined($found), 'envelope keyed offense defers awaiting its session capture' );
$found
	= $session->check( syslog_line('Jul 12 08:15:53 vixen42 sshd[300]: Connection from 192.0.2.71 port 41000'), 'e' );
ok( defined($found), 'session capture completes the deferred offense' );
is( $found->{data}{SRC}, '192.0.2.71', 'completion carries the session address' );

# a different host sharing the log is a different session
$session->check( syslog_line('Jul 12 08:16:00 vixen42 sshd[400]: Connection from 192.0.2.72 port 42000'), 'e' );
$found = $session->check( syslog_line('Jul 12 08:16:02 otherhost sshd[400]: Too many authentication failures'), 'e' );
ok( !defined($found), 'the same pid on a different host does not correlate' );

# a pid-less line can not resolve the session key... judged a plain offense
$found = $session->check( syslog_line('Jul 12 08:16:10 vixen42 sshd: Too many authentication failures'), 'e' );
ok( defined($found),                 'a line missing a key component is judged a plain unkeyed offense' );
ok( !defined( $found->{data}{SRC} ), 'and carries no correlated address' );

#
# json correlation... offense and address on separate events sharing a field
#

make_path( $rules_dir . '/json' );

sub json_line {
	my ($line) = @_;
	return App::Baphomet::Parser::parse( 'json', $line );
}

write_rule( 'json/conn', <<'EOR' );
---
gate:
  - field: c
    values: [ ACCESS ]
  - field: msg
    values: [ "Authentication failed" ]
key: [ ctx ]
defer: 60
capture:
  - gate:
      - field: msg
        values: [ "Connection ended" ]
    match:
      - field: attr.remote
        regexp: '^%%%%SRC%%%%:\d+$'
    key: [ ctx ]
    ttl: 60
ban_var:
  - SRC
tests:
  positive:
    # offense first, the mongod shape, resolved by the later capture
    - messages:
        - '{"c":"ACCESS","ctx":"conn7","msg":"Authentication failed"}'
        - '{"c":"NETWORK","ctx":"conn7","msg":"Connection ended","attr":{"remote":"192.0.2.90:5555"}}'
      found: 1
      data:
        SRC: "192.0.2.90"
    # address first works the same
    - messages:
        - '{"c":"NETWORK","ctx":"conn8","msg":"Connection ended","attr":{"remote":"192.0.2.91:5556"}}'
        - '{"c":"ACCESS","ctx":"conn8","msg":"Authentication failed"}'
      found: 1
      data:
        SRC: "192.0.2.91"
  negative:
    # a different ctx is a different connection
    - messages:
        - '{"c":"ACCESS","ctx":"conn9","msg":"Authentication failed"}'
        - '{"c":"NETWORK","ctx":"conn10","msg":"Connection ended","attr":{"remote":"192.0.2.92:5557"}}'
      found: 0
EOR

my $conn = $rules->load('json/conn');
ok( defined($conn), 'json correlation rule loaded, embedded sequence tests passed' );

# the found shape by hand... the offense's fields win, the capture's SRC rides in
$conn->check( json_line('{"c":"NETWORK","ctx":"connA","msg":"Connection ended","attr":{"remote":"192.0.2.93:1"}}'),
	'j' );
$found = $conn->check( json_line('{"c":"ACCESS","ctx":"connA","msg":"Authentication failed"}'), 'j' );
ok( defined($found), 'keyed json offense resolves through stored context' );
is( $found->{data}{SRC}, '192.0.2.93',            'address from the stored capture' );
is( $found->{data}{msg}, 'Authentication failed', 'the offense own fields are authoritative' );

# scope isolation
$found = $conn->check( json_line('{"c":"ACCESS","ctx":"connA","msg":"Authentication failed"}'), 'j2' );
ok( !defined($found), 'a different scope has no context for the same key' );

# several deferred offenses on one connection all complete at once
$conn->check( json_line('{"c":"ACCESS","ctx":"connB","msg":"Authentication failed"}'), 'j' );
$conn->check( json_line('{"c":"ACCESS","ctx":"connB","msg":"Authentication failed"}'), 'j' );
$found
	= $conn->check(
		json_line('{"c":"NETWORK","ctx":"connB","msg":"Connection ended","attr":{"remote":"192.0.2.94:2"}}'), 'j' );
ok( defined($found), 'capture completes the deferred offenses' );
is( $found->{data}{SRC},           '192.0.2.94', 'completion carries the address' );
is( scalar( @{ $found->{more} } ), 1,            'second completion in more' );

# TTL expiry via sweep_state
$conn->check( json_line('{"c":"ACCESS","ctx":"connC","msg":"Authentication failed"}'), 'j' );
$conn->sweep_state( time + 120 );
$found
	= $conn->check(
		json_line('{"c":"NETWORK","ctx":"connC","msg":"Connection ended","attr":{"remote":"192.0.2.95:3"}}'), 'j' );
ok( !defined($found), 'a swept pending does not complete' );

# a keyed rule with out defer... unresolved is not judged an offense
write_rule( 'json/nodefer', <<'EOR' );
---
gate:
  - field: msg
    values: [ "Authentication failed" ]
key: [ ctx ]
capture:
  - gate:
      - field: msg
        values: [ "Connection ended" ]
    match:
      - field: attr.remote
        regexp: '^%%%%SRC%%%%:\d+$'
    key: [ ctx ]
    ttl: 60
ban_var:
  - SRC
tests:
  positive:
    - messages:
        - '{"ctx":"c1","msg":"Connection ended","attr":{"remote":"192.0.2.96:4"}}'
        - '{"ctx":"c1","msg":"Authentication failed"}'
      found: 1
      data:
        SRC: "192.0.2.96"
  negative:
    - message: '{"ctx":"c2","msg":"Authentication failed"}'
      found: 0
EOR
my $nodefer = $rules->load('json/nodefer');
ok( defined($nodefer), 'undeferred json correlation rule loaded' );

# a key component that does not resolve leaves the offense standing plain
$found = $nodefer->check( json_line('{"msg":"Authentication failed"}'), 'j' );
ok( defined($found),                 'a offense missing its key field is judged plain' );
ok( !defined( $found->{data}{SRC} ), 'and carries no correlated address' );

#
# invalid defs
#

write_rule( 'raw/badcap', "---\ncapture_regexp:\n  - regexp: 'x'\nmessage_regexp:\n  - 'y'\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/badcap'); 1 }, 'capture entry with out a key refuses to load' );

write_rule( 'raw/badhash', "---\nmessage_regexp:\n  - regexp: 'x'\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/badhash'); 1 }, 'hash message entry with out a key refuses to load' );

write_rule( 'raw/badenvelope', "---\nmessage_regexp:\n  - regexp: 'x'\n    key: [ syslog.pid ]\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/badenvelope'); 1 }, 'a raw rule keying on the envelope refuses to load' );

write_rule( 'raw/emptykey', "---\nmessage_regexp:\n  - regexp: 'x'\n    key: []\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/emptykey'); 1 }, 'a empty key array refuses to load' );

write_rule( 'syslog/badenvelope',
	"---\ndaemons:\n  - x\nmessage_regexp:\n  - regexp: 'x'\n    key: [ syslog.severity ]\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('syslog/badenvelope'); 1 }, 'a unknown envelope field refuses to load' );

write_rule( 'json/baddefer', "---\ngate:\n  - field: a\n    values: [ b ]\ndefer: 60\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('json/baddefer'); 1 }, 'a json defer with out a key refuses to load' );

write_rule( 'json/badcapture',
	"---\ngate:\n  - field: a\n    values: [ b ]\nkey: [ x ]\ncapture:\n  - key: [ x ]\n    ttl: 60\nban_var:\n  - SRC\n"
);
ok( !eval { $rules->load('json/badcapture'); 1 }, 'a json capture with neither gate nor match refuses to load' );

write_rule( 'json/badkey', "---\ngate:\n  - field: a\n    values: [ b ]\nkey: [ syslog.pid ]\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('json/badkey'); 1 }, 'a json rule keying on the reserved syslog namespace refuses to load' );

done_testing;
