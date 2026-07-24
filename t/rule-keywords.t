#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp   qw( tempdir );
use File::Path   qw( make_path );
use MIME::Base64 qw( encode_base64 );
use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();

# keyword search across fields... the reserved %%%ANY%%% field fans a predicate
# over every value, %%%ANY:prefix%%% over a subtree, and the keywords shorthand
# is sugar over it

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/json' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

my $rules = App::Baphomet::Rules->new( 'rules_dir' => $dir, shipped => 0 );

sub matches {
	my ( $name, $line ) = @_;
	my $parsed = App::Baphomet::Parser::parse( 'json', $line );
	my $rule   = $rules->load($name);
	return defined( $rule->check($parsed) ) ? 1 : 0;
}

my $head = "---\nban_var:\n  - id\n";

# --- %%%ANY%%% ... a keyword anywhere ---
write_rule( 'json/any', $head . "gate:\n  - { field: '%%%ANY%%%', op: contains, value: mimikatz }\n" );
is( matches( 'json/any', '{"process":{"cmd":"run mimikatz now"},"id":"a"}' ), 1, 'a keyword in a nested field is found' );
is( matches( 'json/any', '{"network":{"host":"mimikatz.evil.com"},"id":"a"}' ), 1, 'and in any other field' );
is( matches( 'json/any', '{"process":{"cmd":"whoami"},"id":"a"}' ),           0, 'a keyword nowhere does not match' );

# --- %%%ANY:prefix%%% ... scoped to a subtree, ignoring unrelated data ---
write_rule( 'json/scoped', $head . "gate:\n  - { field: '%%%ANY:process%%%', op: contains, value: mimikatz }\n" );
is( matches( 'json/scoped', '{"process":{"cmd":"run mimikatz"},"network":{"host":"clean"},"id":"a"}' ),
	1, 'scoped: a keyword under the named subtree is found' );
is( matches( 'json/scoped', '{"process":{"cmd":"whoami"},"network":{"host":"mimikatz.evil.com"},"id":"a"}' ),
	0, 'scoped: a match in an unrelated branch is ignored' );

# --- decode over every field ---
write_rule( 'json/decoded', $head . "gate:\n  - { field: '%%%ANY%%%', op: contains, value: DownloadString, decode: [ base64 ] }\n" );
my $b64 = encode_base64( 'IEX Net.WebClient.DownloadString', '' );
is( matches( 'json/decoded', qq({"data":{"blob":"$b64"},"id":"a"}) ), 1, 'a decoded keyword is found in whatever field carried it' );
is( matches( 'json/decoded', '{"data":{"blob":"aGVsbG8="},"id":"a"}' ), 0, 'a field that decodes to something else does not match' );

# --- a negated keyword means the string is in no field ---
write_rule( 'json/absent', $head . "gate:\n  - { field: '%%%ANY%%%', op: contains, value: healthcheck, negate: true }\n" );
is( matches( 'json/absent', '{"user":"root","id":"a"}' ),        1, 'negated keyword holds when the string is absent from all fields' );
is( matches( 'json/absent', '{"user":"healthcheck","id":"a"}' ), 0, 'negated keyword fails when some field carries the string' );

# --- keywords shorthand, all fields ---
write_rule( 'json/kw', $head . "keywords: [ mimikatz, sekurlsa ]\n" );
is( matches( 'json/kw', '{"x":{"y":"loaded sekurlsa"},"id":"a"}' ), 1, 'the keywords list matches any of its strings anywhere' );
is( matches( 'json/kw', '{"x":{"y":"nothing here"},"id":"a"}' ),    0, 'and misses when none appear' );

# --- keywords shorthand, scoped with in ---
write_rule( 'json/kwin', $head . "keywords:\n  in: '%%%ANY:process%%%'\n  values: [ mimikatz ]\n" );
is( matches( 'json/kwin', '{"process":{"cmd":"mimikatz"},"other":{"z":"clean"},"id":"a"}' ), 1, 'scoped keywords match under the subtree' );
is( matches( 'json/kwin', '{"process":{"cmd":"clean"},"other":{"z":"mimikatz"},"id":"a"}' ), 0, 'scoped keywords ignore other branches' );

# --- keywords compose with a gate (ANDed) ---
write_rule( 'json/kwgate', $head . "keywords: [ mimikatz ]\ngate:\n  - { field: level, op: eq, value: high }\n" );
is( matches( 'json/kwgate', '{"msg":"mimikatz","level":"high","id":"a"}' ), 1, 'keywords AND a gate, both satisfied' );
is( matches( 'json/kwgate', '{"msg":"mimikatz","level":"low","id":"a"}' ),  0, 'keywords hold but the gate fails' );
is( matches( 'json/kwgate', '{"msg":"clean","level":"high","id":"a"}' ),    0, 'the gate holds but the keyword is absent' );

# --- errors ---
write_rule( 'json/kwbad', $head . "keywords:\n  in: process\n" );
ok( !eval { $rules->load('json/kwbad'); 1 }, 'keywords with no values is a load error' );

# --- keywords standing alone on the syslog type ... with no gate or
# selections the keyword filter must still judge the found ---
make_path( $dir . '/syslog' );

sub syslog_matches {
	my ( $name, $message ) = @_;
	my $parsed = App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 vixen42 sshd[123]: ' . $message );
	my $rule   = $rules->load($name);
	return defined( $rule->check($parsed) ) ? 1 : 0;
}

write_rule( 'syslog/kwonly', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
keywords: [ mimikatz ]
EOR
is( syslog_matches( 'syslog/kwonly', 'bad thing from 1.2.3.4 ran mimikatz' ),
	1, 'syslog: lone keywords pass a regexp match carrying the string' );
is( syslog_matches( 'syslog/kwonly', 'bad thing from 1.2.3.4' ),
	0, 'syslog: lone keywords veto a regexp match lacking the string' );

# --- keywords standing alone as the whole matcher of a message_json rule,
# which must load (the banish-every-line check knows keywords count) and
# must filter on them ---
write_rule( 'syslog/kwjson', <<'EOR' );
---
daemons:
  - sshd
message_json: true
ban_var:
  - src_ip
keywords: [ mimikatz ]
EOR
ok( eval { $rules->load('syslog/kwjson'); 1 }, 'message_json with only keywords loads' )
	|| diag($@);
is( syslog_matches( 'syslog/kwjson', '{"src_ip":"1.2.3.4","note":"ran mimikatz"}' ),
	1, 'message_json: lone keywords match on a json field' );
is( syslog_matches( 'syslog/kwjson', '{"src_ip":"1.2.3.4","note":"clean"}' ),
	0, 'message_json: lone keywords veto a line lacking the string' );

# --- and a message_json rule with no matcher at all still refuses to load ---
write_rule( 'syslog/kwjson-none', <<'EOR' );
---
daemons:
  - sshd
message_json: true
ban_var:
  - src_ip
EOR
ok( !eval { $rules->load('syslog/kwjson-none'); 1 },
	'message_json with no matcher at all is still a load error' );

done_testing;
