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

# gate predicates on the syslog and raw types... the operator/decode engine of
# cuts 1 and 2 run as a post-match refinement over the captures, plus the
# reserved MESSAGE field. a rule with no gate is unchanged

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/syslog', $dir . '/raw' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

my $rules = App::Baphomet::Rules->new( 'rules_dir' => $dir, shipped => 0 );

sub matches {
	my ( $name, $parser, $line ) = @_;
	my $parsed = App::Baphomet::Parser::parse( $parser, $line );
	my $rule   = $rules->load($name);
	return defined( $rule->check($parsed) ) ? 1 : 0;
}

my $b64_evil = encode_base64( 'please run mimikatz', '' );
my $b64_ok   = encode_base64( 'nothing to see',      '' );

#
# syslog... a gate decoding an extracted capture
#
write_rule( 'syslog/cmd', <<'EOR' );
---
daemons:
  - myapp
message_regexp:
  - 'ran command (?<CMD>\S+) as %%%%SRC%%%%'
gate:
  - field: CMD
    op: contains
    value: mimikatz
    decode: [ base64 ]
ban_var:
  - SRC
EOR

is( matches( 'syslog/cmd', 'bsd_syslog', "Jul 16 08:15:50 vixen42 myapp[1]: ran command $b64_evil as 1.2.3.4" ),
	1, 'syslog gate: a base64 capture decodes and the needle is found' );
is( matches( 'syslog/cmd', 'bsd_syslog', "Jul 16 08:15:50 vixen42 myapp[1]: ran command $b64_ok as 1.2.3.4" ),
	0, 'syslog gate: the offense is dropped when the decoded capture misses' );
is( matches( 'syslog/cmd', 'bsd_syslog', 'Jul 16 08:15:50 vixen42 myapp[1]: some other line entirely' ),
	0, 'syslog gate: a non-matching message is not an offense either' );

#
# syslog... the reserved MESSAGE field, and legacy + cidr over captures
#
write_rule( 'syslog/msg', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'login from %%%%SRC%%%%'
gate:
  - field: MESSAGE
    op: contains
    value: "login from"
  - field: SRC
    op: cidr
    value: 10.0.0.0/8
ban_var:
  - SRC
EOR

is( matches( 'syslog/msg', 'bsd_syslog', 'Jul 16 08:15:50 vixen42 sshd[1]: login from 10.1.2.3' ),
	1, 'syslog gate: MESSAGE contains and SRC cidr both pass' );
is( matches( 'syslog/msg', 'bsd_syslog', 'Jul 16 08:15:50 vixen42 sshd[1]: login from 8.8.8.8' ),
	0, 'syslog gate: the SRC cidr fails and drops it' );

#
# syslog... a rule with no gate is unchanged
#
write_rule( 'syslog/plain', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'bad from %%%%SRC%%%%'
ban_var:
  - SRC
EOR
is( matches( 'syslog/plain', 'bsd_syslog', 'Jul 16 08:15:50 vixen42 sshd[1]: bad from 1.2.3.4' ),
	1, 'a gateless syslog rule matches as before' );

#
# raw... a gate decoding a capture from the whole line
#
write_rule( 'raw/blob', <<'EOR' );
---
message_regexp:
  - 'blob=(?<BLOB>\S+) ip=%%%%SRC%%%%'
gate:
  - field: BLOB
    op: contains
    value: mimikatz
    decode: [ base64 ]
ban_var:
  - SRC
EOR
is( matches( 'raw/blob', 'raw', "blob=$b64_evil ip=9.9.9.9" ), 1, 'raw gate: a base64 capture decodes and matches' );
is( matches( 'raw/blob', 'raw', "blob=$b64_ok ip=9.9.9.9" ),   0, 'raw gate: a decoded capture that misses drops the offense' );

#
# syslog... the boolean selections/condition form over captures (OR + not)
#
write_rule( 'syslog/sel', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'user=(?<USER>\S+) from %%%%SRC%%%%'
selections:
  admin:  [ { field: USER, op: eq, values: [ root, admin ] } ]
  office: [ { field: SRC,  op: cidr, value: 10.0.0.0/8 } ]
condition: "admin and not office"
ban_var:
  - SRC
EOR
is( matches( 'syslog/sel', 'bsd_syslog', "Jul 16 08:15:50 vixen42 sshd[1]: user=root from 8.8.8.8" ),
	1, 'syslog selections: admin and not office holds' );
is( matches( 'syslog/sel', 'bsd_syslog', "Jul 16 08:15:50 vixen42 sshd[1]: user=root from 10.1.2.3" ),
	0, 'syslog selections: from the office is filtered out' );
is( matches( 'syslog/sel', 'bsd_syslog', "Jul 16 08:15:50 vixen42 sshd[1]: user=guest from 8.8.8.8" ),
	0, 'syslog selections: a non-admin user does not match' );

#
# raw... selections over captures too
#
write_rule( 'raw/sel', <<'EOR' );
---
message_regexp:
  - 'act=(?<ACT>\w+) ip=%%%%SRC%%%%'
selections:
  bad: [ { field: ACT, op: eq, values: [ drop, deny ] } ]
condition: "1 of them"
ban_var:
  - SRC
EOR
is( matches( 'raw/sel', 'raw', 'act=drop ip=1.1.1.1' ),   1, 'raw selections: 1 of them matches' );
is( matches( 'raw/sel', 'raw', 'act=accept ip=1.1.1.1' ), 0, 'raw selections: no selection true, no match' );

done_testing;
