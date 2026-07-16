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

# the message_json flag... a syslog rule whose daemon logs a JSON object as its
# message decodes it into fields the gate tests, with the envelope under
# syslog.* keys. message_regexp becomes optional, the gate matching

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/syslog' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

my $rules = App::Baphomet::Rules->new( 'rules_dir' => $dir );

sub found {
	my ( $name, $line ) = @_;
	my $parsed = App::Baphomet::Parser::parse( 'bsd_syslog', $line );
	my $rule   = $rules->load($name);
	return $rule->check($parsed);
}
sub matches { return defined( found(@_) ) ? 1 : 0; }

my $stamp = 'Jul 16 08:15:50 vixen42';

# --- gate over json fields, no message_regexp ---
write_rule( 'syslog/jgate', <<'EOR' );
---
daemons:
  - myapp
message_json: true
gate:
  - field: event
    op: eq
    value: auth_fail
ban_var:
  - src
EOR
is( matches( 'syslog/jgate', "$stamp myapp[1]: {\"event\":\"auth_fail\",\"src\":\"1.2.3.4\"}" ),
	1, 'a json message field passes the gate' );
is( matches( 'syslog/jgate', "$stamp myapp[1]: {\"event\":\"login\",\"src\":\"1.2.3.4\"}" ),
	0, 'a json message that misses the gate is not an offense' );
is( matches( 'syslog/jgate', "$stamp myapp[1]: just plain text, not json at all" ),
	0, 'a non-json message yields no fields and falls through' );

# the offender comes out of a json field via ban_var
my $f = found( 'syslog/jgate', "$stamp myapp[1]: {\"event\":\"auth_fail\",\"src\":\"9.9.9.9\"}" );
is( $f->{data}{src}, '9.9.9.9', 'ban_var resolves against a json field' );

# --- the envelope under reserved syslog.* keys ---
write_rule( 'syslog/jenv', <<'EOR' );
---
daemons:
  - myapp
message_json: true
gate:
  - field: syslog.daemon
    op: eq
    value: myapp
  - field: event
    op: eq
    value: hit
ban_var:
  - src
EOR
is( matches( 'syslog/jenv', "$stamp myapp[1]: {\"event\":\"hit\",\"src\":\"1.1.1.1\"}" ),
	1, 'a gate can test the envelope daemon and a json field together' );

# --- decode over a json field ---
write_rule( 'syslog/jdecode', <<'EOR' );
---
daemons:
  - myapp
message_json: true
gate:
  - field: cmd
    op: contains
    value: mimikatz
    decode: [ base64 ]
ban_var:
  - src
EOR
my $b64 = encode_base64( 'go run mimikatz', '' );
is( matches( 'syslog/jdecode', "$stamp myapp[1]: {\"cmd\":\"$b64\",\"src\":\"2.2.2.2\"}" ),
	1, 'decode runs on a json field, matching the plaintext needle' );

# --- message_json plus message_regexp: the regexp is the matcher ---
write_rule( 'syslog/jboth', <<'EOR' );
---
daemons:
  - combined
message_json: true
message_regexp:
  - 'authentication'
gate:
  - field: user
    op: eq
    value: admin
ban_var:
  - src
EOR
is( matches( 'syslog/jboth', "$stamp combined[1]: {\"msg\":\"authentication failed\",\"user\":\"admin\",\"src\":\"5.5.5.5\"}" ),
	1, 'message_regexp matches the raw line and the gate refines on a json field' );
is( matches( 'syslog/jboth', "$stamp combined[1]: {\"msg\":\"authentication failed\",\"user\":\"guest\",\"src\":\"5.5.5.5\"}" ),
	0, 'the json-field gate can still veto a regexp match' );
is( matches( 'syslog/jboth', "$stamp combined[1]: {\"msg\":\"login ok\",\"user\":\"admin\",\"src\":\"5.5.5.5\"}" ),
	0, 'no regexp match means no offense even if the gate would pass' );

# --- a gateless syslog rule is unchanged (message_json off) ---
write_rule( 'syslog/plain', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'bad from %%%%SRC%%%%'
ban_var:
  - SRC
EOR
is( matches( 'syslog/plain', "$stamp sshd[1]: bad from 1.2.3.4" ), 1, 'a normal syslog rule is untouched' );

# --- load errors ---
write_rule( 'syslog/jbad', "---\ndaemons: [ x ]\nmessage_json: true\nban_var: [ src ]\n" );
write_rule( 'syslog/jbadtype', "---\ndaemons: [ x ]\nmessage_json: [ 1 ]\ngate: [ { field: a, op: eq, value: b } ]\nban_var: [ src ]\n" );
ok( !eval { $rules->load('syslog/jbad');     1 }, 'message_json with no message_regexp and no gate is a load error' );
ok( !eval { $rules->load('syslog/jbadtype'); 1 }, 'a non-boolean message_json is a load error' );

done_testing;
