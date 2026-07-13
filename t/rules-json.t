#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp            qw( tempdir );
use File::Path            qw( make_path );
use App::Baphomet::Config qw( check_kur_def );
use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();

my $rules_dir = tempdir( CLEANUP => 1 );
make_path( $rules_dir . '/json' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $rules_dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

sub json_line {
	my ($json) = @_;
	return App::Baphomet::Parser::parse( 'json', $json );
}

write_rule( 'json/probes', <<'EOR' );
---
gate:
  - field: c
    values: [ ACCESS, //^AUTH// ]
match:
  - field: attr.remote
    regexp: '^%%%%SRC%%%%:\d+$'
  - field: msg
    regexp: 'denied for %%%%ADDR%%%%'
ignore:
  - field: attr.user
    regexp: '^healthcheck$'
ban_var:
  - SRC
tests:
  positive:
    - message: '{"c":"ACCESS","msg":"failed","attr":{"remote":"192.0.2.5:54321"}}'
      found: 1
      data:
        SRC: "192.0.2.5"
  negative:
    - message: '{"c":"NETWORK","msg":"failed","attr":{"remote":"192.0.2.5:54321"}}'
      found: 0
      undefed: ["SRC"]
EOR

my $rules = App::Baphomet::Rules->new( rules_dir => $rules_dir );
my $rule  = $rules->load('json/probes');
ok( defined($rule), 'json rule loaded' );
is( ( $rule->ban_var )[0], 'SRC', 'ban_var' );

my $found = $rule->check( json_line('{"c":"ACCESS","msg":"failed","attr":{"remote":"192.0.2.5:54321"}}') );
ok( defined($found), 'match found' );
is( $found->{data}{SRC},           '192.0.2.5',       'token capture in data' );
is( $found->{data}{'attr.remote'}, '192.0.2.5:54321', 'flattened field in data' );
is( $found->{regexp},              0,                 'first match entry hit' );

$found = $rule->check( json_line('{"c":"AUTHZ","msg":"denied for 2001:db8::9"}') );
ok( defined($found), 'gate regexp entry and second match hit' );
is( $found->{regexp}, 1, 'second match entry index' );

ok( !defined( $rule->check( json_line('{"c":"NETWORK","attr":{"remote":"192.0.2.5:54321"}}') ) ),
	'gate blocks a wrong field value' );
ok( !defined( $rule->check( json_line('{"msg":"failed","attr":{"remote":"192.0.2.5:54321"}}') ) ),
	'gate blocks a absent field' );
ok( !defined(
		$rule->check( json_line('{"c":"ACCESS","attr":{"remote":"192.0.2.5:54321","user":"healthcheck"}}') )
	),
	'ignore vetoes'
);
ok( !defined( $rule->check( json_line('{"c":"ACCESS","msg":"nothing of note"}') ) ),
	'no match entry hit means not found' );

# other parser shapes are refused
my $syslog_parsed = App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 vixen42 sshd[1]: foo' );
ok( !defined( $rule->check($syslog_parsed) ), 'syslog shaped lines are refused' );

#
# field path ban_var and gates only rules
#

write_rule( 'json/direct', <<'EOR' );
---
gate:
  - field: event_type
    values: [ alert ]
ban_var:
  - src_ip
tests:
  positive:
    - message: '{"event_type":"alert","src_ip":"192.0.2.66"}'
      found: 1
      data:
        src_ip: "192.0.2.66"
EOR

my $direct = $rules->load('json/direct');
$found = $direct->check( json_line('{"event_type":"alert","src_ip":"192.0.2.66"}') );
ok( defined($found), 'gates only rule found' );
is( $found->{data}{src_ip}, '192.0.2.66', 'field path resolvable as the ban_var' );
ok( !defined( $found->{regexp} ), 'gates only rule has no regexp index' );

#
# invalid defs
#

write_rule( 'json/empty', "---\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('json/empty'); 1 }, 'no gates and no matches refuses to load' );

write_rule( 'json/nobanvar', "---\ngate:\n  - field: a\n    values: [ b ]\n" );
ok( !eval { $rules->load('json/nobanvar'); 1 }, 'missing ban_var refuses to load' );

write_rule( 'json/badtoken', "---\nmatch:\n  - field: a\n    regexp: '%%%%LAMASHTU%%%%'\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('json/badtoken'); 1 }, 'unknown token refuses to load' );

#
# pairing
#

ok( App::Baphomet::Rules::type_accepts_parser( 'json', 'json' ),         'json takes json' );
ok( !App::Baphomet::Rules::type_accepts_parser( 'json', 'json_syslog' ), 'json refuses json_syslog' );
ok( !App::Baphomet::Rules::type_accepts_parser( 'syslog', 'json' ),      'syslog refuses json' );

my $good_def = { 'applog' => { 'log' => '/var/log/app.json', 'parser' => 'json', 'rule' => 'json/probes' } };
ok( eval { check_kur_def( 'app', $good_def ); 1 }, 'json rule with the json parser checks out' ) || diag($@);

my $bad_def = { 'applog' => { 'log' => '/var/log/app.json', 'rule' => 'json/probes' } };
ok( !eval { check_kur_def( 'app', $bad_def ); 1 }, 'json rule with the default syslog parser refuses' );

done_testing;
