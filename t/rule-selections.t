#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );
use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();

# the boolean form... named selections plus a condition composing them with
# and/or/not, parens, and N-of-M. an alternative to the flat gate

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/json' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

my $rules = App::Baphomet::Rules->new( 'rules_dir' => $dir );

sub matches {
	my ( $name, $line ) = @_;
	my $parsed = App::Baphomet::Parser::parse( 'json', $line );
	my $rule   = $rules->load($name);
	return defined( $rule->check($parsed) ) ? 1 : 0;
}

# --- OR ---
write_rule( 'json/or', <<'EOR' );
---
ban_var:
  - src
selections:
  a: [ { field: event, op: eq, value: x } ]
  b: [ { field: event, op: eq, value: y } ]
condition: "a or b"
EOR
is( matches( 'json/or', '{"event":"x","src":"1.1.1.1"}' ), 1, 'or: left selection matches' );
is( matches( 'json/or', '{"event":"y","src":"1.1.1.1"}' ), 1, 'or: right selection matches' );
is( matches( 'json/or', '{"event":"z","src":"1.1.1.1"}' ), 0, 'or: neither matches' );

# --- nested NOT ---
write_rule( 'json/andnot', <<'EOR' );
---
ban_var:
  - src
selections:
  a:      [ { field: event, op: eq, value: auth } ]
  filter: [ { field: user,  op: eq, value: healthcheck } ]
condition: "a and not filter"
EOR
is( matches( 'json/andnot', '{"event":"auth","user":"root","src":"1.1.1.1"}' ),        1, 'a and not filter: passes' );
is( matches( 'json/andnot', '{"event":"auth","user":"healthcheck","src":"1.1.1.1"}' ), 0, 'a and not filter: filtered out' );
is( matches( 'json/andnot', '{"event":"other","user":"root","src":"1.1.1.1"}' ),       0, 'a and not filter: a is false' );

# --- parens + double negation ---
write_rule( 'json/paren', <<'EOR' );
---
ban_var:
  - src
selections:
  a: [ { field: a, op: eq, value: "1" } ]
  b: [ { field: b, op: eq, value: "1" } ]
  c: [ { field: c, op: eq, value: "1" } ]
condition: "(a or b) and not not c"
EOR
is( matches( 'json/paren', '{"a":"1","c":"1","src":"1.1.1.1"}' ), 1, 'parens: (a or b) and c holds' );
is( matches( 'json/paren', '{"a":"1","src":"1.1.1.1"}' ),         0, 'parens: c missing fails' );
is( matches( 'json/paren', '{"c":"1","src":"1.1.1.1"}' ),         0, 'parens: neither a nor b fails' );

# --- N of M ---
write_rule( 'json/nom', <<'EOR' );
---
ban_var:
  - src
selections:
  sig_a: [ { field: a, op: eq, value: "1" } ]
  sig_b: [ { field: b, op: eq, value: "1" } ]
  sig_c: [ { field: c, op: eq, value: "1" } ]
condition: "2 of sig_*"
EOR
is( matches( 'json/nom', '{"a":"1","b":"1","src":"1.1.1.1"}' ),         1, '2 of sig_*: two true' );
is( matches( 'json/nom', '{"a":"1","b":"1","c":"1","src":"1.1.1.1"}' ), 1, '2 of sig_*: three true' );
is( matches( 'json/nom', '{"a":"1","src":"1.1.1.1"}' ),                 0, '2 of sig_*: only one true' );

# --- all of them / 1 of them ---
write_rule( 'json/allof', <<'EOR' );
---
ban_var:
  - src
selections:
  a: [ { field: a, op: eq, value: "1" } ]
  b: [ { field: b, op: eq, value: "1" } ]
condition: "all of them"
EOR
write_rule( 'json/oneof', <<'EOR' );
---
ban_var:
  - src
selections:
  a: [ { field: a, op: eq, value: "1" } ]
  b: [ { field: b, op: eq, value: "1" } ]
condition: "1 of them"
EOR
is( matches( 'json/allof', '{"a":"1","b":"1","src":"1.1.1.1"}' ), 1, 'all of them: both true' );
is( matches( 'json/allof', '{"a":"1","src":"1.1.1.1"}' ),         0, 'all of them: one missing' );
is( matches( 'json/oneof', '{"b":"1","src":"1.1.1.1"}' ),         1, '1 of them: one true' );
is( matches( 'json/oneof', '{"src":"1.1.1.1"}' ),                 0, '1 of them: none true' );

# --- a selection ANDs its own predicates ---
write_rule( 'json/multi', <<'EOR' );
---
ban_var:
  - src
selections:
  sel:
    - { field: event, op: eq, value: auth }
    - { field: user,  op: eq, values: [ root, admin ] }
condition: "sel"
EOR
is( matches( 'json/multi', '{"event":"auth","user":"root","src":"1.1.1.1"}' ),  1, 'selection ANDs its predicates: both hold' );
is( matches( 'json/multi', '{"event":"auth","user":"guest","src":"1.1.1.1"}' ), 0, 'selection ANDs its predicates: one fails' );

# --- errors ---
write_rule( 'json/both',    "---\nban_var: [ src ]\ngate: [ { field: a, op: eq, value: 1 } ]\nselections:\n  s: [ { field: b, op: eq, value: 1 } ]\ncondition: s\n" );
write_rule( 'json/nocond',  "---\nban_var: [ src ]\nselections:\n  s: [ { field: b, op: eq, value: 1 } ]\n" );
write_rule( 'json/nosel',   "---\nban_var: [ src ]\ncondition: s\n" );
write_rule( 'json/unknown', "---\nban_var: [ src ]\nselections:\n  s: [ { field: b, op: eq, value: 1 } ]\ncondition: \"s and nope\"\n" );
write_rule( 'json/unbal',   "---\nban_var: [ src ]\nselections:\n  s: [ { field: b, op: eq, value: 1 } ]\ncondition: \"( s\"\n" );
ok( !eval { $rules->load('json/both');    1 }, 'gate and selections together is a load error' );
ok( !eval { $rules->load('json/nocond');  1 }, 'selections without a condition is a load error' );
ok( !eval { $rules->load('json/nosel');   1 }, 'a condition without selections is a load error' );
ok( !eval { $rules->load('json/unknown'); 1 }, 'a condition referencing an unknown selection is a load error' );
ok( !eval { $rules->load('json/unbal');   1 }, 'an unbalanced paren is a load error' );

# quantifier edge cases... each would be vacuously true or never true
write_rule( 'json/star0',
	"---\nban_var: [ src ]\nselections:\n  s: [ { field: b, op: eq, value: 1 } ]\ncondition: \"all of typo_*\"\n" );
write_rule( 'json/toomany',
	"---\nban_var: [ src ]\nselections:\n  s: [ { field: b, op: eq, value: 1 } ]\ncondition: \"3 of them\"\n" );
write_rule( 'json/zeroof',
	"---\nban_var: [ src ]\nselections:\n  s: [ { field: b, op: eq, value: 1 } ]\ncondition: \"0 of them\"\n" );
ok( !eval { $rules->load('json/star0');   1 }, 'a *-pattern covering no selections is a load error' );
ok( !eval { $rules->load('json/toomany'); 1 }, 'asking for more than the selection count is a load error' );
ok( !eval { $rules->load('json/zeroof');  1 }, '0 of is a load error' );

done_testing;
