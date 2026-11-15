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

my $rules = App::Baphomet::Rules->new( 'rules_dir' => $dir, shipped => 0 );

sub matches {
	my ( $name, $line ) = @_;
	my $parsed = App::Baphomet::Parser::parse( 'json', $line );
	my $rule   = $rules->load($name);
	return defined( $rule->check($parsed) ) ? 1 : 0;
}

# --- OR ---
write_rule( 'json/or', <<'EOR' );
---
rule_gates:
  - condition:
      condition: "a or b"
      selections:
        a: [ { field: event, op: eq, value: x } ]
        b: [ { field: event, op: eq, value: y } ]
  - ban_var:
      - src
EOR
is( matches( 'json/or', '{"event":"x","src":"1.1.1.1"}' ), 1, 'or: left selection matches' );
is( matches( 'json/or', '{"event":"y","src":"1.1.1.1"}' ), 1, 'or: right selection matches' );
is( matches( 'json/or', '{"event":"z","src":"1.1.1.1"}' ), 0, 'or: neither matches' );

# --- nested NOT ---
write_rule( 'json/andnot', <<'EOR' );
---
rule_gates:
  - condition:
      condition: "a and not filter"
      selections:
        a:      [ { field: event, op: eq, value: auth } ]
        filter: [ { field: user,  op: eq, value: healthcheck } ]
  - ban_var:
      - src
EOR
is( matches( 'json/andnot', '{"event":"auth","user":"root","src":"1.1.1.1"}' ),        1, 'a and not filter: passes' );
is( matches( 'json/andnot', '{"event":"auth","user":"healthcheck","src":"1.1.1.1"}' ), 0, 'a and not filter: filtered out' );
is( matches( 'json/andnot', '{"event":"other","user":"root","src":"1.1.1.1"}' ),       0, 'a and not filter: a is false' );

# --- parens + double negation ---
write_rule( 'json/paren', <<'EOR' );
---
rule_gates:
  - condition:
      condition: "(a or b) and not not c"
      selections:
        a: [ { field: a, op: eq, value: "1" } ]
        b: [ { field: b, op: eq, value: "1" } ]
        c: [ { field: c, op: eq, value: "1" } ]
  - ban_var:
      - src
EOR
is( matches( 'json/paren', '{"a":"1","c":"1","src":"1.1.1.1"}' ), 1, 'parens: (a or b) and c holds' );
is( matches( 'json/paren', '{"a":"1","src":"1.1.1.1"}' ),         0, 'parens: c missing fails' );
is( matches( 'json/paren', '{"c":"1","src":"1.1.1.1"}' ),         0, 'parens: neither a nor b fails' );

# --- N of M ---
write_rule( 'json/nom', <<'EOR' );
---
rule_gates:
  - condition:
      condition: "2 of sig_*"
      selections:
        sig_a: [ { field: a, op: eq, value: "1" } ]
        sig_b: [ { field: b, op: eq, value: "1" } ]
        sig_c: [ { field: c, op: eq, value: "1" } ]
  - ban_var:
      - src
EOR
is( matches( 'json/nom', '{"a":"1","b":"1","src":"1.1.1.1"}' ),         1, '2 of sig_*: two true' );
is( matches( 'json/nom', '{"a":"1","b":"1","c":"1","src":"1.1.1.1"}' ), 1, '2 of sig_*: three true' );
is( matches( 'json/nom', '{"a":"1","src":"1.1.1.1"}' ),                 0, '2 of sig_*: only one true' );

# --- all of them / 1 of them ---
write_rule( 'json/allof', <<'EOR' );
---
rule_gates:
  - condition:
      condition: "all of them"
      selections:
        a: [ { field: a, op: eq, value: "1" } ]
        b: [ { field: b, op: eq, value: "1" } ]
  - ban_var:
      - src
EOR
write_rule( 'json/oneof', <<'EOR' );
---
rule_gates:
  - condition:
      condition: "1 of them"
      selections:
        a: [ { field: a, op: eq, value: "1" } ]
        b: [ { field: b, op: eq, value: "1" } ]
  - ban_var:
      - src
EOR
is( matches( 'json/allof', '{"a":"1","b":"1","src":"1.1.1.1"}' ), 1, 'all of them: both true' );
is( matches( 'json/allof', '{"a":"1","src":"1.1.1.1"}' ),         0, 'all of them: one missing' );
is( matches( 'json/oneof', '{"b":"1","src":"1.1.1.1"}' ),         1, '1 of them: one true' );
is( matches( 'json/oneof', '{"src":"1.1.1.1"}' ),                 0, '1 of them: none true' );

# --- a selection ANDs its own predicates ---
write_rule( 'json/multi', <<'EOR' );
---
rule_gates:
  - condition:
      condition: "sel"
      selections:
        sel:
          - { field: event, op: eq, value: auth }
          - { field: user,  op: eq, values: [ root, admin ] }
  - ban_var:
      - src
EOR
is( matches( 'json/multi', '{"event":"auth","user":"root","src":"1.1.1.1"}' ),  1, 'selection ANDs its predicates: both hold' );
is( matches( 'json/multi', '{"event":"auth","user":"guest","src":"1.1.1.1"}' ), 0, 'selection ANDs its predicates: one fails' );

# --- errors ---
# writes the passed rule and returns what loading it dies with, or undef when
# it loads
sub load_error {
	my ( $name, $yaml ) = @_;

	write_rule( $name, "---\nrule_gates:\n" . $yaml );
	if ( eval { $rules->load($name); 1 } ) {
		return undef;
	}
	return $@;
} ## end sub load_error

# a condition of the one selection, s, told the passed expression
sub condition_error {
	my ( $name, $expression ) = @_;

	return load_error( $name,
			  "  - condition:\n      condition: \"" . $expression
			. "\"\n      selections:\n        s: [ { field: b, op: eq, value: 1 } ]\n  - ban_var: [ src ]\n" );
}

like(
	load_error( 'json/both', <<'EOR' ),
  - gate: [ { field: a, op: eq, value: 1 } ]
  - condition:
      condition: s
      selections:
        s: [ { field: b, op: eq, value: 1 } ]
  - ban_var: [ src ]
EOR
	qr/The gate gate of the rule "json\/both" \(rule_gates entry 0\) is beside a condition gate/,
	'a gate and a condition together is a load error'
);
like(
	load_error( 'json/nocond', <<'EOR' ),
  - condition:
      selections:
        s: [ { field: b, op: eq, value: 1 } ]
  - ban_var: [ src ]
EOR
	qr/\(rule_gates entry 0\) lacks a condition/,
	'selections without a condition is a load error'
);
like(
	load_error( 'json/nosel', "  - condition:\n      condition: s\n  - ban_var: [ src ]\n" ),
	qr/\(rule_gates entry 0\) lacks a selections/,
	'a condition without selections is a load error'
);
like(
	load_error( 'json/plaincond', "  - condition: s\n  - ban_var: [ src ]\n" ),
	qr/The condition gate of the rule "json\/plaincond" \(rule_gates entry 0\) is not a hash/,
	'a condition told the bare expression is a load error'
);
like(
	load_error( 'json/selgate', <<'EOR' ),
  - selections:
      s: [ { field: b, op: eq, value: 1 } ]
  - condition:
      condition: s
      selections:
        s: [ { field: b, op: eq, value: 1 } ]
  - ban_var: [ src ]
EOR
	qr/entry 0 names the gate "selections", which is not a known gate type/,
	'selections written as a gate of its own is a load error'
);
like(
	condition_error( 'json/unknown', 's and nope' ),
	qr/\(rule_gates entry 0\) references the unknown selection "nope"/,
	'a condition referencing an unknown selection is a load error'
);
like(
	condition_error( 'json/unbal', '( s' ),
	qr/\(rule_gates entry 0\) has an unbalanced paren/,
	'an unbalanced paren is a load error'
);

# quantifier edge cases... each would be vacuously true or never true
like(
	condition_error( 'json/star0', 'all of typo_*' ),
	qr/has an "of" target "typo_\*" that covers no selections/,
	'a *-pattern covering no selections is a load error'
);
like(
	condition_error( 'json/toomany', '3 of them' ),
	qr/asks for 3 of 1 selections, which can never be met/,
	'asking for more than the selection count is a load error'
);
like(
	condition_error( 'json/zeroof', '0 of them' ),
	qr/asks for 0 of, which is vacuously true/,
	'0 of is a load error'
);

done_testing;
