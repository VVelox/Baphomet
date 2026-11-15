#!perl
# direct unit tests for App::Baphomet::Gate, what finds a gate type, compiles
# a rule's rule_gates, and binds them for asking... over gate types of the
# test's own, so the order, the passes, and every refusal are pinned with out
# a rule file or a galla
use 5.006;
use strict;
use warnings;
use Test::More;
use List::Util qw( all );

use App::Baphomet::Gate qw( gate_class compile_rule_gates bind_rule_gates );

# stands in for a rule, of which the gates only ask if it is detection-only
package Local::Rule {

	sub new {
		my ( $class, $is_detection ) = @_;
		return bless( { 'is_detection' => $is_detection }, $class );
	}

	sub is_detection {
		my ($self) = @_;
		return $self->{is_detection};
	}
} ## end package Local::Rule

# a gate type as one from outside the tree would be, a class under the
# namespace... it keeps what it is told, answers what it was told to, and
# notes each asking, so the order gates are asked in can be read back
package App::Baphomet::Gate::Probe {
	use parent -norequire, 'App::Baphomet::Gate';

	our @asked;

	sub compile {
		my ( $self, $args, $where, $rule ) = @_;

		if ( ref($args) ne 'HASH' ) {
			die( $where . ' is not a hash' );
		}
		foreach my $key ( keys( %{$args} ) ) {
			$self->{$key} = $args->{$key};
		}
		return;
	} ## end sub compile

	sub needs {
		my ($self) = @_;
		return @{ $self->{wants} // [] };
	}

	sub holds {
		my ( $self, $data, $ip, $now ) = @_;

		push( @asked, $self->{name} . ( defined($ip) ? ' of ' . $ip : '' ) );
		return $self->{answer};
	}
} ## end package App::Baphomet::Gate::Probe

# three that are each wrong one way... nothing to be asked by, a pass that is
# neither of the two, and a class that is no gate at all
package App::Baphomet::Gate::Mute {
	use parent -norequire, 'App::Baphomet::Gate';
	sub compile { return; }
}

package App::Baphomet::Gate::Sometime {
	use parent -norequire, 'App::Baphomet::Gate';
	sub compile { return; }
	sub pass    { return 'sometime'; }
	sub holds   { return 1; }
}

package App::Baphomet::Gate::Stranger {
	sub new { return bless( {}, $_[0] ); }
}

package main;

# the types above live in this file, so the load gate_class does finds them
# already loaded
foreach my $class_file ( 'Probe', 'Mute', 'Sometime', 'Stranger' ) {
	$INC{ 'App/Baphomet/Gate/' . $class_file . '.pm' } = __FILE__;
}

my $banning   = Local::Rule->new(0);
my $detection = Local::Rule->new(1);

#
# gate_class... a type name to its class, and nothing from outside the
# namespace
#

is( gate_class( 'country',     'here' ), 'App::Baphomet::Gate::Country', 'a one word type is that word capitalized' );
is( gate_class( 'namtar_list', 'here' ), 'App::Baphomet::Gate::NamtarList', 'each word of a type is capitalized' );
is( gate_class( 'reverse_dns', 'here' ), 'App::Baphomet::Gate::ReverseDns', 'and only its first letter' );
is( gate_class( 'probe', 'here' ), 'App::Baphomet::Gate::Probe', 'a type from outside the tree is found the same way' );

ok( !eval { gate_class( 'no_such_gate', 'here' ); 1; }, 'a type there is no class for dies' );
is(
	$@ =~ s/ at \S+ line \d+\.\n\z//r,
	'here names the gate "no_such_gate", which is not a known gate type',
	'and says so plainly'
);

foreach my $not_a_name ( 'Country', 'country::evil', '../country', 'a__b', '_a', 'a_', '9lives', '' ) {
	ok( !eval { gate_class( $not_a_name, 'here' ); 1; }, 'the name "' . $not_a_name . '" is refused' );
	like( $@, qr/^here names the gate ".*", which is not a gate type name/, 'as not a gate type name' );
}

ok( !eval { gate_class( 'stranger', 'here' ); 1; }, 'a class that is not a App::Baphomet::Gate dies' );
like(
	$@,
	qr/^here names the gate "stranger", whose class App::Baphomet::Gate::Stranger is not a App::Baphomet::Gate/,
	'and the die names the class'
);

#
# compile_rule_gates... the list to its gates, in order
#

is_deeply( compile_rule_gates( undef, $banning, 'json/x' ), [], 'a rule with out rule_gates has none' );

foreach my $not_a_list ( {}, 'probe', [] ) {
	ok( !eval { compile_rule_gates( $not_a_list, $banning, 'json/x' ); 1; }, 'a rule_gates that is no list dies' );
	like( $@, qr/^The rule_gates of the rule "json\/x" is not a non-empty array/, 'naming the rule' );
}

foreach my $not_a_entry ( 'probe', ['probe'], {}, { 'probe' => {}, 'mute' => {} } ) {
	ok( !eval { compile_rule_gates( [ { 'probe' => {} }, $not_a_entry ], $banning, 'json/x' ); 1; },
		'a entry that is not a hash of one key dies' );
	like(
		$@,
		qr/^The rule_gates of the rule "json\/x" entry 1 is not a hash of one key, the gate type/,
		'naming the rule and the entry'
	);
}

my $compiled = compile_rule_gates(
	[
		{ 'probe' => { 'name' => 'first', 'var' => 'user' } },
		{ 'probe' => { 'name' => 'second' } },
		{ 'probe' => { 'name' => 'third', 'vars' => [ 'user', 'host' ] } },
		{ 'probe' => { 'name' => 'fourth' } },
	],
	$banning, 'json/x'
);
is_deeply(
	[ map { $_->{name} } @{$compiled} ],
	[ 'first', 'second', 'third', 'fourth' ],
	'the gates are in the order written'
);
is_deeply(
	[ map { $_->pass } @{$compiled} ],
	[ 'result', 'offender', 'result', 'offender' ],
	'one naming a var or vars is of the result pass, one naming neither of the offender pass'
);
is( $compiled->[0]{type}, 'probe', 'a gate knows the type it was named by' );

ok( !eval { compile_rule_gates( [ { 'probe' => 'told nothing' } ], $banning, 'json/x' ); 1; },
	'what a type refuses of what it is told dies' );
is(
	$@ =~ s/ at \S+ line \d+\.\n\z//r,
	'The probe gate of the rule "json/x" (rule_gates entry 0) is not a hash',
	'led by the gate, the rule, and the entry'
);

ok( !eval { compile_rule_gates( [ { 'mute' => {} } ], $banning, 'json/x' ); 1; },
	'a type with nothing to be asked by dies' );
like(
	$@,
	qr/^The mute gate of the rule "json\/x" \(rule_gates entry 0\) is of a type with no holds method/,
	'at load, not on the first match'
);

ok( !eval { compile_rule_gates( [ { 'sometime' => {} } ], $banning, 'json/x' ); 1; },
	'a pass that is neither of the two dies' );
like( $@, qr/is of the pass "sometime", which is neither result nor offender/, 'as it would never be asked' );

#
# a gate keyed by the offender on a detection rule, which has no offender
#

ok( !eval { compile_rule_gates( [ { 'probe' => { 'name' => 'by offender' } } ], $detection, 'json/x' ); 1; },
	'a gate of the offender pass on a detection rule dies' );
is(
	$@ =~ s/ at \S+ line \d+\.\n\z//r,
	'The probe gate of the rule "json/x" (rule_gates entry 0) keys on the offender, '
		. 'which a detection rule does not have... name a var for it to check',
	'saying why and the way out'
);
is(
	scalar(
		@{ compile_rule_gates( [ { 'probe' => { 'name' => 'by var', 'var' => 'user' } } ], $detection, 'json/x' ) }
	),
	1,
	'while one of the result pass loads on it'
);

#
# bind_rule_gates... sorted by pass, the order kept, and nothing left out
#

my $bound = bind_rule_gates( $compiled, {}, 'the rule "x"' );
is_deeply(
	[ map { $_->{name} } @{ $bound->{result} } ],
	[ 'first', 'third' ],
	'the result pass keeps the order written'
);
is_deeply( [ map { $_->{name} } @{ $bound->{offender} } ], [ 'second', 'fourth' ], 'and so does the offender pass' );
ok( ( all { !exists( $_->{context} ) } @{$compiled} ), 'binding leaves the compiled gates as they were' );

is_deeply(
	bind_rule_gates( [], {}, 'the rule "x"' ),
	{ 'result' => [], 'offender' => [] },
	'a rule with out gates binds to two empty passes'
);

my $wanting = compile_rule_gates( [ { 'probe' => { 'name' => 'wanting', 'wants' => [ 'marks', 'locator' ] } } ],
	$banning, 'json/x' );
my %context = ( 'marks' => sub { return {}; }, 'locator' => sub { return 'US'; }, 'resolver' => sub { return undef; } );
is_deeply(
	[ sort( keys( %{ bind_rule_gates( $wanting, \%context, 'the rule "x"' )->{offender}[0]{context} } ) ) ],
	[ 'locator', 'marks' ],
	'a bound gate holds what it needs of the context and no more'
);

ok( !eval { bind_rule_gates( $wanting, { 'marks' => $context{marks} }, 'the rule "x"' ); 1; },
	'a gate needing what the context lacks dies' );
is(
	$@ =~ s/ at \S+ line \d+\.\n\z//r,
	'the rule "x" has a probe gate, which can not judge with out locator, and there is none here',
	'naming the rule, the gate, and what is missing'
);

#
# asking... each pass in the order written, the first veto ending it
#

my $asked = compile_rule_gates(
	[
		{ 'probe' => { 'name' => 'one',   'answer' => 1, 'var' => 'user' } },
		{ 'probe' => { 'name' => 'two',   'answer' => 1 } },
		{ 'probe' => { 'name' => 'three', 'answer' => 0, 'var' => 'user' } },
		{ 'probe' => { 'name' => 'four',  'answer' => 0 } },
		{ 'probe' => { 'name' => 'five',  'answer' => 1, 'var' => 'user' } },
		{ 'probe' => { 'name' => 'six',   'answer' => 1 } },
	],
	$banning, 'json/x'
);
my $asked_bound = bind_rule_gates( $asked, {}, 'the rule "x"' );

@App::Baphomet::Gate::Probe::asked = ();
ok(
	!( all { $_->holds( {}, undef, 0 ) } @{ $asked_bound->{result} } ),
	'a pass with a gate that does not hold does not hold'
);
is_deeply( \@App::Baphomet::Gate::Probe::asked, [ 'one', 'three' ], 'and the gates after the veto are not asked' );

@App::Baphomet::Gate::Probe::asked = ();
ok( !( all { $_->holds( {}, '192.0.2.7', 0 ) } @{ $asked_bound->{offender} } ), 'the same of the offender pass' );
is_deeply(
	\@App::Baphomet::Gate::Probe::asked,
	[ 'two of 192.0.2.7', 'four of 192.0.2.7' ],
	'which is handed the offender'
);

done_testing;
