#!perl
# direct unit tests for App::Baphomet::Gate, what finds a gate type, compiles
# a rule's rule_gates, and binds them for asking... over gate types of the
# test's own, so the order, the phases, the passes, and every refusal are
# pinned with out a rule file or a galla
use 5.006;
use strict;
use warnings;
use Test::More;
use List::Util qw( all );

use App::Baphomet::Gate qw( gate_class compile_rule_gates bind_rule_gates walk_offense );

# stands in for a rule, which the gates here are handed and ask nothing of
package Local::Rule {
	sub new { return bless( {}, $_[0] ); }
}

# a gate type as one from outside the tree would be, a class under the
# namespace... it keeps what it is told, answers what it was told to, and
# notes each asking, so the order gates are asked in can be read back. it is
# of the offense phase unless told a phase
package App::Baphomet::Gate::probe {
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

	sub phase {
		my ($self) = @_;
		return $self->{phase} // 'offense';
	}

	sub needs {
		my ($self) = @_;
		return @{ $self->{needs} // [] };
	}

	sub holds {
		my ( $self, $data, $ip, $now ) = @_;

		push( @asked, $self->{name} . ( defined($ip) ? ' of ' . $ip : '' ) );
		return $self->{answer};
	}

	# one told to be of the line phase lets every line by, a gate of that
	# phase having to have a ask of its own... of the offense phase it is
	# asked as any gate that judges by holds is
	sub ask {
		my ( $self, $asked_of ) = @_;

		if ( $self->phase eq 'line' ) {
			return 1;
		}
		return $self->SUPER::ask($asked_of);
	}
} ## end package App::Baphomet::Gate::probe

# three that are each wrong one way... nothing to be asked by, a phase that is
# neither of the two, and a class that is no gate at all
package App::Baphomet::Gate::mute {
	use parent -norequire, 'App::Baphomet::Gate';
	sub compile { return; }
}

package App::Baphomet::Gate::sometime {
	use parent -norequire, 'App::Baphomet::Gate';
	sub compile { return; }
	sub phase   { return 'sometime'; }
	sub holds   { return 1; }
}

package App::Baphomet::Gate::stranger {
	sub new { return bless( {}, $_[0] ); }
}

package main;

# the types above live in this file, so the load gate_class does finds them
# already loaded
foreach my $class_file ( 'probe', 'mute', 'sometime', 'stranger' ) {
	$INC{ 'App/Baphomet/Gate/' . $class_file . '.pm' } = __FILE__;
}

my $rule = Local::Rule->new;

#
# gate_class... a type name to its class, and nothing from outside the
# namespace
#

is(
	gate_class( 'country', 'here' ),
	'App::Baphomet::Gate::country',
	'the class of a type is named as the type is'
);
is( gate_class( 'namtar_list', 'here' ), 'App::Baphomet::Gate::namtar_list', 'underscores and all' );
is( gate_class( 'reverse_dns', 'here' ), 'App::Baphomet::Gate::reverse_dns', 'with nothing recased' );
is( gate_class( 'probe', 'here' ), 'App::Baphomet::Gate::probe', 'a type from outside the tree is found the same way' );

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
	qr/^here names the gate "stranger", whose class App::Baphomet::Gate::stranger is not a App::Baphomet::Gate/,
	'and the die names the class'
);

#
# compile_rule_gates... the list to its gates, in order
#

is_deeply( compile_rule_gates( undef, $rule, 'json/x' ), [], 'a rule with out rule_gates has none' );

foreach my $not_a_list ( {}, 'probe', [] ) {
	ok( !eval { compile_rule_gates( $not_a_list, $rule, 'json/x' ); 1; }, 'a rule_gates that is no list dies' );
	like( $@, qr/^The rule_gates of the rule "json\/x" is not a non-empty array/, 'naming the rule' );
}

foreach my $not_a_entry ( 'probe', ['probe'], {}, { 'probe' => {}, 'mute' => {} } ) {
	ok( !eval { compile_rule_gates( [ { 'probe' => { 'var' => 'user' } }, $not_a_entry ], $rule, 'json/x' ); 1; },
		'a entry that is not a hash of one key dies' );
	like(
		$@,
		qr/^The rule_gates of the rule "json\/x" entry 1 is not a hash of one key, the gate type/,
		'naming the rule and the entry'
	);
}

# two of the line phase among the rest, and the ban_var that the ones keyed by
# the offender have to be below
my $compiled = compile_rule_gates(
	[
		{ 'probe'   => { 'name' => 'line one', 'phase' => 'line' } },
		{ 'probe'   => { 'name' => 'first',    'var'   => 'user' } },
		{ 'ban_var' => ['ip'] },
		{ 'probe'   => { 'name' => 'second' } },
		{ 'probe'   => { 'name' => 'line two', 'phase' => 'line' } },
		{ 'probe'   => { 'name' => 'third',    'vars'  => [ 'user', 'host' ] } },
		{ 'probe'   => { 'name' => 'fourth' } },
	],
	$rule, 'json/x'
);
is_deeply(
	[ map { $_->{name} // $_->{type} } @{$compiled} ],
	[ 'line one', 'first', 'ban_var', 'second', 'line two', 'third', 'fourth' ],
	'the gates are in the order written'
);
my %probe_named = map { $_->{name} => $_ } grep { $_->{type} eq 'probe' } @{$compiled};
is_deeply(
	[ map { $probe_named{$_}->pass } ( 'first', 'second', 'third', 'fourth' ) ],
	[ 'result', 'offender', 'result', 'offender' ],
	'one naming a var or vars is of the result pass, one naming neither of the offender pass'
);
is( $compiled->[0]{type}, 'probe', 'a gate knows the type it was named by' );

ok( !eval { compile_rule_gates( [ { 'probe' => 'told nothing' } ], $rule, 'json/x' ); 1; },
	'what a type refuses of what it is told dies' );
is(
	$@ =~ s/ at \S+ line \d+\.\n\z//r,
	'The probe gate of the rule "json/x" (rule_gates entry 0) is not a hash',
	'led by the gate, the rule, and the entry'
);

# below a ban_var, so having nothing to be asked by is all that is wrong with it
ok( !eval { compile_rule_gates( [ { 'ban_var' => ['ip'] }, { 'mute' => {} } ], $rule, 'json/x' ); 1; },
	'a type with nothing to be asked by dies' );
like(
	$@,
	qr/^The mute gate of the rule "json\/x" \(rule_gates entry 1\) is of a type with no ask or holds method/,
	'at load, not on the first match'
);

ok( !eval { compile_rule_gates( [ { 'sometime' => {} } ], $rule, 'json/x' ); 1; },
	'a phase that is neither of the two dies' );
like( $@, qr/is of the phase "sometime", which is neither line nor offense/, 'as it would never be asked' );

#
# a gate keyed by the offender, which has to have one named above it... a
# detection rule, one whose list has a detection_var, has no offender at all
#

ok(
	!eval {
		compile_rule_gates( [ { 'detection_var' => ['user'] }, { 'probe' => { 'name' => 'by offender' } } ],
			$rule, 'json/x' );
		1;
	},
	'a gate of the offender pass on a detection rule dies'
);
is(
	$@ =~ s/ at \S+ line \d+\.\n\z//r,
	'The probe gate of the rule "json/x" (rule_gates entry 1) keys on the offender, '
		. 'which a detection rule does not have... name a var for it to check',
	'saying why and the way out'
);
is(
	scalar(
		@{
			compile_rule_gates(
				[ { 'detection_var' => ['user'] }, { 'probe' => { 'name' => 'by var', 'var' => 'user' } } ],
				$rule, 'json/x'
			)
		}
	),
	2,
	'while one of the result pass loads on it'
);

ok(
	!eval {
		compile_rule_gates( [ { 'probe' => { 'name' => 'by offender' } }, { 'ban_var' => ['ip'] } ], $rule, 'json/x' );
		1;
	},
	'a gate of the offender pass with no ban_var above it dies'
);
is(
	$@ =~ s/ at \S+ line \d+\.\n\z//r,
	'The probe gate of the rule "json/x" (rule_gates entry 0) keys on the offender, '
		. 'and no ban_var above it names one',
	'saying what it lacks'
);

#
# bind_rule_gates... sorted by phase, the order kept, and nothing left out
#

my $bound = bind_rule_gates( $compiled, {}, 'the rule "x"' );
is_deeply(
	[ map { $_->{name} // $_->{type} } @{ $bound->{offense} } ],
	[ 'first', 'ban_var', 'second', 'third', 'fourth' ],
	'the offense phase keeps the order written'
);
is_deeply( [ map { $_->{name} } @{ $bound->{line} } ], [ 'line one', 'line two' ], 'and so does the line phase' );
ok( ( all { !exists( $_->{context} ) } @{$compiled} ), 'binding leaves the compiled gates as they were' );

is_deeply(
	bind_rule_gates( [], {}, 'the rule "x"' ),
	{ 'line' => [], 'offense' => [], 'early' => 0, 'last_always' => -1 },
	'a rule with out gates binds to two empty phases'
);

my $wanting = compile_rule_gates(
	[ { 'probe' => { 'name' => 'wanting', 'var' => 'user', 'needs' => [ 'marks', 'locator' ] } } ],
	$rule, 'json/x'
);
my %context = ( 'marks' => sub { return {}; }, 'locator' => sub { return 'US'; }, 'resolver' => sub { return undef; } );
is_deeply(
	[ sort( keys( %{ bind_rule_gates( $wanting, \%context, 'the rule "x"' )->{offense}[0]{context} } ) ) ],
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
# asking... the offense phase in the order written, the first veto ending it
#

# the gates of the result pass, which read the offense
my $asked_of_result = bind_rule_gates(
	compile_rule_gates(
		[
			{ 'probe' => { 'name' => 'one',   'answer' => 1, 'var' => 'user' } },
			{ 'probe' => { 'name' => 'three', 'answer' => 0, 'var' => 'user' } },
			{ 'probe' => { 'name' => 'five',  'answer' => 1, 'var' => 'user' } },
		],
		$rule, 'json/x'
	),
	{},
	'the rule "x"'
);
# and those of the offender pass, below the ban_var that names who they are
# asked of
my $asked_of_offender = bind_rule_gates(
	compile_rule_gates(
		[
			{ 'ban_var' => ['ip'] },
			{ 'probe'   => { 'name' => 'two',  'answer' => 1 } },
			{ 'probe'   => { 'name' => 'four', 'answer' => 0 } },
			{ 'probe'   => { 'name' => 'six',  'answer' => 1 } },
		],
		$rule, 'json/x'
	),
	{},
	'the rule "x"'
);

@App::Baphomet::Gate::probe::asked = ();
ok(
	!walk_offense( $asked_of_result, { 'data' => { 'user' => 'neti', 'ip' => '192.0.2.7' }, 'now' => 0 } ),
	'a walk with a gate that does not hold does not stand'
);
is_deeply( \@App::Baphomet::Gate::probe::asked, [ 'one', 'three' ], 'and the gates after the veto are not asked' );

@App::Baphomet::Gate::probe::asked = ();
ok( !walk_offense( $asked_of_offender, { 'data' => { 'user' => 'neti', 'ip' => '192.0.2.7' }, 'now' => 0 } ),
	'the same of the offender pass' );
is_deeply(
	\@App::Baphomet::Gate::probe::asked,
	[ 'two of 192.0.2.7', 'four of 192.0.2.7' ],
	'which is handed the offender'
);

done_testing;
