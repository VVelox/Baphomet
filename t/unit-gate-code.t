#!perl
# the compiled gate path... each entry of a gate list whose shape is settled
# at load becomes a code ref built once, and a gate gate whose list is
# nothing but such entries is run by walking them. what is pinned here is
# which shapes compile, which are left to _gate_hit, and that the compiled
# walk and the general path reach the same verdict on every shape either can
# meet
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Rule ();

# builds a json rule from the passed gates, the type whose gate is a per-line
# prefilter, with a ban_var of src_ip after them
sub json_rule {
	my ( $name, @gates ) = @_;

	return App::Baphomet::Rule->new(
		'name' => 'json/' . $name,
		'def'  => { 'rule_gates' => [ @gates, { 'ban_var' => ['src_ip'] } ] }
	);
}

#
# which gate shapes compile
#

my $plain = json_rule( 'plain', { 'gate' => [ { 'field' => 'event_type', 'values' => ['alert'] } ] } );
my ($gate_of_plain) = grep { $_->{type} eq 'gate' } @{ $plain->rule_gates };
ok( defined( $gate_of_plain->{gates}[0]{code} ), 'a plain field/values entry compiles to a code ref' );
ok( defined( $gate_of_plain->{code} ), 'and a gate of nothing but such entries walks them as its whole judgment' );
is( scalar( @{ $gate_of_plain->{code} } ), 1, 'with one code ref per entry' );

my $two = json_rule(
	'two',
	{
		'gate' => [
			{ 'field' => 'event_type',     'values' => ['alert'] },
			{ 'field' => 'alert.category', 'values' => [ 'Misc Attack', 'Web Application Attack' ] },
		]
	}
);
my ($gate_of_two) = grep { $_->{type} eq 'gate' } @{ $two->rule_gates };
is( scalar( @{ $gate_of_two->{code} } ), 2, 'a two-entry gate compiles both' );

my $with_regexp
	= json_rule( 'regexp', { 'gate' => [ { 'field' => 'event_type', 'values' => [ 'alert', '//^anom//' ] } ] } );
my ($gate_of_with_regexp) = grep { $_->{type} eq 'gate' } @{ $with_regexp->rule_gates };
ok( defined( $gate_of_with_regexp->{gates}[0]{code} ), 'a entry carrying a //regexp// still compiles' );
ok( defined( $gate_of_with_regexp->{code} ),           'and its gate still has the code refs to walk' );

# the shapes that keep their branching at runtime
my $predicate
	= json_rule( 'predicate', { 'gate' => [ { 'field' => 'alert.severity', 'op' => 'lt', 'value' => 3 } ] } );
my ($gate_of_predicate) = grep { $_->{type} eq 'gate' } @{ $predicate->rule_gates };
ok( !defined( $gate_of_predicate->{gates}[0]{code} ), 'a typed predicate does not compile' );
ok( !defined( $gate_of_predicate->{code} ),           'so its gate stays on the general path' );

my $keyword = json_rule( 'keyword', { 'gate' => [ { 'field' => '%%%ANY%%%', 'values' => ['bad'] } ] } );
my ($gate_of_keyword) = grep { $_->{type} eq 'gate' } @{ $keyword->rule_gates };
ok( !defined( $gate_of_keyword->{gates}[0]{code} ), 'a keyword fan does not compile' );
ok( !defined( $gate_of_keyword->{code} ),           'nor does its gate' );

# what else a rule matches with is a gate of its own, asked in its turn, so a
# gate whose every entry compiled walks them whatever sits beside it... and
# what sits beside it is still ANDed in
my $keyworded = json_rule(
	'keyworded',
	{ 'keywords' => ['bad'] },
	{ 'gate'     => [ { 'field' => 'event_type', 'values' => ['alert'] } ] }
);
my ($gate_of_keyworded) = grep { $_->{type} eq 'gate' } @{ $keyworded->rule_gates };
ok( defined( $gate_of_keyworded->{gates}[0]{code} ), 'a rule with keywords still compiles the entries of its gate' );
ok( defined( $gate_of_keyworded->{code} ), 'and the gate walks them, the keywords being a gate of their own' );
ok(
	!defined( $keyworded->check( { 'fields' => { 'event_type' => 'alert', 'src_ip' => '192.0.2.1' } }, 'k', {} ) ),
	'but the keywords must be ANDed in, so that walk is not the whole rule'
);
ok(
	defined(
		$keyworded->check(
			{ 'fields' => { 'event_type' => 'alert', 'src_ip' => '192.0.2.1', 'payload' => 'a bad one' } },
			'k', {}
		)
	),
	'and a record that gets by both is a offense'
);

my $conditioned = json_rule(
	'conditioned',
	{
		'condition' => {
			'condition'  => 'is_alert or is_flow',
			'selections' => {
				'is_alert' => [ { 'field' => 'event_type', 'values' => ['alert'] } ],
				'is_flow'  => [ { 'field' => 'event_type', 'values' => ['flow'] } ],
			},
		}
	}
);
my ($condition_of_conditioned) = grep { $_->{type} eq 'condition' } @{ $conditioned->rule_gates };
ok( defined( $condition_of_conditioned->{selections}{is_alert}[0]{code} ), 'a selection arm compiles its entries too' );
ok(
	!( grep { defined( $_->{code} ) } @{ $conditioned->rule_gates } ),
	'but a condition decides the rule, so no gate of it has code refs to walk'
);

# MESSAGE reads the raw message when the data does not carry it, which is a
# runtime question, so it is left alone
my $message_gate = App::Baphomet::Rule->new(
	'name' => 'syslog/message-gate',
	'def'  => {
		'rule_gates' => [
			{ 'daemons'        => ['testd'] },
			{ 'message_regexp' => ['bad thing from %%%SRC%%%'] },
			{ 'gate'           => [ { 'field' => 'MESSAGE', 'values' => ['//port//'] } ] },
			{ 'ban_var'        => ['SRC'] },
		],
	}
);
my ($gate_of_message_gate) = grep { $_->{type} eq 'gate' } @{ $message_gate->rule_gates };
ok( !defined( $gate_of_message_gate->{gates}[0]{code} ), 'a MESSAGE entry does not compile' );
ok( !defined( $gate_of_message_gate->{code} ),           'so its gate stays on the general path' );

#
# and the point... compiled and general reach the same verdict. each rule is
# run both ways over the same records, the compiled path of its gate stood
# down exactly as a gate of an uncompilable shape already is
#

sub both_ways_agree {
	my ( $rule, $records, $label ) = @_;

	my @compiled = map { $rule->check( { 'fields' => $_ }, 'c', {} ) ? 1 : 0 } @{$records};

	my ($gate)       = grep { $_->{type} eq 'gate' } @{ $rule->rule_gates };
	my $held_gate    = $gate->{code};
	my @held_entries = map { $_->{code} } @{ $gate->{gates} };
	$gate->{code} = undef;
	foreach my $entry ( @{ $gate->{gates} } ) { $entry->{code} = undef; }

	my @general = map { $rule->check( { 'fields' => $_ }, 'g', {} ) ? 1 : 0 } @{$records};

	$gate->{code} = $held_gate;
	for ( my $i = 0; $i < scalar(@held_entries); $i++ ) { $gate->{gates}[$i]{code} = $held_entries[$i]; }

	is_deeply( \@compiled, \@general, 'compiled and general agree on ' . $label );

	return;
} ## end sub both_ways_agree

my @records = (
	{ 'event_type' => 'alert',   'src_ip' => '192.0.2.1', 'alert.category' => 'Misc Attack' },
	{ 'event_type' => 'alert',   'src_ip' => '192.0.2.2', 'alert.category' => 'Web Application Attack' },
	{ 'event_type' => 'alert',   'src_ip' => '192.0.2.3', 'alert.category' => 'Not Suspicious Traffic' },
	{ 'event_type' => 'anomaly', 'src_ip' => '192.0.2.4' },
	{ 'event_type' => 'flow',    'src_ip' => '192.0.2.5' },
	# the indexed field absent, and present but empty
	{ 'src_ip'     => '192.0.2.6' },
	{ 'event_type' => '', 'src_ip' => '192.0.2.7' },
	# a field carrying 0, which must not be read as absent
	{ 'event_type' => '0', 'src_ip' => '192.0.2.8' },
);

both_ways_agree( $plain,       \@records, 'a one-entry gate' );
both_ways_agree( $two,         \@records, 'a two-entry gate' );
both_ways_agree( $with_regexp, \@records, 'a gate whose values carry a regexp' );
both_ways_agree( $predicate,   \@records, 'a predicate gate' );
both_ways_agree( $keyworded,   \@records, 'a rule with keywords beside its gate' );

# a value of 0 is a value... the specialized leaf must test defined and
# membership, not truth, or a gate on it would silently never hit
my $zero = json_rule( 'zero', { 'gate' => [ { 'field' => 'event_type', 'values' => ['0'] } ] } );
ok( defined( $zero->check( { 'fields' => { 'event_type' => '0', 'src_ip' => '192.0.2.1' } }, 'z', {} ) ),
	'a gate value of "0" hits, truth not being the test' );
ok( !defined( $zero->check( { 'fields' => { 'event_type' => 'alert', 'src_ip' => '192.0.2.1' } }, 'z', {} ) ),
	'and still refuses everything else' );

done_testing();
