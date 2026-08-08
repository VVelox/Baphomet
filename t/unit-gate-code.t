#!perl
# the compiled gate path... each gate whose shape is settled at load becomes
# a code ref built once, and a rule that is nothing but such gates is run by
# walking them. what is pinned here is which shapes compile, which are left
# to _gate_hit, and that a compiled rule and the general path reach the same
# verdict on every shape either can meet
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Rules::JSON   ();
use App::Baphomet::Rules::Syslog ();

# builds a json rule from a def, the type whose gate is a per-line prefilter
sub json_rule {
	my ( $name, %def ) = @_;

	return App::Baphomet::Rules::JSON->new( 'name' => 'json/' . $name, 'def' => { %def, 'ban_var' => ['src_ip'] } );
}

#
# which gate shapes compile
#

my $plain = json_rule( 'plain', 'gate' => [ { 'field' => 'event_type', 'values' => ['alert'] } ] );
ok( defined( $plain->{gates}[0]{code} ), 'a plain field/values gate compiles to a code ref' );
ok( defined( $plain->{gate_code} ),      'and a rule that is nothing but such gates takes the whole-rule path' );
is( scalar( @{ $plain->{gate_code} } ), 1, 'with one code ref per gate' );

my $two = json_rule(
	'two',
	'gate' => [
		{ 'field' => 'event_type',     'values' => ['alert'] },
		{ 'field' => 'alert.category', 'values' => [ 'Misc Attack', 'Web Application Attack' ] },
	]
);
is( scalar( @{ $two->{gate_code} } ), 2, 'a two-gate rule compiles both' );

my $with_regexp
	= json_rule( 'regexp', 'gate' => [ { 'field' => 'event_type', 'values' => [ 'alert', '//^anom//' ] } ] );
ok( defined( $with_regexp->{gates}[0]{code} ), 'a gate carrying a //regexp// still compiles' );
ok( defined( $with_regexp->{gate_code} ),      'and its rule still takes the whole-rule path' );

# the shapes that keep their branching at runtime
my $predicate = json_rule( 'predicate', 'gate' => [ { 'field' => 'alert.severity', 'op' => 'lt', 'value' => 3 } ] );
ok( !defined( $predicate->{gates}[0]{code} ), 'a typed predicate does not compile' );
ok( !defined( $predicate->{gate_code} ),      'so its rule stays on the general path' );

my $keyword = json_rule( 'keyword', 'gate' => [ { 'field' => '%%%ANY%%%', 'values' => ['bad'] } ] );
ok( !defined( $keyword->{gates}[0]{code} ), 'a keyword fan does not compile' );
ok( !defined( $keyword->{gate_code} ),      'nor does its rule' );

# a rule whose boolean is more than a gate list keeps the general path even
# when every gate of it compiled
my $keyworded
	= json_rule( 'keyworded', 'gate' => [ { 'field' => 'event_type', 'values' => ['alert'] } ], 'keywords' => ['bad'] );
ok( defined( $keyworded->{gates}[0]{code} ), 'a rule with keywords still compiles its gates' );
ok( !defined( $keyworded->{gate_code} ),     'but the keywords must be ANDed in, so it is not a whole-rule walk' );

my $conditioned = json_rule(
	'conditioned',
	'selections' => {
		'is_alert' => [ { 'field' => 'event_type', 'values' => ['alert'] } ],
		'is_flow'  => [ { 'field' => 'event_type', 'values' => ['flow'] } ],
	},
	'condition' => 'is_alert or is_flow'
);
ok( defined( $conditioned->{selections}{is_alert}[0]{code} ), 'a selection arm compiles its gates too' );
ok( !defined( $conditioned->{gate_code} ), 'but a condition decides the rule, so there is no whole-rule walk' );

# MESSAGE reads the raw message when the data does not carry it, which is a
# runtime question, so it is left alone
my $message_gate = App::Baphomet::Rules::Syslog->new(
	'name' => 'syslog/message-gate',
	'def'  => {
		'daemons'        => ['testd'],
		'message_regexp' => ['bad thing from %%%SRC%%%'],
		'gate'           => [ { 'field' => 'MESSAGE', 'values' => ['//port//'] } ],
		'ban_var'        => ['SRC'],
	}
);
ok( !defined( $message_gate->{gates}[0]{code} ), 'a MESSAGE gate does not compile' );
ok( !defined( $message_gate->{gate_code} ),      'so its rule stays on the general path' );

#
# and the point... compiled and general reach the same verdict. each rule is
# run both ways over the same records, the compiled path stood down exactly
# as a rule of an uncompilable shape already is
#

sub both_ways_agree {
	my ( $rule, $records, $label ) = @_;

	my @compiled = map { $rule->check( { 'fields' => $_ }, 'c', {} ) ? 1 : 0 } @{$records};

	my $held_rule = $rule->{gate_code};
	my @held_gate = map { $_->{code} } @{ $rule->{gates} };
	$rule->{gate_code} = undef;
	foreach my $gate ( @{ $rule->{gates} } ) { $gate->{code} = undef; }

	my @general = map { $rule->check( { 'fields' => $_ }, 'g', {} ) ? 1 : 0 } @{$records};

	$rule->{gate_code} = $held_rule;
	for ( my $i = 0; $i < scalar(@held_gate); $i++ ) { $rule->{gates}[$i]{code} = $held_gate[$i]; }

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

both_ways_agree( $plain,       \@records, 'a one-gate rule' );
both_ways_agree( $two,         \@records, 'a two-gate rule' );
both_ways_agree( $with_regexp, \@records, 'a rule whose values carry a regexp' );
both_ways_agree( $predicate,   \@records, 'a predicate rule' );
both_ways_agree( $keyworded,   \@records, 'a rule with keywords beside its gate' );

# a value of 0 is a value... the specialized leaf must test defined and
# membership, not truth, or a gate on it would silently never hit
my $zero = json_rule( 'zero', 'gate' => [ { 'field' => 'event_type', 'values' => ['0'] } ] );
ok( defined( $zero->check( { 'fields' => { 'event_type' => '0', 'src_ip' => '192.0.2.1' } }, 'z', {} ) ),
	'a gate value of "0" hits, truth not being the test' );
ok( !defined( $zero->check( { 'fields' => { 'event_type' => 'alert', 'src_ip' => '192.0.2.1' } }, 'z', {} ) ),
	'and still refuses everything else' );

done_testing();
