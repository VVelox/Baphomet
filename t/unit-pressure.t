#!perl
# direct unit tests for App::Baphomet::Gate::pressure, the pressure gate... a
# reading it is handed stands in for the galla's meter, so the mark, the
# latch, and what it says when it flips are pinned with out one
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::pressure ();

# what the meter reads, what it was asked for, and what the gate said
my $matched = 0;
my @asked;
my @said;

# a pressure gate told what a rule entry would tell it, bound over the
# reading above
sub pressure_gate {
	my ($args) = @_;

	my $gate = App::Baphomet::Gate::pressure->new( 'type' => 'pressure', 'args' => $args, 'where' => 'the gate' );
	return $gate->bound(
		{
			'pressure' => sub { push( @asked, [@_] ); return $matched; },
			'notice'   => sub { push( @said,  $_[0] ); return; },
		},
		'The rule "syslog/siege" of the watcher "auth"'
	);
} ## end sub pressure_gate

my $compiled = App::Baphomet::Gate::pressure->new(
	'type'  => 'pressure',
	'args'  => { 'above' => 200, 'seconds' => 60 },
	'where' => 'the gate'
);
is( $compiled->phase,   'line',    'it is of the line phase' );
is( $compiled->early,   1,         'and may be asked before anything is made of the line' );
is( $compiled->{hold},  0,         'it does not hold unless told to' );
is( $compiled->{scope}, 'watcher', 'and counts over its watcher unless told otherwise' );
is_deeply( [ $compiled->needs ], ['pressure'], 'it needs the meter' );
is_deeply( [ $compiled->wants ], ['notice'],   'and uses notice when it is there' );

foreach my $bad ( { 'seconds' => 60 }, { 'above' => 200 }, { 'above' => 0, 'seconds' => 60 },
	{ 'above' => 200, 'seconds' => 60, 'scope' => 'kur' } )
{
	ok(
		!eval {
			App::Baphomet::Gate::pressure->new( 'type' => 'pressure', 'args' => $bad, 'where' => 'the gate' );
			1;
		},
		'a entry of ' . join( ', ', map { $_ . ' ' . $bad->{$_} } sort( keys( %{$bad} ) ) ) . ' is refused'
	);
} ## end foreach my $bad ( { 'seconds' => 60 }, { 'above' =>...})
like( $@, qr/^the gate has a scope that is not one of watcher or galla/, 'and says why' );

#
# the mark
#

my $gate = pressure_gate( { 'above' => 200, 'seconds' => 60, 'scope' => 'galla' } );
$matched = 200;
is( $gate->ask( { 'now' => 1000 } ), 0, 'a count at the mark is not above it' );
is_deeply( $asked[-1], [ 'galla', 60, 1000 ], 'the meter is asked for the gate\'s scope and seconds, up to the line\'s time' );
is_deeply( \@said, [], 'and a gate that stays shut says nothing' );

$matched = 201;
is( $gate->ask( { 'now' => 1001 } ), 1, 'one above the mark lets the line by' );
is_deeply(
	\@said,
	['The rule "syslog/siege" of the watcher "auth" is under pressure, 201 matched lines in the last 60 seconds'],
	'and the gate says it has opened, once'
);
is( $gate->ask( { 'now' => 1002 } ), 1, 'it goes on letting lines by' );
is( scalar(@said), 1, 'and does not say so again' );

$matched = 150;
is( $gate->ask( { 'now' => 1003 } ), 0, 'with no hold it shuts as soon as the count is not above the mark' );
is(
	$said[-1],
	'The rule "syslog/siege" of the watcher "auth" is no longer under pressure, 150 matched lines in the last 60 seconds',
	'and says that it has'
);

# asked with nothing of a line but what was parsed, as a gate leading a rule
# is, it reads the clock for itself
my $before = time;
$gate->ask( { 'parsed' => {} } );
ok( $asked[-1][2] >= $before, 'with no time on what it is asked of it reads the clock' );

#
# the latch
#

@said = ();
my $latched = pressure_gate( { 'above' => 200, 'seconds' => 60, 'hold' => 300 } );
$matched = 500;
is( $latched->ask( { 'now' => 5000 } ), 1, 'above the mark' );
$matched = 0;
is( $latched->ask( { 'now' => 5001 } ), 1, 'a lull does not shut a gate that holds' );
is( $latched->ask( { 'now' => 5299 } ), 1, 'not for the whole of the hold' );
is( $latched->ask( { 'now' => 5300 } ), 0, 'the hold over, it shuts' );
is( scalar(@said),                      2, 'having said so twice, once each way' );
$matched = 500;
is( $latched->ask( { 'now' => 5400 } ), 1, 'a second wave opens it again' );
$matched = 0;
is( $latched->ask( { 'now' => 5699 } ), 1, 'and the hold is measured from when the count was last above the mark' );
is( $latched->ask( { 'now' => 5700 } ), 0, 'not from when the gate first opened' );

# two watchers binding the one rule each have a gate of their own
my $other = pressure_gate( { 'above' => 200, 'seconds' => 60, 'hold' => 300 } );
$matched = 500;
$other->ask( { 'now' => 9000 } );
$matched = 0;
is( $latched->ask( { 'now' => 9001 } ), 0, 'one bound gate being held open does not hold another' );

done_testing();
