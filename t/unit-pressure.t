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

#
# times and baseline... the mark as so many times what is usual
#

# what the meter reads for the seconds up to now, and for the baseline
# before them
my ( $of_late, $usual_before ) = ( 0, 0 );

sub relative_gate {
	my (%args) = @_;

	my $gate = App::Baphomet::Gate::pressure->new(
		'type'  => 'pressure',
		'args'  => { 'times' => 5, 'seconds' => 60, 'baseline' => 3600, %args },
		'where' => 'the gate'
	);
	return $gate->bound(
		{
			'pressure' => sub {
				my ( $scope, $seconds, $up_to ) = @_;
				push( @asked, [@_] );
				return $seconds == 60 ? $of_late : $usual_before;
			},
		},
		'The rule "syslog/siege" of the watcher "auth"'
	);
} ## end sub relative_gate

my $relative = relative_gate();
@asked = ();
( $of_late, $usual_before ) = ( 51, 600 );
is( $relative->ask( { 'now' => 10_000 } ), 1, 'six hundred a hour is ten a minute, and fifty one is more than five times that' );
is_deeply( $asked[-1], [ 'watcher', 3600, 9940 ], 'the baseline is read up to where the seconds begin' );
( $of_late, $usual_before ) = ( 50, 600 );
is( $relative->ask( { 'now' => 10_000 } ), 0, 'exactly five times what is usual is not more than it' );
( $of_late, $usual_before ) = ( 50, 0 );
is( $relative->ask( { 'now' => 10_000 } ), 0, 'with nothing in the baseline there is no saying what is usual, and it is not above it' );

my $floored = relative_gate( 'above' => 100 );
( $of_late, $usual_before ) = ( 51, 600 );
@asked = ();
is( $floored->ask( { 'now' => 10_000 } ), 0, 'with a above beside it the count has to be over that first' );
is( scalar(@asked), 1, 'and under it the baseline is not even read' );
( $of_late, $usual_before ) = ( 101, 600 );
is( $floored->ask( { 'now' => 10_000 } ), 1, 'over both, it lets the line by' );
( $of_late, $usual_before ) = ( 101, 6000 );
is( $floored->ask( { 'now' => 10_000 } ), 0, 'over the count but not the times, it does not' );

my %unpaired = (
	'neither above nor times' => [ { 'seconds' => 60 }, qr/^the gate has neither above nor times/ ],
	'a times with no baseline' => [ { 'seconds' => 60, 'times' => 5 }, qr/^the gate has a times with out a baseline/ ],
	'a baseline with no times' => [ { 'seconds' => 60, 'above' => 5, 'baseline' => 3600 }, qr/^the gate has a times with out a baseline/ ],
);
foreach my $description ( sort( keys(%unpaired) ) ) {
	my ( $args, $message ) = @{ $unpaired{$description} };
	my $error
		= eval { App::Baphomet::Gate::pressure->new( 'type' => 'pressure', 'args' => $args, 'where' => 'the gate' ); 1 }
		? ''
		: $@;
	like( $error, $message, $description . ' is refused' );
}

done_testing();
