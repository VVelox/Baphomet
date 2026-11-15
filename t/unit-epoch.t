#!perl
# direct unit tests for App::Baphomet::Gate::epoch and
# App::Baphomet::Gate::fresh... what a timestamp comes to however it was
# written, where the seconds are put, and which lines are old news
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::epoch qw( timestamp_epoch );
use App::Baphomet::Gate::fresh ();

# 2026-07-12T13:15:50Z, and a now a little after it
my $instant = 1783862150;
my $now     = $instant + 100;

#
# timestamp_epoch... each way a timestamp is written
#

my @readings = (
	[ '12/Jul/2026:08:15:50 -0500',      'auto',     'utc',    'a access log timestamp, its own zone settling the instant' ],
	[ 'Jul 12 13:15:50',                 'auto',     'utc',    'a syslog timestamp, given this year' ],
	[ 'Sun Jul 12 13:15:50.123456 2026', 'auto',     'utc',    'a apache error log timestamp, its fraction of a second off' ],
	[ '2026/07/12 13:15:50',             'auto',     'utc',    'a nginx error log timestamp' ],
	[ '2026-07-12T13:15:50.123Z',        'auto',     'local',  'a ISO 8601 timestamp in Z, whatever zone was passed' ],
	[ '2026-07-12T15:15:50+02:00',       'iso8601',  'utc',    'a ISO 8601 timestamp with a offset' ],
	[ '2026-07-12 08:15:50',             'iso8601',  '-05:00', 'a ISO 8601 timestamp with no zone, read in the one passed' ],
	[ '2026-07-12 08:15:50',             'iso8601',  '-0500',  'a offset written with no colon' ],
	[ '1783862150',                      'auto',     'utc',    'seconds since the epoch' ],
	[ '1783862150123',                   'auto',     'utc',    'milliseconds, told by how many digits there are' ],
	[ '1783862150123456',                'auto',     'utc',    'and microseconds' ],
	[ '1783862150',                      'epoch',    'utc',    'seconds, said to be' ],
	[ '1783862150999',                   'epoch_ms', 'utc',    'milliseconds, said to be' ],
	[ '1783862150999999',                'epoch_us', 'utc',    'microseconds, said to be' ],
	[ '12.07.2026 13:15:50',             '%d.%m.%Y %H:%M:%S', 'utc', 'a strptime format of the rule\'s own' ],
	[ '12.07.2026 14:15:50',             '%d.%m.%Y %H:%M:%S', '+01:00', 'and that in a zone ahead of utc' ],
);
foreach my $reading (@readings) {
	my ( $timestamp, $format, $zone, $description ) = @{$reading};
	is( timestamp_epoch( $timestamp, $format, $zone, $now ), $instant, $description );
}

is( timestamp_epoch( 'Jul  2 13:15:50', 'auto', 'utc', $now ), $instant - 10 * 86400, 'a syslog day under ten, padded with a second blank' );
is( timestamp_epoch( 'Dec 31 23:59:59', 'auto', 'utc', $now ),
	1767225599, 'a timestamp with no year that would be months ahead is last year\'s' );
is( timestamp_epoch( 'Jul 13 12:00:00', 'auto', 'utc', $now ),
	$instant + 81850, 'one less than a day ahead is this year\'s, the clock that wrote it running fast' );

# the host's own zone, checked against what perl makes of the same parts
is( timestamp_epoch( '2026-07-12 13:15:50', 'iso8601', 'local', $now ),
	Time::Local::timelocal( 50, 15, 13, 12, 6, 2026 ), 'local is the host\'s own zone' );

foreach my $unreadable (
	[ 'garbage',               'auto' ],
	[ '',                      'auto' ],
	[ undef,                   'auto' ],
	[ [],                      'auto' ],
	[ 'Jul 12 13:15:50 extra', '%b %d %H:%M:%S' ],
	[ 'Jul 12 13:15:50',       'iso8601' ],
	[ '2026-02-31T00:00:00Z',  'iso8601' ],
	[ 'soon',                  'epoch' ],
	)
{
	is( timestamp_epoch( $unreadable->[0], $unreadable->[1], 'utc', $now ),
		undef, 'a timestamp that is not as ' . $unreadable->[1] . ' has it is undef' );
} ## end foreach my $unreadable ( [ 'garbage', 'auto' ], [...])

#
# the epoch gate... where the seconds go
#

sub epoch_gate {
	my (%args) = @_;

	return App::Baphomet::Gate::epoch->new( 'type' => 'epoch', 'args' => { 'zone' => 'utc', %args }, 'where' => 'the gate' );
}

my $own = epoch_gate( 'into' => 'WHEN' );
is( $own->phase, 'line', 'it is of the line phase' );

# a syslog line has no fields until a gate lays some down
my %passage = ( 'parsed' => { 'time' => 'Jul 12 13:15:50' }, 'now' => $now, 'rule' => {} );
is( $own->ask( \%passage ), 1, 'it turns no line away' );
is_deeply( $passage{fields}, { 'WHEN' => $instant }, 'the line\'s own timestamp goes into the into, a field space made for it' );
ok( $passage{fields_owned}, 'which is the rule\'s own' );

# a field space every rule on the line shares is not written to
my %shared = ( 'time' => '12/Jul/2026:08:15:50 -0500', 'host' => '203.0.113.9' );
%passage = ( 'parsed' => {}, 'now' => $now, 'rule' => {}, 'fields' => \%shared, 'fields_owned' => 0 );
epoch_gate( 'var' => 'time', 'into' => 'WHEN' )->ask( \%passage );
is( $passage{fields}{WHEN}, $instant,                     'with a var and a into the seconds go into the into' );
is( $passage{fields}{time}, '12/Jul/2026:08:15:50 -0500', 'and the var is left as it was' );
ok( !exists( $shared{WHEN} ), 'the shared fields are copied, not written to' );

%passage = ( 'parsed' => {}, 'now' => $now, 'rule' => {}, 'fields' => {%shared}, 'fields_owned' => 1 );
epoch_gate( 'var' => 'time' )->ask( \%passage );
is( $passage{fields}{time}, $instant, 'with no into the var is converted where it is' );

%passage = ( 'parsed' => {}, 'now' => $now, 'rule' => {}, 'fields' => { 'time' => 'whenever' }, 'fields_owned' => 1 );
is( epoch_gate( 'var' => 'time' )->ask( \%passage ), 1, 'a timestamp that can not be read turns no line away' );
is( $passage{fields}{time}, 'whenever', 'and is left as it was' );
%passage = ( 'parsed' => {}, 'now' => $now, 'rule' => {}, 'fields' => { 'time' => 'whenever' }, 'fields_owned' => 1 );
epoch_gate( 'var' => 'time', 'into' => 'WHEN' )->ask( \%passage );
ok( !exists( $passage{fields}{WHEN} ), 'or the into left unset' );

ok( !eval { epoch_gate(); 1 }, 'a gate with neither a var nor a into is refused' );
like( $@, qr/^the gate has neither a var nor a into/, 'and says so' );
ok( !eval { epoch_gate( 'into' => 'WHEN', 'zone' => 'Europe/Paris' ); 1 }, 'a zone that is neither local, utc, nor a offset is refused' );
like( $@, qr/^the gate has a zone that is not local, utc, or a offset as \+02:00/, 'and says so' );

#
# the fresh gate
#

sub fresh_gate {
	my (%args) = @_;

	return App::Baphomet::Gate::fresh->new( 'type' => 'fresh', 'args' => { 'var' => 'WHEN', 'within' => 300, %args }, 'where' => 'the gate' );
}

# asks the gate of a line written at the passed time and read at $now
sub read_at {
	my ( $gate, $written ) = @_;

	return $gate->ask( { 'parsed' => {}, 'now' => $now, 'rule' => {}, 'fields' => { 'WHEN' => $written }, 'fields_owned' => 1 } );
}

my $fresh = fresh_gate();
is( $fresh->phase, 'line', 'it is of the line phase' );
is( read_at( $fresh, $now ),        1, 'a line written this second is fresh' );
is( read_at( $fresh, $now - 300 ),  1, 'as is one exactly as old as it may be' );
is( read_at( $fresh, $now - 301 ),  0, 'one a second older is turned away' );
is( read_at( $fresh, $now + 3600 ), 1, 'a line written by a clock running ahead is fresh' );
is( read_at( $fresh, undef ),       0, 'a line with no time to read is turned away' );
is( read_at( $fresh, 'Jul 12' ),    0, 'as is one whose time is no number' );

my $lenient = fresh_gate( 'on_unparsed' => 'pass' );
is( read_at( $lenient, undef ),       1, 'on_unparsed pass lets a line with no time by' );
is( read_at( $lenient, $now - 301 ),  0, 'and changes nothing for one whose time can be read' );

ok( !eval { fresh_gate( 'within' => 0 ); 1 }, 'a within of nothing is refused' );
ok( !eval { fresh_gate( 'on_unparsed' => 'compare' ); 1 }, 'as is a on_unparsed that is neither' );
like( $@, qr/^the gate has a on_unparsed that is not one of pass or fail/, 'which says so' );

done_testing();
