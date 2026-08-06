#!/usr/bin/env perl
# The injection tests section, and the load-time demand for one.
use 5.006;
use strict;
use warnings;
use Test::More;

use lib './lib';
use App::Baphomet::Rules::Syslog ();

# a rule def with the pieces every case here shares
sub rule {
	my (%over) = @_;
	my %def = (
		'daemons'        => ['newd'],
		'message_regexp' => ['^auth failed for user .*? from %%%%SRC%%%%'],
		'ban_var'        => ['SRC'],
		%over,
	);
	return App::Baphomet::Rules::Syslog->new( 'name' => 'syslog/t', 'def' => \%def );
}

my $good = 'Jul 12 08:15:50 host01 newd[1]: auth failed for user bob from 192.0.2.7';
my $forged
	= 'Jul 12 08:15:50 host01 newd[1]: auth failed for user bob from 203.0.113.222 from 192.0.2.7';

#
# the shape is detected, and asked about... as a warning, since the shape alone
# does not make a rule exploitable. whether a client can reach that wildcard is
# a property of the log, so the rule loads and the question is raised
#
my $bare = rule(
	'tests' => { 'positive' => [ { 'message' => $good, 'data' => { 'SRC' => '192.0.2.7' } } ] } );
ok( $bare->{needs_injection_test}, 'a lazy unanchored offender is spotted at compile' );
like( $bare->{needs_injection_test}, qr/\Qauth failed for user\E/, 'and named by its pattern' );
my $r = $bare->run_tests;
is( $r->{fail}, 0, 'a rule of that shape with no injection tests still loads' );
is( scalar( @{ $r->{warnings} } ), 1, 'and is warned about instead' );
like( join( ' ', @{ $r->{warnings} } ), qr/lazy wildcard/, 'the warning says what the shape is' );
like( join( ' ', @{ $r->{warnings} } ), qr/tests\.injection/, 'and how to settle it' );

#
# anchoring the token settles it with no test needed
#
my $anchored = rule(
	'message_regexp' => ['^auth failed for user .*? from %%%%SRC%%%%\s*$'],
	'tests'          => { 'positive' => [ { 'message' => $good, 'data' => { 'SRC' => '192.0.2.7' } } ] },
);
ok( !$anchored->{needs_injection_test}, 'an anchored offender is not asked about' );
my $ar = $anchored->run_tests;
is( $ar->{fail}, 0, 'and the rule loads clean' );
is( scalar( @{ $ar->{warnings} } ), 0, 'with nothing warned' );

#
# greedy is not asked about either... it takes the last candidate, so a forgery
# planted ahead of the real field can not win
#
my $greedy = rule(
	'message_regexp' => ['^auth failed for user .* from %%%%SRC%%%%'],
	'tests'          => { 'positive' => [ { 'message' => $good, 'data' => { 'SRC' => '192.0.2.7' } } ] },
);
ok( !$greedy->{needs_injection_test}, 'a greedy run is not the shape at issue' );
my $gr = $greedy->run_tests;
is( $gr->{fail}, 0, 'and needs no injection test' );
is( scalar( @{ $gr->{warnings} } ), 0, 'so is not warned about either' );

# and once a injection test answers the question, the warning goes
my $answered = rule(
	'tests' => {
		'positive'  => [ { 'message' => $good,   'data' => { 'SRC' => '192.0.2.7' } } ],
		'injection' => [ { 'message' => $forged, 'data' => { 'SRC' => '203.0.113.222' } } ],
	}
);
my $anr = $answered->run_tests;
is( scalar( @{ $anr->{warnings} } ), 0, 'a injection test silences the warning' );
is( $anr->{fail}, 0, 'even when it records that the shape IS steerable here' );

#
# the test can not be satisfied by a rule that is actually steerable
#
my $lying = rule(
	'tests' => {
		'positive'  => [ { 'message' => $good,   'data' => { 'SRC' => '192.0.2.7' } } ],
		'injection' => [ { 'message' => $forged, 'data' => { 'SRC' => '192.0.2.7' } } ],
	}
);
my $lr = $lying->run_tests;
ok( $lr->{fail}, 'a injection test over a steerable pattern fails' );
like( join( ' ', @{ $lr->{failures} } ), qr/203\.0\.113\.222/, 'reporting the address it was steered to' );

# and passes once the pattern is anchored
my $fixed = rule(
	'message_regexp' => ['^auth failed for user .*? from %%%%SRC%%%%\s*$'],
	'tests'          => {
		'positive'  => [ { 'message' => $good,   'data' => { 'SRC' => '192.0.2.7' } } ],
		'injection' => [ { 'message' => $forged, 'data' => { 'SRC' => '192.0.2.7' } } ],
	}
);
is( $fixed->run_tests->{fail}, 0, 'the same test passes once the offender is anchored' );

#
# a injection test asserts the aim, so the data block is not optional
#
my $nodata = rule(
	'message_regexp' => ['^auth failed for user .*? from %%%%SRC%%%%\s*$'],
	'tests'          => {
		'positive'  => [ { 'message' => $good, 'data' => { 'SRC' => '192.0.2.7' } } ],
		'injection' => [ { 'message' => $forged } ],
	}
);
my $nr = $nodata->run_tests;
ok( $nr->{fail}, 'a injection test with no data block is refused' );
like( join( ' ', @{ $nr->{failures} } ), qr/no data block/, 'and says what is missing' );

#
# found defaults to 1, so over-tightening until the forged line stops matching
# is a failure and not a fix... it would trade a wrong ban for no ban at all
#
my $overtight = rule(
	'message_regexp' => ['^auth failed for user \S+ from %%%%SRC%%%%\s*$'],
	'tests'          => {
		'positive'  => [ { 'message' => $good,   'data' => { 'SRC' => '192.0.2.7' } } ],
		'injection' => [ { 'message' => $forged, 'data' => { 'SRC' => '192.0.2.7' } } ],
	}
);
my $or = $overtight->run_tests;
ok( $or->{fail}, 'a forged line the rule no longer matches at all is a failure' );
like( join( ' ', @{ $or->{failures} } ), qr/expected found=1 but got found=0/, 'named as a miss, not a misaim' );

done_testing();
