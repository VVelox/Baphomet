#!perl
# direct unit tests for the offense walk of App::Baphomet::Gate, the one order
# both the galla and run_tests take a offense down... who it is named against,
# who of them the gates leave, and who is branded. pins the verdict that
# drifted... a gated-out offense stands for nobody and brands nobody, only the
# survivors are branded... independent of either caller
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate qw( compile_rule_gates bind_rule_gates walk_offense settle_offenders );

# a gate type of the test's own, holding only for the values it is told... of
# each offender when it names no var, and of what the var holds when it names
# one. it stands in for whatever a rule judges a offense by
package App::Baphomet::Gate::only {
	use parent -norequire, 'App::Baphomet::Gate';

	sub compile {
		my ( $self, $args, $where, $rule ) = @_;

		if ( defined( $args->{var} ) ) {
			$self->{var} = $args->{var};
		}
		$self->{of} = { map { $_ => 1 } @{ $args->{of} } };
		return;
	}

	sub holds {
		my ( $self, $data, $ip, $now ) = @_;

		my $judged = defined( $self->{var} ) ? $data->{ $self->{var} } : $ip;
		return ( defined($judged) && $self->{of}{$judged} ) ? 1 : 0;
	}
} ## end package App::Baphomet::Gate::only

package main;

# the type above lives in this file, so the load gate_class does finds it
# already loaded
$INC{'App/Baphomet/Gate/only.pm'} = __FILE__;

my $now = 1_000_000_000;

# the mark store the brands here land in, and what hands it to a gate
my %store;
my $marks = sub { return \%store; };

# takes one offense down a rule_gates list, as the galla and run_tests both
# do... the list compiled as a rule's is, with no rule behind it as the gates
# here ask nothing of one, bound over the context, and walked at $now.
#
# args:
#   $rule_gates :: the list, each entry a hash of one key, the gate type
#   $data       :: the found data of the offense
#   %with       :: the context the gates are bound over, marks, internal,
#                  brandable, on_set, and on_unset, and beside those usedns,
#                  the sub the offense's hostnames are settled by, which is
#                  put on the offense as the galla puts its watcher's
#
# returns the list of whether the offense stood, 1 or 0, and the offense, a
# hash of data, now, subjects once named, offenders once settled, and set
# and lifted, the brands the walk set and lifted.
#
#   my ( $stood, $offense ) = walked( [ { 'ban_var' => ['ip'] } ], { 'ip' => '192.0.2.7' } );
#   # ( 1, { 'named' => 1, 'subjects' => [ { 'var' => 'ip', 'value' => '192.0.2.7' } ], ... } )
sub walked {
	my ( $rule_gates, $data, %with ) = @_;

	my $usedns  = delete( $with{usedns} );
	my $gates   = compile_rule_gates( $rule_gates, undef, 'json/x' );
	my $bound   = bind_rule_gates( $gates, \%with, 'the rule "x"' );
	my $offense = { 'data' => $data, 'regexp' => undef, 'now' => $now, 'set' => [], 'lifted' => [] };
	if ( defined($usedns) ) {
		$offense->{usedns} = $usedns;
	}
	my $stood = walk_offense( $bound, $offense );

	return ( $stood, $offense );
} ## end sub walked

#
# who a offense is named against... a subject for each var that holds a
# value, and each value a offender once
#

my ( $stood, $offense ) = walked( [ { 'ban_var' => ['ip'] } ], { 'ip' => '1.1.1.1', 'user' => 'bob' } );
ok( $stood,            'a offense nothing vetoes stands' );
ok( $offense->{named}, 'and has been named' );
is_deeply(
	$offense->{subjects},
	[ { 'var' => 'ip', 'value' => '1.1.1.1' } ],
	'its subject is the var and what it held'
);
is_deeply( settle_offenders($offense), ['1.1.1.1'], 'and its offender the value' );

( $stood, $offense ) = walked(
	[ { 'ban_var' => [ 'src', 'dest', 'peer', 'via' ] } ],
	{ 'src' => '1.1.1.1', 'dest' => '2.2.2.2', 'via' => '1.1.1.1' }
);
is_deeply(
	$offense->{subjects},
	[
		{ 'var' => 'src',  'value' => '1.1.1.1' },
		{ 'var' => 'dest', 'value' => '2.2.2.2' },
		{ 'var' => 'via',  'value' => '1.1.1.1' },
	],
	'a var the offense has no value for names nobody'
);
is_deeply(
	settle_offenders($offense),
	[ '1.1.1.1', '2.2.2.2' ],
	'and a value is a offender once however many vars named it'
);

( $stood, $offense ) = walked( [ { 'ban_var' => ['ip'] } ], { 'user' => 'bob' } );
ok( $stood,            'a offense named against nobody still stands' );
ok( $offense->{named}, 'named all the same' );
is_deeply( [ $offense->{subjects}, settle_offenders($offense) ], [ [], [] ], 'counting against no one' );

#
# no gate... every offender survives, the survivors are branded
#

%store = ();
( $stood, $offense ) = walked(
	[ { 'ban_var' => [ 'src', 'dest' ] }, { 'mark' => { 'name' => 'recon', 'ttl' => 100 } } ],
	{ 'src' => '1.1.1.1', 'dest' => '2.2.2.2' },
	'marks' => $marks,
);
ok( $stood, 'with no gate the offense stands' );
is_deeply( settle_offenders($offense), [ '1.1.1.1', '2.2.2.2' ], 'every offender survives' );
ok( defined( $store{recon}{'1.1.1.1'} ) && defined( $store{recon}{'2.2.2.2'} ), 'and both are branded' );

#
# the gated-out verdict... offenders existed, none survived, so the offense
# does not stand and brands nobody. the regression this file exists to pin
#

%store = ();
( $stood, $offense ) = walked(
	[
		{ 'ban_var' => ['ip'] },
		{ 'only'    => { 'of'   => [] } },                      # nobody passes
		{ 'mark'    => { 'name' => 'recon', 'ttl' => 100 } },
	],
	{ 'ip' => '1.1.1.1' },
	'marks' => $marks,
);
ok( !$stood, 'a offense whose every offender is gated out does not stand' );
is_deeply( settle_offenders($offense), [], 'no survivors' );
ok( !defined( $store{recon} ), 'and NOTHING is branded... the leak this guards against' );
ok( $offense->{named},         'though it got as far as its naming, and so matched' );

#
# the partial-survivor case... one offender gated out, one through. only
# the survivor is branded
#

%store = ();
( $stood, $offense ) = walked(
	[
		{ 'ban_var' => [ 'src', 'dest' ] },
		{ 'only'    => { 'of'   => ['2.2.2.2'] } },
		{ 'mark'    => { 'name' => 'recon', 'ttl' => 100 } },
	],
	{ 'src' => '1.1.1.1', 'dest' => '2.2.2.2' },
	'marks' => $marks,
);
ok( $stood, 'a offense with one surviving offender stands' );
is_deeply( settle_offenders($offense), ['2.2.2.2'], 'only the survivor is a survivor' );
ok( !defined( $store{recon}{'1.1.1.1'} ), 'the gated-out offender is not branded' );
ok( defined( $store{recon}{'2.2.2.2'} ),  'and the survivor is' );

#
# no offenders (a purely var-keyed rule)... stands, branding its data-keyed
# marks
#

%store = ();
( $stood, $offense ) = walked(
	[
		{ 'ban_var' => ['ip'] },
		{ 'only'    => { 'of'   => [] } },                                      # a gate, but no offenders to ask it of
		{ 'mark'    => { 'name' => 'acct', 'ttl' => 100, 'var' => 'user' } },
	],
	{ 'user' => 'bob' },
	'marks' => $marks,
);
ok( $stood,                       'a offense with no offenders stands regardless of the gate' );
ok( defined( $store{acct}{bob} ), 'and its data-keyed mark is branded' );

#
# a rule that brands nothing... it still stands, with nothing set or lifted,
# never touching the store
#

%store = ();
( $stood, $offense ) = walked(
	[ { 'ban_var' => ['ip'] }, { 'only' => { 'of' => ['1.1.1.1'] } } ],
	{ 'ip' => '1.1.1.1' },
	'marks' => $marks
);
ok( $stood, 'a mark-less rule stands' );
is_deeply( settle_offenders($offense),              ['1.1.1.1'], 'with its survivor' );
is_deeply( [ $offense->{set}, $offense->{lifted} ], [ [], [] ],  'and an empty set/lifted' );
is_deeply( \%store,                                 {}, 'the store is untouched when there is nothing to brand' );

#
# the brandable filter... a survivor the caller marks unbrandable (the
# galla ignore_ips) counts but is not branded
#

%store = ();
( $stood, $offense ) = walked(
	[ { 'ban_var' => [ 'src', 'dest' ] }, { 'mark' => { 'name' => 'recon', 'ttl' => 100 } } ],
	{ 'src' => '1.1.1.1', 'dest' => '127.0.0.1' },
	'marks'     => $marks,
	'brandable' => sub { return $_[0] ne '127.0.0.1'; },
);
is_deeply( settle_offenders($offense), [ '1.1.1.1', '127.0.0.1' ], 'both offenders survive the (absent) gate' );
ok( defined( $store{recon}{'1.1.1.1'} ),    'the brandable survivor is branded' );
ok( !defined( $store{recon}{'127.0.0.1'} ), 'the unbrandable one is not, though it still survives for counting' );

#
# the brands set and lifted are noted on the offense, and the callbacks ride
# through to the mark core
#

%store = ( 'suspect' => { '1.1.1.1' => { 'expires' => $now + 100 } } );
my ( @heard, @heard_lifts );
( $stood, $offense ) = walked(
	[
		{ 'ban_var' => ['ip'] },
		{ 'mark'    => { 'name' => 'recon', 'ttl' => 100 } },
		{ 'unmark'  => { 'name' => 'suspect' } },
	],
	{ 'ip' => '1.1.1.1' },
	'marks'    => $marks,
	'on_set'   => sub { push( @heard,       [@_] ); return; },
	'on_unset' => sub { push( @heard_lifts, [@_] ); return; },
);
is( scalar(@heard), 1,         'the on_set callback fired for the branded survivor' );
is( $heard[0][1],   '1.1.1.1', 'on the right key' );
is_deeply( \@heard_lifts, [ [ 'suspect', '1.1.1.1' ] ], 'and the on_unset callback for the brand lifted from it' );
is( $store{recon}{'1.1.1.1'}{expires}, $now + 100, 'the brand is set for its ttl from the time of the offense' );
ok( !defined( $store{suspect} ), 'and the lifted one is gone from the store' );
is_deeply( $offense->{set},    [ { 'name' => 'recon',   'key' => '1.1.1.1' } ], 'the offense notes the brand set' );
is_deeply( $offense->{lifted}, [ { 'name' => 'suspect', 'key' => '1.1.1.1' } ], 'and the one lifted' );

#
# a veto stops the walk... the gates below it are not asked, so one ahead of
# the naming leaves the offense unnamed and unbranded
#

%store = ();
( $stood, $offense ) = walked(
	[
		{ 'only'    => { 'of' => ['alice'], 'var' => 'user' } },
		{ 'ban_var' => ['ip'] },
		{ 'mark'    => { 'name' => 'recon', 'ttl' => 100 } },
	],
	{ 'user' => 'bob', 'ip' => '1.1.1.1' },
	'marks' => $marks,
);
ok( !$stood,                          'a offense a gate that reads it vetoes does not stand' );
ok( !$offense->{named},               'the walk ending there, short of the naming' );
ok( !defined( $offense->{subjects} ), 'so it has no subjects' );
is_deeply( \%store, {}, 'and nobody is branded' );

( $stood, $offense ) = walked(
	[
		{ 'only'    => { 'of' => ['bob'], 'var' => 'user' } },
		{ 'ban_var' => ['ip'] },
		{ 'mark'    => { 'name' => 'recon', 'ttl' => 100 } },
	],
	{ 'user' => 'bob', 'ip' => '1.1.1.1' },
	'marks' => $marks,
);
ok( $stood && $offense->{named},         'while one the same gate holds for goes on to its naming' );
ok( defined( $store{recon}{'1.1.1.1'} ), 'and its brand' );

#
# a detection rule... it has subjects, under no obligation to be a address,
# and no offenders
#

my $usedns_asked = 0;
%store = ();
( $stood, $offense ) = walked(
	[
		{ 'detection_var' => [ 'user', 'host', 'realm' ] },
		{ 'mark' => { 'name' => 'acct',  'ttl' => 100, 'var' => 'user' } },
		{ 'mark' => { 'name' => 'recon', 'ttl' => 100 } },
	],
	{ 'user' => 'bob', 'host' => '', 'ip' => '1.1.1.1' },
	'marks'  => $marks,
	'usedns' => sub { $usedns_asked++; return (); },
);
ok( $stood && $offense->{named}, 'a detection offense stands, named' );
is_deeply(
	$offense->{subjects},
	[ { 'var' => 'user', 'value' => 'bob' } ],
	'its subjects are the vars that hold a value, a empty one naming nothing'
);
is_deeply( settle_offenders($offense), [], 'and it has no offenders' );
is( $usedns_asked, 0, 'so its subjects are never put through usedns' );
ok( defined( $store{acct}{bob} ), 'its data-keyed mark is branded' );
ok( !defined( $store{recon} ),    'while a mark keyed by the offender brands nobody' );

#
# ban_not_internal... the operator's own hosts are dropped, vetoing nothing
#

my $internal = sub { return $_[0] =~ /^10\./ ? 1 : 0; };

%store = ();
( $stood, $offense ) = walked(
	[
		{ 'ban_var'          => [ 'src', 'dest' ] },
		{ 'ban_not_internal' => 1 },
		{ 'mark'             => { 'name' => 'recon', 'ttl' => 100 } },
	],
	{ 'src' => '203.0.113.9', 'dest' => '10.0.0.5' },
	'marks'    => $marks,
	'internal' => $internal,
);
ok( $stood, 'a offense with a internal host among its subjects stands' );
is_deeply( $offense->{subjects}, [ { 'var' => 'src', 'value' => '203.0.113.9' } ], 'the internal host is no subject' );
is_deeply( settle_offenders($offense),             ['203.0.113.9'], 'and no offender' );
is_deeply( [ sort( keys( %{ $store{recon} } ) ) ], ['203.0.113.9'], 'so only the end that is not internal is branded' );

( $stood, $offense ) = walked(
	[
		{ 'ban_var'          => [ 'src', 'dest' ] },
		{ 'only'             => { 'of' => [ '203.0.113.9', '10.0.0.5' ] } },
		{ 'ban_not_internal' => 1 },
	],
	{ 'src' => '203.0.113.9', 'dest' => '10.0.0.5' },
	'internal' => $internal,
);
is_deeply( settle_offenders($offense),
	['203.0.113.9'], 'it is dropped from offenders a gate above had already settled' );

( $stood, $offense ) = walked(
	[ { 'ban_var' => [ 'src', 'dest' ] }, { 'ban_not_internal' => 1 } ],
	{ 'src' => '10.0.0.9', 'dest' => '10.0.0.5' },
	'internal' => $internal,
);
ok( $stood, 'a offense with every subject internal still stands' );
is_deeply( [ $offense->{subjects}, settle_offenders($offense) ], [ [], [] ], 'counting against no one' );

( $stood, $offense ) = walked(
	[ { 'detection_var' => ['host'] }, { 'ban_not_internal' => 1 } ],
	{ 'host' => '10.0.0.5' },
	'internal' => $internal,
);
is_deeply(
	$offense->{subjects},
	[ { 'var' => 'host', 'value' => '10.0.0.5' } ],
	'on a detection rule it spares nobody, a subject being nobody to banish'
);

# told false it is left out when the rule is bound, so it needs no internal
( $stood, $offense ) = walked( [ { 'ban_var' => [ 'src', 'dest' ] }, { 'ban_not_internal' => 0 } ],
	{ 'src' => '203.0.113.9', 'dest' => '10.0.0.5' } );
is_deeply( settle_offenders($offense), [ '203.0.113.9', '10.0.0.5' ], 'one told false drops nobody' );

ok(
	!eval {
		walked( [ { 'ban_var' => ['src'] }, { 'ban_not_internal' => 1 } ], { 'src' => '203.0.113.9' } );
		1;
	},
	'one told true with no internal in the context does not bind'
);
is(
	$@ =~ s/ at \S+ line \d+\.\n\z//r,
	'the rule "x" has a ban_not_internal gate, which can not judge with out internal, and there is none here',
	'the die naming the gate and what is missing'
);

#
# usedns... the offenders are settled out of the subjects by the offense's
# usedns sub, when it has one, on first asking
#

# as the galla's does with a watcher set to resolve... a address passes, and a
# hostname becomes a record for each address it answers with, a name with no
# answer becoming none
my %answers = ( 'bad.example.com' => [ '192.0.2.72', '192.0.2.73' ] );
my @usedns_handed;
my $usedns = sub {
	my ($subjects) = @_;

	# a copy, so what was handed is still there to read once the walk is done
	my @handed = map { +{ %{$_} } } @{$subjects};
	push( @usedns_handed, \@handed );
	my @kept;
	foreach my $subject ( @{$subjects} ) {
		if ( $subject->{value} =~ /^[0-9.]+$/ ) {
			push( @kept, { %{$subject} } );
			next;
		}
		foreach my $addr ( @{ $answers{ $subject->{value} } // [] } ) {
			push( @kept, { 'var' => $subject->{var}, 'value' => $addr, 'hostname' => $subject->{value} } );
		}
	}
	return @kept;
}; ## end $usedns = sub

( $stood, $offense ) = walked( [ { 'ban_var' => ['src'] } ], { 'src' => 'bad.example.com' } );
is_deeply( settle_offenders($offense), ['bad.example.com'], 'with no usedns sub a hostname is a offender as it is' );

%store = ();
( $stood, $offense ) = walked(
	[
		{ 'ban_var' => [ 'src', 'peer' ] },
		{ 'only'    => { 'of'   => [ '192.0.2.73', '1.1.1.1', 'bad.example.com' ] } },
		{ 'mark'    => { 'name' => 'recon', 'ttl' => 100 } },
	],
	{ 'src' => 'bad.example.com', 'peer' => '1.1.1.1' },
	'marks'  => $marks,
	'usedns' => $usedns,
);
ok( $stood, 'a offense whose hostname resolves stands' );
is_deeply(
	\@usedns_handed,
	[ [ { 'var' => 'src', 'value' => 'bad.example.com' }, { 'var' => 'peer', 'value' => '1.1.1.1' } ] ],
	'the usedns sub is handed the subjects as they were named, the once'
);
is_deeply(
	$offense->{subjects},
	[
		{ 'var' => 'src',  'value' => '192.0.2.72', 'hostname' => 'bad.example.com' },
		{ 'var' => 'src',  'value' => '192.0.2.73', 'hostname' => 'bad.example.com' },
		{ 'var' => 'peer', 'value' => '1.1.1.1' },
	],
	'what it returns is the subjects from there on'
);
is_deeply(
	settle_offenders($offense),
	[ '192.0.2.73', '1.1.1.1' ],
	'a gate keyed by the offender is asked of what the name resolved to'
);
is_deeply(
	[ sort( keys( %{ $store{recon} } ) ) ],
	[ '1.1.1.1', '192.0.2.73' ],
	'and the brands land on the addresses, not the name'
);
is( scalar(@usedns_handed), 1, 'settling again does not ask the usedns sub again' );

@usedns_handed = ();
( $stood, $offense ) = walked(
	[ { 'ban_var' => ['src'] }, { 'only' => { 'of' => [] } } ],
	{ 'src' => 'gone.example.com' },
	'usedns' => $usedns,
);
ok( $stood, 'a offense whose hostname the usedns sub drops stands, there being no offender to gate out' );
is_deeply( [ $offense->{subjects}, settle_offenders($offense) ], [ [], [] ], 'counting against no one' );

@usedns_handed = ();
( $stood, $offense ) = walked( [ { 'ban_var' => ['src'] } ], { 'user' => 'bob' }, 'usedns' => $usedns );
settle_offenders($offense);
is( scalar(@usedns_handed), 0, 'a offense named against nobody has nothing to hand the usedns sub' );

#
# what a list can not be... a mark or unmark keyed by the offender with
# nothing above it to name one, and a second naming
#

%store = ();
my %told_no_var = ( 'mark' => { 'name' => 'recon', 'ttl' => 100 }, 'unmark' => { 'name' => 'recon' } );
foreach my $type ( sort( keys(%told_no_var) ) ) {
	ok(
		!eval {
			walked(
				[ { $type => $told_no_var{$type} }, { 'ban_var' => ['ip'] } ],
				{ 'ip' => '1.1.1.1' },
				'marks' => $marks
			);
			1;
		},
		'a ' . $type . ' keyed by the offender above the ban_var that names one refuses to load'
	);
	is(
		$@ =~ s/ at \S+ line \d+\.\n\z//r,
		'The '
			. $type
			. ' gate of the rule "json/x" (rule_gates entry 0) keys on the offender, and no ban_var above it names one',
		'the die naming the gate and what it lacks'
	);
} ## end foreach my $type ( sort( keys(%told_no_var) ) )
is_deeply( \%store, {}, 'and nothing was branded on the way' );

ok(
	!eval {
		walked( [ { 'ban_var' => ['ip'] }, { 'detection_var' => ['user'] } ],
			{ 'ip' => '1.1.1.1', 'user' => 'bob' } );
		1;
	},
	'a list naming who a offense counts against twice refuses to load'
);
is(
	$@ =~ s/ at \S+ line \d+\.\n\z//r,
	'The detection_var gate of the rule "json/x" (rule_gates entry 1) comes after a ban_var, '
		. 'and a rule names who it counts against once',
	'the die naming the second and the first'
);

done_testing;
