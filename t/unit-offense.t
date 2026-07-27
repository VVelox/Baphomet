#!perl
# direct unit tests for App::Baphomet::Offense, the shared gate-and-brand
# order both the galla and run_tests depend on. pins the verdict that
# drifted... a gated-out result fires nobody and brands nobody, only the
# survivors are branded... independent of either caller
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Offense qw( resolve_offense data_gate_pass );

my $now = 1_000_000_000;

#
# data_gate_pass... all checks must hold, and it short-circuits on the
# first veto so a later gate's lookup is spared
#

ok( data_gate_pass( [ sub { 1 }, sub { 1 } ] ), 'all passing is a pass' );
ok( data_gate_pass( [] ), 'no checks is a vacuous pass' );
{
	my @ran;
	my $ok = data_gate_pass(
		[ sub { push( @ran, 'a' ); 1 }, sub { push( @ran, 'b' ); 0 }, sub { push( @ran, 'c' ); 1 } ] );
	ok( !$ok, 'a veto anywhere fails the pass' );
	is_deeply( \@ran, [ 'a', 'b' ], 'and it short-circuits... the check after the veto never runs' );
}

# a gate predicate that passes only the listed IPs
sub only {
	my %ok = map { $_ => 1 } @_;
	return sub { return $ok{ $_[0] } ? 1 : 0; };
}

#
# no gate... every offender survives, the survivors are branded
#

my %store;
my $out = resolve_offense(
	'store'     => \%store,
	'marks'     => [ { 'name' => 'recon', 'ttl' => 100 } ],
	'unmarks'   => [],
	'data'      => {},
	'offenders' => [ '1.1.1.1', '2.2.2.2' ],
	'now'       => $now,
);
ok( $out->{fired}, 'with no gate the result fires' );
is_deeply( $out->{survivors}, [ '1.1.1.1', '2.2.2.2' ], 'every offender survives' );
ok( defined( $store{recon}{'1.1.1.1'} ) && defined( $store{recon}{'2.2.2.2'} ), 'and both are branded' );

#
# the gated-out verdict... offenders existed, none survived, so the result
# did not fire and brands nobody. the regression this module exists to pin
#

%store = ();
$out   = resolve_offense(
	'store'     => \%store,
	'marks'     => [ { 'name' => 'recon', 'ttl' => 100 } ],
	'unmarks'   => [],
	'data'      => {},
	'offenders' => ['1.1.1.1'],
	'now'       => $now,
	'gate'      => only(),    # nobody passes
);
ok( !$out->{fired}, 'a result whose every offender is gated out did not fire' );
is_deeply( $out->{survivors}, [], 'no survivors' );
ok( !defined( $store{recon} ), 'and NOTHING is branded... the leak this module guards against' );

#
# the partial-survivor case... one offender gated out, one through. only
# the survivor is branded
#

%store = ();
$out   = resolve_offense(
	'store'     => \%store,
	'marks'     => [ { 'name' => 'recon', 'ttl' => 100 } ],
	'unmarks'   => [],
	'data'      => {},
	'offenders' => [ '1.1.1.1', '2.2.2.2' ],
	'now'       => $now,
	'gate'      => only('2.2.2.2'),
);
ok( $out->{fired}, 'a result with one surviving offender fires' );
is_deeply( $out->{survivors}, ['2.2.2.2'], 'only the survivor is a survivor' );
ok( !defined( $store{recon}{'1.1.1.1'} ), 'the gated-out offender is not branded' );
ok( defined( $store{recon}{'2.2.2.2'} ),  'and the survivor is' );

#
# no offenders (a detection or purely var-keyed rule)... fires, branding
# its data-keyed marks
#

%store = ();
$out   = resolve_offense(
	'store'     => \%store,
	'marks'     => [ { 'name' => 'acct', 'ttl' => 100, 'var' => 'user' } ],
	'unmarks'   => [],
	'data'      => { 'user' => 'bob' },
	'offenders' => [],
	'now'       => $now,
	'gate'      => only(),    # a gate, but no offenders to run it over
);
ok( $out->{fired}, 'a result with no offenders fires regardless of the gate' );
ok( defined( $store{acct}{bob} ), 'and its data-keyed mark is branded' );

#
# the no-marks short circuit... a rule that brands nothing still fires and
# returns empty set/lifted, never touching the store
#

%store = ();
$out   = resolve_offense(
	'store'     => \%store,
	'marks'     => [],
	'unmarks'   => [],
	'data'      => {},
	'offenders' => ['1.1.1.1'],
	'now'       => $now,
	'gate'      => only('1.1.1.1'),
);
ok( $out->{fired}, 'a mark-less rule fires' );
is_deeply( $out->{survivors}, ['1.1.1.1'], 'with its survivor' );
is_deeply( [ $out->{set}, $out->{lifted} ], [ [], [] ], 'and an empty set/lifted' );
is_deeply( \%store, {}, 'the store is untouched when there is nothing to brand' );

#
# the brandable filter... a survivor the caller marks unbrandable (the
# galla ignore_ips) counts but is not branded
#

%store = ();
$out   = resolve_offense(
	'store'     => \%store,
	'marks'     => [ { 'name' => 'recon', 'ttl' => 100 } ],
	'unmarks'   => [],
	'data'      => {},
	'offenders' => [ '1.1.1.1', '127.0.0.1' ],
	'now'       => $now,
	'brandable' => sub { return $_[0] ne '127.0.0.1'; },
);
is_deeply( $out->{survivors}, [ '1.1.1.1', '127.0.0.1' ], 'both offenders survive the (absent) gate' );
ok( defined( $store{recon}{'1.1.1.1'} ),   'the brandable survivor is branded' );
ok( !defined( $store{recon}{'127.0.0.1'} ), 'the unbrandable one is not, though it still survives for counting' );

#
# the callbacks ride through to the mark core
#

%store = ();
my @heard;
$out = resolve_offense(
	'store'     => \%store,
	'marks'     => [ { 'name' => 'recon', 'ttl' => 100 } ],
	'unmarks'   => [],
	'data'      => {},
	'offenders' => ['1.1.1.1'],
	'now'       => $now,
	'on_set'    => sub { push( @heard, [@_] ); return; },
);
is( scalar(@heard), 1, 'the on_set callback fired for the branded survivor' );
is( $heard[0][1], '1.1.1.1', 'on the right key' );

done_testing;
