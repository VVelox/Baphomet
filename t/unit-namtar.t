#!perl
# direct unit tests for App::Baphomet::Namtar, the namtar_list gate's pure
# judgment... sets compiled from lines here stand in for the files the galla
# reads, so the two passes and the fail-closed rules are pinned with no file
# and no galla
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Namtar qw( resolve_namtar_gate namtar_set namtar_listed namtar_gate_pass );

#
# resolve_namtar_gate... names to slots, and the loud die on a undefined list
#

my %lists = (
	'bad'       => { 'type' => 'cidr',   'nocase' => 0, 'paths' => [ '/feeds/bad-a', '/feeds/bad-b' ] },
	'tor'       => { 'type' => 'cidr',   'nocase' => 0, 'paths' => ['/feeds/bad-b'] },
	'users'     => { 'type' => 'string', 'nocase' => 0, 'paths' => ['/feeds/users'] },
	'bots'      => { 'type' => 'string', 'nocase' => 1, 'paths' => ['/feeds/bots'] },
	'bad_names' => { 'type' => 'string', 'nocase' => 0, 'paths' => ['/feeds/bad-a'] },
);

is( resolve_namtar_gate( undef, \%lists, 'x' ), undef, 'no namtar_list key resolves to undef' );

my $gate
	= resolve_namtar_gate(
		[ { 'lists' => [ 'bad', 'tor' ], 'var' => undef }, { 'lists' => ['users'], 'var' => 'user' } ],
		\%lists, 'the rule "x"' );
is( scalar( @{$gate} ), 2,      'one entry per entry of the gate' );
is( $gate->[1]{var},    'user', 'the var carries through' );
is( $gate->[0]{var},    undef,  'and so does the lack of one' );
is_deeply(
	[ map { $_->{path} } @{ $gate->[0]{slots} } ],
	[ '/feeds/bad-a', '/feeds/bad-b' ],
	'a file two lists of one entry both name is one slot'
);

my ( $bad_a_slot, $bad_b_slot ) = @{ $gate->[0]{slots} };
my $users_slot = $gate->[1]{slots}[0];
is_deeply(
	$users_slot,
	{
		'key'    => join( "\0", 'string', 0, '/feeds/users' ),
		'type'   => 'string',
		'nocase' => 0,
		'path'   => '/feeds/users',
	},
	'a slot holds its key, type, nocase, and path'
);

my $both_ways = resolve_namtar_gate( [ { 'lists' => [ 'bad', 'bad_names' ] } ], \%lists, 'x' );
is( scalar( grep { $_->{path} eq '/feeds/bad-a' } @{ $both_ways->[0]{slots} } ),
	2, 'one file read as cidr and as string is two slots' );

ok( !eval { resolve_namtar_gate( [ { 'lists' => ['nope'] } ], \%lists, 'the rule "x"' ); 1; },
	'referencing a list the set does not define dies' );
like( $@, qr/the rule "x" references namtar_lists\{nope\}/, 'and the die names the rule and the missing list' );

#
# namtar_set... comments, blanks, the fold, and a bad cidr entry
#

my $bots_slot = resolve_namtar_gate( [ { 'lists' => ['bots'] } ], \%lists, 'x' )->[0]{slots}[0];

is_deeply(
	namtar_set( $users_slot, [ '# bait accounts', 'root', '  admin  # the usual', '', '   ' ] ),
	{ 'root' => 1, 'admin' => 1 },
	'comments and blanks are dropped and the entries trimmed'
);
is_deeply(
	namtar_set( $bots_slot, [ 'EvilBot', 'Scanner' ] ),
	{ 'evilbot' => 1, 'scanner' => 1 },
	'a nocase slot folds its entries to lower case'
);
is_deeply( namtar_set( $bad_a_slot, [] ), {}, 'no lines compile to a empty set' );
ok( !eval { namtar_set( $bad_a_slot, ['not-a-network'] ); 1; }, 'a cidr entry that is not a address or CIDR dies' );
like( $@, qr{namtar list "/feeds/bad-a"}, 'and the die names the file' );

#
# namtar_listed... each slot matched its own way, and fail closed
#

my %files = (
	$bad_a_slot->{key} => { 'set' => namtar_set( $bad_a_slot, [ '10.0.0.0/8', '192.0.2.5' ] ) },
	$bad_b_slot->{key} => { 'set' => namtar_set( $bad_b_slot, ['203.0.113.0/24'] ) },
	$users_slot->{key} => { 'set' => namtar_set( $users_slot, [ 'root', 'admin' ] ) },
	$bots_slot->{key}  => { 'set' => namtar_set( $bots_slot,  ['EvilBot'] ) },
);

ok( namtar_listed( \%files,  $gate->[0]{slots}, '10.1.2.3' ),      'a address in a listed CIDR is listed' );
ok( namtar_listed( \%files,  $gate->[0]{slots}, '203.0.113.9' ),   'and so is one on the second of two slots' );
ok( !namtar_listed( \%files, $gate->[0]{slots}, '198.51.100.1' ),  'a address on neither is not' );
ok( namtar_listed( \%files,  [$users_slot],     'root' ),          'a string slot lists a exact entry' );
ok( !namtar_listed( \%files, [$users_slot],     'ROOT' ),          'and is case sensitive with out nocase' );
ok( namtar_listed( \%files,  [$bots_slot],      'EVILBOT' ),       'a nocase slot folds the value too' );
ok( !namtar_listed( \%files, [$users_slot],     undef ),           'a undef value is on no list' );
ok( !namtar_listed( {},      [$users_slot],     'root' ),          'and nothing is on a slot that is not loaded' );
ok( !namtar_listed( \%files, [$bad_a_slot],     'not-a-address' ), 'a value that is not a address is on no cidr list' );

#
# namtar_gate_pass... the two passes, and every entry judged having to hold
#

my $offender_gate = resolve_namtar_gate( [ { 'lists' => [ 'bad', 'tor' ] } ],           \%lists, 'x' );
my $var_gate      = resolve_namtar_gate( [ { 'lists' => ['users'], 'var' => 'user' } ], \%lists, 'x' );

ok( namtar_gate_pass( \%files, undef, {}, '10.1.2.3' ), 'a undef gate passes' );

# a var-less entry is offender-keyed, ran in the offender pass (ip set)
ok( namtar_gate_pass( \%files,  $offender_gate, {}, '10.1.2.3' ),     'a listed offender holds' );
ok( !namtar_gate_pass( \%files, $offender_gate, {}, '198.51.100.1' ), 'a unlisted one fails closed' );
ok(
	namtar_gate_pass( \%files, $offender_gate, {}, undef ),
	'a var-less entry is skipped in the data pass, holding vacuously'
);

# a var entry is data-driven, ran in the data pass (ip undef)
ok( namtar_gate_pass( \%files,  $var_gate, { 'user' => 'admin' }, undef ), 'a listed var value holds' );
ok( !namtar_gate_pass( \%files, $var_gate, { 'user' => 'neti' },  undef ), 'a unlisted one fails closed' );
ok( !namtar_gate_pass( \%files, $var_gate, {}, undef ), 'and so does a var the result lacks' );
ok(
	namtar_gate_pass( \%files, $var_gate, { 'user' => 'neti' }, '198.51.100.1' ),
	'a var entry is skipped in the offender pass, holding vacuously'
);

# every entry judged in a pass must hold
my $two_entry_gate = [ @{$var_gate}, { 'slots' => [$bots_slot], 'var' => 'agent' } ];
ok( namtar_gate_pass( \%files, $two_entry_gate, { 'user' => 'admin', 'agent' => 'evilbot' }, undef ),
	'two entries that both hold pass' );
ok( !namtar_gate_pass( \%files, $two_entry_gate, { 'user' => 'admin', 'agent' => 'Firefox' }, undef ),
	'one entry failing vetoes though the other held' );

done_testing;
