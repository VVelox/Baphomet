#!perl
# direct unit tests for App::Baphomet::Namtar and
# App::Baphomet::Gate::namtar_list, the namtar lists' core and the gate that
# judges by them... sets compiled from lines here stand in for the files the
# galla reads, so the fail-closed rules are pinned with no file and no galla
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Namtar           qw( namtar_slots namtar_set namtar_listed );
use App::Baphomet::Gate::namtar_list ();

my %lists = (
	'bad'       => { 'type' => 'cidr',   'nocase' => 0, 'paths' => [ '/feeds/bad-a', '/feeds/bad-b' ] },
	'tor'       => { 'type' => 'cidr',   'nocase' => 0, 'paths' => ['/feeds/bad-b'] },
	'users'     => { 'type' => 'string', 'nocase' => 0, 'paths' => ['/feeds/users'] },
	'bots'      => { 'type' => 'string', 'nocase' => 1, 'paths' => ['/feeds/bots'] },
	'bad_names' => { 'type' => 'string', 'nocase' => 0, 'paths' => ['/feeds/bad-a'] },
);

#
# namtar_slots... a slot per file a list names
#

my ( $bad_a_slot, $bad_b_slot ) = namtar_slots( $lists{bad} );
my ($users_slot) = namtar_slots( $lists{users} );
my ($bots_slot)  = namtar_slots( $lists{bots} );

is( $bad_b_slot->{path}, '/feeds/bad-b', 'a list of two files comes to two slots, in the order it names them' );
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
isnt( ( namtar_slots( $lists{bad_names} ) )[0]{key},
	$bad_a_slot->{key}, 'one file read as cidr and as string is two slots' );

#
# namtar_set... comments, blanks, the fold, and a bad cidr entry
#

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
my @bad_slots = ( $bad_a_slot, $bad_b_slot );

ok( namtar_listed( \%files,  \@bad_slots,   '10.1.2.3' ),      'a address in a listed CIDR is listed' );
ok( namtar_listed( \%files,  \@bad_slots,   '203.0.113.9' ),   'and so is one on the second of two slots' );
ok( !namtar_listed( \%files, \@bad_slots,   '198.51.100.1' ),  'a address on neither is not' );
ok( namtar_listed( \%files,  [$users_slot], 'root' ),          'a string slot lists a exact entry' );
ok( !namtar_listed( \%files, [$users_slot], 'ROOT' ),          'and is case sensitive with out nocase' );
ok( namtar_listed( \%files,  [$bots_slot],  'EVILBOT' ),       'a nocase slot folds the value too' );
ok( !namtar_listed( \%files, [$users_slot], undef ),           'a undef value is on no list' );
ok( !namtar_listed( {},      [$users_slot], 'root' ),          'and nothing is on a slot that is not loaded' );
ok( !namtar_listed( \%files, [$bad_a_slot], 'not-a-address' ), 'a value that is not a address is on no cidr list' );

#
# the gate... compiled from what a rule entry tells it
#

# a namtar_list gate told what a rule entry would tell it, bound over the
# named lists and the loaded files above
sub namtar_gate {
	my ($args) = @_;

	my $gate = App::Baphomet::Gate::namtar_list->new( 'type' => 'namtar_list', 'args' => $args, 'where' => 'the gate' );
	return $gate->bound( { 'namtar_lists' => \%lists, 'namtar_files' => \%files }, 'the rule "x"' );
}

my $compiled = App::Baphomet::Gate::namtar_list->new(
	'type'  => 'namtar_list',
	'args'  => { 'list' => 'users', 'var' => 'user' },
	'where' => 'the gate'
);
is_deeply( $compiled->{lists}, ['users'], 'a lone list is a list of one' );
is( $compiled->pass, 'result', 'a gate naming a var is of the result pass' );
is_deeply( [ $compiled->needs ], [ 'namtar_lists', 'namtar_files' ], 'it needs the named lists and the loaded files' );

ok(
	!eval {
		App::Baphomet::Gate::namtar_list->new(
			'type'  => 'namtar_list',
			'args'  => { 'list' => 'bad', 'lists' => ['tor'] },
			'where' => 'the gate'
		);
		1;
	},
	'a entry naming both list and lists dies'
);
like( $@, qr/^the gate has both list and lists/, 'and the die leads with the where it was passed' );

#
# bound... names to slots, and the loud die on a undefined list
#

my $offender_gate = namtar_gate( { 'lists' => [ 'bad', 'tor' ] } );
is( $offender_gate->pass, 'offender', 'a gate naming no var is of the offender pass' );
is_deeply(
	[ map { $_->{path} } $offender_gate->list_slots ],
	[ '/feeds/bad-a', '/feeds/bad-b' ],
	'a file two of its lists name is one slot, and the slots are what it reads'
);

my $both_ways = namtar_gate( { 'lists' => [ 'bad', 'bad_names' ] } );
is( scalar( grep { $_->{path} eq '/feeds/bad-a' } $both_ways->list_slots ),
	2, 'one file named as cidr and as string is two slots of the one gate' );

ok( !eval { namtar_gate( { 'list' => 'nope' } ); 1; }, 'referencing a list the context does not define dies' );
like( $@, qr/^the rule "x" references namtar_lists\{nope\}/, 'and the die names the rule and the missing list' );

#
# holds... the value checked, and fail closed
#

# a gate naming no var reads the offender
ok( $offender_gate->holds( {},  '10.1.2.3' ),     'a listed offender holds' );
ok( $offender_gate->holds( {},  '203.0.113.9' ),  'and so does one on the second of its lists' );
ok( !$offender_gate->holds( {}, '198.51.100.1' ), 'a unlisted one fails closed' );

# a gate naming a var reads the found data
my $var_gate = namtar_gate( { 'list' => 'users', 'var' => 'user' } );
ok( $var_gate->holds( { 'user'  => 'admin' }, undef ), 'a listed var value holds' );
ok( !$var_gate->holds( { 'user' => 'neti' },  undef ), 'a unlisted one fails closed' );
ok( !$var_gate->holds( {}, undef ), 'and so does a var the result lacks' );

done_testing;
