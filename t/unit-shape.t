#!perl
# direct unit tests for App::Baphomet::Shape, the walker every rule def is
# vetted with... no rule, just hashes, shapes, and kinds. pins what each kind
# takes and refuses and the exact wording of each failure, which the rule
# tests mostly assert only as a def that will not load
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Shape qw( check_hash check_entries check_value is_kind is_non_negative_int is_positive_int );

# what a check dies with, less the at-line tail perl adds, or undef when it
# passes
sub death_of {
	my ($check) = @_;

	if ( eval { $check->(); 1 } ) {
		return undef;
	}
	my $error = $@;
	$error =~ s/ at \S+ line \d+\.\n\z//;
	return $error;
} ## end sub death_of

#
# the named kinds... what each takes and what it refuses
#

my @kind_cases = (
	[ 'any',               undef,                1, 'any takes even undef' ],
	[ 'any',               { 'a' => [] },        1, 'any takes a structure' ],
	[ 'scalar',            '',                   1, 'scalar takes a empty string' ],
	[ 'scalar',            0,                    1, 'scalar takes a number' ],
	[ 'scalar',            ['x'],                0, 'scalar refuses a ref' ],
	[ 'scalar',            undef,                0, 'scalar refuses undef' ],
	[ 'string',            'x',                  1, 'string takes a non-empty string' ],
	[ 'string',            0,                    1, 'string takes a zero, which is not empty' ],
	[ 'string',            '',                   0, 'string refuses a empty string' ],
	[ 'string',            undef,                0, 'string refuses undef' ],
	[ 'string',            ['x'],                0, 'string refuses a ref' ],
	[ 'name',              'mail-queue_2',       1, 'name takes letters, digits, _, and -' ],
	[ 'name',              'mail queue',         0, 'name refuses a space' ],
	[ 'name',              'mail/queue',         0, 'name refuses a slash' ],
	[ 'name',              '',                   0, 'name refuses a empty string' ],
	[ 'name',              ['mail-queue'],       0, 'name refuses a ref' ],
	[ 'positive_int',      5,                    1, 'positive_int takes a whole number of one or more' ],
	[ 'positive_int',      0,                    0, 'positive_int refuses zero' ],
	[ 'positive_int',      '5.0',                0, 'positive_int refuses a point' ],
	[ 'positive_int',      -5,                   0, 'positive_int refuses a sign' ],
	[ 'positive_int',      'five',               0, 'positive_int refuses a word' ],
	[ 'positive_int',      [5],                  0, 'positive_int refuses a ref' ],
	[ 'seconds',           60,                   1, 'seconds is a positive int' ],
	[ 'seconds',           0,                    0, 'seconds refuses zero' ],
	[ 'non_negative_int',  0,                    1, 'non_negative_int takes zero' ],
	[ 'non_negative_int',  7,                    1, 'non_negative_int takes a whole number above it' ],
	[ 'non_negative_int',  '',                   0, 'non_negative_int refuses a empty string' ],
	[ 'non_negative_int',  -1,                   0, 'non_negative_int refuses a sign' ],
	[ 'seconds_or_zero',    0,                   1, 'seconds_or_zero takes zero' ],
	[ 'seconds_or_zero',   '1h',                 0, 'seconds_or_zero refuses a unit' ],
	[ 'positive_number',   2,                    1, 'positive_number takes a whole number' ],
	[ 'positive_number',   '0.5',                1, 'positive_number takes a fraction' ],
	[ 'positive_number',   0,                    0, 'positive_number refuses zero' ],
	[ 'positive_number',   '0.0',                0, 'positive_number refuses a zero with a fraction' ],
	[ 'positive_number',   '.5',                 0, 'positive_number refuses a fraction with no whole part' ],
	[ 'positive_number',   '1e3',                0, 'positive_number refuses a exponent' ],
	[ 'boolean',           1,                    1, 'boolean takes a true scalar' ],
	[ 'boolean',           '',                   1, 'boolean takes a false scalar' ],
	[ 'boolean',           { 'yes' => 1 },       0, 'boolean refuses a ref' ],
	[ 'hash',              {},                   1, 'hash takes a hash, empty or not' ],
	[ 'hash',              [],                   0, 'hash refuses a array' ],
	[ 'hash',              'x',                  0, 'hash refuses a string' ],
	[ 'severity',          'high',               1, 'severity takes a level' ],
	[ 'severity',          'loud',               0, 'severity refuses what is not one' ],
	[ 'severity',          'HIGH',               0, 'severity refuses a level in the wrong case' ],
	[ 'severity',          ['high'],             0, 'severity refuses a ref' ],
	[ 'strings',           [ 'a', 'b' ],         1, 'strings takes a array of non-empty strings' ],
	[ 'strings',           [],                   0, 'strings refuses a empty array' ],
	[ 'strings',           [ 'a', '' ],          0, 'strings refuses a empty string among them' ],
	[ 'strings',           [ 'a', undef ],       0, 'strings refuses a undef among them' ],
	[ 'strings',           [ 'a', ['b'] ],       0, 'strings refuses a array among them' ],
	[ 'strings',           'a',                  0, 'strings refuses a lone string' ],
	[ 'string_list',       [],                   1, 'string_list takes a empty array' ],
	[ 'string_list',       ['a'],                1, 'string_list takes a array of non-empty strings' ],
	[ 'string_list',       [''],                 0, 'string_list refuses a empty string among them' ],
	[ 'string_list',       'a',                  0, 'string_list refuses a lone string' ],
	[ 'string_or_strings', 'a',                  1, 'string_or_strings takes a lone string' ],
	[ 'string_or_strings', [ 'a', 'b' ],         1, 'string_or_strings takes a array of them' ],
	[ 'string_or_strings', [],                   0, 'string_or_strings refuses a empty array' ],
	[ 'string_or_strings', '',                   0, 'string_or_strings refuses a lone empty string' ],
	[ 'string_or_strings', { 'a' => 1 },         0, 'string_or_strings refuses a hash' ],
	[ 'string_or_strings', undef,                0, 'string_or_strings refuses undef' ],
	[ 'names',             [ 'feed', 'feed-2' ], 1, 'names takes a array of names' ],
	[ 'names',             ['bad name'],         0, 'names refuses a array holding what is not a name' ],
	[ 'names',             [],                   0, 'names refuses a empty array' ],
	[ 'names',             'feed',               0, 'names refuses a lone name' ],
	[ 'name_or_names',     'feed',               1, 'name_or_names takes a lone name' ],
	[ 'name_or_names',     [ 'feed', 'other' ],  1, 'name_or_names takes a array of them' ],
	[ 'name_or_names',     ['bad name'],         0, 'name_or_names refuses a array holding what is not a name' ],
	[ 'name_or_names',     [],                   0, 'name_or_names refuses a empty array' ],
);
foreach my $kind_case (@kind_cases) {
	my ( $kind, $value, $expected, $description ) = @{$kind_case};
	is( is_kind( $value, $kind ), $expected, $description );
}

like(
	death_of( sub { is_kind( 1, 'nope' ) } ),
	qr/^The kind "nope" is not a known one$/,
	'a kind name that is not a known one is the caller\'s mistake and dies'
);

#
# kinds spelled out in place
#

my $failure_action = { 'in' => [qw( pass fail compare )], 'says' => 'one of pass, fail, or compare' };
ok( is_kind( 'compare',    $failure_action ), 'a in kind takes a listed value' );
ok( !is_kind( 'drop',      $failure_action ), 'and refuses one that is not listed' );
ok( !is_kind( ['compare'], $failure_action ), 'and refuses a ref holding a listed one' );

my $country_code = { 'match' => qr/^[A-Z]{2}$/, 'says' => 'a 2-letter code' };
ok( is_kind( 'US',    $country_code ), 'a match kind takes what its regexp does' );
ok( !is_kind( 'USA',  $country_code ), 'and refuses what it does not' );
ok( !is_kind( ['US'], $country_code ), 'and refuses a ref rather than matching its stringified form' );
ok( !is_kind( undef,  $country_code ), 'and refuses undef' );

my $even = { 'test' => sub { return $_[0] % 2 == 0; }, 'says' => 'a even number' };
ok( is_kind( 4,  $even ), 'a test kind takes what its code ref calls true' );
ok( !is_kind( 3, $even ), 'and refuses what it calls false' );

my $mark_names = { 'each' => 'name', 'min' => 2, 'says' => 'a array of at least two mark names' };
ok( is_kind( [ 'first', 'second' ],      $mark_names ), 'a each kind takes a list of at least min items of the kind' );
ok( !is_kind( ['first'],                 $mark_names ), 'and refuses a list shorter than min' );
ok( !is_kind( [ 'first', 'not a name' ], $mark_names ), 'and refuses a list holding a item not of the kind' );
ok( !is_kind( 'first',                   $mark_names ), 'and refuses a lone item when or_one is not set' );
ok( is_kind( [],             { 'each' => 'name' } ),                'min left off allows a empty list' );
ok( is_kind( 'first',        { 'each' => 'name', 'or_one' => 1 } ), 'or_one lets a lone item stand for a list of one' );
ok( !is_kind( 'not a name',  { 'each' => 'name', 'or_one' => 1 } ), 'which still has to be of the kind' );
ok( is_kind( [ 'US', 'CA' ], { 'each' => $country_code } ), 'the kind each names may itself be spelled out in place' );
ok( !is_kind( [ 'US', 'CAN' ], { 'each' => $country_code } ), 'and is held to the same' );

#
# check_value
#

my $mungers_where = 'The mungers of the rule "syslog/x"';
is( death_of( sub { check_value( ['postfix'], 'strings', $mungers_where ) } ), undef, 'a value of its kind passes' );
is(
	death_of( sub { check_value( [], 'strings', $mungers_where ) } ),
	$mungers_where . ' is not a non-empty array of non-empty strings',
	'a value not of its kind dies with where and then the words of the kind'
);
is(
	death_of( sub { check_value( undef, 'seconds', 'The defer of the rule "json/x"' ) } ),
	'The defer of the rule "json/x" is not a positive int of seconds',
	'a undef value is not of any kind but any'
);
is(
	death_of( sub { check_value( 'drop', $failure_action, 'The on_nxdomain' ) } ),
	'The on_nxdomain is not one of pass, fail, or compare',
	'a kind spelled out in place brings its own words'
);

#
# check_hash
#

my $mark_shape = {
	'required' => { 'name' => 'name',   'ttl'  => 'seconds' },
	'optional' => { 'var'  => 'string', 'vars' => 'strings' },
	'not_both' => [ [ 'var', 'vars' ] ],
};
my $mark_where = 'The mark of the rule "syslog/x" entry 0';

is( death_of( sub { check_hash( { 'name' => 'brute', 'ttl' => 60 }, $mark_shape, $mark_where ) } ),
	undef, 'a hash of its shape passes' );
is(
	death_of( sub { check_hash( { 'name' => 'brute', 'ttl' => 60, 'var' => 'USER' }, $mark_shape, $mark_where ) } ),
	undef,
	'with a optional key or with out'
);
is(
	death_of( sub { check_hash( ['brute'], $mark_shape, $mark_where ) } ),
	$mark_where . ' is not a hash',
	'a array where the hash belongs'
);
is(
	death_of( sub { check_hash( 'brute', $mark_shape, $mark_where ) } ),
	$mark_where . ' is not a hash',
	'a string where the hash belongs'
);
is(
	death_of( sub { check_hash( { 'name' => 'brute', 'ttl' => 60, 'tll' => 5 }, $mark_shape, $mark_where ) } ),
	$mark_where . ' has the unknown key "tll"',
	'a key in neither required nor optional is unknown'
);
is(
	death_of(
		sub { check_hash( { 'name' => 'brute', 'ttl' => 60, 'zzz' => 1, 'aaa' => 1 }, $mark_shape, $mark_where ) }
	),
	$mark_where . ' has the unknown key "aaa"',
	'of several unknown keys the first sorted is the one named'
);
is(
	death_of( sub { check_hash( { 'name' => 'brute' }, $mark_shape, $mark_where ) } ),
	$mark_where . ' lacks a ttl',
	'a required key left off is missing'
);
is(
	death_of( sub { check_hash( { 'name' => 'brute', 'ttl' => undef }, $mark_shape, $mark_where ) } ),
	$mark_where . ' lacks a ttl',
	'as is one set to undef'
);
is(
	death_of( sub { check_hash( {}, $mark_shape, $mark_where ) } ),
	$mark_where . ' lacks a name',
	'of several missing keys the first sorted is the one named'
);
is(
	death_of( sub { check_hash( { 'name' => 'brute', 'ttl' => 'soon' }, $mark_shape, $mark_where ) } ),
	$mark_where . ' has a ttl that is not a positive int of seconds',
	'a required key of the wrong kind'
);
is(
	death_of( sub { check_hash( { 'name' => 'brute', 'ttl' => 60, 'var' => '' }, $mark_shape, $mark_where ) } ),
	$mark_where . ' has a var that is not a non-empty string',
	'a optional key of the wrong kind'
);
is(
	death_of( sub { check_hash( { 'name' => 'brute', 'ttl' => 60, 'var' => undef }, $mark_shape, $mark_where ) } ),
	undef,
	'a optional key set to undef is regarded as not set'
);
is(
	death_of( sub { check_hash( { 'ttl' => 'soon', 'nope' => 1 }, $mark_shape, $mark_where ) } ),
	$mark_where . ' has the unknown key "nope"',
	'a unknown key is named ahead of a missing one'
);
is(
	death_of( sub { check_hash( { 'ttl' => 'soon' }, $mark_shape, $mark_where ) } ),
	$mark_where . ' lacks a name',
	'and a missing key ahead of a value of the wrong kind'
);
is(
	death_of(
		sub {
			check_hash( { 'name' => 'brute', 'ttl' => 60, 'var' => 'USER', 'vars' => [ 'USER', 'SRC' ] },
				$mark_shape, $mark_where );
		}
	),
	$mark_where . ' has both var and vars',
	'not_both refuses both keys of a pair'
);
is(
	death_of(
		sub {
			check_hash( { 'name' => 'brute', 'ttl' => 60, 'vars' => [ 'USER', 'SRC' ] }, $mark_shape, $mark_where );
		}
	),
	undef,
	'and takes either alone'
);

is( death_of( sub { check_hash( {}, {}, 'The empty' ) } ), undef, 'a shape naming no keys takes a empty hash' );
is(
	death_of( sub { check_hash( { 'any' => 1 }, {}, 'The empty' ) } ),
	'The empty has the unknown key "any"',
	'and regards every key as unknown'
);

# one_of... exactly one of a pair
my $gate_shape = { 'optional' => { 'is' => 'strings', 'isnot' => 'strings' }, 'one_of' => [ [ 'is', 'isnot' ] ] };
is( death_of( sub { check_hash( { 'is' => ['US'] }, $gate_shape, 'The gate' ) } ),
	undef, 'one_of takes one key of a pair' );
is(
	death_of( sub { check_hash( {}, $gate_shape, 'The gate' ) } ),
	'The gate has neither is nor isnot',
	'one_of refuses neither'
);
is(
	death_of( sub { check_hash( { 'is' => ['US'], 'isnot' => ['CA'] }, $gate_shape, 'The gate' ) } ),
	'The gate has both is and isnot',
	'one_of refuses both'
);

# any_of... at least one of a pair, and a pair saying why
my $read_shape = {
	'optional' => { 'where' => 'any', 'into' => 'strings' },
	'any_of'   => [ [ 'where', 'into', 'so it does nothing' ] ],
};
is( death_of( sub { check_hash( { 'into' => ['client_ip'] }, $read_shape, 'The read' ) } ),
	undef, 'any_of takes one key of a pair' );
is( death_of( sub { check_hash( { 'into' => ['client_ip'], 'where' => [] }, $read_shape, 'The read' ) } ),
	undef, 'any_of takes both' );
is(
	death_of( sub { check_hash( {}, $read_shape, 'The read' ) } ),
	'The read has neither where nor into, so it does nothing',
	'any_of refuses neither, the message ending on the why'
);
is(
	death_of(
		sub {
			check_hash(
				{ 'list' => 'feed', 'lists' => ['feed'] },
				{
					'optional' => { 'list' => 'any', 'lists' => 'any' },
					'not_both' => [ [ 'list', 'lists', 'so which is meant can not be told' ] ],
				},
				'The entry'
			);
		}
	),
	'The entry has both list and lists, so which is meant can not be told',
	'a not_both pair may say why as well'
);

#
# check_entries
#

my $marks_where = 'The mark of the rule "syslog/x"';
my $good_mark   = { 'name' => 'brute', 'ttl' => 60 };

is( death_of( sub { check_entries( [ $good_mark, $good_mark ], $mark_shape, $marks_where ) } ),
	undef, 'a list of hashes each of the shape passes' );
is(
	death_of( sub { check_entries( [], $mark_shape, $marks_where ) } ),
	$marks_where . ' is not a non-empty array',
	'a empty list'
);
is(
	death_of( sub { check_entries( $good_mark, $mark_shape, $marks_where ) } ),
	$marks_where . ' is not a non-empty array',
	'a hash where the list belongs'
);
is(
	death_of( sub { check_entries( undef, $mark_shape, $marks_where ) } ),
	$marks_where . ' is not a non-empty array',
	'a undef where the list belongs'
);
is(
	death_of( sub { check_entries( [ $good_mark, { 'name' => 'second' } ], $mark_shape, $marks_where ) } ),
	$marks_where . ' entry 1 lacks a ttl',
	'a entry is named by its place in the list, counted from zero'
);
is(
	death_of( sub { check_entries( [ $good_mark, 'second' ], $mark_shape, $marks_where ) } ),
	$marks_where . ' entry 1 is not a hash',
	'a entry that is not a hash'
);

#
# the int predicates the config shares
#

ok( is_non_negative_int(0),      'is_non_negative_int takes zero' );
ok( is_non_negative_int('042'),  'and digits with a leading zero' );
ok( !is_non_negative_int('-1'),  'and refuses a sign' );
ok( !is_non_negative_int('1.0'), 'and a point' );
ok( !is_non_negative_int(' 1'),  'and a space' );
ok( !is_non_negative_int("1\n"), 'and a trailing newline' );
ok( !is_non_negative_int(''),    'and a empty string' );
ok( !is_non_negative_int(undef), 'and undef' );
ok( !is_non_negative_int( [1] ), 'and a ref' );

ok( is_positive_int(1),      'is_positive_int takes one' );
ok( !is_positive_int('00'),  'and refuses all zeros' );
ok( !is_positive_int(0),     'and refuses zero' );
ok( !is_positive_int('1.5'), 'and a point' );
ok( !is_positive_int(undef), 'and undef' );

done_testing;
