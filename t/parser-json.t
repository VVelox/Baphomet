#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Parser ();

my $parsed = App::Baphomet::Parser::parse( 'json',
	'{"c":"ACCESS","msg":"Authentication failed","n":5,"ok":true,"bad":false,"nothing":null,"attr":{"remote":"192.0.2.5:54321","deep":{"deeper":"x"}},"tags":["a","b"]}'
);
ok( defined($parsed), 'line parsed' ) || BAIL_OUT('the most basic line did not parse');
is( $parsed->{format}, 'json', 'format' );
my $fields = $parsed->{fields};
is( ref($fields),                 'HASH',                  'fields is a hash' );
is( $fields->{c},                 'ACCESS',                'top level scalar' );
is( $fields->{msg},               'Authentication failed', 'string with spaces' );
is( $fields->{n},                 5,                       'number kept' );
is( $fields->{ok},                1,                       'true flattens to 1' );
is( $fields->{bad},               0,                       'false flattens to 0' );
ok( !exists( $fields->{nothing} ), 'null counts as absent' );
is( $fields->{'attr.remote'},     '192.0.2.5:54321',       'nested hash dotted' );
is( $fields->{'attr.deep.deeper'}, 'x',                    'deeper nesting dotted' );
is( $fields->{'tags.0'},          'a',                     'array indexed' );
is( $fields->{'tags.1'},          'b',                     'array indexed further' );

# depth cap... build 12 levels of nesting, the bottom is dropped
my $deep_json = '"leaf"';
foreach my $level ( 1 .. 12 ) {
	$deep_json = '{"d":' . $deep_json . '}';
}
$parsed = App::Baphomet::Parser::parse( 'json', $deep_json );
ok( defined($parsed), 'deep line still parses' );
ok( !( grep { /leaf/ } values( %{ $parsed->{fields} } ) ), 'past the depth cap is dropped' );

# literal dotted key colliding with nesting is last wins, not a crash
$parsed = App::Baphomet::Parser::parse( 'json', '{"a.b":"literal","a":{"b":"nested"}}' );
ok( defined($parsed), 'colliding line parses' );
ok( defined( $parsed->{fields}{'a.b'} ), 'the collided path exists' );

# garbage
is( App::Baphomet::Parser::parse( 'json', '[1,2,3]' ),           undef, 'non-object JSON returns undef' );
is( App::Baphomet::Parser::parse( 'json', '{"truncated":' ),     undef, 'truncated JSON returns undef' );
is( App::Baphomet::Parser::parse( 'json', 'not json at all' ),   undef, 'non-JSON returns undef' );
is( App::Baphomet::Parser::parse( 'json', undef ),               undef, 'undef returns undef' );

ok( App::Baphomet::Parser::is_known('json'), 'json is a known parser' );

done_testing;
