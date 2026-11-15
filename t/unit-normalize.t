#!perl
# direct unit tests for App::Baphomet::Gate::normalize... each step, the order
# they are done in, the two ways of taking a .. above /, and where the copy
# is lifted to
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::normalize qw( normalize_path );

sub with {
	my ( $path, @ops ) = @_;

	return normalize_path( $path, { map { $_ => 1 } @ops } );
}

#
# each step alone
#

is( with( '/%77p-login.php', 'url' ),   '/wp-login.php', 'url decodes' );
is( with( '/%2577p-login.php', 'url' ), '/wp-login.php', 'and decodes again while it changes things' );
is( with( '/%25252577p', 'url' ),       '/%77p',         'three times at the most' );
is( with( '/%zz%4', 'url' ),            '/%zz%4',        'a % that is no escape is left' );

is( with( '/%c0%afetc', 'url', 'overlong' ), '//etc', 'overlong makes a two byte form of / the /' );
is( with( "/a\xc0\xaeb", 'overlong' ),        '/a.b',  'and a two byte form of .' );
is( with( "/a\xe0\x80\xaeb", 'overlong' ),    '/a.b',  'and a three byte one' );
is( with( '/%u002e%u002e/x', 'overlong' ),    '/../x', 'and the %u form IIS takes' );
is( with( "/\xc3\xa9t\xc3\xa9", 'overlong' ), "/\xc3\xa9t\xc3\xa9", 'and leaves a real two byte character be' );

is( with( "/x.php\0.jpg", 'nul' ),            '/x.php',  'nul cuts at a NUL' );
is( with( '/x.php%00.jpg', 'url', 'nul' ),    '/x.php',  'one a url decode made' );
is( with( '/a\\b\\c', 'backslash' ),          '/a/b/c',  'backslash makes each \\ a /' );
is( with( '///a//b/', 'slashes' ),            '/a/b/',   'slashes makes each run of / one' );
is( with( '/admin;x=1/y;z/w', 'params' ),     '/admin/y/w', 'params cuts the ;parameters of each segment' );
is( with( '/WP-Login.PHP', 'lower' ),         '/wp-login.php', 'lower lowercases' );

#
# dot_segment and dot_segment_below
#

my %dots = (
	'/a/b/../c'              => [ '/a/c',        '/a/c' ],
	'/a/./b/.'               => [ '/a/b/',       '/a/b/' ],
	'/a/b/..'                => [ '/a/',         '/a/' ],
	'/../../etc/passwd'      => [ '/etc/passwd', '/../../etc/passwd' ],
	'/a/../../etc/passwd'    => [ '/etc/passwd', '/../etc/passwd' ],
	'/a/b/../../../c/../d'   => [ '/d',          '/../d' ],
	'a/../../b'              => [ 'b',           '../b' ],
	'/..'                    => [ '/',           '/../' ],
	'/a..b/.c/...'           => [ '/a..b/.c/...', '/a..b/.c/...' ],
);
foreach my $path ( sort( keys(%dots) ) ) {
	is( with( $path, 'dot_segment' ),       $dots{$path}[0], 'dot_segment makes ' . $path . ' ' . $dots{$path}[0] );
	is( with( $path, 'dot_segment_below' ), $dots{$path}[1], 'dot_segment_below makes it ' . $dots{$path}[1] );
}

#
# the query, and the order
#

is( with( '/a/../b?x=/../y', 'dot_segment' ),           '/b?x=/../y', 'the query is put back as it was, never resolved' );
is( with( '/a/../b?x=1', 'dot_segment', 'query' ),      '/b',         'and query leaves it off' );
is( with( '/a/../b#frag', 'dot_segment', 'query' ),     '/b',         'a fragment as well' );
is( with( '/%3f/../x?q', 'url', 'dot_segment' ),        '/x?q',       'a %3f is part of the path, the split being made ahead of the decode' );
is( with( '/a/%2e%2e/b', 'dot_segment', 'url' ),        '/b',         'url is done ahead of dot_segment whatever order they are named in' );
is( with( '/a/..%5c..%5cetc', 'url', 'backslash', 'dot_segment_below' ), '/../etc', 'and backslash ahead of it too' );
is( with( '/A/%2E%2E/WP-LOGIN.PHP', 'url', 'dot_segment', 'lower' ), '/wp-login.php', 'lower last of all' );
is( with( '//x/..//%77P-login.php?a=1', qw( url overlong nul backslash slashes params dot_segment lower ) ),
	'/wp-login.php?a=1', 'all of them' );

#
# the gate
#

sub normalize_gate {
	my (%args) = @_;

	return App::Baphomet::Gate::normalize->new(
		'type'  => 'normalize',
		'args'  => { 'var' => 'path', 'into' => 'PATH', 'ops' => [ 'url', 'dot_segment' ], %args },
		'where' => 'the gate'
	);
}

my $gate = normalize_gate();
is( $gate->phase, 'line', 'it is of the line phase' );

my %shared  = ( 'path' => '/a/../%77p' );
my %passage = ( 'parsed' => {}, 'rule' => {}, 'fields' => \%shared, 'fields_owned' => 0 );
is( $gate->ask( \%passage ), 1, 'it lets the line by' );
is( $passage{fields}{PATH}, '/wp', 'and lifts the copy into the line\'s fields' );
is( $passage{fields}{path}, '/a/../%77p', 'leaving the path as it was' );
ok( !exists( $shared{PATH} ), 'a field space every rule shares is copied, not written to' );

my %own = ( 'data' => { 'path' => '/a/../b', 'PATH' => 'from the line' } );
%passage = ( 'parsed' => {}, 'rule' => {}, 'own' => \%own, 'results' => [ \%own ] );
$gate->ask( \%passage );
is( $own{data}{PATH}, 'from the line', 'a copy is never lifted over a value already there' );

%passage = ( 'parsed' => {}, 'rule' => {}, 'fields' => { 'host' => '203.0.113.9' }, 'fields_owned' => 1 );
$gate->ask( \%passage );
ok( !exists( $passage{fields}{PATH} ), 'a path that is not there lifts nothing' );

my %refused = (
	'no ops'                       => [ { 'ops' => [] },                                    qr/^the gate has a ops that is not a non-empty array/ ],
	'a op there is none of'        => [ { 'ops' => ['decode'] },                            qr/^the gate has a ops that is not a non-empty array/ ],
	'a op named twice'             => [ { 'ops' => [ 'url', 'url' ] },                      qr/^the gate names the op url twice/ ],
	'both kinds of dot_segment'    => [ { 'ops' => [ 'dot_segment', 'dot_segment_below' ] }, qr/^the gate names both dot_segment and dot_segment_below/ ],
);
foreach my $description ( sort( keys(%refused) ) ) {
	my ( $args, $message ) = @{ $refused{$description} };
	my $error = eval { normalize_gate( %{$args} ); 1 } ? '' : $@;
	like( $error, $message, $description . ' is refused' );
}
ok( !eval { App::Baphomet::Gate::normalize->new( 'type' => 'normalize', 'args' => { 'var' => 'path', 'ops' => ['url'] }, 'where' => 'the gate' ); 1 },
	'and one with no into' );

done_testing();
