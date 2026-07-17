#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp   qw( tempdir );
use File::Path   qw( make_path );
use MIME::Base64 qw( encode_base64 );
use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();

# keyword search across fields... the reserved %%%ANY%%% field fans a predicate
# over every value, %%%ANY:prefix%%% over a subtree, and the keywords shorthand
# is sugar over it

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/json' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

my $rules = App::Baphomet::Rules->new( 'rules_dir' => $dir );

sub matches {
	my ( $name, $line ) = @_;
	my $parsed = App::Baphomet::Parser::parse( 'json', $line );
	my $rule   = $rules->load($name);
	return defined( $rule->check($parsed) ) ? 1 : 0;
}

my $head = "---\nban_var:\n  - id\n";

# --- %%%ANY%%% ... a keyword anywhere ---
write_rule( 'json/any', $head . "gate:\n  - { field: '%%%ANY%%%', op: contains, value: mimikatz }\n" );
is( matches( 'json/any', '{"process":{"cmd":"run mimikatz now"},"id":"a"}' ), 1, 'a keyword in a nested field is found' );
is( matches( 'json/any', '{"network":{"host":"mimikatz.evil.com"},"id":"a"}' ), 1, 'and in any other field' );
is( matches( 'json/any', '{"process":{"cmd":"whoami"},"id":"a"}' ),           0, 'a keyword nowhere does not match' );

# --- %%%ANY:prefix%%% ... scoped to a subtree, ignoring unrelated data ---
write_rule( 'json/scoped', $head . "gate:\n  - { field: '%%%ANY:process%%%', op: contains, value: mimikatz }\n" );
is( matches( 'json/scoped', '{"process":{"cmd":"run mimikatz"},"network":{"host":"clean"},"id":"a"}' ),
	1, 'scoped: a keyword under the named subtree is found' );
is( matches( 'json/scoped', '{"process":{"cmd":"whoami"},"network":{"host":"mimikatz.evil.com"},"id":"a"}' ),
	0, 'scoped: a match in an unrelated branch is ignored' );

# --- decode over every field ---
write_rule( 'json/decoded', $head . "gate:\n  - { field: '%%%ANY%%%', op: contains, value: DownloadString, decode: [ base64 ] }\n" );
my $b64 = encode_base64( 'IEX Net.WebClient.DownloadString', '' );
is( matches( 'json/decoded', qq({"data":{"blob":"$b64"},"id":"a"}) ), 1, 'a decoded keyword is found in whatever field carried it' );
is( matches( 'json/decoded', '{"data":{"blob":"aGVsbG8="},"id":"a"}' ), 0, 'a field that decodes to something else does not match' );

# --- a negated keyword means the string is in no field ---
write_rule( 'json/absent', $head . "gate:\n  - { field: '%%%ANY%%%', op: contains, value: healthcheck, negate: true }\n" );
is( matches( 'json/absent', '{"user":"root","id":"a"}' ),        1, 'negated keyword holds when the string is absent from all fields' );
is( matches( 'json/absent', '{"user":"healthcheck","id":"a"}' ), 0, 'negated keyword fails when some field carries the string' );

# --- keywords shorthand, all fields ---
write_rule( 'json/kw', $head . "keywords: [ mimikatz, sekurlsa ]\n" );
is( matches( 'json/kw', '{"x":{"y":"loaded sekurlsa"},"id":"a"}' ), 1, 'the keywords list matches any of its strings anywhere' );
is( matches( 'json/kw', '{"x":{"y":"nothing here"},"id":"a"}' ),    0, 'and misses when none appear' );

# --- keywords shorthand, scoped with in ---
write_rule( 'json/kwin', $head . "keywords:\n  in: '%%%ANY:process%%%'\n  values: [ mimikatz ]\n" );
is( matches( 'json/kwin', '{"process":{"cmd":"mimikatz"},"other":{"z":"clean"},"id":"a"}' ), 1, 'scoped keywords match under the subtree' );
is( matches( 'json/kwin', '{"process":{"cmd":"clean"},"other":{"z":"mimikatz"},"id":"a"}' ), 0, 'scoped keywords ignore other branches' );

# --- keywords compose with a gate (ANDed) ---
write_rule( 'json/kwgate', $head . "keywords: [ mimikatz ]\ngate:\n  - { field: level, op: eq, value: high }\n" );
is( matches( 'json/kwgate', '{"msg":"mimikatz","level":"high","id":"a"}' ), 1, 'keywords AND a gate, both satisfied' );
is( matches( 'json/kwgate', '{"msg":"mimikatz","level":"low","id":"a"}' ),  0, 'keywords hold but the gate fails' );
is( matches( 'json/kwgate', '{"msg":"clean","level":"high","id":"a"}' ),    0, 'the gate holds but the keyword is absent' );

# --- errors ---
write_rule( 'json/kwbad', $head . "keywords:\n  in: process\n" );
ok( !eval { $rules->load('json/kwbad'); 1 }, 'keywords with no values is a load error' );

done_testing;
