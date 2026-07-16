#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );
use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();
use MIME::Base64          qw( encode_base64 );
use Encode                ();
use JSON::MaybeXS         ();

# typed field-operator predicates on the json rule gate... the opt-in richer
# form. the legacy field/values gate is exercised alongside to prove it is
# untouched

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

# does rule NAME match the json LINE?
sub matches {
	my ( $name, $line ) = @_;
	my $parsed = App::Baphomet::Parser::parse( 'json', $line );
	my $rule   = $rules->load($name);
	return defined( $rule->check($parsed) ) ? 1 : 0;
}

my $head = "---\nban_var:\n  - src\ngate:\n";

# --- eq (default op, and explicit) ---
write_rule( 'json/eq', $head . "  - field: event\n    op: eq\n    value: auth_fail\n" );
is( matches( 'json/eq', '{"event":"auth_fail","src":"1.2.3.4"}' ), 1, 'eq matches' );
is( matches( 'json/eq', '{"event":"login","src":"1.2.3.4"}' ),     0, 'eq misses' );
is( matches( 'json/eq', '{"src":"1.2.3.4"}' ),                     0, 'eq on a missing field misses' );

# --- contains / startswith / endswith ---
write_rule( 'json/contains',   $head . "  - field: cmd\n    op: contains\n    value: powershell\n" );
write_rule( 'json/startswith', $head . "  - field: uri\n    op: startswith\n    value: /admin\n" );
write_rule( 'json/endswith',   $head . "  - field: file\n    op: endswith\n    value: .exe\n" );
is( matches( 'json/contains',   '{"cmd":"C:/x/powershell.exe -enc","src":"1.1.1.1"}' ), 1, 'contains matches' );
is( matches( 'json/contains',   '{"cmd":"cmd.exe","src":"1.1.1.1"}' ),                  0, 'contains misses' );
is( matches( 'json/startswith', '{"uri":"/admin/login","src":"1.1.1.1"}' ),             1, 'startswith matches' );
is( matches( 'json/startswith', '{"uri":"/public","src":"1.1.1.1"}' ),                  0, 'startswith misses' );
is( matches( 'json/endswith',   '{"file":"evil.exe","src":"1.1.1.1"}' ),                1, 'endswith matches' );
is( matches( 'json/endswith',   '{"file":"evil.dll","src":"1.1.1.1"}' ),                0, 'endswith misses' );

# --- re (tokened) ---
write_rule( 'json/re', $head . "  - field: remote\n    op: re\n    value: '^%%%%SRC%%%%:\\d+\$'\n" );
is( matches( 'json/re', '{"remote":"1.2.3.4:22","src":"1.2.3.4"}' ), 1, 're with a token matches' );
is( matches( 'json/re', '{"remote":"not-an-addr","src":"1.2.3.4"}' ), 0, 're misses' );

# --- numeric gt/lt/ge/le ---
write_rule( 'json/gt', $head . "  - field: bytes\n    op: gt\n    value: 1000\n" );
write_rule( 'json/le', $head . "  - field: code\n    op: le\n    value: 400\n" );
is( matches( 'json/gt', '{"bytes":2000,"src":"1.1.1.1"}' ),   1, 'gt matches a larger number' );
is( matches( 'json/gt', '{"bytes":500,"src":"1.1.1.1"}' ),    0, 'gt misses a smaller number' );
is( matches( 'json/gt', '{"bytes":"1000","src":"1.1.1.1"}' ), 0, 'gt is strict (equal is not greater)' );
is( matches( 'json/gt', '{"bytes":"lots","src":"1.1.1.1"}' ), 0, 'gt misses a non-numeric field' );
is( matches( 'json/le', '{"code":400,"src":"1.1.1.1"}' ),     1, 'le matches an equal number' );
is( matches( 'json/le', '{"code":500,"src":"1.1.1.1"}' ),     0, 'le misses a larger number' );

# --- cidr, v4 and v6 ---
write_rule( 'json/cidr', $head . "  - field: src\n    op: cidr\n    values: [ 10.0.0.0/8, 2001:db8::/32 ]\n" );
is( matches( 'json/cidr', '{"src":"10.9.8.7"}' ),      1, 'cidr matches an in-range v4' );
is( matches( 'json/cidr', '{"src":"8.8.8.8"}' ),       0, 'cidr misses an out-of-range v4' );
is( matches( 'json/cidr', '{"src":"2001:db8::1"}' ),   1, 'cidr matches an in-range v6' );
is( matches( 'json/cidr', '{"src":"not-an-ip"}' ),     0, 'cidr misses a non-address' );

# --- negate ---
write_rule( 'json/neg', $head . "  - field: user\n    op: eq\n    value: healthcheck\n    negate: true\n" );
is( matches( 'json/neg', '{"user":"root","src":"1.1.1.1"}' ),        1, 'negate holds when the value differs' );
is( matches( 'json/neg', '{"user":"healthcheck","src":"1.1.1.1"}' ), 0, 'negate fails when the value matches' );
is( matches( 'json/neg', '{"src":"1.1.1.1"}' ),                      1, 'negate holds when the field is absent (Sigma semantics)' );

# --- all vs any across values ---
write_rule( 'json/all', $head . "  - field: cmd\n    op: contains\n    values: [ foo, bar ]\n    all: true\n" );
write_rule( 'json/any', $head . "  - field: cmd\n    op: contains\n    values: [ foo, bar ]\n" );
is( matches( 'json/all', '{"cmd":"foo and bar","src":"1.1.1.1"}' ), 1, 'all matches when every value is present' );
is( matches( 'json/all', '{"cmd":"only foo","src":"1.1.1.1"}' ),    0, 'all misses when one value is absent' );
is( matches( 'json/any', '{"cmd":"only foo","src":"1.1.1.1"}' ),    1, 'any (default) matches on one value' );

# --- predicate ANDed with a legacy gate entry, mixed in one rule ---
write_rule( 'json/mixed',
	"---\nban_var:\n  - src\ngate:\n  - field: event\n    values: [ ACCESS ]\n  - field: bytes\n    op: gt\n    value: 100\n" );
is( matches( 'json/mixed', '{"event":"ACCESS","bytes":200,"src":"1.1.1.1"}' ), 1, 'legacy + predicate gate, both pass' );
is( matches( 'json/mixed', '{"event":"ACCESS","bytes":50,"src":"1.1.1.1"}' ),  0, 'legacy passes, predicate fails, ANDed out' );
is( matches( 'json/mixed', '{"event":"OTHER","bytes":200,"src":"1.1.1.1"}' ),  0, 'predicate passes, legacy fails, ANDed out' );

# --- compile-time errors ---
write_rule( 'json/badop',  $head . "  - field: x\n    op: wat\n    value: y\n" );
write_rule( 'json/badnum', $head . "  - field: x\n    op: gt\n    value: notanum\n" );
write_rule( 'json/badcidr', $head . "  - field: x\n    op: cidr\n    value: 999.999.0.0/8\n" );
ok( !eval { $rules->load('json/badop');   1 }, 'an unknown op is a load error' );
ok( !eval { $rules->load('json/badnum');  1 }, 'a non-numeric value for a numeric op is a load error' );
ok( !eval { $rules->load('json/badcidr'); 1 }, 'a bad cidr is a load error' );

# --- decode: base64 ---
write_rule( 'json/b64', $head . "  - field: blob\n    op: contains\n    value: malware\n    decode: [ base64 ]\n" );
my $b64_mal = encode_base64( 'this is malware', '' );
my $b64_ok  = encode_base64( 'all clean here', '' );
is( matches( 'json/b64', qq({"blob":"$b64_mal","src":"1.1.1.1"}) ), 1, 'base64 decodes and the needle is found' );
is( matches( 'json/b64', qq({"blob":"$b64_ok","src":"1.1.1.1"}) ),  0, 'base64 decodes but the needle is absent' );

# --- decode chain: base64 then utf16le, the PowerShell -enc shape ---
write_rule( 'json/enc', $head . "  - field: cmd\n    op: contains\n    value: DownloadString\n    decode: [ base64, utf16le ]\n" );
my $enc = encode_base64( Encode::encode( 'UTF-16LE', 'IEX (New-Object Net.WebClient).DownloadString(x)' ), '' );
is( matches( 'json/enc', qq({"cmd":"$enc","src":"1.1.1.1"}) ), 1, 'base64 then utf16le decodes a -enc blob' );

# --- decode: base64offset ---
write_rule( 'json/off', $head . "  - field: blob\n    op: contains\n    value: secretword\n    decode: [ base64offset ]\n" );
my $b64_off = encode_base64( 'xx secretword xx', '' );
is( matches( 'json/off', qq({"blob":"$b64_off","src":"1.1.1.1"}) ), 1, 'base64offset decodes and finds the needle' );

# --- decode: url ---
write_rule( 'json/url', $head . "  - field: uri\n    op: contains\n    value: '../etc/passwd'\n    decode: [ url ]\n" );
is( matches( 'json/url', q({"uri":"%2e%2e%2fetc%2fpasswd","src":"1.1.1.1"}) ), 1, 'url percent-decodes before matching' );

# --- decode: lower ---
write_rule( 'json/low', $head . "  - field: user\n    op: eq\n    value: administrator\n    decode: [ lower ]\n" );
is( matches( 'json/low', q({"user":"ADMINISTRATOR","src":"1.1.1.1"}) ), 1, 'lower folds case before matching' );

# --- decode: windash (a unicode dash normalized to ascii) ---
write_rule( 'json/dash', $head . "  - field: flag\n    op: eq\n    value: '-enc'\n    decode: [ windash ]\n" );
# a real log line arrives as UTF-8 bytes, which is what the parser decodes
my $dash_line = JSON::MaybeXS::encode_json( { 'flag' => "\x{2013}enc", 'src' => '1.1.1.1' } );
is( matches( 'json/dash', $dash_line ), 1, 'windash folds a unicode dash to ascii' );

# --- a decode that cannot complete drops the candidate, no match, no crash ---
write_rule( 'json/drop', $head . "  - field: blob\n    op: contains\n    value: anything\n    decode: [ base64, utf16be ]\n" );
is( matches( 'json/drop', q({"blob":"aGVsbG8","src":"1.1.1.1"}) ), 0, 'a decode chain that cannot finish drops safely' );

# --- unknown decode transform is a load error ---
write_rule( 'json/baddecode', $head . "  - field: x\n    op: eq\n    value: y\n    decode: [ rot13 ]\n" );
ok( !eval { $rules->load('json/baddecode'); 1 }, 'an unknown decode transform is a load error' );

done_testing;
