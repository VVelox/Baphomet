#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp            qw( tempdir );
use File::Path            qw( make_path );
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

my $rules = App::Baphomet::Rules->new( 'rules_dir' => $dir, shipped => 0 );

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
is( matches( 'json/re', '{"remote":"1.2.3.4:22","src":"1.2.3.4"}' ),  1, 're with a token matches' );
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
is( matches( 'json/cidr', '{"src":"10.9.8.7"}' ),    1, 'cidr matches an in-range v4' );
is( matches( 'json/cidr', '{"src":"8.8.8.8"}' ),     0, 'cidr misses an out-of-range v4' );
is( matches( 'json/cidr', '{"src":"2001:db8::1"}' ), 1, 'cidr matches an in-range v6' );
is( matches( 'json/cidr', '{"src":"not-an-ip"}' ),   0, 'cidr misses a non-address' );

# --- negate ---
write_rule( 'json/neg', $head . "  - field: user\n    op: eq\n    value: healthcheck\n    negate: true\n" );
is( matches( 'json/neg', '{"user":"root","src":"1.1.1.1"}' ),        1, 'negate holds when the value differs' );
is( matches( 'json/neg', '{"user":"healthcheck","src":"1.1.1.1"}' ), 0, 'negate fails when the value matches' );
is( matches( 'json/neg', '{"src":"1.1.1.1"}' ), 1, 'negate holds when the field is absent (Sigma semantics)' );

# --- all vs any across values ---
write_rule( 'json/all', $head . "  - field: cmd\n    op: contains\n    values: [ foo, bar ]\n    all: true\n" );
write_rule( 'json/any', $head . "  - field: cmd\n    op: contains\n    values: [ foo, bar ]\n" );
is( matches( 'json/all', '{"cmd":"foo and bar","src":"1.1.1.1"}' ), 1, 'all matches when every value is present' );
is( matches( 'json/all', '{"cmd":"only foo","src":"1.1.1.1"}' ),    0, 'all misses when one value is absent' );
is( matches( 'json/any', '{"cmd":"only foo","src":"1.1.1.1"}' ),    1, 'any (default) matches on one value' );

# --- predicate ANDed with a legacy gate entry, mixed in one rule ---
write_rule( 'json/mixed',
	"---\nban_var:\n  - src\ngate:\n  - field: event\n    values: [ ACCESS ]\n  - field: bytes\n    op: gt\n    value: 100\n"
);
is( matches( 'json/mixed', '{"event":"ACCESS","bytes":200,"src":"1.1.1.1"}' ), 1,
	'legacy + predicate gate, both pass' );
is( matches( 'json/mixed', '{"event":"ACCESS","bytes":50,"src":"1.1.1.1"}' ),
	0, 'legacy passes, predicate fails, ANDed out' );
is( matches( 'json/mixed', '{"event":"OTHER","bytes":200,"src":"1.1.1.1"}' ),
	0, 'predicate passes, legacy fails, ANDed out' );

# --- compile-time errors ---
write_rule( 'json/badop',   $head . "  - field: x\n    op: wat\n    value: y\n" );
write_rule( 'json/badnum',  $head . "  - field: x\n    op: gt\n    value: notanum\n" );
write_rule( 'json/badcidr', $head . "  - field: x\n    op: cidr\n    value: 999.999.0.0/8\n" );
ok( !eval { $rules->load('json/badop');   1 }, 'an unknown op is a load error' );
ok( !eval { $rules->load('json/badnum');  1 }, 'a non-numeric value for a numeric op is a load error' );
ok( !eval { $rules->load('json/badcidr'); 1 }, 'a bad cidr is a load error' );

# --- decode: base64 ---
write_rule( 'json/b64', $head . "  - field: blob\n    op: contains\n    value: malware\n    decode: [ base64 ]\n" );
my $b64_mal = encode_base64( 'this is malware', '' );
my $b64_ok  = encode_base64( 'all clean here',  '' );
is( matches( 'json/b64', qq({"blob":"$b64_mal","src":"1.1.1.1"}) ), 1, 'base64 decodes and the needle is found' );
is( matches( 'json/b64', qq({"blob":"$b64_ok","src":"1.1.1.1"}) ),  0, 'base64 decodes but the needle is absent' );

# --- decode chain: base64 then utf16le, the PowerShell -enc shape ---
write_rule( 'json/enc',
	$head . "  - field: cmd\n    op: contains\n    value: DownloadString\n    decode: [ base64, utf16le ]\n" );
my $enc = encode_base64( Encode::encode( 'UTF-16LE', 'IEX (New-Object Net.WebClient).DownloadString(x)' ), '' );
is( matches( 'json/enc', qq({"cmd":"$enc","src":"1.1.1.1"}) ), 1, 'base64 then utf16le decodes a -enc blob' );

# --- decode: base64offset ---
write_rule( 'json/off',
	$head . "  - field: blob\n    op: contains\n    value: secretword\n    decode: [ base64offset ]\n" );
my $b64_off = encode_base64( 'xx secretword xx', '' );
is( matches( 'json/off', qq({"blob":"$b64_off","src":"1.1.1.1"}) ), 1, 'base64offset decodes and finds the needle' );

# --- decode: url ---
write_rule( 'json/url', $head . "  - field: uri\n    op: contains\n    value: '../etc/passwd'\n    decode: [ url ]\n" );
is( matches( 'json/url', q({"uri":"%2e%2e%2fetc%2fpasswd","src":"1.1.1.1"}) ),
	1, 'url percent-decodes before matching' );

# --- decode: lower ---
write_rule( 'json/low', $head . "  - field: user\n    op: eq\n    value: administrator\n    decode: [ lower ]\n" );
is( matches( 'json/low', q({"user":"ADMINISTRATOR","src":"1.1.1.1"}) ), 1, 'lower folds case before matching' );

# --- decode: windash (a unicode dash normalized to ascii) ---
write_rule( 'json/dash', $head . "  - field: flag\n    op: eq\n    value: '-enc'\n    decode: [ windash ]\n" );
# a real log line arrives as UTF-8 bytes, which is what the parser decodes
my $dash_line = JSON::MaybeXS::encode_json( { 'flag' => "\x{2013}enc", 'src' => '1.1.1.1' } );
is( matches( 'json/dash', $dash_line ), 1, 'windash folds a unicode dash to ascii' );

# --- a decode that cannot complete drops the candidate, no match, no crash ---
write_rule( 'json/drop',
	$head . "  - field: blob\n    op: contains\n    value: anything\n    decode: [ base64, utf16be ]\n" );
is( matches( 'json/drop', q({"blob":"aGVsbG8","src":"1.1.1.1"}) ), 0,
	'a decode chain that cannot finish drops safely' );

# --- unknown decode transform is a load error ---
write_rule( 'json/baddecode', $head . "  - field: x\n    op: eq\n    value: y\n    decode: [ rot13 ]\n" );
ok( !eval { $rules->load('json/baddecode'); 1 }, 'an unknown decode transform is a load error' );

# --- nocase: case-insensitive string ops ---
write_rule( 'json/nceq', $head . "  - field: user\n    op: eq\n    value: Administrator\n    nocase: true\n" );
is( matches( 'json/nceq', '{"user":"ADMINISTRATOR","src":"1.1.1.1"}' ), 1, 'nocase eq matches across case' );
is( matches( 'json/nceq', '{"user":"administrator","src":"1.1.1.1"}' ), 1, 'nocase eq matches lowercased' );
is( matches( 'json/nceq', '{"user":"admin","src":"1.1.1.1"}' ),         0, 'nocase eq still needs the whole value' );

write_rule( 'json/nccont', $head . "  - field: cmd\n    op: contains\n    value: mimikatz\n    nocase: true\n" );
is( matches( 'json/nccont', '{"cmd":"Invoke-MimiKatz -DumpCreds","src":"1.1.1.1"}' ),
	1, 'nocase contains matches mixed case' );

write_rule( 'json/ncends', $head . "  - field: file\n    op: endswith\n    value: .dll\n    nocase: true\n" );
is( matches( 'json/ncends', '{"file":"EVIL.DLL","src":"1.1.1.1"}' ), 1, 'nocase endswith matches uppercased suffix' );

# --- case sensitive by default (no nocase) ---
write_rule( 'json/cs', $head . "  - field: user\n    op: eq\n    value: Administrator\n" );
is( matches( 'json/cs', '{"user":"ADMINISTRATOR","src":"1.1.1.1"}' ),
	0, 'without nocase the compare is case-sensitive' );
is( matches( 'json/cs', '{"user":"Administrator","src":"1.1.1.1"}' ), 1, 'and the exact case still matches' );

# --- nocase re bakes in (?i) ---
write_rule( 'json/ncre', $head . "  - field: ua\n    op: re\n    value: 'sqlmap'\n    nocase: true\n" );
is( matches( 'json/ncre', '{"ua":"SQLMap/1.5","src":"1.1.1.1"}' ), 1, 'nocase re matches case-insensitively' );

# --- nocase composes with decode ---
write_rule( 'json/ncdec',
	$head . "  - field: blob\n    op: contains\n    value: malware\n    nocase: true\n    decode: [ base64 ]\n" );
my $b64_upper = encode_base64( 'this is MALWARE payload', '' );
is( matches( 'json/ncdec', qq({"blob":"$b64_upper","src":"1.1.1.1"}) ), 1, 'nocase folds the decoded candidate too' );

# --- nocase on a numeric or cidr op is a load error ---
write_rule( 'json/ncnum',  $head . "  - field: n\n    op: gt\n    value: 5\n    nocase: true\n" );
write_rule( 'json/nccidr', $head . "  - field: s\n    op: cidr\n    value: 10.0.0.0/8\n    nocase: true\n" );
ok( !eval { $rules->load('json/ncnum');  1 }, 'nocase on a numeric op is a load error' );
ok( !eval { $rules->load('json/nccidr'); 1 }, 'nocase on a cidr op is a load error' );

# --- fieldref: compare a field to another field's live value ---
write_rule( 'json/fr', $head . "  - field: auth_user\n    op: eq\n    fieldref: cert_user\n" );
is( matches( 'json/fr', '{"auth_user":"alice","cert_user":"alice","src":"1.1.1.1"}' ),
	1, 'fieldref eq matches when the two fields are equal' );
is( matches( 'json/fr', '{"auth_user":"alice","cert_user":"bob","src":"1.1.1.1"}' ),
	0, 'fieldref eq misses when they differ' );
is( matches( 'json/fr', '{"auth_user":"alice","src":"1.1.1.1"}' ),
	0, 'fieldref misses when the referenced field is absent' );
is( matches( 'json/fr', '{"cert_user":"alice","src":"1.1.1.1"}' ),
	0, 'fieldref misses when the source field is absent' );

# --- fieldref + negate: fire when the fields DIFFER ---
write_rule( 'json/frneg', $head . "  - field: auth_user\n    op: eq\n    fieldref: cert_user\n    negate: true\n" );
is( matches( 'json/frneg', '{"auth_user":"alice","cert_user":"bob","src":"1.1.1.1"}' ),
	1, 'fieldref negate holds when the fields differ' );
is( matches( 'json/frneg', '{"auth_user":"alice","cert_user":"alice","src":"1.1.1.1"}' ),
	0, 'fieldref negate fails when they are equal' );

# --- fieldref + contains ---
write_rule( 'json/frcont', $head . "  - field: path\n    op: contains\n    fieldref: tenant\n" );
is( matches( 'json/frcont', '{"path":"/orgs/acme/x","tenant":"acme","src":"1.1.1.1"}' ),
	1, 'fieldref contains matches when the ref value is a substring' );
is( matches( 'json/frcont', '{"path":"/orgs/other/x","tenant":"acme","src":"1.1.1.1"}' ),
	0, 'fieldref contains misses otherwise' );

# --- fieldref + nocase folds the dynamic needle too ---
write_rule( 'json/frnc', $head . "  - field: a\n    op: eq\n    fieldref: b\n    nocase: true\n" );
is( matches( 'json/frnc', '{"a":"Alice","b":"ALICE","src":"1.1.1.1"}' ),
	1, 'fieldref nocase folds both the field and the referenced needle' );
is( matches( 'json/frnc', '{"a":"Alice","b":"ALICE","src":"1.1.1.1"}' ), 1, 'and stays a match' );

# --- fieldref load errors ---
write_rule( 'json/frboth',  $head . "  - field: a\n    op: eq\n    fieldref: b\n    value: c\n" );
write_rule( 'json/frnum',   $head . "  - field: a\n    op: gt\n    fieldref: b\n" );
write_rule( 'json/frempty', $head . "  - field: a\n    op: eq\n    fieldref: ''\n" );
ok( !eval { $rules->load('json/frboth');  1 }, 'fieldref plus a literal value is a load error' );
ok( !eval { $rules->load('json/frnum');   1 }, 'fieldref with a numeric op is a load error' );
ok( !eval { $rules->load('json/frempty'); 1 }, 'an empty fieldref is a load error' );

# --- exists: field presence ---
write_rule( 'json/ex', $head . "  - field: ParentImage\n    op: exists\n" );
is( matches( 'json/ex', '{"ParentImage":"/usr/bin/x","src":"1.1.1.1"}' ),
	1, 'exists matches when the field is present' );
is( matches( 'json/ex', '{"ParentImage":"","src":"1.1.1.1"}' ), 1, 'exists matches a present-but-empty field' );
is( matches( 'json/ex', '{"src":"1.1.1.1"}' ),                  0, 'exists misses when the field is absent' );

# --- exists + negate: field absence (Sigma exists:false) ---
write_rule( 'json/exneg', $head . "  - field: CommandLine\n    op: exists\n    negate: true\n" );
is( matches( 'json/exneg', '{"src":"1.1.1.1"}' ), 1, 'exists+negate matches when the field is absent' );
is( matches( 'json/exneg', '{"CommandLine":"whoami","src":"1.1.1.1"}' ),
	0, 'exists+negate misses when the field is present' );

# --- exists composes in a selection alongside a value predicate ---
write_rule( 'json/exsel',
	"---\nban_var:\n  - src\nselections:\n  s:\n    - field: EventID\n      op: eq\n      value: 1\n    - field: ParentImage\n      op: exists\ncondition: s\n"
);
is( matches( 'json/exsel', '{"EventID":1,"ParentImage":"/x","src":"1.1.1.1"}' ), 1,
	'exists in a selection, both hold' );
is( matches( 'json/exsel', '{"EventID":1,"src":"1.1.1.1"}' ), 0, 'exists in a selection, field absent fails the AND' );

# --- exists load errors: it takes no value/fieldref/decode ---
write_rule( 'json/exval', $head . "  - field: a\n    op: exists\n    value: x\n" );
write_rule( 'json/exdec', $head . "  - field: a\n    op: exists\n    decode: [ base64 ]\n" );
ok( !eval { $rules->load('json/exval'); 1 }, 'exists with a value is a load error' );
ok( !eval { $rules->load('json/exdec'); 1 }, 'exists with a decode is a load error' );

# --- fieldref under a keyword field can never match, so it may not load ---
write_rule( 'json/frkw', $head . "  - field: '%%%ANY%%%'\n    op: eq\n    fieldref: cert_user\n" );
ok( !eval { $rules->load('json/frkw'); 1 }, 'fieldref under a keyword field is a load error' );
like( $@, qr/keyword field/, 'and the error names the pairing' );

done_testing;
