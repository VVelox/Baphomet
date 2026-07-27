#!perl
# the EVE output stays valid, faithful UTF-8 no matter what bytes a log
# line carries... real UTF-8 in a captured field rides through as itself,
# hostile or malformed bytes become the replacement character rather than
# breaking the JSON, and the offender always survives to the audit record
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp    qw( tempdir );
use File::Path    qw( make_path );
use JSON::MaybeXS qw( decode_json );
use Encode        ();

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla  ();
use App::Baphomet::Parser ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run', $dir . '/cache', $dir . '/eve' );

# a rule capturing a USER tail beside the SRC, so hostile bytes can ride a
# captured field into EVE
open( my $fh, '>', $dir . '/rules/syslog/auth.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - myauth
message_regexp:
  - 'login (?<USER>\S+) from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jan  1 00:00:00 h myauth[1]: login alice from 1.2.3.4"
      found: 1
      data:
        USER: alice
        SRC: "1.2.3.4"
EOR
close($fh);

open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
eve_log = "$dir/eve/eve.json"
eve_enable = true
max_score = 3
find_time = 600

[kur.auth]
ban_time = 300

[kur.auth.log]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/auth"
EOC
close($cfg);

{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { return; };
}

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'auth' );

sub read_events {
	my $path = $dir . '/eve/eve.json';
	return () if !-f $path;
	open( my $efh, '<', $path ) || die($!);
	binmode($efh);
	my @lines = <$efh>;
	close($efh);
	# decode_json expects UTF-8 bytes and dies on anything malformed, so
	# this is itself the assertion that every emitted line is valid UTF-8
	return map { decode_json($_) } @lines;
}

# a USER whose bytes are valid UTF-8 (café) followed by SRC... feed it as a
# raw byte line the way the tailer delivers one
my $cafe_bytes = "caf\xc3\xa9";    # UTF-8 for café
$galla->_handle_line( 'log', "Jan  1 00:00:00 h myauth[1]: login ${cafe_bytes} from 192.0.2.7", $dir . '/log' );

# and a USER carrying a lone invalid byte
$galla->_handle_line( 'log', "Jan  1 00:00:00 h myauth[1]: login ev\xffil from 192.0.2.8", $dir . '/log' );

my @events = eval { read_events() };
ok( !$@, 'every EVE line decodes as valid UTF-8 JSON' ) || diag($@);

my ($cafe) = grep { ( $_->{found}{SRC} // '' ) eq '192.0.2.7' } @events;
ok( defined($cafe), 'the café event emitted' );
is( $cafe->{found}{SRC}, '192.0.2.7', 'the offender IP is intact' );
is(
	Encode::encode_utf8( $cafe->{found}{USER} ),
	$cafe_bytes,
	'a valid-UTF-8 captured field rides through faithfully, not Latin-1 mojibake'
);

my ($evil) = grep { ( $_->{found}{SRC} // '' ) eq '192.0.2.8' } @events;
ok( defined($evil), 'the hostile-byte event still emitted, not dropped' );
is( $evil->{found}{SRC}, '192.0.2.8', 'with the offender IP intact' );
like( $evil->{found}{USER}, qr/\x{fffd}/, 'and the invalid byte became the replacement character' );

done_testing;
