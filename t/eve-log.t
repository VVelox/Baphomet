#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp    qw( tempdir );
use File::Path    qw( make_path );
use JSON::MaybeXS qw( decode_json );
use Digest::MD5   qw( md5 );

# the same stable name hash the rule sid accessor uses, to check the wiring
# with out hardcoding a magic number
sub expected_sid { return unpack( 'N', substr( md5( $_[0] ), 0, 4 ) ) & 0x7fffffff; }

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

open( my $fh, '>', $dir . '/rules/syslog/sshd.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
EOR
close($fh);

open( $fh, '>', $dir . '/rules/json/app.yaml' ) || die($!);
print $fh <<'EOR';
---
msg: "[APP] authentication failure"
severity: high
classtype: unsuccessful-user
rev: 5
references:
  - "https://example.com/app-auth"
attack:
  - T1110
gate:
  - field: event
    values: [ authfail ]
match:
  - field: src
    regexp: '^%%%%SRC%%%%$'
ban_var:
  - SRC
EOR
close($fh);

sub write_config {
	my ($enable) = @_;
	open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
	print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
eve_log = "$dir/eve/eve.json"
eve_enable = $enable
max_score = 3
find_time = 600

[kur.sshd]
ban_time = 300

[kur.sshd.authlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"

[kur.sshd.appjson]
log = "$dir/app.json"
parser = "json"
rule = "json/app"
max_score = 7
EOC
	close($cfg);
	return;
} ## end sub write_config

sub read_events {
	my $path = $dir . '/eve/eve.json';
	return () if !-f $path;
	open( my $efh, '<', $path ) || die($!);
	my @lines = <$efh>;
	close($efh);
	return map { decode_json($_) } @lines;
}

# capture banishments so nothing tries to reach Ereshkigal
my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}

#
# disabled... default path set but nothing written
#

write_config('false');
my $off = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );
is( $off->{eve_log},    $dir . '/eve/eve.json', 'eve_log has its default even when off' );
is( $off->{eve_enable}, 0,                      'eve_enable off' );
$off->_handle_line( 'authlog', 'Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 5.5.5.5', $dir . '/log' );
ok( !-f $dir . '/eve/eve.json', 'nothing written while disabled' );

#
# enabled
#

write_config('true');
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );
is( $galla->{eve_enable}, 1, 'eve_enable on' );
ok( -d $dir . '/eve', 'the eve dir was created' );

# three bad lines... the first two found under the threshold, the third
# crosses and banishes. the banishing line emits only the banish, which
# stands for the match, not a found beside it
foreach ( 1 .. 3 ) {
	$galla->_handle_line( 'authlog', 'Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 9.9.9.9', $dir . '/log' );
}

my @events = read_events();
my @found  = grep { $_->{event_type} eq 'found' } @events;
my @banish = grep { $_->{event_type} eq 'banish' } @events;
is( scalar(@found),  2, 'two found events... the sub-threshold hits only' );
is( scalar(@banish), 1, 'one banish event' );

my $f = $found[0];
is( $f->{eve_type},   'baphomet', 'eve_type is baphomet' );
is( $f->{event_type}, 'found',    'event_type found' );
is( $f->{kur},        'sshd',     'kur' );
ok( defined( $f->{hostname} ), 'hostname present' );
like( $f->{timestamp}, qr/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/, 'ISO8601 timestamp' );
is( $f->{path},           $dir . '/log',                                             'path is the source file' );
is( $f->{raw},            'Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 9.9.9.9', 'raw line' );
is( $f->{found}{SRC},     '9.9.9.9',                                                 'found carries the check data' );
is( $f->{parsed}{daemon}, 'sshd', 'parsed carries the parser output' );
is( $f->{score},          1,      'score on the first found is 1' );
is( $found[1]{score},     2,      'score on the second found is 2' );

# the threshold the score is racing rides beside it, so a reader never has to
# resolve the watcher-over-kur-over-global layers out of the config to know
# whether a score of 2 is nearly a ban or nowhere near one
is( $f->{threshold},      3,             'threshold is the effective max_score' );
is( $found[1]{threshold}, 3,             'and on every found, not just the first' );
is( $f->{msg},            'syslog/sshd', 'msg falls back to the rule name when the rule sets none' );
ok( !exists( $f->{severity} ),   'severity absent when the rule sets none and no default_severity' );
ok( !exists( $f->{category} ),   'category absent when the rule sets no classtype' );
ok( !exists( $f->{classtype} ),  'and the slug itself is never emitted, the category standing alone' );
ok( !exists( $f->{references} ), 'references absent when the rule sets none' );
ok( !exists( $f->{attack} ),     'attack absent when the rule sets none' );

# the Suricata-style gid/sid/rev, always present as integers... these rules
# resolve from the temp override dir, so gid is 1, and this rule sets no rev
is( $f->{gid}, 1,                           'gid is 1 for a rule from the override dir' );
is( $f->{sid}, expected_sid('syslog/sshd'), 'sid is the stable hash of the rule name' );
like( $f->{sid}, qr/^\d+$/, 'sid is a bare integer' );
is( $f->{rev}, 0, 'rev defaults to 0 when the rule sets none' );

# rule info present but without the tests
is( $f->{rule}{name}, 'syslog/sshd', 'rule name' );
ok( defined( $f->{rule}{def}{message_regexp} ), 'rule def present' );
ok( !exists( $f->{rule}{def}{tests} ),          'rule tests stripped for space' );

# the banish event... it stands for the crossing line whole, carrying the
# same raw/parsed/found the suppressed found would have
my $c = $banish[0];
is( $c->{event_type},  'banish',  'banish event_type' );
is( $c->{ip},          '9.9.9.9', 'banish ip' );
is( $c->{ban_time},    300,       'banish ban_time' );
is( $c->{score},       3,         'banish score' );
is( $c->{threshold},   3,         'banish threshold, the score it had to reach' );
is( $c->{found}{SRC},  '9.9.9.9', 'banish carries the triggering found' );
is( $c->{raw},         'Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 9.9.9.9', 'banish carries the raw line' );
is( $c->{path},        $dir . '/log',                                             'banish carries the source path' );
is( $found[-1]{score}, 2, 'the last found is the second hit, not the banishing third' );

#
# a JSON watcher... parsed holds the parsed JSON
#

$galla->_handle_line( 'appjson', '{"event":"authfail","src":"2.2.2.2","user":"root"}', $dir . '/app.json' );
@events = read_events();
my ($json_found) = grep { $_->{event_type} eq 'found' && $_->{found}{SRC} && $_->{found}{SRC} eq '2.2.2.2' } @events;
ok( defined($json_found), 'json watcher produced a found event' );
is( $json_found->{parsed}{event}, 'authfail',                     'parsed holds the flattened JSON fields' );
is( $json_found->{parsed}{src},   '2.2.2.2',                      'including the source field' );
is( $json_found->{msg},           '[APP] authentication failure', 'the rule\'s own msg reaches the EVE event' );
is( $json_found->{severity},      'high',                         'the rule severity reaches EVE' );

# the rule carries the short classtype and the event carries the prose, the way
# Suricata's classification.config supplies it... so the slug never reaches a
# reader and the field lines up with a Suricata event of the same class
is(
	$json_found->{category},
	'Unsuccessful User Privilege Gain',
	'the classtype reaches EVE as its Suricata category, in words'
);
ok( !exists( $json_found->{classtype} ), 'with the slug itself left out, the category being the lone field' );

is_deeply( $json_found->{references}, ['https://example.com/app-auth'], 'references reach EVE as an array' );
is_deeply( $json_found->{attack},     ['T1110'],                        'attack reaches EVE as an array' );
is( $json_found->{gid}, 1,                        'json rule gid is 1 from the override dir' );
is( $json_found->{sid}, expected_sid('json/app'), 'json rule sid is the hash of its name' );
isnt( $json_found->{sid}, $f->{sid}, 'a different rule name hashes to a different sid' );
is( $json_found->{rev}, 5, 'the rule rev reaches EVE' );

# this watcher sets its own max_score of 7 over the global 3, so the threshold
# on its events proves the field is the resolved effective number and not
# whatever the top of the config happened to say
is( $json_found->{threshold}, 7, 'the threshold is the watcher\'s own, not the global max_score' );
is( $json_found->{score},     1, 'with the score counted against it' );

# a TOML integer stays a JSON integer... a threshold quoted as a string would
# break arithmetic on the consumer's side, and the per-rule config table
# validates its numbers as strings, so the coercion is load bearing
my ($raw_line) = grep { /"threshold"/ } do {
	open( my $rfh, '<', $dir . '/eve/eve.json' ) || die($!);
	my @all = <$rfh>;
	close($rfh);
	@all;
};
like( $raw_line, qr/"threshold":\s*\d/, 'threshold is written as a JSON number, not a quoted string' );

#
# the envelope hash doubles as the per-line scratch space a rule memoises its
# decodes on (message_json its flatten, mungers their decomposed fields), keyed
# with a leading underscore so _eve_parsed can drop them. without the drop an
# event carried the rule's internal cache, nested hash and all
#
my $scratch = {
	'format'               => 'bsd_syslog',
	'message'              => 'a message',
	'daemon'               => 'sshd',
	'_message_json_fields' => { 'evt'  => 'fail' },
	'_munge_fields'        => { 'sshd' => { 'ssh_user' => 'bob' } },
};
my $cleaned = App::Baphomet::Galla::_eve_parsed( undef, $scratch );
is_deeply( [ sort grep { /^_/ } keys %{$cleaned} ],
	[], 'a rule\'s per-line caches are kept out of the EVE parsed field' );
is( $cleaned->{message}, 'a message', 'while the parser\'s own fields survive' );
is( $cleaned->{daemon},  'sshd',      'all of them' );
ok( exists( $scratch->{_munge_fields} ), 'and the live parsed line keeps its cache, the copy being the event\'s' );

# a json log's own leading-underscore field is the log's business, not ours
my $doc = { 'fields' => { '_id' => 'abc123', 'src' => '1.2.3.4' } };
is_deeply(
	App::Baphomet::Galla::_eve_parsed( undef, $doc ),
	{ '_id' => 'abc123', 'src' => '1.2.3.4' },
	'a json document keeps its own underscored fields'
);

done_testing;
