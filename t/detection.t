#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp    qw( tempdir );
use File::Path    qw( make_path );
use JSON::MaybeXS qw( decode_json );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();
use App::Baphomet::Rules ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/rules/http', $dir . '/run', $dir . '/cache' );

# a detection-only rule... it counts by a username, not a IP, and carries no
# ban_var. it never banishes, only records sightings
open( my $fh, '>', $dir . '/rules/syslog/tripwire.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - audit
message_regexp:
  - 'policy tripwire tripped by (?<USER>\S+)'
detection_var:
  - USER
msg: "[POLICY] tripwire tripped"
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 audit[1]: policy tripwire tripped by alice"
      found: 1
      data:
        USER: "alice"
  negative:
    - message: "Jul 12 08:15:50 vixen42 audit[1]: all is well"
      found: 0
EOR
close($fh);

# a plain banning rule sharing the watcher, to prove the two do not mix
open( $fh, '>', $dir . '/rules/syslog/ban.yaml' ) || die($!);
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

# eve_enable is deliberately off... a loaded detection rule must force it on
open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
eve_log = "$dir/eve/eve.json"
eve_enable = false
max_score = 3
find_time = 600
ignore_ips = [ "10.0.0.0/8" ]

[kur.k]
ban_time = 300

[kur.k.detectw]
log = "$dir/d.log"
parser = "bsd_syslog"
rule = "syslog/tripwire"

[kur.k.banw]
log = "$dir/b.log"
parser = "bsd_syslog"
rule = "syslog/ban"
EOC
close($cfg);

sub read_events {
	my $path = $dir . '/eve/eve.json';
	return () if !-f $path;
	open( my $efh, '<', $path ) || die($!);
	my @lines = <$efh>;
	close($efh);
	return map { decode_json($_) } @lines;
}

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}

sub feed {
	my ( $galla, $watcher, $daemon, $log, $msg, $times ) = @_;
	foreach ( 1 .. $times ) {
		$galla->_handle_line( $watcher, 'Jul 12 08:15:50 vixen42 ' . $daemon . '[1]: ' . $msg, $dir . '/' . $log );
	}
	return;
}

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'k' );

#
# a loaded detection rule forces EVE output on, off in the config or not
#

ok( $galla->{eve_enable}, 'a loaded detection rule forces EVE output on' );

#
# a detection rule counts its subject and records sightings, banishing nobody
#

@sent = ();
feed( $galla, 'detectw', 'audit', 'd.log', 'policy tripwire tripped by alice', 3 );
my @ev = read_events();

is( scalar( grep { $_->{event_type} eq 'sighting' && $_->{found}{USER} eq 'alice' } @ev ),
	3, 'each detection match emits a sighting' );
is( scalar( grep { $_->{event_type} eq 'sighted' && $_->{subject} eq 'alice' } @ev ),
	1, 'and a sighted when the subject crosses the threshold' );

is( scalar( grep { $_->{event_type} eq 'found' } @ev ),  0, 'never a found' );
is( scalar( grep { $_->{event_type} eq 'noted' } @ev ),  0, 'never a noted' );
is( scalar( grep { $_->{event_type} eq 'banish' } @ev ), 0, 'never a banish' );
is( scalar( grep { $_->{event_type} eq 'alert' } @ev ),  0, 'never an alert' );
is_deeply( \@sent, [], 'a detection rule sends nothing to Kur' );
ok( !defined( $galla->{counters}{'alice'} ), 'detection leaves the real counters untouched' );

my ($sighted) = grep { $_->{event_type} eq 'sighted' && $_->{subject} eq 'alice' } @ev;
is( $sighted->{subject},     'alice',                     'the sighted names the subject' );
is( $sighted->{score},       3,                           'and carries the score' );
is( $sighted->{found}{USER}, 'alice',                     'and the triggering found' );
is( $sighted->{msg},         '[POLICY] tripwire tripped', 'and the rule msg' );
ok( !exists( $sighted->{ip} ), 'a sighted has no ip... the subject is not a offender' );

#
# subjects are isolated... a second subject accrues on its own, into the
# shadow bucket, and below threshold raises no sighted
#

@sent = ();
feed( $galla, 'detectw', 'audit', 'd.log', 'policy tripwire tripped by bob', 2 );
@ev = read_events();
is( scalar( grep { $_->{event_type} eq 'sighted' && $_->{subject} eq 'bob' } @ev ),
	0, 'below the threshold a subject raises no sighted' );
is( scalar( @{ $galla->{shadow_counters}{'bob'} } ), 2, 'a detection subject counts into the shadow bucket' );
ok( !defined( $galla->{counters}{'bob'} ), 'and never the real bucket' );

#
# the plain banning rule on the same watcher-set still banishes as ever
#

@sent = ();
feed( $galla, 'banw', 'sshd', 'b.log', 'bad thing from 9.9.9.9', 3 );
@ev = read_events();
is( scalar( grep { $_->{event_type} eq 'found' && $_->{found}{SRC} eq '9.9.9.9' } @ev ),
	3, 'a plain rule alongside a detection rule still emits found' );
is( scalar( grep { $_->{event_type} eq 'banish' && $_->{ip} eq '9.9.9.9' } @ev ), 1, 'and banishes' );
is_deeply( \@sent, ['9.9.9.9'], 'the plain rule reaches Kur' );

# the detected subject never touched the ledger
my $ledger          = $dir . '/cache/banishments.csv';
my $alice_in_ledger = 0;
if ( -f $ledger ) {
	open( my $lfh, '<', $ledger ) || die($!);
	$alice_in_ledger = grep { /alice/ } <$lfh>;
	close($lfh);
}
is( $alice_in_ledger, 0, 'a detected subject is not chiseled into the ledger' );

#
# validation... detection_var and ban_var are mutually exclusive, the array
# must be well formed, and a detection rule needs no ban_var
#

my $vdir = tempdir( CLEANUP => 1 );
make_path( $vdir . '/syslog', $vdir . '/http' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $vfh, '>', $vdir . '/' . $name . '.yaml' ) || die($!);
	print $vfh $yaml;
	close($vfh);
	return;
}

write_rule( 'syslog/detonly', <<'EOR' );
---
daemons:
  - audit
message_regexp:
  - 'tripped by (?<USER>\S+)'
detection_var:
  - USER
EOR

write_rule( 'syslog/both', <<'EOR' );
---
daemons:
  - audit
message_regexp:
  - 'tripped by (?<USER>\S+) from %%%%SRC%%%%'
ban_var:
  - SRC
detection_var:
  - USER
EOR

write_rule( 'syslog/baddetvar', <<'EOR' );
---
daemons:
  - audit
message_regexp:
  - 'tripped by (?<USER>\S+)'
detection_var: USER
EOR

write_rule( 'http/uri-watch', <<'EOR' );
---
status:
  - '404'
detection_var:
  - request
EOR

my $vrules = App::Baphomet::Rules->new( rules_dir => $vdir );

my $det = $vrules->load('syslog/detonly');
ok( defined($det), 'a syslog detection rule loads with no ban_var' );
is_deeply( [ $det->detection_var ], ['USER'], 'and reports its detection_var' );
ok( $det->is_detection, 'and knows it is a detection rule' );

ok( !eval { $vrules->load('syslog/both');      1 }, 'a rule with both ban_var and detection_var refuses to load' );
ok( !eval { $vrules->load('syslog/baddetvar'); 1 }, 'a non-array detection_var refuses to load' );

my $http = $vrules->load('http/uri-watch');
ok( defined($http),      'an http detection rule loads counting by request' );
ok( $http->is_detection, 'and knows it is a detection rule' );
is_deeply( [ $http->detection_var ], ['request'], 'and reports its detection_var over the hardcoded host' );

done_testing;
