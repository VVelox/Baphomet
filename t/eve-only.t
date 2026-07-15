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

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run', $dir . '/cache' );

# one plain rule, and one that opts back in to real banning with eve_only:false
open( my $fh, '>', $dir . '/rules/syslog/hit.yaml' ) || die($!);
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

open( $fh, '>', $dir . '/rules/syslog/hit-real.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
eve_only: false
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
ignore_ips = [ "10.0.0.0/8" ]

[kur.k]
ban_time = 300

[kur.k.realw]
log = "$dir/real.log"
parser = "bsd_syslog"
rule = "syslog/hit"

[kur.k.observew]
eve_only = true
log = "$dir/obs.log"
parser = "bsd_syslog"
rule = "syslog/hit"

[kur.k.overridew]
eve_only = true
log = "$dir/over.log"
parser = "bsd_syslog"
rule = "syslog/hit-real"

[kur.k.observe_ig]
eve_only = true
observe_ignored = true
log = "$dir/ig.log"
parser = "bsd_syslog"
rule = "syslog/hit"

[kur.k.observe_noig]
eve_only = true
log = "$dir/noig.log"
parser = "bsd_syslog"
rule = "syslog/hit"
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
	my ( $galla, $watcher, $log, $ip, $times ) = @_;
	foreach ( 1 .. $times ) {
		$galla->_handle_line( $watcher, 'Jul 12 08:15:50 vixen42 sshd[1]: bad thing from ' . $ip, $dir . '/' . $log );
	}
	return;
}

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'k' );

#
# a real watcher bans as ever... found events and a banish
#

@sent = ();
feed( $galla, 'realw', 'real.log', '9.9.9.9', 3 );
my @ev = read_events();
is( scalar( grep { $_->{event_type} eq 'found' && $_->{found}{SRC} eq '9.9.9.9' } @ev ),
	3, 'the real watcher emits found events' );
is( scalar( grep { $_->{event_type} eq 'banish' && $_->{ip} eq '9.9.9.9' } @ev ), 1, 'and a banish' );
is_deeply( \@sent, ['9.9.9.9'], 'the real watcher actually banishes' );

#
# an eve_only watcher observes... noted and alert, never found/banish, no ban
#

@sent = ();
feed( $galla, 'observew', 'obs.log', '8.8.8.8', 3 );
@ev = read_events();
is( scalar( grep { $_->{event_type} eq 'noted' && $_->{found}{SRC} eq '8.8.8.8' } @ev ),
	3, 'observe mode emits noted events' );
is( scalar( grep { $_->{event_type} eq 'alert' && $_->{ip} eq '8.8.8.8' } @ev ),
	1, 'and an alert at the threshold' );
is( scalar( grep { $_->{event_type} eq 'found'  && $_->{found}{SRC} eq '8.8.8.8' } @ev ), 0, 'never a found' );
is( scalar( grep { $_->{event_type} eq 'banish' && $_->{ip} eq '8.8.8.8' } @ev ),         0, 'never a banish' );
is_deeply( \@sent, [], 'observe mode sends nothing to Kur' );
ok( !defined( $galla->{counters}{'8.8.8.8'} ), 'observe mode leaves the real counters untouched' );

my ($alert) = grep { $_->{event_type} eq 'alert' && $_->{ip} eq '8.8.8.8' } @ev;
is( $alert->{ban_time},   300,       'the alert carries the would-be ban_time' );
is( $alert->{score},      3,         'the alert carries the score' );
is( $alert->{found}{SRC}, '8.8.8.8', 'the alert carries the triggering found' );

# the observed IP never reached the ledger
my $ledger = $dir . '/cache/banishments.csv';
my $in_ledger = 0;
if ( -f $ledger ) {
	open( my $lfh, '<', $ledger ) || die($!);
	$in_ledger = grep { /8\.8\.8\.8/ } <$lfh>;
	close($lfh);
}
is( $in_ledger, 0, 'the observed IP is not chiseled into the ledger' );

#
# a rule with eve_only:false opts back in to real banning under an
# eve_only watcher
#

@sent = ();
feed( $galla, 'overridew', 'over.log', '7.7.7.7', 3 );
@ev = read_events();
is( scalar( grep { $_->{event_type} eq 'found'  && $_->{found}{SRC} eq '7.7.7.7' } @ev ), 3, 'the rule override emits found' );
is( scalar( grep { $_->{event_type} eq 'banish' && $_->{ip} eq '7.7.7.7' } @ev ),         1, 'and banishes' );
is_deeply( \@sent, ['7.7.7.7'], 'a eve_only:false rule bans despite the watcher observing' );

#
# observe_ignored... watching what ignore_ips would drop
#

# without it, an ignored IP is noted (telemetry, like a real found) but never
# shadow-counted, so it never reaches an alert... a faithful simulation, since
# in real mode ignore_ips drops the ban, not the found event
@sent = ();
feed( $galla, 'observe_noig', 'noig.log', '10.1.2.3', 3 );
@ev = read_events();
is( scalar( grep { $_->{event_type} eq 'noted' && $_->{found}{SRC} eq '10.1.2.3' } @ev ),
	3, 'without observe_ignored, an ignored IP is still noted' );
is( scalar( grep { $_->{event_type} eq 'alert' && $_->{ip} eq '10.1.2.3' } @ev ),
	0, 'but never alerts... it is not shadow-counted' );
ok( !defined( $galla->{shadow_counters}{'10.1.2.3'} ), 'and lands in no shadow bucket' );

# with it, the ignored IP is shadow-counted too... noted and alert, still no ban
@sent = ();
feed( $galla, 'observe_ig', 'ig.log', '10.4.5.6', 3 );
@ev = read_events();
is( scalar( grep { $_->{event_type} eq 'noted' && $_->{found}{SRC} eq '10.4.5.6' } @ev ),
	3, 'observe_ignored surfaces an ignored IP as noted' );
is( scalar( grep { $_->{event_type} eq 'alert' && $_->{ip} eq '10.4.5.6' } @ev ),
	1, 'and alerts on it' );
is_deeply( \@sent, [], 'still sends nothing to Kur' );

#
# shadow isolation... an observed count does not leak into a real bucket
#

@sent = ();
feed( $galla, 'observew', 'obs.log', '5.5.5.5', 2 );    # shadow score 2, no alert yet
feed( $galla, 'realw',    'real.log', '5.5.5.5', 1 );    # real score should be 1, not 3
is_deeply( \@sent, [], 'one real hit after two observed ones does not ban' );
is( $galla->_cmd_accused->{accused}{'5.5.5.5'}{score}, 1, 'the real bucket holds only the real hit' );

done_testing;
