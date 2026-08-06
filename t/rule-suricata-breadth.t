#!perl
use 5.006; use strict; use warnings;
use Test::More; use File::Temp qw(tempdir); use File::Path qw(make_path);
BEGIN { eval { require Ereshkigal::Client; }; plan skip_all => 'no client' if $@; }
use JSON::MaybeXS (); use App::Baphomet::Galla ();

# json/suricata-breadth, the shipped rule that counts how many DIFFERENT
# signatures a source has tripped rather than how often. Its own embedded tests
# prove the gate and the captures; the counting is the galla's, and the whole
# claim of the rule is that volume cannot trigger it while breadth can.
my $dir = tempdir(CLEANUP=>1); make_path("$dir/rules/json","$dir/run","$dir/cache");
system( 'cp', 'share/rules/json/suricata-breadth.yaml', $dir . '/rules/json/suricata-breadth.yaml' ) == 0
	or die('could not stage the rule under test');
open(my $c,'>',"$dir/config.toml")||die $!;
print $c <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nope.sock"
allow_per_rule_thresholds = true
max_score = 99
[kur.d]
[kur.d.w]
log = "$dir/log"
parser = "json"
rule = [ "json/suricata-breadth" ]
EOC
close($c);
my @sent; { no warnings 'redefine'; *App::Baphomet::Galla::_send_ban = sub { push @sent,$_[1]; return }; }
my $j = JSON::MaybeXS->new(canonical=>1);
my $g = App::Baphomet::Galla->new(config=>"$dir/config.toml", name=>'d');
sub alert { my ($sid,$src)=@_; $g->_handle_line('w', $j->encode({
  event_type=>'alert', src_ip=>$src, dest_ip=>'192.0.2.1',
  alert=>{ signature_id=>$sid, signature=>"SIG $sid", category=>'Misc' } }), "$dir/log") }

# one chatty signature firing over and over is NOT breadth
@sent=(); alert(2001219,'10.0.0.1') for 1..10;
is_deeply(\@sent, [], 'ten hits of ONE signature does not ban');
is(scalar(keys %{ $g->{distinct_counters}{'json/suricata-breadth'}{'10.0.0.1'} }), 1,
   'the set holds one signature however many hits');

# three DIFFERENT signatures is a source doing several things at once
@sent=(); alert(2001219,'10.0.0.2'); alert(2010935,'10.0.0.2');
is_deeply(\@sent, [], 'two distinct signatures has not crossed');
alert(2402000,'10.0.0.2');
is_deeply(\@sent, ['10.0.0.2'], 'the third distinct signature bans the source');
done_testing();
