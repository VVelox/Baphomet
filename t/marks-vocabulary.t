#!perl
# the standard brands end to end... the shipped setter rules brand their
# offenders with the shared vocabulary and the shipped reader rules gate
# on it, through a live galla running the real shipped rules
use 5.006;
use strict;
use warnings;
use Test::More;
use Cwd qw( getcwd );
use File::Temp qw( tempdir );
use File::Path qw( make_path );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();

my $dir        = tempdir( CLEANUP => 1 );
my $shipped    = getcwd() . '/share/rules';
my $groups_dir = getcwd() . '/share/groups';
make_path( $dir . '/run', $dir . '/cache' );

open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$shipped"
groups_dir = "$groups_dir"
ereshkigal_socket = "$dir/nonexistent.sock"
ignore_ips = [ "127.0.0.0/8" ]
# the alerts' dest is ours, so ban_not_internal counts only the src
internal = [ "127.0.0.0/8", "203.0.113.0/24" ]

[kur.vocab]
max_score = 5
allow_per_rule_thresholds = true

[kur.vocab.auth]
log = "$dir/l1"
parser = "syslog"
rule = [ "syslog/sshd-condemned", "syslog/sshd", "syslog/sshd-breach" ]

[kur.vocab.ids]
log = "$dir/l2"
parser = "json"
rule = [ "json/suricata-condemned", "json/suricata-escalation", "json/suricata-attempted-recon", "json/suricata-attempted-user" ]
EOC
close($cfg);

my @sent;
my @sighted;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
	*App::Baphomet::Galla::_eve_emit = sub {
		my ( $self, $event_type, $fields ) = @_;
		if ( $event_type eq 'sighting' ) {
			push( @sighted, $fields->{found}{SRC} );
		}
		return;
	};
}

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'vocab' );

sub sshd_fail {
	my ($ip) = @_;
	return 'Jul 12 08:15:50 vixen42 sshd[2278]: Failed password for invalid user admin from ' . $ip
		. ' port 4711 ssh2';
}

sub suricata_alert {
	my ( $ip, $category ) = @_;
	return
		  '{"timestamp":"2026-07-12T08:15:50.123456+0000","event_type":"alert","src_ip":"' . $ip
		. '","dest_ip":"203.0.113.5","proto":"TCP","alert":{"signature":"TEST","category":"' . $category
		. '","severity":2}}';
}

#
# the condemned returns... the first sshd failure is counted by syslog/sshd,
# which brands the standard brute_force, and the second is seized by the
# sshd-condemned reader at weight 10, one hit a verdict
#

@sent = ();
$galla->_handle_line( 'auth', sshd_fail('192.0.2.7'), $dir . '/l1' );
is_deeply( \@sent, [], 'the first failure does not banish' );
ok( defined( $galla->{marks}{brute_force}{'192.0.2.7'} ), 'and the shipped rule branded the standard brute_force' );

$galla->_handle_line( 'auth', sshd_fail('192.0.2.7'), $dir . '/l1' );
is_deeply( \@sent, ['192.0.2.7'], 'the second failure from the branded source is seized at once' );

#
# cross-product... the brute_force brand set by sshd condemns the same
# source's very first IDS alert, whatever its class
#

@sent = ();
$galla->_handle_line( 'auth', sshd_fail('192.0.2.8'), $dir . '/l1' );
$galla->_handle_line( 'ids', suricata_alert( '192.0.2.8', 'Not Suspicious Traffic' ), $dir . '/l2' );
is_deeply( \@sent, ['192.0.2.8'], 'a branded brute forcer tripping the IDS is seized on the first alert' );

#
# escalation... recon then exploit_attempt in order, the brands set by the
# per-class rules, read by the sequence reader
#

@sent = ();
$galla->_handle_line( 'ids', suricata_alert( '192.0.2.9', 'Attempted Information Leak' ), $dir . '/l2' );
ok( defined( $galla->{marks}{recon}{'192.0.2.9'} ), 'a recon-class alert brands recon' );
is_deeply( \@sent, [], 'and alone banishes nobody' );

$galla->_handle_line( 'ids', suricata_alert( '192.0.2.9', 'Attempted User Privilege Gain' ), $dir . '/l2' );
ok( defined( $galla->{marks}{exploit_attempt}{'192.0.2.9'} ), 'an exploit-class alert brands exploit_attempt' );

@sent = ();
$galla->_handle_line( 'ids', suricata_alert( '192.0.2.9', 'Not Suspicious Traffic' ), $dir . '/l2' );
is_deeply( \@sent, ['192.0.2.9'], 'and the next alert from the scanned-then-exploited source is seized' );

#
# order matters... exploit first then recon does not satisfy the sequence.
# both brands land inside one second here, which non-decreasing set times
# would forgive, so the recon set time is pushed later by hand
#

@sent = ();
$galla->_handle_line( 'ids', suricata_alert( '192.0.2.10', 'Attempted User Privilege Gain' ), $dir . '/l2' );
$galla->_handle_line( 'ids', suricata_alert( '192.0.2.10', 'Attempted Information Leak' ), $dir . '/l2' );
$galla->{marks}{recon}{'192.0.2.10'}{set} = $galla->{marks}{exploit_attempt}{'192.0.2.10'}{set} + 5;
@sent = ();
$galla->_handle_line( 'ids', suricata_alert( '192.0.2.10', 'Not Suspicious Traffic' ), $dir . '/l2' );
is_deeply( \@sent, [], 'exploited-then-scanned does not read as escalation' );

#
# the breach reader... a success from a branded source is sighted,
# detection-only, and a success from a unbranded one passes unremarked
#

sub sshd_accept {
	my ($ip) = @_;
	return 'Jul 12 08:25:49 vixen42 sshd[2278]: Accepted password for root from ' . $ip . ' port 4711 ssh2';
}

@sent    = ();
@sighted = ();
$galla->_handle_line( 'auth', sshd_fail('192.0.2.11'), $dir . '/l1' );
$galla->_handle_line( 'auth', sshd_accept('192.0.2.11'), $dir . '/l1' );
is_deeply( \@sighted, ['192.0.2.11'], 'a success from a branded source is sighted' );
is_deeply( \@sent, [], 'and sighted only... the breach rule banishes nobody' );

@sighted = ();
$galla->_handle_line( 'auth', sshd_accept('192.0.2.12'), $dir . '/l1' );
is_deeply( \@sighted, [], 'a success from a unbranded source passes unremarked' );

done_testing;
