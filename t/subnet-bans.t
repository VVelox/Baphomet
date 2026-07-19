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

use App::Baphomet::Config qw( load_config check_kur_def ip_network ip_family );
use App::Baphomet::Galla  ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache', $dir . '/eve' );

# a plain rule banning the src_ip of an alert
open( my $fh, '>', $dir . '/rules/json/suri.yaml' ) || die($!);
print $fh <<'EOR';
---
gate:
  - field: event_type
    values: [ alert ]
ban_var:
  - src_ip
msg: "[SURICATA] test"
EOR
close($fh);

sub write_config {
	my ($extra) = @_;
	open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
	print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
ignore_ips = [ "127.0.0.0/8" ]
internal = [ "192.168.0.0/16" ]
eve_log = "$dir/eve/eve.json"
eve_enable = 1
$extra

[kur.ids]
max_score = 100
$extra

[kur.ids.eve]
log = "$dir/watch.json"
parser = "json"
rule = "json/suri"
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

sub reset_eve {
	unlink( $dir . '/eve/eve.json' );
	return;
}

my @ip_bans;
my @cidr_bans;    # the CIDR strings, for the simple assertions
my @cidr_sent;    # { cidr, ban_time, kur } for the recidive assertions
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban      = sub { push( @ip_bans, $_[1] ); return; };
	*App::Baphomet::Galla::_send_cidr_ban = sub {
		my ( $self, $cidr, $ban_time, $kur ) = @_;
		push( @cidr_bans, $cidr );
		push( @cidr_sent, { cidr => $cidr, ban_time => $ban_time, kur => defined($kur) ? $kur : $self->{name} } );
		return;
	};
}

sub feed {
	my ( $galla, $src ) = @_;
	$galla->_handle_line(
		'eve',
		'{"event_type":"alert","src_ip":"' . $src . '","dest_ip":"10.0.0.1","alert":{"category":"x"}}',
		$dir . '/watch.json'
	);
	return;
}

#
# the helpers themselves
#
is( ip_network( '65.49.1.118', 24 ), '65.49.1.0/24',  'ip_network masks a v4 /24' );
is( ip_network( '2001:db8::5', 64 ), '2001:db8::/64', 'ip_network masks a v6 /64' );
is( ip_network( 'not-an-ip', 24 ),   undef,           'ip_network refuses a non-IP' );
is( ip_network( '65.49.1.118', 33 ), undef,           'ip_network refuses a v4 prefix past 32' );
is( ip_family('65.49.1.118'),        'v4',            'ip_family v4' );
is( ip_family('2001:db8::5'),        'v6',            'ip_family v6' );
is( ip_family('::ffff:65.49.1.118'), 'v4',            'ip_family maps a v4-in-v6 to v4' );
is( ip_family('nope'),               undef,           'ip_family refuses a non-IP' );

#
# a v4 /24 crosses subnet_max_score across distinct members
#
write_config("ban_subnet_v4 = 24\nsubnet_max_score = 3\nsubnet_find_time = 3600");
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );

@ip_bans = @cidr_bans = ();
reset_eve();
feed( $galla, '65.49.1.10' );
feed( $galla, '65.49.1.20' );
is_deeply( \@cidr_bans, [], 'no subnet ban before the threshold' );

feed( $galla, '65.49.1.30' );
is_deeply( \@cidr_bans, ['65.49.1.0/24'], 'the /24 is banished when the third member lands' );
is_deeply( \@ip_bans,   [],               'no per-IP ban, max_score is far higher' );

my ($banish) = grep { $_->{event_type} eq 'banish' } read_events();
ok( defined($banish), 'a banish event was written' );
is( $banish->{ip},             '65.49.1.0/24', 'the banish ip is the CIDR' );
is( $banish->{raw}{src_ip},    '65.49.1.30',   'raw is the last triggering line' );
is( $banish->{bucket}{family}, 'v4',           'bucket family is v4' );
is( $banish->{bucket}{cidr},   '65.49.1.0/24', 'bucket cidr' );
is( $banish->{bucket}{prefix}, 24,             'bucket prefix' );
is( $banish->{bucket}{score},  3,              'bucket score' );
is_deeply(
	$banish->{bucket}{members},
	[ '65.49.1.10', '65.49.1.20', '65.49.1.30' ],
	'bucket members are the distinct offenders in first-seen order'
);

#
# only v4 is configured, so v6 offenders never bucket
#
@cidr_bans = ();
feed( $galla, '2001:db8::1' );
feed( $galla, '2001:db8::2' );
feed( $galla, '2001:db8::3' );
feed( $galla, '2001:db8::4' );
is_deeply( \@cidr_bans, [], 'v6 offenders are not bucketed when only ban_subnet_v4 is set' );

#
# internal space is never subnet-bucketed even when it would count per-IP
#
write_config("ban_subnet_v4 = 24\nsubnet_max_score = 2\nsubnet_find_time = 3600");
$galla     = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
@cidr_bans = ();
feed( $galla, '192.168.5.1' );
feed( $galla, '192.168.5.2' );
feed( $galla, '192.168.5.3' );
is_deeply( \@cidr_bans, [], 'an internal /24 is never subnet-banished' );

#
# v6 bucketing, separate family
#
write_config("ban_subnet_v6 = 48\nsubnet_max_score = 2\nsubnet_find_time = 3600");
$galla     = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
@cidr_bans = ();
feed( $galla, '2001:db8:1::1' );
feed( $galla, '2001:db8:1:ffff::9' );
is_deeply( \@cidr_bans, ['2001:db8:1::/48'], 'a v6 /48 is banished on its own bucket' );

#
# the subnet counter survives a checkpoint and restart
#
write_config("ban_subnet_v4 = 24\nsubnet_max_score = 3\nsubnet_find_time = 3600");
$galla     = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
@cidr_bans = ();
feed( $galla, '203.0.113.10' );
feed( $galla, '203.0.113.20' );
$galla->checkpoint;
is_deeply( \@cidr_bans, [], 'still under threshold at checkpoint' );

my $revived = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
feed( $revived, '203.0.113.30' );
is_deeply( \@cidr_bans, ['203.0.113.0/24'], 'restored deposits carry the count across a restart' );

#
# observe mode raises an alert on the CIDR, not a ban
#
write_config("ban_subnet_v4 = 24\nsubnet_max_score = 2\nsubnet_find_time = 3600\neve_only = true");
$galla     = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
@cidr_bans = ();
reset_eve();
feed( $galla, '198.51.100.5' );
feed( $galla, '198.51.100.6' );
is_deeply( \@cidr_bans, [], 'observe mode sends no CIDR ban' );
my ($alert) = grep { $_->{event_type} eq 'alert' && $_->{ip} && $_->{ip} eq '198.51.100.0/24' } read_events();
ok( defined($alert), 'observe mode raises an alert on the CIDR' );
is( $alert->{bucket}{cidr}, '198.51.100.0/24', 'the observe alert carries the bucket' );

#
# a subnet banished repeatedly escalates to the recidive kur, as a cidr_ban
#
make_path( $dir . '/cache_r' );
open( my $rcfg, '>', $dir . '/recidive.toml' ) || die($!);
print $rcfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache_r"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
eve_log = "$dir/eve/eve.json"
eve_enable = 1

[recidive]
kur = "recidive"
max_score = 3
find_time = 604800

[kur.ids]
max_score = 100
ban_subnet_v4 = 24
subnet_max_score = 2
subnet_find_time = 3600

[kur.ids.eve]
log = "$dir/watch.json"
parser = "json"
rule = "json/suri"
EOC
close($rcfg);

my $rgalla = App::Baphomet::Galla->new( config => $dir . '/recidive.toml', name => 'ids' );
@cidr_bans = @cidr_sent = ();
reset_eve();

# every two deposits re-bans the /24 (subnet_max_score = 2); the third such ban
# trips the recidive threshold (max_score = 3)
feed( $rgalla, '45.148.10.1' );
feed( $rgalla, '45.148.10.2' );    # subnet ban 1
feed( $rgalla, '45.148.10.3' );
feed( $rgalla, '45.148.10.4' );    # subnet ban 2
is( scalar( grep { $_->{kur} eq 'recidive' } @cidr_sent ), 0, 'no subnet escalation below the recidive threshold' );

feed( $rgalla, '45.148.10.5' );
feed( $rgalla, '45.148.10.6' );    # subnet ban 3 -> escalate

my @esc = grep { $_->{kur} eq 'recidive' } @cidr_sent;
is( scalar(@esc),      1,                'the /24 escalated to the recidive kur on the third subnet ban' );
is( $esc[0]{cidr},     '45.148.10.0/24', 'the escalated subject is the CIDR' );
is( $esc[0]{ban_time}, 0,                'with the recidive ban_time' );

my ($recev)
	= grep { $_->{event_type} eq 'banish' && $_->{recidive} && $_->{ip} eq '45.148.10.0/24' } read_events();
ok( defined($recev), 'a recidive banish event for the CIDR was written' );
is( $recev->{kur}, 'recidive', 'the escalation event names the recidive kur' );

open( my $lfh, '<', $dir . '/cache_r/banishments.csv' ) || die($!);
my @lrows = <$lfh>;
close($lfh);
is( scalar( grep { m{,45\.148\.10\.0/24,} } @lrows ), 3, 'three ledger rows keyed on the CIDR' );

#
# config validation
#
my %bad = (
	'ban_subnet_v4 out of range' => { ban_subnet_v4    => 33 },
	'ban_subnet_v6 out of range' => { ban_subnet_v6    => 200 },
	'subnet_max_score zero'      => { subnet_max_score => 0 },
	'subnet_find_time non-int'   => { subnet_find_time => 'x' },
);
foreach my $why ( sort( keys(%bad) ) ) {
	my $def = { %{ $bad{$why} }, w => { log => '/x', parser => 'json', rule => 'json/r' } };
	my $ok  = eval { check_kur_def( 'k', $def ); 1 };
	ok( !$ok, "check_kur_def rejects $why" );
}
my $good = eval {
	check_kur_def(
		'k',
		{
			ban_subnet_v4    => 24,
			ban_subnet_v6    => 64,
			subnet_max_score => 10,
			subnet_find_time => 1800,
			w                => { log => '/x', parser => 'json', rule => 'json/r' }
		}
	);
	1;
};
ok( $good, 'check_kur_def accepts valid subnet settings' );

done_testing();
