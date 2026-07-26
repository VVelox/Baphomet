#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp    qw( tempdir );
use File::Path    qw( make_path );
use JSON::MaybeXS qw( decode_json );
use JSON::PP      ();

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla  ();
use App::Baphomet::Config qw( check_kur_def resolve_rule_config );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache', $dir . '/eve' );

#
# resolve_rule_config... kur under watcher, merged per rule then per key
#

# nothing set anywhere resolves to nothing
is_deeply( resolve_rule_config( {}, {} ), {}, 'no rule_config resolves to a empty hash' );
is_deeply( resolve_rule_config( undef, undef ), {}, 'undef levels are tolerated' );

# a kur-only table carries through untouched, eve_only normalized, weight a number
my $resolved = resolve_rule_config(
	{ rule_config => { 'json/suricata-admin' => { max_score => 1, eve_only => JSON::PP::true, weight => 2 } } }, {} );
is( $resolved->{'json/suricata-admin'}{max_score}, 1, 'kur rule_config max_score carries through' );
is( $resolved->{'json/suricata-admin'}{eve_only},  1, 'a TOML true eve_only normalizes to 1' );
is( $resolved->{'json/suricata-admin'}{weight},    2, 'weight resolves as a number' );

# the watcher merges over the kur per key... it tweaks severity while the
# kur's max_score and ban_time stay inherited, and its own rule stands alone
$resolved = resolve_rule_config(
	{ rule_config => { 'json/suricata-admin' => { max_score => 1, ban_time => 4242, severity => 'critical' } } },
	{ rule_config => { 'json/suricata-admin' => { severity => 'high' }, 'json/suricata-dos' => { weight => 3 } } },
);
is( $resolved->{'json/suricata-admin'}{max_score}, 1,      'the kur max_score survives a watcher that does not touch it' );
is( $resolved->{'json/suricata-admin'}{ban_time},  4242,   'the kur ban_time is inherited' );
is( $resolved->{'json/suricata-admin'}{severity},  'high', 'the watcher severity wins over the kur' );
is( $resolved->{'json/suricata-dos'}{weight},      3,      'a watcher-only rule stands on its own' );

#
# check_kur_def... a valid rule_config at both levels, and the rejections
#

my $valid = {
	max_score   => 3,
	rule_config => { 'json/suricata-admin' => { max_score => 1, ban_time => 3600, severity => 'high' } },
	eve         => {
		log         => $dir . '/eve.json',
		parser      => 'json',
		rule        => [ 'json/suricata-admin', 'json/suricata-dos' ],
		rule_config => { 'json/suricata-dos' => { max_score => 20, weight => 2, eve_only => JSON::PP::true } },
	},
};
eval { check_kur_def( 'ids', $valid ); };
is( $@, '', 'a kur with rule_config at both levels validates' );

# each rejection... a bad rule name, a unknown override, a zero threshold, a
# bad weight, a bad severity, a non-table override, and a non-hash table
my @bad = (
	[ { 'notarule'          => { max_score => 1 } }, qr/invalid rule/,                       'a rule name without a slash' ],
	[ { 'json/x'            => { max_scoree => 1 } }, qr/unknown override "max_scoree"/,      'a misspelled override key' ],
	[ { 'json/x'            => { max_score => 0 } },  qr/not a positive int/,                 'a zero max_score' ],
	[ { 'json/x'            => { weight => 'heavy' } }, qr/not a positive number/,            'a non-numeric weight' ],
	[ { 'json/x'            => { weight => 0 } },     qr/not a positive number/,              'a zero weight' ],
	[ { 'json/x'            => { severity => 'urgent' } }, qr/info.low.medium.high.critical/, 'a bogus severity' ],
	[ { 'json/x'            => 'nope' },              qr/not a table of overrides/,           'a scalar where a table belongs' ],
	[ 'nope',                                        qr/not a hash of per-rule override/,     'a scalar rule_config' ],
);
foreach my $case (@bad) {
	my ( $rule_config, $re, $desc ) = @{$case};
	my $def = { max_score => 3, rule_config => $rule_config, eve => { %{ $valid->{eve} } } };
	delete( $def->{eve}{rule_config} );
	eval { check_kur_def( 'ids', $def ); };
	like( $@, $re, 'rejected: ' . $desc );
}

#
# galla behavior... the config table over live rules, the flag deliberately
# off to prove the override speaks regardless
#

my %rules = (
	'suricata-admin' => '',
	'suricata-dos'   => '',
	'plain'          => '',
);
foreach my $name ( keys(%rules) ) {
	open( my $rfh, '>', $dir . '/rules/json/' . $name . '.yaml' ) || die($!);
	print $rfh "---\ngate:\n  - field: which\n    values: [ " . $name . " ]\nban_var:\n  - src_ip\n" . $rules{$name};
	close($rfh);
}

open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
eve_log = "$dir/eve/eve.json"
eve_enable = 1
allow_per_rule_thresholds = false

[kur.ids]
max_score = 3

[kur.ids.rule_config."json/suricata-admin"]
max_score = 1
ban_time = 4242
severity = "critical"

[kur.ids.eve]
log = "$dir/eve.json"
parser = "json"
rule = [ "json/suricata-admin", "json/suricata-dos", "json/plain" ]

[kur.ids.eve.rule_config."json/suricata-admin"]
severity = "high"

[kur.ids.eve.rule_config."json/suricata-dos"]
weight = 3

[kur.ids.eve.rule_config."json/plain"]
eve_only = true
EOC
close($cfg);

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, [ $_[1], $_[2] ] ); return; };
}

sub read_events {
	my $path = $dir . '/eve/eve.json';
	return () if !-f $path;
	open( my $efh, '<', $path ) || die($!);
	my @lines = <$efh>;
	close($efh);
	return map { decode_json($_) } @lines;
}

sub feed {
	my ( $galla, $which, $ip ) = @_;
	$galla->_handle_line( 'eve', '{"which":"' . $which . '","src_ip":"' . $ip . '"}', $dir . '/eve.json' );
	return;
}

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
is( $galla->{watchers}{eve}{settings}{allow_per_rule_thresholds}, 0, 'the per-rule-thresholds flag is off' );

# admin... a config max_score of 1 bans on the first hit despite the flag,
# with the config ban_time, forming a per-rule bucket that drops on the ban
@sent = ();
feed( $galla, 'suricata-admin', '203.0.113.1' );
is_deeply( \@sent, [ [ '203.0.113.1', 4242 ] ], 'a config max_score 1 bans on the first hit, flag off, config ban_time' );
ok( !defined( $galla->{rule_counters}{'json/suricata-admin'}{'203.0.113.1'} ), 'the per-rule bucket dropped on the ban' );

# the watcher severity won over the kur, and reached EVE... the first hit
# crosses and banishes, so the match surfaces as a banish (which stands for
# the line), not a found beside it
my ($admin_banish) = grep { $_->{event_type} eq 'banish' && ( $_->{ip} || '' ) eq '203.0.113.1' } read_events();
ok( defined($admin_banish), 'the admin match produced a banish event, not a redundant found' );
is( scalar( grep { $_->{event_type} eq 'found' && ( $_->{ip} || '' ) eq '203.0.113.1' } read_events() ),
	0, 'and no found beside the banish' );
is( $admin_banish->{severity}, 'high', 'the watcher rule_config severity won over the kur and reached EVE' );

# dos... a config weight of 3 reaches the watcher max_score of 3 in one hit,
# again with the flag off, counting in the shared bucket
@sent = ();
feed( $galla, 'suricata-dos', '203.0.113.2' );
is_deeply( \@sent, [ [ '203.0.113.2', undef ] ], 'a config weight 3 bans in one hit against a max_score of 3' );

# plain... a config eve_only routes the hit to the shadow bucket, never a ban
@sent = ();
feed( $galla, 'plain', '203.0.113.3' );
is_deeply( \@sent, [], 'a config eve_only rule never bans' );
ok( defined( $galla->{shadow_counters}{'203.0.113.3'} ), 'its hit lands in the shadow bucket' );
ok( !defined( $galla->{counters}{'203.0.113.3'} ),       'and not the real one' );

done_testing;
