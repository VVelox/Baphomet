#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();
use App::Baphomet::Config qw( load_config resolve_settings );
use App::Baphomet::Rules::JSON ();
use JSON::PP ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

#
# resolve_settings layering and normalization
#

my $resolved = resolve_settings( { max_score => 5, find_time => 600, allow_per_rule_thresholds => 0 }, {}, {} );
is( $resolved->{allow_per_rule_thresholds}, 0, 'flag defaults off via the global' );

$resolved = resolve_settings(
	{ max_score => 5, find_time => 600, allow_per_rule_thresholds => 0 },
	{ allow_per_rule_thresholds => JSON::PP::true },
	{}
);
is( $resolved->{allow_per_rule_thresholds}, 1, 'kur-level flag wins over the global and normalizes to 1' );

$resolved = resolve_settings(
	{ max_score => 5, find_time => 600, allow_per_rule_thresholds => 1 },
	{ allow_per_rule_thresholds => 1 },
	{ allow_per_rule_thresholds => JSON::PP::false }
);
is( $resolved->{allow_per_rule_thresholds}, 0, 'watcher-level flag wins over the kur and normalizes to 0' );

# default_severity layers watcher over kur over global, undef when unset
$resolved = resolve_settings( { max_score => 5, find_time => 600, allow_per_rule_thresholds => 0 }, {}, {} );
is( $resolved->{default_severity}, undef, 'default_severity is undef when nothing sets it' );
$resolved = resolve_settings(
	{ max_score => 5, find_time => 600, allow_per_rule_thresholds => 0, default_severity => 'low' },
	{ default_severity => 'medium' },
	{ default_severity => 'high' }
);
is( $resolved->{default_severity}, 'high', 'watcher default_severity wins over kur and global' );

#
# rule def validation and the thresholds accessor
#

my $base_def = {
	gate    => [ { field => 'which', values => ['x'] } ],
	ban_var => ['src_ip'],
};

my $rule = App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base_def} } );
is_deeply( $rule->thresholds, {}, 'a rule without overrides has empty thresholds' );

$rule = App::Baphomet::Rules::JSON->new(
	name => 'json/x',
	def  => { %{$base_def}, max_score => 1, ban_time => 0 }
);
is_deeply( $rule->thresholds, { max_score => 1, ban_time => 0 }, 'thresholds holds only the keys the def sets' );

foreach my $bad ( { max_score => 0 }, { find_time => 'soon' }, { ban_time => -1 } ) {
	my $err;
	eval { App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base_def}, %{$bad} } ); };
	$err = $@;
	like(
		$err,
		qr/(?:positive|non-negative) int/,
		'a rule with a bad ' . join( '', keys( %{$bad} ) ) . ' refuses to load'
	);
}

# the metadata keys... accessors and validation
$rule = App::Baphomet::Rules::JSON->new(
	name => 'json/x',
	def  => { %{$base_def}, severity => 'high', classtype => 'brute-force', references => ['http://x'], attack => ['T1110'] }
);
is( $rule->severity,  'high',        'severity accessor' );
is( $rule->classtype, 'brute-force', 'classtype accessor' );
is_deeply( $rule->references, ['http://x'], 'references accessor' );
is_deeply( $rule->attack,     ['T1110'],    'attack accessor' );

$rule = App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base_def} } );
is( $rule->severity,  undef, 'severity is undef when the rule sets none' );
is( $rule->classtype, undef, 'classtype is undef when the rule sets none' );

foreach my $bad (
	{ key => 'severity',  val => 'urgent',          re => qr/info.low.medium.high.critical/ },
	{ key => 'classtype', val => '',                re => qr/non-empty string/ },
	{ key => 'references', val => [],               re => qr/non-empty array/ },
	{ key => 'attack',     val => [ '', 'T1' ],     re => qr/non-empty string/ },
	)
{
	my $err;
	eval {
		App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base_def}, $bad->{key} => $bad->{val} } );
	};
	$err = $@;
	like( $err, $bad->{re}, 'a bad ' . $bad->{key} . ' refuses to load' );
}

#
# galla behavior... rules with their own thresholds against the flag
#

# fast bans on the first hit, two on the second, bt only overrides the ban
# duration, slow carries nothing of its own
my %rules = (
	fast => "max_score: 1\nban_time: 9999\n",
	two  => "max_score: 2\n",
	bt   => "ban_time: 777\n",
	slow => '',
);
foreach my $name ( keys(%rules) ) {
	open( my $fh, '>', $dir . '/rules/json/' . $name . '.yaml' ) || die($!);
	print $fh "---\ngate:\n  - field: which\n    values: [ " . $name . " ]\nban_var:\n  - src_ip\n" . $rules{$name};
	close($fh);
}

sub write_config {
	my ($allow) = @_;
	open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
	print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"

[kur.ids]
max_score = 3
allow_per_rule_thresholds = $allow

[kur.ids.eve]
log = "$dir/eve.json"
parser = "json"
rule = [ "json/fast", "json/two", "json/bt", "json/slow" ]
EOC
	close($cfg);
	return;
} ## end sub write_config

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, [ $_[1], $_[2] ] ); return; };
}

sub feed {
	my ( $galla, $which, $ip ) = @_;
	$galla->_handle_line( 'eve', '{"which":"' . $which . '","src_ip":"' . $ip . '"}', $dir . '/eve.json' );
	return;
}

#
# flag off... the rule's numbers are inert
#

write_config('false');
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );

@sent = ();
feed( $galla, 'fast', '203.0.113.1' );
is_deeply( \@sent, [], 'flag off, a max_score 1 rule does not ban on the first hit' );
is( scalar( @{ $galla->{counters}{'203.0.113.1'} } ), 1, 'flag off, the hit lands in the shared bucket' );
is_deeply( $galla->{rule_counters}, {}, 'flag off, no per-rule buckets form' );

#
# flag on... the rule speaks over the watcher
#

write_config('true');
$galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
# a stale checkpoint from the flag-off galla would pollute the counters
delete( $galla->{counters}{'203.0.113.1'} );

@sent = ();
feed( $galla, 'fast', '203.0.113.2' );
is_deeply( \@sent, [ [ '203.0.113.2', 9999 ] ], 'flag on, a max_score 1 rule bans on the first hit, its ban_time' );
ok( !defined( $galla->{rule_counters}{'json/fast'}{'203.0.113.2'} ), 'the bucket is dropped on the ban' );

# the shared bucket and a per-rule bucket do not cross-contaminate
@sent = ();
feed( $galla, 'slow', '203.0.113.3' );
feed( $galla, 'slow', '203.0.113.3' );
is_deeply( \@sent, [], 'two slow hits are under the watcher max_score of 3' );
feed( $galla, 'two', '203.0.113.3' );
is_deeply( \@sent, [], 'a first hit on a max_score 2 rule does not borrow the shared count' );
is( scalar( @{ $galla->{counters}{'203.0.113.3'} } ),                       2, 'the shared bucket still holds 2' );
is( scalar( @{ $galla->{rule_counters}{'json/two'}{'203.0.113.3'} } ),      1, 'the rule bucket holds its own 1' );

# the accused view unions the buckets and breaks the per-rule ones out
my $accused = $galla->_cmd_accused->{accused};
is( $accused->{'203.0.113.3'}{hits}, 3, 'accused unions the shared and per-rule hits' );
is( $accused->{'203.0.113.3'}{rules}{'json/two'}{hits}, 1, 'accused breaks the per-rule bucket out' );

# a ban_time-only override counts in the shared bucket and bans differently
@sent = ();
feed( $galla, 'bt', '203.0.113.4' );
feed( $galla, 'bt', '203.0.113.4' );
is_deeply( $galla->{rule_counters}{'json/bt'}, undef, 'a ban_time-only override forms no bucket' );
is( scalar( @{ $galla->{counters}{'203.0.113.4'} } ), 2, 'its hits count in the shared bucket' );
feed( $galla, 'bt', '203.0.113.4' );
is_deeply( \@sent, [ [ '203.0.113.4', 777 ] ], 'the third hit bans with the rule ban_time' );

#
# the counters tablet round-trips the buckets
#

feed( $galla, 'two', '203.0.113.5' );
$galla->checkpoint;

my $reborn = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
is( scalar( @{ $reborn->{counters}{'203.0.113.3'} } ),                  2, 'shared bucket rides the tablet' );
is( scalar( @{ $reborn->{rule_counters}{'json/two'}{'203.0.113.5'} } ), 1, 'per-rule bucket rides the tablet' );

# rows chiseled before the third column existed land in the shared bucket
my $now = time;
open( my $fh, '>', $galla->state_path('counters') ) || die($!);
print $fh "ip,hit\n203.0.113.6," . $now . "\n";
close($fh);
$reborn = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
is( scalar( @{ $reborn->{counters}{'203.0.113.6'} } ), 1, 'old two-field rows restore into the shared bucket' );

done_testing;
