#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use FindBin      ();
use File::Temp qw( tempdir );
use File::Path qw( make_path );
use JSON::MaybeXS ();

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();
use App::Baphomet::Rules::JSON ();
use App::Baphomet::Config qw( kur_split resolve_country_codes );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

#
# config layer... resolve, validate, and the kur_split hash-setting
#

my $resolved = resolve_country_codes(
	{ country_codes => { allowed => [ 'us', 'ca' ], high_risk => ['CN'] } },
	{ country_codes => { high_risk => [ 'ru', 'kp' ] } },
	{ country_codes => { allowed   => ['US'] } }
);
is_deeply( $resolved->{allowed},   ['US'],       'watcher overrides a same-named list' );
is_deeply( $resolved->{high_risk}, [ 'RU', 'KP' ], 'kur overrides and codes uppercase' );

is( App::Baphomet::Config::_country_codes_error( { x => ['US'] }, 'w' ), undef, 'a good country_codes passes' );
like( App::Baphomet::Config::_country_codes_error( { x => 'US' }, 'w' ), qr/non-empty array/, 'a non-array list fails' );
like(
	App::Baphomet::Config::_country_codes_error( { x => ['USA'] }, 'w' ),
	qr/2-letter/,
	'a 3-letter code fails'
);

my ( $settings, $watchers ) = kur_split( { country_codes => { a => ['US'] }, w => { log => 'x' } } );
ok( defined( $settings->{country_codes} ), 'kur_split keeps country_codes a setting, not a watcher' );
ok( !defined( $watchers->{country_codes} ), '...and it is not mistaken for a watcher' );

#
# rule def validation of the country gate
#

my $base = {
	gate    => [ { field => 'event', values => ['fail'] } ],
	ban_var => ['ip'],
};
my %bad = (
	'both is and isnot'    => { is => ['US'], isnot => ['CA'] },
	'neither is nor isnot' => { vars => ['ip'] },
	'a non-code entry'     => { is => ['USA'] },
	'a unknown key'        => { is => ['US'], nope => 1 },
	'an empty vars entry'  => { is => ['US'], vars => [''] },
);
foreach my $desc ( sort( keys(%bad) ) ) {
	eval { App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base}, country => $bad{$desc} } ); };
	ok( $@, 'a country gate with ' . $desc . ' refuses to load' );
}

# a good gate loads and the accessor normalizes it
my $rule = App::Baphomet::Rules::JSON->new(
	name => 'json/x',
	def  => { %{$base}, country => { is => 'US', vars => 'dest_ip' } }
);
is( $rule->country->{mode}, 'is', 'country accessor reports the mode' );
is_deeply( $rule->country->{entries}, ['US'],      'a scalar is normalizes to a list' );
is_deeply( $rule->country->{vars},    ['dest_ip'], 'a scalar vars normalizes to a list' );

#
# the rule files the galla tests share
#

my %rules = (
	'iso-block'  => "country:\n  isnot:\n    - \"%%%country_codes{allowed}%%%\"\nmax_retrys: 1\n",
	'iso-hunt'   => "country:\n  is: [ CN, RU ]\nmax_retrys: 1\n",
	'dest-guard' => "country:\n  is: [ US ]\n  vars: [ dest_ip ]\nmax_retrys: 1\n",
);
# dest-guard bans the src, not the geo-checked dest
my %ban_var = ( 'dest-guard' => 'src_ip' );
foreach my $name ( keys(%rules) ) {
	open( my $fh, '>', $dir . '/rules/json/' . $name . '.yaml' ) || die($!);
	my $bv = defined( $ban_var{$name} ) ? $ban_var{$name} : 'ip';
	print $fh "---\ngate:\n  - field: event\n    values: [ fail ]\nban_var:\n  - " . $bv . "\n" . $rules{$name};
	close($fh);
}

my $json = JSON::MaybeXS->new( 'canonical' => 1 );

sub feed {
	my ( $galla, $watcher, %fields ) = @_;
	$galla->_handle_line( $watcher, $json->encode( \%fields ), $dir . '/l' );
	return;
}

# _send_ban and log_drek are stubbed for every galla here... _country_of is
# left real for the fixture section below, then stubbed for the rest
my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
	*App::Baphomet::Galla::log_drek  = sub { return; };
}

#
# the real MMDB path... a real galla over the committed MaxMind test
# fixture, no lookup stub, so _open_geoip and _country_of are exercised for
# real and the isnot gate resolves against actual geography
#

my $fixture = $FindBin::Bin . '/mmdb/GeoLite2-Country-Test.mmdb';
SKIP: {
	skip( 'no MMDB fixture at ' . $fixture, 8 ) unless -f $fixture;

	open( my $rc, '>', $dir . '/config-real.toml' ) || die($!);
	print $rc <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
geoip_db = "$fixture"

[country_codes]
allowed = [ "US" ]

[kur.georeal]
max_retrys = 5
allow_per_rule_thresholds = true

[kur.georeal.rw]
log = "$dir/lr"
parser = "json"
rule = [ "json/iso-block" ]
EOC
	close($rc);

	my $rgalla = App::Baphomet::Galla->new( config => $dir . '/config-real.toml', name => 'georeal' );
	ok( defined( $rgalla->{geoip} ), 'the committed fixture opens as a real database' );
	is( $rgalla->_country_of('81.2.69.142'),   'GB',  '_country_of resolves a GB address from the fixture' );
	is( $rgalla->_country_of('216.160.83.56'), 'US',  '_country_of resolves a US address from the fixture' );
	is( $rgalla->_country_of('1.1.1.1'),       undef, '_country_of is undef for an address the fixture can not locate' );
	is( $rgalla->_country_of('not-an-ip'),     undef, '_country_of is undef for a value that is not an address' );

	# isnot the allowed list (US), against real geography
	@sent = ();
	feed( $rgalla, 'rw', event => 'fail', ip => '216.160.83.56' );
	is_deeply( \@sent, [], 'isnot US spares a real US offender through the real MMDB' );
	feed( $rgalla, 'rw', event => 'fail', ip => '81.2.69.142' );
	is_deeply( \@sent, ['81.2.69.142'], 'isnot US bans a real GB offender' );
	@sent = ();
	feed( $rgalla, 'rw', event => 'fail', ip => '1.1.1.1' );
	is_deeply( \@sent, [], 'the gate fails closed on an address the real database can not locate' );
} ## end SKIP:

#
# the exhaustive gate logic, over a stubbed lookup with a controlled map
#

my %country = (
	'1.1.1.1' => 'US',
	'2.2.2.2' => 'CN',
	'3.3.3.3' => 'RU',
	'4.4.4.4' => undef,      # unlocatable
	'9.9.9.9' => 'US',       # a dest
	'8.8.8.8' => 'CN',       # a dest
);
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_country_of = sub { return $country{ $_[1] }; };
}

open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"

[country_codes]
allowed = [ "US", "CA" ]

[kur.geo]
max_retrys = 5
allow_per_rule_thresholds = true

[kur.geo.blockw]
log = "$dir/l1"
parser = "json"
rule = [ "json/iso-block" ]

[kur.geo.huntw]
log = "$dir/l2"
parser = "json"
rule = [ "json/iso-hunt" ]

[kur.geo.destw]
log = "$dir/l3"
parser = "json"
rule = [ "json/dest-guard" ]

[kur.geo.overridew]
log = "$dir/l4"
parser = "json"
rule = [ "json/iso-block" ]

[kur.geo.overridew.country_codes]
allowed = [ "CA" ]
EOC
close($cfg);

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'geo' );

# isnot the allowed list, offender-keyed
@sent = ();
feed( $galla, 'blockw', event => 'fail', ip => '1.1.1.1' );
is_deeply( \@sent, [], 'isnot allowed does not ban an allowed-country offender' );
feed( $galla, 'blockw', event => 'fail', ip => '2.2.2.2' );
is_deeply( \@sent, ['2.2.2.2'], 'isnot allowed bans a non-allowed-country offender' );
@sent = ();
feed( $galla, 'blockw', event => 'fail', ip => '4.4.4.4' );
is_deeply( \@sent, [], 'isnot fails closed on an unlocatable offender' );

# is a literal list, offender-keyed
@sent = ();
feed( $galla, 'huntw', event => 'fail', ip => '2.2.2.2' );
is_deeply( \@sent, ['2.2.2.2'], 'is [CN,RU] bans a matching-country offender' );
feed( $galla, 'huntw', event => 'fail', ip => '1.1.1.1' );
is_deeply( \@sent, ['2.2.2.2'], 'is [CN,RU] does not ban a non-matching offender' );

# vars gate, data-keyed... check the dest, ban the src
@sent = ();
feed( $galla, 'destw', event => 'fail', src_ip => '2.2.2.2', dest_ip => '9.9.9.9' );
is_deeply( \@sent, ['2.2.2.2'], 'a vars gate bans the src when the dest is in-country' );
@sent = ();
feed( $galla, 'destw', event => 'fail', src_ip => '2.2.2.2', dest_ip => '8.8.8.8' );
is_deeply( \@sent, [], 'a vars gate vetoes the whole result when the dest is out of country' );
feed( $galla, 'destw', event => 'fail', src_ip => '2.2.2.2', dest_ip => '4.4.4.4' );
is_deeply( \@sent, [], 'a vars gate fails closed on an unlocatable var' );

# the same rule under a watcher that overrides the list resolves differently
@sent = ();
feed( $galla, 'overridew', event => 'fail', ip => '1.1.1.1' );
is_deeply( \@sent, ['1.1.1.1'], 'a watcher-overridden list bans a US offender the base watcher spared' );

#
# a import of a list the watcher does not define is fatal at bind
#

my $import_rule = App::Baphomet::Rules::JSON->new(
	name => 'json/z',
	def  => { %{$base}, country => { isnot => ['%%%country_codes{nope}%%%'] } }
);
eval { $galla->_resolve_country_gate( $import_rule, { allowed => ['US'] }, 'where' ); };
like( $@, qr/nope.*not a defined list/, 'importing a undefined country_codes list dies' );
my $ok = $galla->_resolve_country_gate( $import_rule, { nope => [ 'cn', 'ru' ] }, 'where' );
is_deeply( $ok->{codes}, { CN => 1, RU => 1 }, 'a defined import resolves and uppercases into a set' );

done_testing;
