#!perl
# the asn, dnsbl, account, and limit gates and the country lift under a
# galla... the config behind them, the lookups the galla answers them with,
# the consents, and each gate deciding who is banished. nothing here touches
# a real database or real DNS, a stand-in reader and the lookup seams
# answering for both
use 5.006;
use strict;
use warnings;
use Test::More;
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
use App::Baphomet::Config qw( load_config kur_split check_kur_def resolve_asn_lists );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

#
# the config layer
#

my $resolved = resolve_asn_lists(
	{ asn_lists => { office  => [ 'AS64496', 64497 ], hosting => [64500] } },
	{ asn_lists => { hosting => [ 'as64501', '064502' ] } },
	{ asn_lists => { office  => [64499] } }
);
is_deeply( $resolved->{office},  [64499],          'watcher overrides a same-named list' );
is_deeply( $resolved->{hosting}, [ 64501, 64502 ], 'kur overrides, and every number comes back bare' );

is( App::Baphomet::Config::_asn_lists_error( { x => [ 64496, 'AS64497' ] }, 'w' ), undef, 'a good asn_lists passes' );
like( App::Baphomet::Config::_asn_lists_error( { x => 64496 }, 'w' ), qr/non-empty array/, 'a non-array list fails' );
like( App::Baphomet::Config::_asn_lists_error( { x => ['AS-SET'] }, 'w' ), qr/not a AS number/, 'a entry that is no number fails' );
like( App::Baphomet::Config::_asn_lists_error( [], 'w' ), qr/not a hash of named AS number lists/, 'as does a asn_lists that is no hash' );

my ( $settings, $watchers ) = kur_split( { asn_lists => { a => [64496] }, w => { log => 'x' } } );
ok( defined( $settings->{asn_lists} ),  'kur_split keeps asn_lists a setting, not a watcher' );
ok( !defined( $watchers->{asn_lists} ), '...and it is not mistaken for a watcher' );

# what load_config makes of the three settings, over a config of the passed
# lines... the config hash, or the error it died with
sub loaded {
	my ($lines) = @_;

	my $path = $dir . '/load.toml';
	open( my $fh, '>', $path ) || die($!);
	print $fh $lines;
	close($fh);
	my $config = eval { load_config($path) };
	return defined($config) ? $config : $@;
}

my $defaults = loaded('');
is( $defaults->{enable_dnsbl}, 0,     'enable_dnsbl defaults off' );
is( $defaults->{geoip_asn_db}, undef, 'geoip_asn_db defaults unset' );
is_deeply( $defaults->{asn_lists}, {}, 'asn_lists defaults empty' );
is( loaded("enable_dnsbl = true\n")->{enable_dnsbl}, 1, 'enable_dnsbl normalizes to 1' );
like( loaded("geoip_asn_db = \"\"\n"),               qr/^geoip_asn_db is not a path/, 'a empty geoip_asn_db is refused' );
like(
	loaded("[asn_lists]\noffice = [ \"AS-SET\" ]\n"),
	qr/^The top level asn_lists list "office" has a entry that is not a AS number/,
	'a bad top level asn_lists is refused'
);
my %watcher = ( log => '/var/log/x', parser => 'json', rule => 'json/x' );
ok( eval { check_kur_def( 'app', { asn_lists => { office => [64496] }, w => { %watcher, asn_lists => { lab => ['AS64497'] } } } ); 1 },
	'asn_lists is a setting of a kur and of a watcher' )
	|| diag($@);
ok( !eval { check_kur_def( 'app', { w => { %watcher, asn_lists => { office => 'AS64496' } } } ); 1 },
	'a bad watcher level asn_lists is refused' );
like( $@, qr/asn_lists list "office" is not a non-empty array/, 'and says what is wrong with it' );

# the gates of each rule below the one every rule here leads with
my %rules = (
	'asn-office'  => "  - ban_var: [ ip ]\n  - asn:\n      isnot: [ \"%%%asn_lists{office}%%%\" ]\n",
	'asn-hosting' => "  - asn: { org_is: '(?i)hosting', vars: [ ip ], into: ASN, org_into: ASN_ORG }\n  - ban_var: [ ip ]\n",
	'listed'      => "  - ban_var: [ ip ]\n  - dnsbl: { zones: [ bl.example.org ] }\n",
	'guess'       => "  - account: { var: user, exists: false }\n  - ban_var: [ ip ]\n",
	'quiet'       => "  - ban_var: [ ip ]\n  - limit: { by: [ ip ], seconds: 60 }\n",
);
foreach my $name ( keys(%rules) ) {
	open( my $fh, '>', $dir . '/rules/json/' . $name . '.yaml' ) || die($!);
	print $fh "---\nmax_score: 1\nrule_gates:\n  - gate:\n      - field: event\n        values: [ fail ]\n"
		. $rules{$name};
	close($fh);
}

# how many countries one account is seen from, which only the lift lets a
# rule count
open( my $travel_fh, '>', $dir . '/rules/json/travel.yaml' ) || die($!);
print $travel_fh <<'EOR';
---
max_score: 2
find_time: 3600
distinct: { of: COUNTRY, by: user }
rule_gates:
  - gate:
      - field: event
        values: [ login ]
  - country: { vars: [ ip ], into: COUNTRY }
  - ban_var: [ ip ]
EOR
close($travel_fh);

# the galla's log lines, kept so what it says at start can be read
my @sent;
my @logged;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent,   $_[1] ); return; };
	*App::Baphomet::Galla::log_drek  = sub { push( @logged, $_[1] ); return; };
}

# writes a config of the passed top level lines and the watchers of the kur
# "app", one a rule and named for it, and returns the galla over it
my $config_count = 0;
sub galla_over {
	my ( $top_level, @rule_names ) = @_;

	$config_count++;
	my $path = $dir . '/config' . $config_count . '.toml';
	open( my $fh, '>', $path ) || die($!);
	print $fh "run_base_dir = \"$dir/run\"\n"
		. "tablet_base_dir = \"$dir/cache$config_count\"\n"
		. "rules_dir = \"$dir/rules\"\n"
		. "ereshkigal_socket = \"$dir/nonexistent.sock\"\n"
		. $top_level
		. "\n[kur.app]\nmax_score = 5\nallow_per_rule_thresholds = true\n";
	foreach my $rule_name (@rule_names) {
		print $fh "\n[kur.app.$rule_name]\nlog = \"$dir/l-$rule_name\"\nparser = \"json\"\nrule = [ \"json/$rule_name\" ]\n";
	}
	close($fh);

	@logged = ();
	my $galla = App::Baphomet::Galla->new( config => $path, name => 'app' );
	ok( defined($galla) && !$galla->{perror}, 'a galla over ' . join( ', ', @rule_names ) . ' came up' )
		|| diag( $galla->{errorString} );
	return $galla;
} ## end sub galla_over

my $json = JSON::MaybeXS->new( 'canonical' => 1 );

sub feed {
	my ( $galla, $watcher, %fields ) = @_;
	$galla->_handle_line( $watcher, $json->encode( \%fields ), $dir . '/l' );
	return;
}

# stands in for a MaxMind reader, answering from a map of address to record
# and dying on what is no address, as the real one does
{

	package Local::Reader;

	sub new {
		my ( $class, %records ) = @_;
		return bless( { 'records' => \%records, 'asked' => 0 }, $class );
	}

	sub record_for_address {
		my ( $self, $address ) = @_;
		$self->{asked}++;
		if ( $address !~ /^[0-9a-fA-F:.]+$/ ) {
			die('not a address');
		}
		return $self->{records}{$address};
	}
}

#
# asn... no database is a loud hole, and one stood in for is judged over
#

my $galla = galla_over( "\n[asn_lists]\noffice = [ \"AS64496\" ]\n", 'asn-office', 'asn-hosting' );
ok( ( grep { /^asn-gated rules are configured but no ASN database is loaded\.\.\. geoip_asn_db is unset/ } @logged ),
	'asn-gated rules with no database are said loudly at start' );
feed( $galla, 'asn-office', event => 'fail', ip => '203.0.113.9' );
is_deeply( \@sent, [], 'and with no database the gate fails closed' );

my $reader = Local::Reader->new(
	'203.0.113.9'  => { 'autonomous_system_number' => 64496, 'autonomous_system_organization' => 'Example Office' },
	'198.51.100.5' => { 'autonomous_system_number' => 64500, 'autonomous_system_organization' => 'Example Hosting' },
	'192.0.2.77'   => { 'autonomous_system_number' => 64511 },
	'192.0.2.78'   => {},
);
$galla->{geoip_asn} = $reader;

is_deeply(
	$galla->_asn_of('198.51.100.5'),
	{ 'number' => 64500, 'org' => 'Example Hosting' },
	'_asn_of answers the number and the name'
);
is_deeply( $galla->_asn_of('192.0.2.77'), { 'number' => 64511, 'org' => undef }, 'a network with no name has a undef org' );
is( $galla->_asn_of('192.0.2.78'), undef, 'a record with no AS number is no network' );
is( $galla->_asn_of('192.0.2.1'),  undef, 'nor is a address the database can not place' );
is( $galla->_asn_of('not-an-ip'),  undef, 'nor a value that is not a address, the reader dying on it' );
my $asked_before = $reader->{asked};
$galla->_asn_of('198.51.100.5');
is( $reader->{asked}, $asked_before, 'a answer is cached, the reader not asked again' );

feed( $galla, 'asn-office', event => 'fail', ip => '203.0.113.9' );
is_deeply( \@sent, [], 'isnot the office list spares a office address' );
feed( $galla, 'asn-office', event => 'fail', ip => '198.51.100.5' );
is_deeply( \@sent, ['198.51.100.5'], 'and banishes one on another network' );
@sent = ();
feed( $galla, 'asn-office', event => 'fail', ip => '192.0.2.1' );
is_deeply( \@sent, [], 'a address the database can not place fails closed' );

feed( $galla, 'asn-hosting', event => 'fail', ip => '203.0.113.9' );
is_deeply( \@sent, [], 'org_is spares a network whose name does not match' );
feed( $galla, 'asn-hosting', event => 'fail', ip => '198.51.100.5' );
is_deeply( \@sent, ['198.51.100.5'], 'and banishes one whose name does' );

#
# account... the galla's own host is who is asked
#

@sent = ();
my $real_account = getpwuid($<);
SKIP: {
	skip( 'no account name for the uid the tests run as', 2 ) unless defined($real_account);
	is( $galla->_account_exists($real_account), 1, 'the account the tests run as exists' );
	my $guess_galla = galla_over( '', 'guess' );
	feed( $guess_galla, 'guess', event => 'fail', ip => '203.0.113.9', user => $real_account );
	is_deeply( \@sent, [], 'exists false spares a failure for a real account' );
	feed( $guess_galla, 'guess', event => 'fail', ip => '203.0.113.9', user => 'no-such-account-of-this-host' );
	is_deeply( \@sent, ['203.0.113.9'], 'and banishes one for a name that is nobody\'s' );
	@sent = ();
	feed( $guess_galla, 'guess', event => 'fail', ip => '203.0.113.10' );
	is_deeply( \@sent, [], 'a failure with no name fails closed' );
} ## end SKIP:
is( $galla->_account_exists('no-such-account-of-this-host'), 0, 'a name that is nobody\'s is no account' );
is( $galla->_account_exists(''),                             0, 'nor is a empty name' );
is( $galla->_account_exists(undef),                          0, 'nor no name' );
foreach my $never_asked ( "neti\x00", 'neti/..', 'neti:0', 'n' x 257 ) {
	$galla->_account_exists($never_asked);
	ok( !exists( $galla->{account_cache}{$never_asked} ), 'a name no account could have is never asked about' );
}
ok( exists( $galla->{account_cache}{'no-such-account-of-this-host'} ), 'while one that was asked about is cached' );

#
# dnsbl... off unless consented to, and then judged over the lookups
#

@sent = ();
my $unconsented = galla_over( '', 'listed' );
is( $unconsented->{enable_dnsbl}, 0, 'enable_dnsbl defaults off' );
ok( ( grep { /^dnsbl-gated rules are configured but enable_dnsbl is off/ } @logged ),
	'dnsbl-gated rules with out the consent are said loudly at start' );
$unconsented->{dns_listed} = sub { return ['127.0.0.2']; };
feed( $unconsented, 'listed', event => 'fail', ip => '203.0.113.9' );
is_deeply( \@sent, [], 'and with out the consent the gate fails closed, whatever a lookup would say' );

my $listing = galla_over( "enable_dnsbl = true\n", 'listed' );
ok( !( grep { /enable_dnsbl is off/ } @logged ), 'with the consent nothing is said of it' );

# the mock blocklist, injected through the closure seam... a array ref of
# what the zone answers, empty for not listed, or undef for a failed lookup
my %asked_names;
$listing->{dns_listed} = sub {
	my ($query_name) = @_;
	$asked_names{$query_name}++;
	my %answers = (
		'9.113.0.203.bl.example.org'  => ['127.0.0.2'],
		'10.113.0.203.bl.example.org' => [],
		'12.113.0.203.bl.example.org' => ['127.255.255.254'],
	);
	return $answers{$query_name};
};

feed( $listing, 'listed', event => 'fail', ip => '203.0.113.9' );
is_deeply( \@sent, ['203.0.113.9'], 'a listed address is banished' );
@sent = ();
feed( $listing, 'listed', event => 'fail', ip => '203.0.113.10' );
is_deeply( \@sent, [], 'one on no list is spared' );
my $failures_before = $listing->{stats}{dnsbl_failures};
feed( $listing, 'listed', event => 'fail', ip => '203.0.113.11' );
is_deeply( \@sent, [], 'a lookup that failed fails closed' );
is( $listing->{stats}{dnsbl_failures}, $failures_before + 1, 'and ticked dnsbl_failures' );
is( $listing->{stats}{rdns_failures},  0,                    'not rdns_failures' );
feed( $listing, 'listed', event => 'fail', ip => '203.0.113.12' );
is_deeply( \@sent, [], 'a zone refusing the query banishes nobody' );

feed( $listing, 'listed', event => 'fail', ip => '203.0.113.10' );
is( $asked_names{'10.113.0.203.bl.example.org'}, 1, 'a answer is cached, the zone not asked again' );

# under the background engine a cold address is a failed lookup for its
# first line, and the answer is there for the next
my @queries;
$listing->{dns_bg} = sub {
	my ( $kind, $qname, $qtype, $done ) = @_;
	push( @queries, { 'qname' => $qname, 'qtype' => $qtype, 'done' => $done } );
	return;
};
$listing->{dns_async}  = 1;
$listing->{dns_listed} = sub { die('the blocking closure must not be asked on the async path'); };

feed( $listing, 'listed', event => 'fail', ip => '203.0.113.20' );
is_deeply( \@sent, [], 'a cold address fails closed for the line that asked' );
is_deeply(
	[ map { $_->{qname} . ' ' . $_->{qtype} } @queries ],
	['20.113.0.203.bl.example.org A'],
	'and one A query is fired for it, with no AAAA beside it'
);
feed( $listing, 'listed', event => 'fail', ip => '203.0.113.20' );
is( scalar(@queries), 1, 'a second line while it is in flight fires nothing more' );
$queries[0]{done}->( ['127.0.0.2'] );
feed( $listing, 'listed', event => 'fail', ip => '203.0.113.20' );
is_deeply( \@sent, ['203.0.113.20'], 'the answer landed, the next line is banished on it' );

#
# limit... only so many of a key reach the counting
#

@sent = ();
my $limited = galla_over( '', 'quiet' );
foreach my $line_count ( 1 .. 3 ) {
	feed( $limited, 'quiet', event => 'fail', ip => '203.0.113.9' );
}
# with no limit each of the three would cross the max_score of 1
is_deeply( \@sent, ['203.0.113.9'], 'three lines of one key inside a window count once' );
feed( $limited, 'quiet', event => 'fail', ip => '203.0.113.10' );
is_deeply( \@sent, [ '203.0.113.9', '203.0.113.10' ], 'and another key is let by on its own' );

#
# the country lift, counted by distinct... one account from two countries
#

@sent = ();
my $travel = galla_over( '', 'travel' );
$travel->{geoip} = Local::Reader->new(
	'198.51.100.5' => { 'country' => { 'iso_code' => 'US' } },
	'198.51.100.6' => { 'country' => { 'iso_code' => 'US' } },
	'203.0.113.9'  => { 'country' => { 'iso_code' => 'nl' } },
);

feed( $travel, 'travel', event => 'login', user => 'neti', ip => '198.51.100.5' );
feed( $travel, 'travel', event => 'login', user => 'neti', ip => '198.51.100.6' );
is_deeply( \@sent, [], 'two addresses in the one country are one country' );
is_deeply(
	[ sort( keys( %{ $travel->{distinct_counters}{'json/travel'}{neti} } ) ) ],
	['US'],
	'the lifted code is what distinct counted'
);
feed( $travel, 'travel', event => 'login', user => 'namtar', ip => '203.0.113.9' );
is_deeply( \@sent, [], 'another account in another country is its own count' );
feed( $travel, 'travel', event => 'login', user => 'neti', ip => '192.0.2.1' );
is_deeply( \@sent, [], 'a address the database can not place adds no country' );
feed( $travel, 'travel', event => 'login', user => 'neti', ip => '203.0.113.9' );
is_deeply( \@sent, ['203.0.113.9'], 'the account seen from a second country banishes the address that tipped it' );

done_testing();
