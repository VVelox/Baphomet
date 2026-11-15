#!perl
# the forgive, pressure, travel, and after gates under a galla... the counts
# a forgive gate takes hits back out of and the tablet they ride, the meter a
# pressure gate reads, the city lookups a travel gate places a address with,
# and each gate deciding who is banished. nothing here touches a real
# database, a stand-in reader answering for it
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
use App::Baphomet::Config qw( load_config );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run' );

# writes a json rule of the passed top level keys and gates, the gates below
# one holding on the passed event
sub write_rule {
	my ( $name, $event, $top_level, $gates ) = @_;

	open( my $fh, '>', $dir . '/rules/json/' . $name . '.yaml' ) || die($!);
	print $fh "---\n"
		. $top_level
		. "rule_gates:\n  - gate:\n      - field: event\n        values: [ $event ]\n"
		. $gates;
	close($fh);
	return;
} ## end sub write_rule

# the rule that counts failed logins, what it was about being its user_var
write_rule( 'fail', 'fail', "user_var: user\n", "  - ban_var: [ ip ]\n" );
# another that counts, about nobody
write_rule( 'probe', 'probe', '', "  - ban_var: [ ip ]\n" );
# one counting in a bucket of its own
write_rule( 'slow', 'slow', "user_var: user\nmax_score: 3\n", "  - ban_var: [ ip ]\n" );
# a login that worked forgives the failures for the same account
write_rule( 'ok', 'ok', "mark_only: true\n",
	"  - ban_var: [ ip ]\n  - forgive: { rules: [ json/fail, json/slow ], same: user }\n" );
# and one forgiving whoever they were about, off a detection rule by a var
write_rule( 'amnesty', 'amnesty', '', "  - forgive: { rules: json/fail, var: ip }\n  - detection_var: [ ip ]\n" );
# a forgive naming a rule nothing lists
write_rule( 'typo', 'typo', "mark_only: true\n", "  - ban_var: [ ip ]\n  - forgive: { rules: json/fial }\n" );

# the harsher copy of fail, only let by under pressure
write_rule( 'siege', 'fail', "max_score: 1\n", "  - ban_var: [ ip ]\n" );
{
	# the pressure gate leads the rule, ahead of the gate on the event
	open( my $fh, '>', $dir . '/rules/json/siege.yaml' ) || die($!);
	print $fh "---\nmax_score: 1\nrule_gates:\n"
		. "  - pressure: { above: 3, seconds: 60 }\n"
		. "  - gate:\n      - field: event\n        values: [ fail ]\n"
		. "  - ban_var: [ ip ]\n";
	close($fh);
}
# a rule that only sights, and one that only brands
write_rule( 'seen', 'seen', '', "  - detection_var: [ ip ]\n" );
write_rule( 'brand', 'brand', "mark_only: true\n", "  - ban_var: [ ip ]\n  - mark: { name: branded, ttl: 60 }\n" );

# a login seen further off than it could have gone
write_rule( 'travel', 'login', "max_score: 1\n",
	"  - travel: { name: last-login, by: user, var: ip, faster_than_kmh: 900 }\n  - ban_var: [ ip ]\n" );
# the third failure against one account, whoever it came from
write_rule( 'many', 'fail', "max_score: 1\n", "  - after: { by: user, count: 3, seconds: 600 }\n  - ban_var: [ ip ]\n" );

my @sent;
my @logged;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent,   $_[1] ); return; };
	*App::Baphomet::Galla::log_drek  = sub { push( @logged, $_[0] . ': ' . $_[1] ); return; };
}

# writes a config of the passed top level lines and one watcher of the kur
# "app" for each of the rest, a name and the rules it lists, and returns the
# galla over it. the tablets are kept under the passed name, so two gallas
# given the one name are a galla and its restart
my $config_count = 0;

sub galla_over {
	my ( $tablet_name, $top_level, %watchers ) = @_;

	$config_count++;
	my $path = $dir . '/config' . $config_count . '.toml';
	open( my $fh, '>', $path ) || die($!);
	print $fh "run_base_dir = \"$dir/run\"\n"
		. "tablet_base_dir = \"$dir/$tablet_name\"\n"
		. "rules_dir = \"$dir/rules\"\n"
		. "ereshkigal_socket = \"$dir/nonexistent.sock\"\n"
		. $top_level
		. "\n[kur.app]\nmax_score = 6\nfind_time = 600\nallow_per_rule_thresholds = true\n";
	foreach my $watcher_name ( sort( keys(%watchers) ) ) {
		my $rule_list = join( ', ', map { '"json/' . $_ . '"' } @{ $watchers{$watcher_name} } );
		print $fh "\n[kur.app.$watcher_name]\nlog = \"$dir/l-$watcher_name\"\nparser = \"json\"\nrule = [ $rule_list ]\n";
	}
	close($fh);

	@logged = ();
	my $galla = App::Baphomet::Galla->new( config => $path, name => 'app' );
	ok( defined($galla) && !$galla->{perror}, 'a galla over ' . join( ', ', sort( keys(%watchers) ) ) . ' came up' )
		|| diag( $galla->{errorString} );
	return $galla;
} ## end sub galla_over

my $json = JSON::MaybeXS->new( 'canonical' => 1 );

sub feed {
	my ( $galla, $watcher, %fields ) = @_;
	$galla->_handle_line( $watcher, $json->encode( \%fields ), $dir . '/l' );
	return;
}

# how many hits the shared bucket holds against a address
sub hits {
	my ( $galla, $address ) = @_;
	return scalar( @{ $galla->{counters}{$address} // [] } );
}

#
# forgive
#

my $galla = galla_over( 'forgive', '', 'auth' => [ 'fail', 'probe', 'slow', 'ok', 'amnesty', 'typo' ] );
ok( ( grep { /^err: forgive gates name rules no watcher lists, so nothing is ever forgiven for them\.\.\. json\/fial$/ } @logged ),
	'a forgive gate naming a rule no watcher lists is said loudly at start' );

my $offender = '203.0.113.9';
foreach my $try ( 1 .. 3 ) {
	feed( $galla, 'auth', event => 'fail', ip => $offender, user => 'neti' );
}
feed( $galla, 'auth', event => 'fail',  ip => $offender, user => 'root' );
feed( $galla, 'auth', event => 'probe', ip => $offender );
is( hits( $galla, $offender ), 5, 'five hits are counted against the address' );
is_deeply(
	$galla->{counters}{$offender}[0],
	[ $galla->{counters}{$offender}[0][0], 1, 'json/fail', 'neti' ],
	'each a time, a weight, the rule that counted it, and the account it was about'
);
is_deeply( [ @{ $galla->{counters}{$offender}[4] }[ 2, 3 ] ], [ 'json/probe', undef ], 'a rule with no user_var counts hits about nobody' );

feed( $galla, 'auth', event => 'ok', ip => $offender, user => 'neti' );
is( hits( $galla, $offender ), 2, 'a login that worked takes back the three failures for its account' );
is_deeply(
	[ map { $_->[2] . ' ' . ( $_->[3] // '-' ) } @{ $galla->{counters}{$offender} } ],
	[ 'json/fail root', 'json/probe -' ],
	'and leaves the one for another account and the hit of a rule it does not name'
);
is( $galla->{stats}{forgiven}, 3, 'what was taken back is ticked' );
is_deeply( \@sent, [], 'nobody is banished by any of it' );

feed( $galla, 'auth', event => 'ok', ip => $offender );
is( hits( $galla, $offender ), 2, 'a login naming no account forgives nothing' );
feed( $galla, 'auth', event => 'ok', ip => '203.0.113.50', user => 'root' );
is( hits( $galla, $offender ), 2, 'nor does one from another address' );

# the count goes on from what was left, so the owner is not one typo from a ban
foreach my $try ( 1 .. 3 ) {
	feed( $galla, 'auth', event => 'fail', ip => $offender, user => 'neti' );
}
is_deeply( \@sent, [], 'three more failures on the two left is five, under the max_score of six' );
feed( $galla, 'auth', event => 'fail', ip => $offender, user => 'neti' );
is_deeply( \@sent, [$offender], 'and the sixth banishes as ever' );
@sent = ();

# a bucket of the rule's own
my $slow_offender = '203.0.113.30';
foreach my $try ( 1 .. 2 ) {
	feed( $galla, 'auth', event => 'slow', ip => $slow_offender, user => 'neti' );
}
is( scalar( @{ $galla->{rule_counters}{'json/slow'}{$slow_offender} } ), 2, 'a rule with thresholds of its own counts in a bucket of its own' );
feed( $galla, 'auth', event => 'ok', ip => $slow_offender, user => 'neti' );
ok( !exists( $galla->{rule_counters}{'json/slow'}{$slow_offender} ), 'and its hits are taken back out of that' );

# whoever they were about, by a var, off a rule that only sights
my $pardoned = '203.0.113.40';
feed( $galla, 'auth', event => 'fail',  ip => $pardoned, user => 'neti' );
feed( $galla, 'auth', event => 'fail',  ip => $pardoned, user => 'root' );
feed( $galla, 'auth', event => 'probe', ip => $pardoned );
feed( $galla, 'auth', event => 'amnesty', ip => $pardoned );
is_deeply(
	[ map { $_->[2] } @{ $galla->{counters}{$pardoned} } ],
	['json/probe'],
	'with no same every hit of the named rule is taken back, and a detection rule forgives by a var'
);

# the shadow buckets of observe mode are kept in step
$galla->{shadow_counters}{'203.0.113.60'} = [ [ time, 1, 'json/fail', 'neti' ], [ time, 1, 'json/probe', undef ] ];
is( $galla->_forgive( '203.0.113.60', { 'json/fail' => 1 }, undef ), 1, '_forgive answers how many hits it took back' );
is( scalar( @{ $galla->{shadow_counters}{'203.0.113.60'} } ), 1, 'and takes them out of the shadow buckets the same' );
is( $galla->_forgive( '203.0.113.61', { 'json/fail' => 1 }, undef ), 0, 'a address nothing is counted against is forgiven nothing' );

# the tablet... a restart remembers what a hit was about
my $restarted_offender = '203.0.113.70';
feed( $galla, 'auth', event => 'fail', ip => $restarted_offender, user => 'neti' );
feed( $galla, 'auth', event => 'fail', ip => $restarted_offender, user => "ro\not" );
$galla->checkpoint;
my @rows = grep { /^\Q$restarted_offender\E,/ } $galla->{tablet}->read('counters');
like( $rows[0], qr/^\Q$restarted_offender\E,[0-9]+,1,,json\/fail,neti$/, 'a row says the rule that counted the hit and the account' );
like( $rows[1], qr/,json\/fail,root$/, 'a account is written less any newline, a tablet being read a line at a time' );

my $reborn = galla_over( 'forgive', '', 'auth' => [ 'fail', 'probe', 'slow', 'ok', 'amnesty' ] );
is_deeply(
	[ map { $_->[2] . ' ' . $_->[3] } @{ $reborn->{counters}{$restarted_offender} } ],
	[ 'json/fail neti', 'json/fail root' ],
	'what each hit was about rides the tablet across a restart'
);
feed( $reborn, 'auth', event => 'ok', ip => $restarted_offender, user => 'neti' );
is( hits( $reborn, $restarted_offender ), 1, 'so a login after the restart forgives the failures from before it' );

# a row from before the two columns is a hit no forgive gate takes back
$reborn->{tablet}->write( 'counters', [ 'ip,hit,weight,rule', '203.0.113.80,' . time . ',1,' ] );
$reborn->{counters} = {};
$reborn->_load_counters(time);
is_deeply( [ @{ $reborn->{counters}{'203.0.113.80'}[0] }[ 2, 3 ] ], [ undef, undef ], 'a four column row loads with no rule and no account' );
feed( $reborn, 'auth', event => 'amnesty', ip => '203.0.113.80' );
is( hits( $reborn, '203.0.113.80' ), 1, 'and is left by a forgive gate, there being no saying which rule counted it' );

#
# pressure
#

@sent = ();
my $plain = galla_over( 'plain', '', 'auth' => ['fail'] );
feed( $plain, 'auth', event => 'fail', ip => '203.0.113.9', user => 'neti' );
is( $plain->{pressure_window}, 0, 'a galla with no pressure gate reads back no way at all' );
is_deeply( $plain->{pressure_meter}, {}, 'and meters nothing' );

my $besieged = galla_over( 'siege', '', 'auth' => [ 'siege', 'fail', 'seen', 'brand' ], 'web' => ['fail'] );
is( $besieged->{pressure_window}, 60, 'the meter is kept as far back as the pressure gate reads' );

feed( $besieged, 'auth', event => 'seen',  ip => '198.51.100.1' );
feed( $besieged, 'auth', event => 'brand', ip => '198.51.100.1' );
is( $besieged->_pressure_of( 'auth', 'watcher', 60, time ), 0, 'a rule that only sights or only brands meters nothing' );

foreach my $source ( 1 .. 3 ) {
	feed( $besieged, 'auth', event => 'fail', ip => '198.51.100.' . $source, user => 'neti' );
}
is( $besieged->_pressure_of( 'auth', 'watcher', 60, time ), 3, 'three lines a banning rule named a offender on are three' );
is_deeply( \@sent, [], 'at the mark and not above it, the harsher rule is not let by' );
ok( !( grep { /under pressure/ } @logged ), 'and nothing is said' );

feed( $besieged, 'auth', event => 'fail', ip => '198.51.100.4', user => 'neti' );
is_deeply( \@sent, [], 'the fourth is still read against the three before it' );
feed( $besieged, 'auth', event => 'fail', ip => '198.51.100.5', user => 'neti' );
is_deeply( \@sent, ['198.51.100.5'], 'above the mark the harsher rule takes the line and banishes on the one hit' );
is(
	( grep { /^notice: The rule "json\/siege" of the watcher "auth" is under pressure, 4 matched lines in the last 60 seconds$/ } @logged ),
	1,
	'and the galla says the gate has opened'
);

# a line the harsher rule took is metered like any other, so the gate
# letting lines by does not lower what it reads
feed( $besieged, 'auth', event => 'fail', ip => '198.51.100.6', user => 'neti' );
feed( $besieged, 'auth', event => 'fail', ip => '198.51.100.7', user => 'neti' );
is_deeply( \@sent, [ '198.51.100.5', '198.51.100.6', '198.51.100.7' ], 'it goes on taking the lines' );
is( $besieged->_pressure_of( 'auth', 'watcher', 60, time ), 7, 'each of them counted once, though two rules may name a offender on a line' );

# the scope, and how far back
feed( $besieged, 'web', event => 'fail', ip => '198.51.100.8', user => 'neti' );
is( $besieged->_pressure_of( 'auth', 'watcher', 60, time ), 7, 'another watcher\'s lines are not this one\'s' );
is( $besieged->_pressure_of( 'auth', 'galla',   60, time ), 8, 'but are the galla\'s' );
is( $besieged->_pressure_of( 'nowhere', 'watcher', 60, time ), 0, 'a watcher nothing was metered on reads nothing' );

my $span = time - ( time % 10 );
$besieged->{pressure_meter} = { 'auth' => { $span - 60 => 5, $span - 70 => 7, $span => 2 } };
is( $besieged->_pressure_of( 'auth', 'watcher', 60, $span + 9 ), 7, 'a span counts while any of it is with in the seconds asked of' );
is( $besieged->_pressure_of( 'auth', 'watcher', 60, $span + 10 ), 2, 'and not once all of it is past them' );
is( $besieged->_pressure_of( 'auth', 'watcher', 10, $span + 9 ), 2,  'a shorter look back reads less' );
$besieged->_sweep;
is_deeply( [ sort( keys( %{ $besieged->{pressure_meter}{auth} } ) ) ], [ $span - 60, $span ], 'the sweep drops the spans no gate reads back as far as' );

#
# travel
#

@sent = ();
my $travel = galla_over( 'travel', '', 'auth' => ['travel'] );
ok( ( grep { /^err: travel-gated rules are configured but no city database is loaded\.\.\. geoip_city_db is unset/ } @logged ),
	'travel-gated rules with no database are said loudly at start' );
feed( $travel, 'auth', event => 'login', ip => '198.51.100.5', user => 'neti' );
ok( !exists( $travel->{marks}{'last-login'} ), 'and with no database no sighting is kept' );

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
my $reader = Local::Reader->new(
	'198.51.100.5' => { 'location' => { 'latitude' => 51.5072, 'longitude' => -0.1276,  'accuracy_radius' => 10 } },
	'203.0.113.9'  => { 'location' => { 'latitude' => 40.7128, 'longitude' => -74.0060, 'accuracy_radius' => 20 } },
	'192.0.2.77'   => { 'location' => { 'latitude' => 48.8566, 'longitude' => 2.3522 } },
	'192.0.2.78'   => { 'location' => { 'latitude' => 48.8566 } },
	'192.0.2.79'   => { 'country'  => { 'iso_code' => 'FR' } },
);
$travel->{geoip_city} = $reader;

is_deeply(
	$travel->_location_of('198.51.100.5'),
	{ 'lat' => 51.5072, 'lon' => -0.1276, 'radius' => 10 },
	'_location_of answers the latitude, longitude, and radius'
);
is( $travel->_location_of('192.0.2.77')->{radius}, 0, 'a place the database gives no radius is good to none' );
is( $travel->_location_of('192.0.2.78'), undef, 'a record with half a place is no place' );
is( $travel->_location_of('192.0.2.79'), undef, 'nor is one with no location' );
is( $travel->_location_of('192.0.2.1'),  undef, 'nor a address the database can not place' );
is( $travel->_location_of('not-an-ip'),  undef, 'nor a value that is not a address, the reader dying on it' );
my $asked_before = $reader->{asked};
$travel->_location_of('198.51.100.5');
is( $reader->{asked}, $asked_before, 'a answer is cached, the reader not asked again' );

feed( $travel, 'auth', event => 'login', ip => '198.51.100.5', user => 'neti' );
is_deeply( \@sent, [], 'a first login holds on nothing' );
like( $travel->{marks}{'last-login'}{neti}{value}, qr/^51\.5072 -0\.1276 10 [0-9]+$/, 'and is kept as the account\'s last sighting' );
feed( $travel, 'auth', event => 'login', ip => '198.51.100.5', user => 'neti' );
is_deeply( \@sent, [], 'the same place again is no distance' );
feed( $travel, 'auth', event => 'login', ip => '203.0.113.9', user => 'namtar' );
is_deeply( \@sent, [], 'another account far off is its own first sighting' );
feed( $travel, 'auth', event => 'login', ip => '203.0.113.9', user => 'neti' );
is_deeply( \@sent, ['203.0.113.9'], 'the account seen across a ocean with in the second banishes the address it was seen at' );

#
# after
#

@sent = ();
my $many = galla_over( 'many', '', 'auth' => ['many'] );
feed( $many, 'auth', event => 'fail', ip => '198.51.100.1', user => 'neti' );
feed( $many, 'auth', event => 'fail', ip => '198.51.100.2', user => 'neti' );
feed( $many, 'auth', event => 'fail', ip => '198.51.100.3', user => 'root' );
is_deeply( \@sent, [], 'two against one account and one against another banish nobody' );
feed( $many, 'auth', event => 'fail', ip => '198.51.100.4', user => 'neti' );
is_deeply( \@sent, ['198.51.100.4'], 'the third against the one account banishes the address that made it' );

#
# banished... the galla brands what it banishes, and a rule reads it
#

@sent = ();
write_rule( 'leak',     'fail', '', "  - banished: { var: ip, now: true }\n  - detection_var: [ ip ]\n" );
write_rule( 'onestrike', 'fail', "max_score: 1\n", "  - ban_var: [ ip ]\n" );
write_rule( 'repeat',   'again', "max_score: 1\n", "  - ban_var: [ ip ]\n  - banished: { times: 2, within: 3600 }\n" );
my $banisher = galla_over( 'banisher', "\n", 'auth' => [ 'leak', 'onestrike', 'repeat' ] );
my $banned   = '198.51.100.77';

feed( $banisher, 'auth', event => 'fail', ip => $banned );
is_deeply( \@sent, [$banned], 'a address is banished' );
ok( exists( $banisher->{marks}{banished}{$banned} ), 'and branded banished' );
ok( $banisher->{marks}{banished}{$banned}{expires} >= time + 86399, 'for a day, the length of the ban being the kur\'s to choose' );
like( $banisher->{marks}{banishments}{$banned}{value}, qr/^[0-9]+$/, 'and with when the ban was made' );
ok( !$banisher->{stats}{per_rule}{'json/leak'}{matched}, 'the line that got it banished was not one from a banished address' );

feed( $banisher, 'auth', event => 'fail', ip => $banned );
is( $banisher->{stats}{per_rule}{'json/leak'}{matched}, 1, 'a line from it after the ban is matched by the rule that asks if it is banished now' );

feed( $banisher, 'auth', event => 'again', ip => $banned );
is_deeply( \@sent, [$banned], 'banished once, it is not yet a address banished twice' );
$banisher->_brand_banished( $banned, 600 );
is( scalar( split( / /, $banisher->{marks}{banishments}{$banned}{value} ) ), 2, 'a second ban is a second time in the brand' );
ok( $banisher->{marks}{banished}{$banned}{expires} <= time + 600, 'and a ban with a length of its own is branded for that long' );
delete( $banisher->{inflight_bans}{ 'ip:' . $banned } );
delete( $banisher->{pending_bans}{$banned} );
feed( $banisher, 'auth', event => 'again', ip => $banned );
is_deeply( \@sent, [ $banned, $banned ], 'banished twice of late, the rule asking that lets it by' );

$banisher->_brand_banished( $banned, 600 ) foreach 1 .. 25;
is( scalar( split( / /, $banisher->{marks}{banishments}{$banned}{value} ) ), 20, 'only the last twenty bans are remembered' );

#
# pressure by what is usual, off the meter
#

my $usual_span = time - ( time % 10 );
$besieged->{pressure_meter} = { 'auth' => { ( map { $usual_span - 60 - ( $_ * 60 ) => 10 } 0 .. 59 ), $usual_span => 51 } };
is( $besieged->_pressure_of( 'auth', 'watcher', 3600, $usual_span - 60 ), 600, 'the meter reads a baseline up to where the seconds begin' );

#
# who set a brand... a galla hearing of one from the fleet, and remembering
#

my $fleet = galla_over( 'fleet', '', 'auth' => ['brand'] );
my $far   = time + 600;
my $seen  = '198.51.100.90';
$fleet->_ingest_mark_event( { 'op' => 'set', 'name' => 'branded', 'key' => $seen, 'expires' => $far, 'origin' => 'mail01' }, time );
is_deeply( $fleet->{marks}{branded}{$seen}{hosts}, { 'mail01' => 1 }, 'a brand heard of from the fleet says which host set it' );
ok( !$fleet->{marks}{branded}{$seen}{here}, 'and not that this one did' );
$fleet->_ingest_mark_event( { 'op' => 'set', 'name' => 'branded', 'key' => $seen, 'expires' => $far, 'origin' => 'web01' },  time );
$fleet->_ingest_mark_event( { 'op' => 'set', 'name' => 'branded', 'key' => $seen, 'expires' => $far, 'origin' => 'mail01' }, time );
is_deeply( $fleet->{marks}{branded}{$seen}{hosts}, { 'mail01' => 1, 'web01' => 1 }, 'a second host is one more, and a host heard of twice is still one' );

feed( $fleet, 'auth', event => 'brand', ip => $seen );
ok( $fleet->{marks}{branded}{$seen}{here}, 'the brand set here as well is set here' );
is_deeply( $fleet->{marks}{branded}{$seen}{hosts}, { 'mail01' => 1, 'web01' => 1 }, 'and keeps the hosts it was heard of from' );
is( App::Baphomet::Marks::mark_hosts( $fleet->{marks}{branded}{$seen} ), 3, 'which is three hosts' );
$fleet->_ingest_mark_event( { 'op' => 'set', 'name' => 'branded', 'key' => $seen, 'expires' => $far + 60, 'origin' => 'db01' }, time );
ok( $fleet->{marks}{branded}{$seen}{here}, 'a later delta from the fleet does not forget that it was set here' );
is( $fleet->_cmd_marked->{marks}{branded}{$seen}{hosts}, 4, 'the marked command says how many hosts set a brand' );

$fleet->checkpoint;
my $fleet_reborn = galla_over( 'fleet', '', 'auth' => ['brand'] );
is_deeply(
	[ $fleet_reborn->{marks}{branded}{$seen}{here}, [ sort( keys( %{ $fleet_reborn->{marks}{branded}{$seen}{hosts} } ) ) ] ],
	[ 1, [ 'db01', 'mail01', 'web01' ] ],
	'who set a brand rides the tablet across a restart'
);

$fleet->_ingest_mark_event( { 'op' => 'unset', 'name' => 'branded', 'key' => $seen, 'origin' => 'mail01' }, time );
ok( !exists( $fleet->{marks}{branded} ), 'a brand lifted anywhere is lifted, hosts and all' );

#
# the config
#

open( my $config_fh, '>', $dir . '/load.toml' ) || die($!);
print $config_fh "geoip_city_db = \"\"\n";
close($config_fh);
ok( !eval { load_config( $dir . '/load.toml' ); 1 }, 'a empty geoip_city_db is refused' );
like( $@, qr/^geoip_city_db is not a path/, 'and says so' );

done_testing();
