#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use POSIX      ();
use Time::Local qw( timegm );
use File::Temp qw( tempdir );
use File::Path qw( make_path );
use JSON::MaybeXS ();

BEGIN {
	# pin the zone so localtime of a epoch is deterministic
	$ENV{TZ} = 'UTC';
	POSIX::tzset();
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();
use App::Baphomet::Rules::JSON ();
use App::Baphomet::Config qw( kur_split resolve_active_time );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

# fixed reference epochs, UTC... 2021-01-03 is a Sunday (wday 0)
my $mon_1030 = timegm( 0, 30, 10, 4, 0, 2021 );    # Mon 10:30
my $mon_0300 = timegm( 0, 0,  3,  4, 0, 2021 );    # Mon 03:00
my $sun_1030 = timegm( 0, 30, 10, 3, 0, 2021 );    # Sun 10:30
my $sat_2330 = timegm( 0, 30, 23, 2, 0, 2021 );    # Sat 23:30

#
# config layer... resolve, validate, and the kur_split hash-setting
#

my $resolved = resolve_active_time(
	{ active_time => { business => { days => [ 1, 2, 3, 4, 5 ], hours => '0900-1700' }, off => { hours => '0000-0600' } } },
	{ active_time => { off => { hours => '2200-0600' } } },
	{ active_time => { business => { days => [1], hours => '0900-1200' } } }
);
is_deeply( $resolved->{business}, [ { days => [1], hours => '0900-1200' } ], 'watcher overrides a same-named window' );
is_deeply( $resolved->{off},      [ { hours => '2200-0600' } ],             'kur overrides, a scalar normalizes to a array' );

is( App::Baphomet::Config::_active_time_error( { w => { hours => '0900-1700' } }, 'x' ), undef, 'a good window passes' );
like( App::Baphomet::Config::_active_time_error( { w => { days => [7] } }, 'x' ), qr/0\.\.6/, 'a day past 6 fails' );
like( App::Baphomet::Config::_active_time_error( { w => { hours => '9-5' } }, 'x' ), qr/HHMM/, 'a bad hours shape fails' );
like( App::Baphomet::Config::_active_time_error( { w => {} }, 'x' ), qr/neither days nor hours/, 'a empty spec fails' );

my ( $settings, $watchers ) = kur_split( { active_time => { a => { hours => '0900-1700' } }, w => { log => 'x' } } );
ok( defined( $settings->{active_time} ),  'kur_split keeps active_time a setting' );
ok( !defined( $watchers->{active_time} ), '...and not a watcher' );

#
# rule def validation of the active_time gate
#

my $base = {
	gate    => [ { field => 'event', values => ['fail'] } ],
	ban_var => ['ip'],
};
my %bad = (
	'both is and isnot'    => { is => ['business'], isnot => ['off'] },
	'neither is nor isnot' => { vars => ['ts'] },
	'a bad window name'    => { is => ['bad name'] },
	'a unknown key'        => { is => ['business'], nope => 1 },
	'an empty var'         => { is => ['business'], vars => [''] },
);
foreach my $desc ( sort( keys(%bad) ) ) {
	eval { App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base}, active_time => $bad{$desc} } ); };
	ok( $@, 'a active_time gate with ' . $desc . ' refuses to load' );
}

my $rule = App::Baphomet::Rules::JSON->new(
	name => 'json/x',
	def  => { %{$base}, active_time => { is => 'business', vars => 'ts' } }
);
is( $rule->active_time->{mode}, 'is', 'the accessor reports the mode' );
is_deeply( $rule->active_time->{windows}, ['business'], 'a scalar is normalizes to a list' );
is_deeply( $rule->active_time->{vars},    ['ts'],       'a scalar vars normalizes to a list' );

#
# the gate helpers over fixed epochs, no wall clock involved
#

my %WIN = (
	business  => [ { days => [ 1, 2, 3, 4, 5 ], hours => '0900-1700' } ],
	overnight => [ { hours => '2200-0600' } ],
	weekend   => [ { days => [ 0, 6 ] } ],
);

sub arule {
	my ($active) = @_;
	return App::Baphomet::Rules::JSON->new(
		name => 'json/a',
		def  => { %{$base}, active_time => $active }
	);
}

my $g = bless( {}, 'App::Baphomet::Galla' );

my $is_biz = $g->_resolve_active_time_gate( arule( { is => ['business'] } ), \%WIN, 'w' );
is( $g->_active_time_pass( $is_biz, {}, $mon_1030 ), 1, 'is business, Mon 10:30, counts' );
is( $g->_active_time_pass( $is_biz, {}, $mon_0300 ), 0, 'is business, Mon 03:00, does not count (outside hours)' );
is( $g->_active_time_pass( $is_biz, {}, $sun_1030 ), 0, 'is business, Sun 10:30, does not count (outside days)' );

my $not_biz = $g->_resolve_active_time_gate( arule( { isnot => ['business'] } ), \%WIN, 'w' );
is( $g->_active_time_pass( $not_biz, {}, $mon_1030 ), 0, 'isnot business, Mon 10:30, does not count' );
is( $g->_active_time_pass( $not_biz, {}, $mon_0300 ), 1, 'isnot business, Mon 03:00, counts' );

my $is_night = $g->_resolve_active_time_gate( arule( { is => ['overnight'] } ), \%WIN, 'w' );
is( $g->_active_time_pass( $is_night, {}, $sat_2330 ), 1, 'is overnight, 23:30, counts across the midnight wrap' );
is( $g->_active_time_pass( $is_night, {}, $mon_1030 ), 0, 'is overnight, 10:30, does not count' );

my $is_union = $g->_resolve_active_time_gate( arule( { is => [ 'business', 'weekend' ] } ), \%WIN, 'w' );
is( $g->_active_time_pass( $is_union, {}, $sun_1030 ), 1, 'is [business, weekend], Sunday, counts via the union' );
is( $g->_active_time_pass( $is_union, {}, $mon_0300 ), 0, 'is [business, weekend], Mon 03:00, in neither' );

#
# vars... the time comes from a found value, epoch or ISO, else fails closed
#

my $var_biz = $g->_resolve_active_time_gate( arule( { is => ['business'], vars => ['ts'] } ), \%WIN, 'w' );
is( $g->_active_time_pass( $var_biz, { ts => $mon_1030 },              0 ), 1, 'a epoch var inside the window counts' );
is( $g->_active_time_pass( $var_biz, { ts => $mon_1030 * 1_000_000 }, 0 ), 1, 'a journal microsecond epoch is scaled and counts' );
is( $g->_active_time_pass( $var_biz, { ts => '2021-01-04T10:30:00Z' }, 0 ), 1, 'a ISO 8601 var inside the window counts' );
is( $g->_active_time_pass( $var_biz, { ts => '2021-01-04 03:00:00' },  0 ), 0, 'a ISO var outside the hours does not count' );
is( $g->_active_time_pass( $var_biz, { ts => 'not-a-time' },           0 ), 0, 'a unparseable var fails closed' );
is( $g->_active_time_pass( $var_biz, {},                               0 ), 0, 'a missing var fails closed' );

#
# a reference to a window the watcher does not define is fatal at bind
#

eval { $g->_resolve_active_time_gate( arule( { is => ['nope'] } ), \%WIN, 'where' ); };
like( $@, qr/nope.*not a defined window/, 'referencing a undefined window dies' );

#
# end to end through _handle_line, the vars path so it stays deterministic
#

open( my $rf, '>', $dir . '/rules/json/timed.yaml' ) || die($!);
print $rf <<'EOR';
---
gate:
  - field: event
    values: [ fail ]
ban_var:
  - ip
active_time:
  is: [ business ]
  vars: [ ts ]
max_retrys: 1
EOR
close($rf);

open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"

[active_time.business]
days = [ 1, 2, 3, 4, 5 ]
hours = "0900-1700"

[kur.at]
max_retrys = 1
allow_per_rule_thresholds = true

[kur.at.w]
log = "$dir/l"
parser = "json"
rule = [ "json/timed" ]
EOC
close($cfg);

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
	*App::Baphomet::Galla::log_drek  = sub { return; };
}

my $json  = JSON::MaybeXS->new( 'canonical' => 1 );
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'at' );

@sent = ();
$galla->_handle_line( 'w', $json->encode( { event => 'fail', ip => '1.2.3.4', ts => $mon_1030 } ), $dir . '/l' );
is_deeply( \@sent, ['1.2.3.4'], 'an offense whose timestamp is in the window is banished' );

@sent = ();
$galla->_handle_line( 'w', $json->encode( { event => 'fail', ip => '5.6.7.8', ts => $sun_1030 } ), $dir . '/l' );
is_deeply( \@sent, [], 'an offense whose timestamp is out of the window is not' );

done_testing;
