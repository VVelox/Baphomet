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
use App::Baphomet::Rule ();
use App::Baphomet::Config qw( kur_split resolve_active_time );
use App::Baphomet::Gate qw( bind_rule_gates );

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

# what every rule here has around its active_time gate... the gate that judges
# the record ahead of it, and the ban_var naming the offender behind it
my $match_gate = { gate    => [ { field => 'event', values => ['fail'] } ] };
my $ban_gate   = { ban_var => ['ip'] };
my %bad = (
	'both is and isnot'    => { is => ['business'], isnot => ['off'] },
	'neither is nor isnot' => { vars => ['ts'] },
	'a bad window name'    => { is => ['bad name'] },
	'a unknown key'        => { is => ['business'], nope => 1 },
	'an empty var'         => { is => ['business'], vars => [''] },
);
foreach my $desc ( sort( keys(%bad) ) ) {
	eval {
		App::Baphomet::Rule->new(
			name => 'json/x',
			def  => { rule_gates => [ $match_gate, { active_time => $bad{$desc} }, $ban_gate ] }
		);
	};
	like( $@, qr/^The active_time gate of the rule "json\/x"/, 'a active_time gate with ' . $desc . ' refuses to load' );
}

my $rule = App::Baphomet::Rule->new(
	name => 'json/x',
	def  => { rule_gates => [ $match_gate, { active_time => { is => 'business', vars => 'ts' } }, $ban_gate ] }
);
my ($compiled) = grep { $_->{type} eq 'active_time' } @{ $rule->rule_gates };
is( $compiled->{mode}, 'is', 'the compiled gate has the mode' );
is_deeply( $compiled->{windows}, ['business'], 'a scalar is normalizes to a list' );
is_deeply( $compiled->{vars},    ['ts'],       'a scalar vars normalizes to a list' );

#
# the gate helpers over fixed epochs, no wall clock involved
#

my %WIN = (
	business  => [ { days => [ 1, 2, 3, 4, 5 ], hours => '0900-1700' } ],
	overnight => [ { hours => '2200-0600' } ],
	weekend   => [ { days => [ 0, 6 ] } ],
);

# the active_time gate of a rule told the passed, bound over the windows above
sub bound_gate {
	my ($active) = @_;
	my $gated = App::Baphomet::Rule->new(
		name => 'json/a',
		def  => { rule_gates => [ $match_gate, { active_time => $active }, $ban_gate ] }
	);
	my $bound = bind_rule_gates( $gated->rule_gates, { active_time => \%WIN }, 'w' );
	my ($gate) = grep { $_->{type} eq 'active_time' } @{ $bound->{offense} };
	return $gate;
}

my $is_biz = bound_gate( { is => ['business'] } );
is( $is_biz->holds( {}, undef, $mon_1030 ), 1, 'is business, Mon 10:30, counts' );
is( $is_biz->holds( {}, undef, $mon_0300 ), 0, 'is business, Mon 03:00, does not count (outside hours)' );
is( $is_biz->holds( {}, undef, $sun_1030 ), 0, 'is business, Sun 10:30, does not count (outside days)' );

my $not_biz = bound_gate( { isnot => ['business'] } );
is( $not_biz->holds( {}, undef, $mon_1030 ), 0, 'isnot business, Mon 10:30, does not count' );
is( $not_biz->holds( {}, undef, $mon_0300 ), 1, 'isnot business, Mon 03:00, counts' );

my $is_night = bound_gate( { is => ['overnight'] } );
is( $is_night->holds( {}, undef, $sat_2330 ), 1, 'is overnight, 23:30, counts across the midnight wrap' );
is( $is_night->holds( {}, undef, $mon_1030 ), 0, 'is overnight, 10:30, does not count' );

my $is_union = bound_gate( { is => [ 'business', 'weekend' ] } );
is( $is_union->holds( {}, undef, $sun_1030 ), 1, 'is [business, weekend], Sunday, counts via the union' );
is( $is_union->holds( {}, undef, $mon_0300 ), 0, 'is [business, weekend], Mon 03:00, in neither' );

# time is the line's and not a offender's, so the gate is of the result pass
# though it names no var, and is never asked of a offender
is( $is_biz->pass, 'result', 'a gate naming no vars is still of the result pass' );

#
# vars... the time comes from a found value, epoch or ISO, else fails closed
#

my $var_biz = bound_gate( { is => ['business'], vars => ['ts'] } );
is( $var_biz->holds( { ts => $mon_1030 },              undef, 0 ), 1, 'a epoch var inside the window counts' );
is( $var_biz->holds( { ts => $mon_1030 * 1_000_000 }, undef, 0 ), 1, 'a journal microsecond epoch is scaled and counts' );
is( $var_biz->holds( { ts => '2021-01-04T10:30:00Z' }, undef, 0 ), 1, 'a ISO 8601 var inside the window counts' );
is( $var_biz->holds( { ts => '2021-01-04 03:00:00' },  undef, 0 ), 0, 'a ISO var outside the hours does not count' );
is( $var_biz->holds( { ts => 'not-a-time' },           undef, 0 ), 0, 'a unparseable var fails closed' );
is( $var_biz->holds( {},                               undef, 0 ), 0, 'a missing var fails closed' );

#
# a reference to a window the watcher does not define is fatal at bind
#

eval { bound_gate( { is => ['nope'] } ); };
like( $@, qr/nope.*not a defined window/, 'referencing a undefined window dies' );

#
# end to end through _handle_line, the vars path so it stays deterministic
#

open( my $rf, '>', $dir . '/rules/json/timed.yaml' ) || die($!);
print $rf <<'EOR';
---
max_score: 1
rule_gates:
  - gate:
      - field: event
        values: [ fail ]
  - active_time: { is: [ business ], vars: [ ts ] }
  - ban_var:
      - ip
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
max_score = 1
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
