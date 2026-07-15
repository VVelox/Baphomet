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
use App::Baphomet::Rules::JSON ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

#
# the weight accessor and its validation
#

my $base_def = {
	gate    => [ { field => 'which', values => ['x'] } ],
	ban_var => ['src_ip'],
};

my $rule = App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base_def} } );
is( $rule->weight, 1, 'weight defaults to 1' );

$rule = App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base_def}, weight => 10 } );
is( $rule->weight, 10, 'an integer weight is carried' );

$rule = App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base_def}, weight => '2.5' } );
is( $rule->weight, 2.5, 'a fractional weight is carried' );

foreach my $bad ( 0, -1, 'heavy' ) {
	my $err;
	eval { App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base_def}, weight => $bad } ); };
	$err = $@;
	like( $err, qr/positive number/, 'a weight of "' . $bad . '" refuses to load' );
}

#
# galla behavior... weights against the shared bucket
#

my %rules = (
	heavy => "weight: 10\n",
	light => '',            # default weight 1
	mid   => "weight: 3\n",
	mid_b => "weight: 3\n",
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
max_score = 5
allow_per_rule_thresholds = $allow

[kur.ids.eve]
log = "$dir/eve.json"
parser = "json"
rule = [ "json/heavy", "json/light", "json/mid", "json/mid_b" ]
EOC
	close($cfg);
	return;
} ## end sub write_config

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}

sub feed {
	my ( $galla, $which, $ip ) = @_;
	$galla->_handle_line( 'eve', '{"which":"' . $which . '","src_ip":"' . $ip . '"}', $dir . '/eve.json' );
	return;
}

#
# flag off... every weight is treated as 1, so the numbers are inert
#

write_config('false');
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );

@sent = ();
feed( $galla, 'heavy', '203.0.113.1' );
is_deeply( \@sent, [], 'flag off, a weight-10 rule does not ban on the first hit' );
is( $galla->_cmd_accused->{accused}{'203.0.113.1'}{score}, 1, 'flag off, the hit scores 1 not 10' );

#
# flag on... weights speak
#

write_config('true');
$galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );

# a heavy hit crosses the max_score of 5 on its own
@sent = ();
feed( $galla, 'heavy', '203.0.113.2' );
is_deeply( \@sent, ['203.0.113.2'], 'flag on, a weight-10 rule bans on one hit' );
ok( !defined( $galla->{counters}{'203.0.113.2'} ), 'the bucket is cleared on the ban' );

# a light rule still needs the full count, each hit worth 1
@sent = ();
foreach ( 1 .. 4 ) {
	feed( $galla, 'light', '203.0.113.3' );
}
is_deeply( \@sent, [], 'four weight-1 hits stay under max_score 5' );
is( $galla->_cmd_accused->{accused}{'203.0.113.3'}{score}, 4, 'their score is 4' );
feed( $galla, 'light', '203.0.113.3' );
is_deeply( \@sent, ['203.0.113.3'], 'the fifth weight-1 hit bans' );

# two different rules against one IP sum into the shared bucket
@sent = ();
feed( $galla, 'mid', '203.0.113.4' );
is_deeply( \@sent, [], 'a lone weight-3 hit is under the threshold' );
is( $galla->_cmd_accused->{accused}{'203.0.113.4'}{score}, 3, 'score is 3 after the first rule' );
feed( $galla, 'mid_b', '203.0.113.4' );
is_deeply( \@sent, ['203.0.113.4'], 'a second rule of weight 3 sums to 6 and bans' );

# accused reports both the raw hit count and the weighted score
@sent = ();
feed( $galla, 'mid', '203.0.113.5' );
my $one = $galla->_cmd_accused->{accused}{'203.0.113.5'};
is( $one->{hits},  1, 'accused hit count is the raw tally' );
is( $one->{score}, 3, 'accused score is the weighted sum' );

#
# the weight rides the counters tablet
#

$galla->checkpoint;
my $reborn = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
is( $reborn->_cmd_accused->{accused}{'203.0.113.5'}{score}, 3, 'a restored hit keeps its weight' );

done_testing;
