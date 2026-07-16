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

use JSON::MaybeXS ();
use App::Baphomet::Galla ();

# distinct-cardinality counting... N distinct values of a field from one IP
# within the window bans the IP, the credential-stuffing shape

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

open( my $r, '>', $dir . '/rules/json/stuff.yaml' ) || die($!);
print $r <<'EOR';
---
gate:
  - field: event
    op: eq
    value: login_fail
distinct:
  of: user
ban_var:
  - src
EOR
close($r);

open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
ignore_ips = [ "127.0.0.0/8" ]
max_score = 3

[kur.d]

[kur.d.w]
log = "$dir/log"
parser = "json"
rule = [ "json/stuff" ]
EOC
close($cfg);

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}

my $json = JSON::MaybeXS->new( 'canonical' => 1 );

sub feed {
	my ( $galla, %fields ) = @_;
	$galla->_handle_line( 'w', $json->encode( \%fields ), $dir . '/log' );
	return;
}

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'd' );

# three distinct users from one IP crosses max_score=3 and bans it
@sent = ();
feed( $galla, event => 'login_fail', user => 'alice', src => '1.1.1.1' );
is_deeply( \@sent, [], 'first distinct user does not ban' );
is( scalar( keys( %{ $galla->{distinct_counters}{'json/stuff'}{'1.1.1.1'} } ) ), 1, 'one distinct value counted' );

feed( $galla, event => 'login_fail', user => 'alice', src => '1.1.1.1' );
is( scalar( keys( %{ $galla->{distinct_counters}{'json/stuff'}{'1.1.1.1'} } ) ), 1, 'the same user again is not a new distinct value' );
is_deeply( \@sent, [], 'a repeat of the same user does not ban' );

feed( $galla, event => 'login_fail', user => 'bob', src => '1.1.1.1' );
is_deeply( \@sent, [], 'second distinct user does not ban' );

@sent = ();
feed( $galla, event => 'login_fail', user => 'carol', src => '1.1.1.1' );
is_deeply( \@sent, ['1.1.1.1'], 'the third distinct user bans the IP' );

# a different IP counts on its own
@sent = ();
feed( $galla, event => 'login_fail', user => 'dave', src => '2.2.2.2' );
feed( $galla, event => 'login_fail', user => 'erin', src => '2.2.2.2' );
is_deeply( \@sent, [], 'a second IP with two distinct users has not crossed yet' );

# a line the gate rejects does not count toward distinct
@sent = ();
feed( $galla, event => 'login_ok', user => 'zzz', src => '2.2.2.2' );
is_deeply( \@sent, [], 'a gate-rejected line adds no distinct value' );
is( scalar( keys( %{ $galla->{distinct_counters}{'json/stuff'}{'2.2.2.2'} } ) ), 2, 'still just two distinct users for the second IP' );

# distinct sets survive a checkpoint and restore
$galla->checkpoint;
my $reborn = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'd' );
is( scalar( keys( %{ $reborn->{distinct_counters}{'json/stuff'}{'2.2.2.2'} } ) ), 2, 'the distinct set rides the tablet across a restart' );

done_testing;
