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

# value_count... distinct with a by grouping key decoupled from the ban. count
# distinct sources per account (distributed spray), banishing the source that
# tips an account over, not the account, and keeping on catching further sources

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

open( my $r, '>', $dir . '/rules/json/vc.yaml' ) || die($!);
print $r <<'EOR';
---
gate:
  - field: event
    op: eq
    value: login_fail
distinct:
  of: src
  by: user
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
max_score = 2

[kur.vc]

[kur.vc.w]
log = "$dir/log"
parser = "json"
rule = [ "json/vc" ]
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

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'vc' );

# two distinct sources against one account crosses, banishing the second source
@sent = ();
feed( $galla, event => 'login_fail', user => 'bob', src => '1.1.1.1' );
is_deeply( \@sent, [], 'the first source against an account does not ban' );
is( scalar( keys( %{ $galla->{distinct_counters}{'json/vc'}{'bob'} } ) ), 1, 'the set is keyed by the account, not the source' );

@sent = ();
feed( $galla, event => 'login_fail', user => 'bob', src => '2.2.2.2' );
is_deeply( \@sent, ['2.2.2.2'], 'the second distinct source banishes that source, not the account' );

# the set is NOT reset, so a third source keeps being caught
@sent = ();
feed( $galla, event => 'login_fail', user => 'bob', src => '3.3.3.3' );
is_deeply( \@sent, ['3.3.3.3'], 'a further source against the sprayed account is caught too' );
is( scalar( keys( %{ $galla->{distinct_counters}{'json/vc'}{'bob'} } ) ), 3, 'and the account set kept growing, not reset' );

# the same source retried does not add a new distinct value
@sent = ();
feed( $galla, event => 'login_fail', user => 'bob', src => '2.2.2.2' );
is( scalar( keys( %{ $galla->{distinct_counters}{'json/vc'}{'bob'} } ) ), 3, 'a repeat source is not a new distinct value' );

# a different account counts on its own and has not crossed
@sent = ();
feed( $galla, event => 'login_fail', user => 'alice', src => '9.9.9.9' );
is_deeply( \@sent, [], 'a second account with one source has not crossed' );
ok( !defined( $galla->{distinct_counters}{'json/vc'}{'2.2.2.2'} ), 'nothing is keyed by a source address' );

# survives a checkpoint and restore, keyed by the account
$galla->checkpoint;
my $reborn = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'vc' );
is( scalar( keys( %{ $reborn->{distinct_counters}{'json/vc'}{'bob'} } ) ), 3, 'the by-keyed set rides the tablet across a restart' );

done_testing;
