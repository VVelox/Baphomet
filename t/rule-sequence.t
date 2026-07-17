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

# the sequence gate... ordered temporal correlation. two mark_only rules brand
# stages, a third bans only when both marks are set for the key in the listed
# order by set time

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $dir . '/rules/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

# stage brands, keyed by the join key, branding only
write_rule( 'json/s1', "---\ngate:\n  - { field: event, op: eq, value: a }\nmark:\n  - { name: stage1, ttl: 600, var: key }\nmark_only: true\nban_var: [ key ]\n" );
write_rule( 'json/s2', "---\ngate:\n  - { field: event, op: eq, value: b }\nmark:\n  - { name: stage2, ttl: 600, var: key }\nmark_only: true\nban_var: [ key ]\n" );
# the correlation... stage1 then stage2 for the key, then ban the source
write_rule( 'json/seq',
	"---\ngate:\n  - { field: event, op: eq, value: go }\nsequence:\n  - { marks: [ stage1, stage2 ], var: key }\nban_var: [ src ]\n" );

open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
ignore_ips = [ "127.0.0.0/8" ]
max_score = 1

[kur.t]

[kur.t.w]
log = "$dir/log"
parser = "json"
rule = [ "json/s1", "json/s2", "json/seq" ]
EOC
close($cfg);

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}

my $json = JSON::MaybeXS->new( 'canonical' => 1 );

sub feed {
	my (%fields) = @_;
	$Galla::galla->_handle_line( 'w', $json->encode( \%fields ), $dir . '/log' );
	return;
}

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 't' );
$Galla::galla = $galla;

# in order: stage1 fired before stage2
feed( event => 'a', key => 'K1' );
feed( event => 'b', key => 'K1' );
ok( defined( $galla->{marks}{stage1}{K1} ), 'stage1 branded for K1' );
ok( defined( $galla->{marks}{stage2}{K1} ), 'stage2 branded for K1' );
$galla->{marks}{stage1}{K1}{set} = 100;
$galla->{marks}{stage2}{K1}{set} = 200;
@sent = ();
feed( event => 'go', key => 'K1', src => '1.1.1.1' );
is_deeply( \@sent, ['1.1.1.1'], 'the sequence in order banishes the source' );

# out of order: stage2 fired before stage1
feed( event => 'a', key => 'K2' );
feed( event => 'b', key => 'K2' );
$galla->{marks}{stage1}{K2}{set} = 200;
$galla->{marks}{stage2}{K2}{set} = 100;
@sent = ();
feed( event => 'go', key => 'K2', src => '2.2.2.2' );
is_deeply( \@sent, [], 'the sequence out of order does not banish' );

# a missing stage
feed( event => 'a', key => 'K3' );
@sent = ();
feed( event => 'go', key => 'K3', src => '3.3.3.3' );
is_deeply( \@sent, [], 'the sequence with a missing stage does not banish' );

# equal set times, the same instant, count as in order
feed( event => 'a', key => 'K4' );
feed( event => 'b', key => 'K4' );
$galla->{marks}{stage1}{K4}{set} = 500;
$galla->{marks}{stage2}{K4}{set} = 500;
@sent = ();
feed( event => 'go', key => 'K4', src => '4.4.4.4' );
is_deeply( \@sent, ['4.4.4.4'], 'equal set times count as in order' );

# an expired stage mark breaks the sequence
feed( event => 'a', key => 'K5' );
feed( event => 'b', key => 'K5' );
$galla->{marks}{stage1}{K5}{expires} = time - 1;
@sent = ();
feed( event => 'go', key => 'K5', src => '5.5.5.5' );
is_deeply( \@sent, [], 'an expired stage breaks the sequence' );

# the set time survives a checkpoint and restore, so ordering holds after
$galla->{marks}{stage1}{K1}{set} = 100;
$galla->{marks}{stage2}{K1}{set} = 200;
$galla->checkpoint;
my $reborn = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 't' );
is( $reborn->{marks}{stage1}{K1}{set}, 100, 'the mark set time rides the tablet across a restart' );

done_testing;
