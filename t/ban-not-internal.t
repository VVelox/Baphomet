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

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

# a Suricata-shaped rule... both endpoints candidates, ban the external one
open( my $fh, '>', $dir . '/rules/json/suri.yaml' ) || die($!);
print $fh <<'EOR';
---
gate:
  - field: event_type
    values: [ alert ]
ban_var:
  - src_ip
  - dest_ip
ban_not_internal: true
EOR
close($fh);

# a plain rule with the same two ban_vars but no ban_not_internal
open( $fh, '>', $dir . '/rules/json/both.yaml' ) || die($!);
print $fh <<'EOR';
---
gate:
  - field: event_type
    values: [ alert ]
ban_var:
  - src_ip
  - dest_ip
EOR
close($fh);

sub write_config {
	my ($extra) = @_;
	open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
	print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
ignore_ips = [ "127.0.0.0/8" ]
$extra

[kur.ids]
max_retrys = 1

[kur.ids.eve]
log = "$dir/eve.json"
parser = "json"
rule = "json/suri"

[kur.ids.eveboth]
log = "$dir/eve2.json"
parser = "json"
rule = "json/both"
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
	my ( $galla, $watcher, $src, $dest ) = @_;
	$galla->_handle_line( $watcher,
		'{"event_type":"alert","src_ip":"' . $src . '","dest_ip":"' . $dest . '","alert":{"category":"x"}}',
		$dir . '/eve.json' );
	return;
} ## end sub feed

#
# internal defaults to ignore_ips
#

write_config('');
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
ok( defined( $galla->{internal} ), 'internal compiled' );

# external src, internal (loopback, via ignore default) dest... ban the src
@sent = ();
feed( $galla, 'eve', '203.0.113.9', '127.0.0.1' );
is_deeply( \@sent, ['203.0.113.9'], 'external src banned, internal dest skipped (internal defaults to ignore)' );

#
# explicit internal network
#

write_config('internal = [ "10.0.0.0/8", "192.168.0.0/16" ]');
$galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );

# attacker is src (external), victim is dest (internal 10.x)... ban src
@sent = ();
feed( $galla, 'eve', '198.51.100.7', '10.1.2.3' );
is_deeply( \@sent, ['198.51.100.7'], 'external src banned when dest is internal' );

# the flow the other way... internal src reaching out to external dest (C2)
# ... ban the external dest
@sent = ();
feed( $galla, 'eve', '10.1.2.3', '198.51.100.8' );
is_deeply( \@sent, ['198.51.100.8'], 'external dest banned when src is internal' );

# both external (transit)... both get banned
@sent = ();
feed( $galla, 'eve', '198.51.100.9', '203.0.113.10' );
is_deeply( [ sort @sent ], [ '198.51.100.9', '203.0.113.10' ], 'both banned when both external' );

# both internal... nobody banned
@sent = ();
feed( $galla, 'eve', '10.1.1.1', '192.168.1.1' );
is_deeply( \@sent, [], 'nothing banned when both internal' );

#
# without ban_not_internal, both ban_vars are banished as before
#

@sent = ();
$galla->_handle_line( 'eveboth',
	'{"event_type":"alert","src_ip":"198.51.100.11","dest_ip":"10.9.9.9","alert":{"category":"x"}}',
	$dir . '/eve2.json' );
is_deeply( [ sort @sent ], [ '10.9.9.9', '198.51.100.11' ],
	'a plain dual ban_var rule still bans both, internal and all' );

done_testing;
