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

use App::Baphomet::Galla  ();
use App::Baphomet::Config qw( check_kur_def );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/raw' );
make_path( $dir . '/run' );

# the offender may be a hostname... the HOST token takes either
open( my $fh, '>', $dir . '/rules/raw/hostile.yaml' ) || die($!);
print $fh <<'EOR';
---
message_regexp:
  - '^bad thing from %%%%HOST%%%%$'
ban_var:
  - HOST
tests:
  positive:
    - message: "bad thing from evil.example.com"
      found: 1
      data:
        HOST: "evil.example.com"
    - message: "bad thing from 192.0.2.5"
      found: 1
      data:
        HOST: "192.0.2.5"
EOR
close($fh);

open( $fh, '>', $dir . '/log' ) || die($!);
print $fh '';
close($fh);

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
max_score = 10
find_time = 600
enable_dns = true
ignore_ips = [ "127.0.0.0/8" ]

[kur.app]
ban_time = 300

[kur.app.seen]
log = "$dir/log"
parser = "raw"
rule = "raw/hostile"
usedns = "resolve_seen"

[kur.app.banw]
log = "$dir/log"
parser = "raw"
rule = "raw/hostile"
usedns = "resolve_ban"
max_score = 2

[kur.app.now]
log = "$dir/log"
parser = "raw"
rule = "raw/hostile"
EOC
close($fh);

my $galla = App::Baphomet::Galla->new( 'config' => $dir . '/config.toml', 'name' => 'app' );
ok( defined($galla),   'new worked' );
ok( !$galla->{perror}, 'no perror' ) || diag( $galla->{errorString} );

# the mock resolver, injected through the dns_resolve seam so nothing here
# touches real DNS, whatever the environment has installed... the watcher
# modes are restored too, in case a missing Net::DNS downgraded them
my %resolve_calls;
$galla->{dns_resolve} = sub {
	my ($hostname) = @_;
	$resolve_calls{$hostname}++;
	my %names = (
		'one.example.com'   => ['192.0.2.70'],
		'mixed.example.com' => [ '127.0.0.5',  '192.0.2.71' ],
		'wide.example.com'  => [ '192.0.2.80', '192.0.2.81', '192.0.2.82', '192.0.2.83', '192.0.2.84' ],
		'ban.example.com'   => [ '192.0.2.72', '192.0.2.73' ],
	);
	return $names{$hostname};
}; ## end sub
$galla->{watchers}{seen}{settings}{usedns} = 'resolve_seen';
$galla->{watchers}{banw}{settings}{usedns} = 'resolve_ban';

is( $galla->{watchers}{now}{settings}{usedns}, 'no', 'usedns defaults to no' );

#
# resolve_seen... the hostname becomes its addresses at match time
#

$galla->_handle_line( 'seen', 'bad thing from one.example.com' );
is( scalar( @{ $galla->{counters}{'192.0.2.70'} } ), 1, 'the hostname counted under its resolved address' );
ok( !defined( $galla->{counters}{'one.example.com'} ), 'and not under its name' );

# a direct hit from the same address lands in the same bucket
$galla->_handle_line( 'seen', 'bad thing from 192.0.2.70' );
is( scalar( @{ $galla->{counters}{'192.0.2.70'} } ), 2, 'a direct IP hit merged into the same bucket' );

# the cache answers the second sighting
$galla->_handle_line( 'seen', 'bad thing from one.example.com' );
is( $resolve_calls{'one.example.com'},               1, 'the resolver was asked once, the cache answered after' );
is( scalar( @{ $galla->{counters}{'192.0.2.70'} } ), 3, 'and the cached answer still counted' );

# resolved addresses that are ignored are dropped absolutely
$galla->_handle_line( 'seen', 'bad thing from mixed.example.com' );
ok( !defined( $galla->{counters}{'127.0.0.5'} ), 'a resolved ignored address never counts' );
is( scalar( @{ $galla->{counters}{'192.0.2.71'} } ), 1, 'while its sibling does' );

# a name resolving past the cap is refused whole
$galla->_handle_line( 'seen', 'bad thing from wide.example.com' );
foreach my $addr ( '192.0.2.80', '192.0.2.81', '192.0.2.82', '192.0.2.83', '192.0.2.84' ) {
	if ( defined( $galla->{counters}{$addr} ) ) {
		fail('a wide resolution was refused whole');
	}
}
pass('a wide resolution was refused whole');

# a name that does not resolve counts nothing
$galla->_handle_line( 'seen', 'bad thing from fail.example.com' );
ok( !defined( $galla->{counters}{'fail.example.com'} ), 'an unresolvable name counted nothing' );

#
# resolve_ban... counted by name, resolved only at the threshold
#

$galla->_handle_line( 'banw', 'bad thing from ban.example.com' );
is( scalar( @{ $galla->{counters}{'ban.example.com'} } ), 1, 'the hostname counted under its own name' );
ok( !defined( $resolve_calls{'ban.example.com'} ), 'with no resolution at match time' );

$galla->_handle_line( 'banw', 'bad thing from ban.example.com' );
is( $resolve_calls{'ban.example.com'}, 1, 'the threshold crossing resolved it' );
ok( defined( $galla->{pending_bans}{'192.0.2.72'} ) && defined( $galla->{pending_bans}{'192.0.2.73'} ),
	'both resolved addresses went to the ban path' );
ok( !defined( $galla->{pending_bans}{'ban.example.com'} ), 'the name itself was never queued' );
ok( !defined( $galla->{counters}{'ban.example.com'} ),     'and its counter cleared' );

#
# no... a hostname names nobody banishable
#

$galla->_handle_line( 'now', 'bad thing from one.example.com' );
is( scalar( @{ $galla->{counters}{'192.0.2.70'} } ), 3, 'under no the hostname resolved nothing new' );
is( $galla->{stats}{hostname_dropped},               1, 'and the drop was ticked' );

# a direct IP is untouched by the mode
$galla->_handle_line( 'now', 'bad thing from 192.0.2.90' );
is( scalar( @{ $galla->{counters}{'192.0.2.90'} } ), 1, 'a direct IP offender still counts under no' );

#
# with out enable_dns a resolve mode is treated as no, loudly
#

open( $fh, '>', $dir . '/config2.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache2"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"

[kur.quiet]
[kur.quiet.w]
log = "$dir/log"
parser = "raw"
rule = "raw/hostile"
usedns = "resolve_seen"
EOC
close($fh);

my $quiet = App::Baphomet::Galla->new( 'config' => $dir . '/config2.toml', 'name' => 'quiet' );
ok( defined($quiet), 'new worked with out enable_dns' );
is( $quiet->{watchers}{w}{settings}{usedns}, 'no', 'a resolve mode with out enable_dns is treated as no' );

#
# config validation
#

ok(
	!eval {
		check_kur_def( 'app',
			{ 'w' => { 'log' => $dir . '/log', 'parser' => 'raw', 'rule' => 'raw/hostile', 'usedns' => 'derp' } } );
		1;
	},
	'a unknown usedns mode refuses'
);
ok(
	!eval {
		check_kur_def( 'app',
			{ 'w' => { 'log' => $dir . '/log', 'parser' => 'raw', 'rule' => 'raw/hostile', 'usedns' => 'raw' } } );
		1;
	},
	'the raw mode of fail2ban does not exist here'
);

done_testing;
