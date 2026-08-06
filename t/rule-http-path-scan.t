#!perl
# http/path-scan over a galla. Its embedded tests prove the status gate and the
# parsed path; the counting is the galla's, and the rule's claim is that one dead
# link hammered is nothing while many different guesses are a scanner... which is
# also why it needs no ignore list for favicon.ico and friends.
use 5.006; use strict; use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );
BEGIN { eval { require Ereshkigal::Client; }; plan skip_all => 'no Ereshkigal::Client' if $@; }
use App::Baphomet::Galla ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/http', $dir . '/run', $dir . '/cache' );
system( 'cp', 'share/rules/http/path-scan.yaml', $dir . '/rules/http/path-scan.yaml' ) == 0
	or die('could not stage the rule under test');

open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
ignore_ips = [ "127.0.0.0/8" ]
allow_per_rule_thresholds = true
max_score = 99

[kur.d]

[kur.d.w]
log = "$dir/log"
parser = "http_access"
rule = [ "http/path-scan" ]
EOC
close($cfg);

my @sent;
{ no warnings 'redefine'; *App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; }; }
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'd' );

sub hit {
	my ( $path, $client, $status ) = @_;
	$status = 404 if !defined($status);
	$galla->_handle_line( 'w',
		"$client - - [12/Jul/2026:08:15:50 -0500] \"GET $path HTTP/1.1\" $status 196 \"-\" \"curl/8\"",
		$dir . '/log' );
}

# one dead link hammered... a broken page, not a scanner
@sent = ();
hit( '/favicon.ico', '10.0.0.1' ) for 1 .. 60;
is_deeply( \@sent, [], 'one missing path fetched sixty times does not ban' );
is( scalar( keys %{ $galla->{distinct_counters}{'http/path-scan'}{'10.0.0.1'} } ),
	1, 'and the set holds one path, however many fetches' );

# a browser's usual handful of missing assets stays far below, with no ignore
# list needed... which is the point of counting paths rather than hits
@sent = ();
hit( $_, '10.0.0.4' ) for qw( /favicon.ico /robots.txt /apple-touch-icon.png );
is_deeply( \@sent, [], 'three missing assets is not a scanner' );

# thirty DIFFERENT missing paths... a list being worked
@sent = ();
hit( "/probe$_.php", '10.0.0.2' ) for 1 .. 29;
is_deeply( \@sent, [], 'twenty nine distinct paths has not crossed' );
hit( '/probe30.php', '10.0.0.2' );
is_deeply( \@sent, ['10.0.0.2'], 'the thirtieth distinct path bans the client' );

# a 200 is no part of it, however many distinct paths
@sent = ();
hit( "/real$_.html", '10.0.0.3', 200 ) for 1 .. 40;
is_deeply( \@sent, [], 'forty distinct paths that EXIST do not ban' );

done_testing();
