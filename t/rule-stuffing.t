#!perl
# syslog/sshd-stuffing, the shipped distinct-cardinality rule, over a galla. Its
# own embedded tests prove the four patterns and their captures; what they can
# not reach is the counting, which is the galla's. This is the discrimination the
# rule exists for: five guesses at one account must NOT ban, five different
# accounts from one source must.
use 5.006; use strict; use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );
BEGIN { eval { require Ereshkigal::Client; }; plan skip_all => 'no Ereshkigal::Client' if $@; }
use App::Baphomet::Galla ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run', $dir . '/cache' );
system( 'cp', 'share/rules/syslog/sshd-stuffing.yaml', $dir . '/rules/syslog/sshd-stuffing.yaml' ) == 0
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
parser = "bsd_syslog"
rule = [ "syslog/sshd-stuffing" ]
EOC
close($cfg);

my @sent;
{ no warnings 'redefine'; *App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; }; }
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'd' );

sub fail_line {
	my ( $user, $src ) = @_;
	$galla->_handle_line( 'w',
		"Jul 12 08:15:50 host01 sshd[2278]: Failed password for invalid user $user from $src port 4711 ssh2",
		$dir . '/log' );
}

# five guesses at ONE account... a forgotten password, not a stuffing run
@sent = ();
fail_line( 'root', '10.0.0.1' ) for 1 .. 5;
is_deeply( \@sent, [], 'five tries at one account does not ban' );
is( scalar( keys %{ $galla->{distinct_counters}{'syslog/sshd-stuffing'}{'10.0.0.1'} } ),
	1, 'and the set holds one account, however many tries' );

# five DIFFERENT accounts from one source... a list being worked
@sent = ();
fail_line( $_, '10.0.0.2' ) for qw( alice bob carol dave );
is_deeply( \@sent, [], 'four distinct accounts has not crossed' );
fail_line( 'erin', '10.0.0.2' );
is_deeply( \@sent, ['10.0.0.2'], 'the fifth distinct account bans the source' );

# and each source counts on its own
@sent = ();
fail_line( $_, '10.0.0.3' ) for qw( alice bob );
is_deeply( \@sent, [], 'a second source is scored separately' );

done_testing();
