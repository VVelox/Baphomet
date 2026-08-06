#!perl
# syslog/postfix-harvest over a galla. Its embedded tests prove the gate and the
# munger's fields; the counting is the galla's, and the rule's claim is that one
# bad address retried is nothing while many different ones are a harvest.
use 5.006; use strict; use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );
BEGIN { eval { require Ereshkigal::Client; }; plan skip_all => 'no Ereshkigal::Client' if $@; }
use App::Baphomet::Galla ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run', $dir . '/cache' );
system( 'cp', 'share/rules/syslog/postfix-harvest.yaml', $dir . '/rules/syslog/postfix-harvest.yaml' ) == 0
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
rule = [ "syslog/postfix-harvest" ]
EOC
close($cfg);

my @sent;
{ no warnings 'redefine'; *App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; }; }
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'd' );

sub reject {
	my ( $rcpt, $client ) = @_;
	$galla->_handle_line(
		'w',
		"Jul 12 08:15:50 mail01 postfix/smtpd[8738]: NOQUEUE: reject: RCPT from unknown[$client]: "
			. "550 5.1.1 <$rcpt>: Recipient address rejected: User unknown in local recipient table; "
			. "from=<spam\@bad.example> to=<$rcpt> proto=ESMTP helo=<bad.example>",
		$dir . '/log'
	);
}

# one bad address retried... a misconfigured sender, not a harvest
@sent = ();
reject( 'nosuch@example.com', '10.0.0.1' ) for 1 .. 20;
is_deeply( \@sent, [], 'one bad recipient retried twenty times does not ban' );
is( scalar( keys %{ $galla->{distinct_counters}{'syslog/postfix-harvest'}{'10.0.0.1'} } ),
	1, 'and the set holds one recipient, however many attempts' );

# ten DIFFERENT unknown recipients... a name list being worked
@sent = ();
reject( $_ . '@example.com', '10.0.0.2' ) for qw( a b c d e f g h i );
is_deeply( \@sent, [], 'nine distinct recipients has not crossed' );
reject( 'j@example.com', '10.0.0.2' );
is_deeply( \@sent, ['10.0.0.2'], 'the tenth distinct recipient bans the client' );

# and each client counts on its own
@sent = ();
reject( $_ . '@example.com', '10.0.0.3' ) for qw( a b );
is_deeply( \@sent, [], 'a second client is scored separately' );

done_testing();
