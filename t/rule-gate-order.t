#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use App::Baphomet::Parser ();
use App::Baphomet::Rule   ();
use App::Baphomet::Marks  qw( mark_set );
use App::Baphomet::Gate   qw( bind_rule_gates walk_offense settle_offenders );

# a rule runs in the order it is written... the same gates in another order
# are another rule. each pair below is one list written two ways

my $now = 1_000_000_000;

sub json_line {
	my ($line) = @_;
	return App::Baphomet::Parser::parse( 'json', $line );
}

sub syslog_line {
	my ($message) = @_;
	return App::Baphomet::Parser::parse( 'bsd_syslog', 'Jul 12 08:15:50 mail01 ' . $message );
}

# checks one json line against a rule of the passed gates, over a tracked
# store of its own, and returns what was found and the store
sub checked {
	my ( $gates, $store, @lines ) = @_;

	my $rule = App::Baphomet::Rule->new( 'name' => 'json/order', 'def' => { 'rule_gates' => $gates } );
	my $found;
	foreach my $line (@lines) {
		$found = $rule->check( json_line($line), 'scope', { 'now' => $now, 'tracked' => $store } );
	}

	return $found;
} ## end sub checked

my $gate    = { 'gate'    => [ { 'field' => 'event', 'values' => ['fail'] } ] };
my $ban_ip  = { 'ban_var' => ['ip'] };
my $track   = { 'track'   => { 'name' => 'seen', 'key' => 'ip' } };
my $ignore  = { 'ignore'  => [ { 'field' => 'ua', 'regexp' => '^HealthCheck' } ] };
my $ignored = '{"event":"fail","ip":"192.0.2.5","ua":"HealthCheck/1.0"}';
my $offense = '{"event":"fail","ip":"192.0.2.5","ua":"curl/8"}';

#
# a gate that turns the line away stops the gates below it and none above
#

my %store;
ok( !defined( checked( [ $ignore, $track, $gate, $ban_ip ], \%store, $ignored ) ), 'a ignored line is no offense' );
is_deeply( \%store, {}, 'and a track below the ignore harvested nothing of it' );

%store = ();
ok(
	!defined( checked( [ $track, $ignore, $gate, $ban_ip ], \%store, $ignored ) ),
	'the same line is no offense with the track written above the ignore'
);
ok( defined( $store{seen} ) && scalar( keys( %{ $store{seen} } ) ) == 1,
	'but the track was asked first, and harvested it' );

#
# a track above the not_tracked that reads its record is read by it
#

my $not_tracked = { 'not_tracked' => { 'name' => 'seen' } };

%store = ();
ok( defined( checked( [ $not_tracked, $track, $gate, $ban_ip ], \%store, $offense ) ),
	'a first line is a offense with not_tracked above its track' );
ok( !defined( checked( [ $not_tracked, $track, $gate, $ban_ip ], \%store, $offense ) ),
	'and the second is not, the first having been harvested' );

%store = ();
ok(
	!defined( checked( [ $track, $not_tracked, $gate, $ban_ip ], \%store, $offense ) ),
	'with the track above it, not_tracked reads the record the line itself just wrote'
);

#
# a gate that judges reads what stands when it is asked
#

my $match      = { 'match' => [ { 'field' => 'ua',    'regexp' => '^(?<AGENT>[a-z]+)/' } ] };
my $agent_gate = { 'gate'  => [ { 'field' => 'AGENT', 'values' => ['curl'] } ] };

ok(
	defined( checked( [ $match, $agent_gate, $ban_ip ], {}, $offense ) ),
	'a gate below the matcher judges the matcher\'s captures'
);
ok(
	!defined( checked( [ $agent_gate, $match, $ban_ip ], {}, $offense ) ),
	'above it there are no captures yet, so the line\'s fields are judged and refused'
);

#
# the gates that only turn a line away, leading the list
#

my $daemons = { 'daemons'        => ['sshd'] };
my $regexp  = { 'message_regexp' => ['^bad thing from %%%%SRC%%%%'] };
my $ban_src = { 'ban_var'        => ['SRC'] };
my $skip    = { 'ignore_regexp'  => ['from 192\.0\.2\.9$'] };
my $capture = { 'capture_regexp' => [ { 'regexp' => '^session (?<SESSION>\d+) opened', 'key' => 'SESSION' } ] };

sub syslog_rule {
	my (@gates) = @_;
	return App::Baphomet::Rule->new( 'name' => 'syslog/order', 'def' => { 'rule_gates' => \@gates } );
}

is( bind_rule_gates( syslog_rule( $daemons, $skip, $regexp, $ban_src )->rule_gates, {}, 'here' )->{early},
	2, 'a daemons and a ignore_regexp leading the list are both asked ahead of the rest' );
is( bind_rule_gates( syslog_rule( $daemons, $regexp, $skip, $ban_src )->rule_gates, {}, 'here' )->{early},
	1, 'a ignore_regexp below the matcher is not' );

my $leading = syslog_rule( $daemons, $capture, $regexp, $ban_src );
ok( !$leading->accepts_daemon('cron'), 'a rule is indexed by a daemons gate that leads its list' );

my $buried = syslog_rule( $capture, $daemons, $regexp, $ban_src );
ok( $buried->accepts_daemon('cron'), 'and not by one below a gate that keeps something, which has to see every line' );
ok(
	!defined( $buried->check( syslog_line('cron[5]: bad thing from 192.0.2.5') ) ),
	'though that daemons gate still turns the line away when it is asked'
);
ok( defined( $buried->check( syslog_line('sshd[5]: bad thing from 192.0.2.5') ) ),
	'and lets a line of its own daemon by' );

#
# a brand set above a gate is set whatever that gate then says
#

my $mark    = { 'mark'       => { 'name' => 'seen', 'ttl' => 600 } };
my $cleared = { 'not_marked' => { 'name' => 'cleared' } };

# walks one offense of the passed gates, the offender already branded cleared,
# and returns if it stood and the marks left behind
sub branded {
	my (@offense_gates) = @_;

	my %marks;
	mark_set( \%marks, 'cleared', '192.0.2.5', undef, 600, $now );
	my $rule
		= App::Baphomet::Rule->new( 'name' => 'json/brand', 'def' => { 'rule_gates' => [ $gate, @offense_gates ] } );
	my $bound = bind_rule_gates( $rule->rule_gates, { 'marks' => sub { return \%marks; } }, 'here' );

	my ($one) = @{ $rule->walk_line( $bound, json_line($offense), 'scope', { 'now' => $now } ) };
	$one->{now}    = $now;
	$one->{set}    = [];
	$one->{lifted} = [];
	my $stands = walk_offense( $bound, $one );

	return ( $stands, \%marks, settle_offenders($one) );
} ## end sub branded

my ( $stands, $marks, $offenders ) = branded( $ban_ip, $cleared, $mark );
ok( !$stands,                   'a offender a not_marked gate does not hold for is no offender' );
ok( !defined( $marks->{seen} ), 'and a mark below that gate is never asked' );

( $stands, $marks, $offenders ) = branded( $ban_ip, $mark, $cleared );
ok( !$stands, 'the same offense is vetoed with the mark written above the gate' );
ok( defined( $marks->{seen}{'192.0.2.5'} ),
	'but the mark was asked first, and branded the offender the gate then spared' );
is_deeply( $offenders, [], 'who is left with out a offender either way' );

done_testing;
