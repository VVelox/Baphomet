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

# the async DNS behavior, driven wholly through the dns_bg seam... the
# engine is stood in for by a recorder whose completions fire by hand, so
# the cache-first judgments, the waiters, the fences, and the proactive
# forward warm are all proven deterministically with no event loop and no
# real DNS

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/raw' );
make_path( $dir . '/run' );

open( my $fh, '>', $dir . '/rules/raw/hostile.yaml' ) || die($!);
print $fh <<'EOR';
---
message_regexp:
  - '^bad thing from %%%%HOST%%%%$'
ban_var:
  - HOST
EOR
close($fh);

open( $fh, '>', $dir . '/log' ) || die($!);
close($fh);

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
enable_dns = true
ignore_ips = [ "127.0.0.0/8" ]

[kur.app]
ban_time = 300

[kur.app.seen]
log = "$dir/log"
parser = "raw"
rule = "raw/hostile"
usedns = "resolve_seen"
EOC
close($fh);

my $galla = App::Baphomet::Galla->new( 'config' => $dir . '/config.toml', 'name' => 'app' );
ok( defined($galla), 'galla built' );

# the recorder seam... queries pile up with their completions for the test
# to answer when it pleases
my @queries;
$galla->{dns_bg} = sub {
	my ( $kind, $qname, $qtype, $done ) = @_;
	push( @queries, { 'kind' => $kind, 'qname' => $qname, 'qtype' => $qtype, 'done' => $done } );
	return;
};
$galla->{dns_async} = 1;
$galla->{watchers}{seen}{settings}{usedns} = 'resolve_seen';

sub fire {
	my ( $qname, $qtype, $answer ) = @_;
	foreach my $query (@queries) {
		if ( !$query->{fired} && $query->{qname} eq $qname && $query->{qtype} eq $qtype ) {
			$query->{fired} = 1;
			$query->{done}->($answer);
			return 1;
		}
	}
	return 0;
}
sub query_count { return scalar( grep { $_->{qname} eq $_[0] } @queries ); }

#
# resolve_seen... cache-first, fail closed on the cold line
#

my @kept = $galla->_usedns_offenders( 'seen', ['cold.example.com'] );
is( scalar(@kept),                    0, 'a cold name counts nobody on its first line' );
is( query_count('cold.example.com'),  2, 'and fired its A and AAAA' );

@kept = $galla->_usedns_offenders( 'seen', ['cold.example.com'] );
is( scalar(@kept),                   0, 'still nobody while the answer is in flight' );
is( query_count('cold.example.com'), 2, 'and no further queries fired' );

ok( fire( 'cold.example.com', 'A',    ['192.0.2.70'] ), 'A answered' );
ok( fire( 'cold.example.com', 'AAAA', [] ),             'AAAA answered empty' );

@kept = $galla->_usedns_offenders( 'seen', ['cold.example.com'] );
is_deeply( \@kept, ['192.0.2.70'], 'the warm cache counts the address on the next line' );

# the fences still stand on the background path... a resolved ignored
# address never counts
$galla->_usedns_offenders( 'seen', ['mixed.example.com'] );
fire( 'mixed.example.com', 'A',    [ '127.0.0.5', '192.0.2.71' ] );
fire( 'mixed.example.com', 'AAAA', [] );
@kept = $galla->_usedns_offenders( 'seen', ['mixed.example.com'] );
is_deeply( \@kept, ['192.0.2.71'], 'the ignored resolved address was dropped by the fence' );

# both families failing reads as a failure and ticks
my $failures_before = $galla->{stats}{dns_failures};
$galla->_usedns_offenders( 'seen', ['dead.example.com'] );
fire( 'dead.example.com', 'A',    undef );
fire( 'dead.example.com', 'AAAA', undef );
is( $galla->{stats}{dns_failures}, $failures_before + 1, 'a failed resolution ticked dns_failures once' );

#
# the resolve_ban terminal... in-flight absorption and the waiters
#

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub {
		my ( $self, $ip, $ban_time ) = @_;
		foreach my $one ( ref($ip) eq 'ARRAY' ? @{$ip} : ($ip) ) {
			push( @sent, $one );
		}
		return;
	};
}

$galla->_ban_ip( 'threshold.example.com', 300, undef, undef );
ok( $galla->{inflight_bans}{'host:threshold.example.com'}, 'the hostname ban is marked in flight' );
is( query_count('threshold.example.com'), 2, 'and fired its resolution' );
$galla->_ban_ip( 'threshold.example.com', 300, undef, undef );
is( query_count('threshold.example.com'), 2, 'a re-crossing is absorbed, not re-asked' );

fire( 'threshold.example.com', 'A',    ['192.0.2.80'] );
fire( 'threshold.example.com', 'AAAA', [] );
is_deeply( \@sent, ['192.0.2.80'], 'the resolved address was banished from the completion' );
ok( !%{ $galla->{inflight_bans} }, 'nothing left in flight' );

# two async resolutions of one cold name... the second joins as a waiter
my ( $first_answer, $second_answer );
$galla->_resolve_hostname_async( 'waiters.example.com', sub { $first_answer  = $_[0]; } );
$galla->_resolve_hostname_async( 'waiters.example.com', sub { $second_answer = $_[0]; } );
is( query_count('waiters.example.com'), 2, 'one A/AAAA pair for both askers' );
fire( 'waiters.example.com', 'A',    ['192.0.2.90'] );
fire( 'waiters.example.com', 'AAAA', [] );
is_deeply( $first_answer,  ['192.0.2.90'], 'the first asker was answered' );
is_deeply( $second_answer, ['192.0.2.90'], 'and the waiter with it' );

#
# the rDNS gate... cache-first, the forward chain warmed proactively
#

$galla->{enable_rdns} = 1;
$galla->{dns_reverse} = sub { die('the blocking closure must not be asked on the async path'); };
$galla->{dns_forward} = sub { die('the blocking closure must not be asked on the async path'); };
$galla->{rdns_resolver} = undef;    # the seam carries the engine

my $entry = {
	'forward_confirm' => 1,
	'regexp'          => qr/\.crawler\.example\.com$/,
	'negate'          => 0,
	'on_nxdomain'     => 'compare',
	'on_servfail'     => 'fail',
};

is( $galla->_rdns_entry_pass( $entry, '198.51.100.9', {} ), 0, 'a cold address fails closed this line' );
is( query_count('198.51.100.9'), 1, 'and fired one PTR' );
is( $galla->_rdns_entry_pass( $entry, '198.51.100.9', {} ), 0, 'in flight still fails closed' );
is( query_count('198.51.100.9'), 1, 'without re-asking' );

ok( fire( '198.51.100.9', 'PTR', ['bot.crawler.example.com'] ), 'PTR answered' );
is( query_count('bot.crawler.example.com'), 2, 'the forward confirmation was warmed proactively' );
fire( 'bot.crawler.example.com', 'A',    ['198.51.100.9'] );
fire( 'bot.crawler.example.com', 'AAAA', [] );

is( $galla->_rdns_entry_pass( $entry, '198.51.100.9', {} ), 1, 'the warm chain passes the gate next line' );

# a PTR failure ticks rdns_failures and honors on_servfail
my $rdns_failures_before = $galla->{stats}{rdns_failures};
$galla->_rdns_entry_pass( $entry, '198.51.100.10', {} );
fire( '198.51.100.10', 'PTR', undef );
is( $galla->{stats}{rdns_failures}, $rdns_failures_before + 1, 'a failed PTR ticked rdns_failures' );
is( $galla->_rdns_entry_pass( $entry, '198.51.100.10', {} ), 0, 'and the cached failure keeps failing the gate' );

# authoritative absence is data... an empty PTR set with negate counts
my $absent = {
	'forward_confirm' => 1,
	'regexp'          => qr/\.crawler\.example\.com$/,
	'negate'          => 1,
	'on_nxdomain'     => 'compare',
	'on_servfail'     => 'fail',
};
$galla->_rdns_entry_pass( $absent, '198.51.100.11', {} );
fire( '198.51.100.11', 'PTR', [] );
is( $galla->_rdns_entry_pass( $absent, '198.51.100.11', {} ), 1, 'no reverse DNS at all, negated, counts' );

done_testing;
