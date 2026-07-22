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
	eval { require Net::DNS::Resolver; require Net::DNS::Nameserver; require Net::DNS::RR; };
	if ($@) {
		plan skip_all => 'Net::DNS with Nameserver not available';
	}
}

use POE;
use App::Baphomet::Galla ();

# the wire half of the background engine... bgsend, the select, and the
# timeout, against a real Net::DNS::Nameserver on loopback in a child
# process, so nothing here touches the outside world. every environment
# hiccup is a skip, not a failure

my $ns;
my $port;
my $ns_child;
# every process the nameserver breathes life into, gathered so the POE
# loop can hand them to its own reaper before it winds down
my @ns_pids;
foreach my $try ( 1 .. 20 ) {
	$port = 20000 + int( rand(20000) );
	$ns   = eval {
		Net::DNS::Nameserver->new(
			'LocalAddr'    => '127.0.0.1',
			'LocalPort'    => $port,
			'Verbose'      => 0,
			'ReplyHandler' => sub {
				my ( $qname, $qclass, $qtype ) = @_;
				if ( $qname eq 'live.test' && $qtype eq 'A' ) {
					return ( 'NOERROR', [ Net::DNS::RR->new('live.test. 60 IN A 192.0.2.99') ], [], [], { 'aa' => 1 } );
				}
				return ( 'NXDOMAIN', [], [], [] );
			},
		);
	};
	last if defined($ns);
}
if ( !defined($ns) ) {
	plan skip_all => 'could not bind a loopback nameserver';
}

# newer Net::DNS spawns its own server subprocesses, older loops in a
# child of ours
if ( $ns->can('start_server') ) {
	$ns->start_server(120);
	# start_server begets its own TCP/UDP subprocesses and stows their
	# pids in this package global... claim them so POE can lay them to
	# rest rather than leaving orphans breathing at kernel shutdown
	@ns_pids = grep { defined($_) } @Net::DNS::Nameserver::pid;
} elsif ( $ns->can('main_loop') ) {
	$ns_child = fork;
	if ( !defined($ns_child) ) {
		plan skip_all => 'could not fork the nameserver child';
	}
	if ( !$ns_child ) {
		$ns->main_loop;
		exit 0;
	}
	@ns_pids = ($ns_child);
} else {
	plan skip_all => 'this Net::DNS::Nameserver offers no way to run';
}

sub stop_ns {
	if ( $ns->can('stop_server') ) {
		$ns->stop_server;
	}
	if ( defined($ns_child) ) {
		kill( 'TERM', $ns_child );
		waitpid( $ns_child, 0 );
	}
	return;
}

# preflight... a blocking probe proves the server answers before anything
# is asserted, so a hostile environment skips rather than fails
my $probe = Net::DNS::Resolver->new(
	'nameservers' => ['127.0.0.1'],
	'port'        => $port,
	'retry'       => 1,
	'udp_timeout' => 1,
);
my $probed;
foreach my $try ( 1 .. 5 ) {
	my $reply = $probe->query( 'live.test', 'A' );
	if ( defined($reply) ) {
		$probed = 1;
		last;
	}
	select( undef, undef, undef, 0.2 );
}
if ( !$probed ) {
	stop_ns();
	plan skip_all => 'the loopback nameserver did not answer a probe';
}

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/raw', $dir . '/run' );
open( my $fh, '>', $dir . '/rules/raw/hostile.yaml' ) || die($!);
print $fh "---\nmessage_regexp:\n  - 'bad thing from %%%%HOST%%%%'\nban_var:\n  - HOST\n";
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
usedns_timeout = 2

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

# the engine rides a resolver aimed at the loopback nameserver only
$galla->{dns_resolver} = Net::DNS::Resolver->new(
	'nameservers' => ['127.0.0.1'],
	'port'        => $port,
	'retry'       => 1,
	'udp_timeout' => 2,
);
$galla->{dns_async} = 1;

my ( $live_answer, $dead_answer, $watchdogged );

POE::Session->create(
	'inline_states' => {
		'_start' => sub {
			$_[KERNEL]->alias_set('galla-tails-app');
			$_[KERNEL]->delay( 'watchdog', 10 );
			$galla->_resolve_hostname_async(
				'live.test',
				sub {
					$live_answer = $_[0];
					$poe_kernel->post( 'galla-tails-app', 'go_dead' );
				}
			);
			return;
		},
		'go_dead' => sub {
			# a resolver aimed at a port nobody listens on... the query
			# must still complete, as a failure, inside the timeout
			$galla->{dns_resolver} = Net::DNS::Resolver->new(
				'nameservers' => ['127.0.0.1'],
				'port'        => 1,
				'retry'       => 1,
				'udp_timeout' => 2,
			);
			$galla->_resolve_hostname_async(
				'dead.test',
				sub {
					$dead_answer = defined( $_[0] ) ? $_[0] : 'failed';
					$poe_kernel->post( 'galla-tails-app', 'finish' );
				}
			);
			return;
		},
		'watchdog' => sub {
			$watchdogged = 1;
			$_[KERNEL]->yield('finish');
			return;
		},
		'finish' => sub {
			$_[KERNEL]->alarm_remove_all;
			foreach my $handle_key ( keys( %{ $galla->{dns_inflight} } ) ) {
				my $query = delete( $galla->{dns_inflight}{$handle_key} );
				$_[KERNEL]->select_read( $query->{handle} ) if defined( $query->{handle} );
			}
			# tear the nameserver down from inside the loop, then hand its
			# offspring to POE's own reaper. otherwise those subprocesses
			# are still breathing when the kernel finalizes its signals,
			# and it scolds about unreaped children. sig_child both reaps
			# them and holds this session open until they are laid to rest,
			# so POE::Kernel->run() returns clean
			stop_ns();
			foreach my $ns_pid (@ns_pids) {
				$_[KERNEL]->sig_child( $ns_pid, 'ns_reaped' ) if defined($ns_pid);
			}
			$_[KERNEL]->alias_remove('galla-tails-app');
			return;
		},
		# the nameserver's subprocesses come home to rest here... nothing
		# to do but let POE clear the watcher, but the handler must exist
		# for sig_child to actually reap rather than merely forget
		'ns_reaped' => sub {
			return;
		},
	},
	'object_states' => [
		$galla => {
			'dns_start'     => '_poe_dns_start',
			'dns_answered'  => '_poe_dns_answered',
			'dns_timed_out' => '_poe_dns_timed_out',
		},
	],
);

POE::Kernel->run;

stop_ns();

ok( !$watchdogged, 'the loop finished on its own, no watchdog' );
is_deeply( $live_answer, ['192.0.2.99'], 'a real background resolution landed through the wire engine' );
is( $dead_answer, 'failed', 'a dead resolver completes as a failure inside the timeout' );

done_testing;
