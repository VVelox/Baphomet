#!perl
# mungers: the optional Log-Munger enrichment pass a rule declares. a rule
# names leaf mungers (never base, which resolves itself), they run before the
# rule's own message_regexp, and the fields they decode land under the
# offense... a message_regexp capture of the same name overwriting, that
# divergence being deliberate. driven through the same run_tests path the
# galla shares, over the sshd munger (syslog, PROGRAM-gated) and the
# http_access_logs munger (raw, message-only). the fatal contract is proven
# cold beside it.
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Rules::Syslog ();
use App::Baphomet::Rules::Raw    ();

# the enrichment needs Log-Munger and its shipped munger files... skip the
# whole file cleanly where the optional dep is absent, the same as a
# deployment using only the offender tokens never loads it
my $have_munger = eval {
	require Log::Munger::LogProcessor;
	Log::Munger::LogProcessor->new( 'rules' => ['sshd'] );
	1;
};
if ( !$have_munger ) {
	plan skip_all => 'Log::Munger (or its sshd munger) is not available';
}

#
# syslog, PROGRAM-gated... the sshd munger decodes ssh_* fields the rule
# never captured, and the rule's own SRC rides beside them
#
my $sshd = App::Baphomet::Rules::Syslog->new(
	name => 'syslog/sshd-munge',
	def  => {
		daemons        => ['sshd'],
		mungers        => ['sshd'],
		message_regexp => ['Failed password for (?:invalid user )?\S+ from (?<SRC>\S+) port'],
		ban_var        => ['SRC'],
		tests          => {
			positive => [
				{
					message =>
						'Jul 12 08:15:50 vixen42 sshd[2278]: Failed password for invalid user admin from 192.0.2.7 port 4711 ssh2',
					found => 1,
					data  => {
						SRC         => '192.0.2.7',    # the rule's own capture
						ssh_user    => 'admin',        # decoded by the munger
						ssh_src_ip  => '192.0.2.7',    # decoded by the munger
						ssh_method  => 'password',
						ssh_invalid => 'invalid',
					},
				},
			],
		},
	},
);
my $sshd_r = $sshd->run_tests;
is( $sshd_r->{fail}, 0, 'the sshd munger enriches the offense with its decoded fields' )
	|| diag( join( "\n", @{ $sshd_r->{failures} } ) );
is_deeply( [ $sshd->mungers ], ['sshd'], 'mungers() reports the declared set' );

#
# collision... the rule binds ssh_user to the port, a value the munger sets to
# the username. the rule's own capture must overwrite the munger field
#
my $collide = App::Baphomet::Rules::Syslog->new(
	name => 'syslog/munge-collide',
	def  => {
		daemons        => ['sshd'],
		mungers        => ['sshd'],
		message_regexp => ['Failed password for invalid user \S+ from \S+ port (?<ssh_user>\d+)'],
		ban_var        => ['ssh_src_ip'],
		tests          => {
			positive => [
				{
					message =>
						'Jul 12 08:15:50 vixen42 sshd[2278]: Failed password for invalid user admin from 192.0.2.7 port 4711 ssh2',
					found => 1,
					data  => {
						ssh_user   => '4711',         # the rule's capture wins over the munger's "admin"
						ssh_src_ip => '192.0.2.7',    # a munger-only field still survives
					},
				},
			],
		},
	},
);
my $collide_r = $collide->run_tests;
is( $collide_r->{fail}, 0, 'a message_regexp capture overwrites the munger field of the same name' )
	|| diag( join( "\n", @{ $collide_r->{failures} } ) );

#
# raw, message-only... no syslog envelope, so only a munger gating on MESSAGE
# matches. http_access_logs decodes an access-log line
#
SKIP: {
	my $have_http = eval { Log::Munger::LogProcessor->new( 'rules' => ['http_access_logs'] ); 1 };
	skip 'the http_access_logs munger is not available', 1 if !$have_http;

	my $raw = App::Baphomet::Rules::Raw->new(
		name => 'raw/access-munge',
		def  => {
			mungers        => ['http_access_logs'],
			message_regexp => ['^(?<SRC>\S+) \S+ \S+ \[[^\]]+\] "\S+ \S+ [^"]+" 401 '],
			ban_var        => ['SRC'],
			tests          => {
				positive => [
					{
						message => '192.0.2.9 - - [10/Oct/2000:13:55:36 -0700] "GET /admin.php HTTP/1.0" 401 2326',
						found   => 1,
						data    => {
							SRC           => '192.0.2.9',
							http_clientip => '192.0.2.9',
							http_verb     => 'GET',
							http_response => '401',
						},
					},
				],
			},
		},
	);
	my $raw_r = $raw->run_tests;
	is( $raw_r->{fail}, 0, 'a raw rule enriches from a message-only munger' )
		|| diag( join( "\n", @{ $raw_r->{failures} } ) );
} ## end SKIP:

#
# the contract... a malformed key, an unresolvable munger, and mungers beside
# stages are all fatal
#
ok(
	!eval {
		App::Baphomet::Rules::Syslog->new( name => 'syslog/m',
			def => { daemons => ['sshd'], mungers => 'sshd', message_regexp => ['x (?<SRC>\S+)'], ban_var => ['SRC'] } );
		1;
	},
	'a scalar mungers key is fatal'
);

ok(
	!eval {
		App::Baphomet::Rules::Syslog->new( name => 'syslog/e',
			def => { daemons => ['sshd'], mungers => [''], message_regexp => ['x (?<SRC>\S+)'], ban_var => ['SRC'] } );
		1;
	},
	'an empty munger name is fatal'
);

#
# staged... mungers are wired through the staged matcher too, enriching the
# completed sequence from its final (completing) line
#
my $staged = App::Baphomet::Rules::Syslog->new(
	name => 'syslog/staged-munge',
	def  => {
		daemons => ['sshd'],
		mungers => ['sshd'],
		stages  => [
			{ message_regexp => ['^Failed password for \S+ from (?<SRC>\S+) port'], count => 2, within => 300 },
			{ message_regexp => ['^Accepted \w+ for (?<USER>\S+) from (?<SRC>\S+) port'], within => 600 },
		],
		per           => ['SRC'],
		detection_var => ['SRC'],
		max_score     => 1,
		tests         => {
			positive => [
				{
					messages => [
						'Jul 12 08:15:50 vixen42 sshd[1]: Failed password for root from 192.0.2.7 port 4711 ssh2',
						'Jul 12 08:15:51 vixen42 sshd[2]: Failed password for root from 192.0.2.7 port 4712 ssh2',
						'Jul 12 08:15:57 vixen42 sshd[3]: Accepted password for root from 192.0.2.7 port 4716 ssh2',
					],
					found => 1,
					data  => {
						SRC  => '192.0.2.7',
						USER => 'root',
						# enriched from the completing Accepted line, not the failures
						ssh_method => 'password',
						ssh_user   => 'root',
					},
				},
			],
		},
	},
);
my $staged_r = $staged->run_tests;
is( $staged_r->{fail}, 0, 'a staged rule enriches the completed sequence from its final line' )
	|| diag( join( "\n", @{ $staged_r->{failures} } ) );

# an unresolvable munger is fatal at processor build... the galla prewarms
# this at load, turning the die into a log_drek error and refusing to run
my $bad = App::Baphomet::Rules::Syslog->new(
	name => 'syslog/bad',
	def  => {
		daemons        => ['sshd'],
		mungers        => ['no-such-munger-xyzzy'],
		message_regexp => ['x (?<SRC>\S+)'],
		ban_var        => ['SRC'],
	}
);
ok( !eval { $bad->_munge_processor; 1 }, 'a munger that will not resolve is fatal at build' );
like( $@, qr/could not be loaded/, 'the unresolvable-munger error names the failure' );

# a set shares one processor whatever the order or repetition named
my $multi = App::Baphomet::Rules::Syslog->new(
	name => 'syslog/multi',
	def  => {
		daemons        => ['sshd'],
		mungers        => [ 'sshd', 'sshd' ],
		message_regexp => ['x (?<SRC>\S+)'],
		ban_var        => ['SRC'],
	}
);
is_deeply( [ $multi->mungers ], ['sshd'], 'mungers() dedups a set' );

done_testing();
