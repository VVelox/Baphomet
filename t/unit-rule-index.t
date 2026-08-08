#!perl
# the watcher's rule index... the prefilter that walks only the rules a
# record could match instead of calling every rule on the watcher to say no.
# two halves: the daemon, for the syslog type, and a mandatory gate equality
# for the types with no daemon. what is pinned here is that skipping and
# calling are the same judgment... the same rules fire, in the same order,
# a rule that could fire around its gate is never indexed on it, and the
# index can not grow without bound on a log chiselling a fresh value per line
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Galla         ();
use App::Baphomet::Rules::Syslog ();
use App::Baphomet::Rules::JSON   ();
use App::Baphomet::Rules::Raw    ();

my $galla = bless( {}, 'App::Baphomet::Galla' );

# a parsed record of the shape the syslog parsers hand back
sub syslog_record {
	my ( $daemon, $message ) = @_;

	return { 'daemon' => $daemon, 'message' => $message };
}

# a parsed record of the shape App::Baphomet::Parser::JSON hands back
sub json_record {
	my (%fields) = @_;

	return { 'fields' => \%fields };
}

#
# accepts_daemon... the rule-side half for syslog. a syslog rule answers off
# its daemons list, every other type keeps the base always-true
#

my $sshd = App::Baphomet::Rules::Syslog->new(
	'name' => 'syslog/sshd-ish',
	'def'  => {
		'daemons'        => [ 'sshd', 'sshd-session' ],
		'message_regexp' => ['bad thing from %%%SRC%%%'],
		'ban_var'        => ['SRC'],
	}
);
ok( $sshd->accepts_daemon('sshd'),         'a listed daemon is accepted' );
ok( $sshd->accepts_daemon('sshd-session'), 'each entry of the list is accepted' );
ok( !$sshd->accepts_daemon('otherd'),      'an unlisted daemon is refused' );
ok( !$sshd->accepts_daemon(undef),         'a line with no daemon is refused' );
ok( !$sshd->accepts_daemon(''),            'and so is an empty one' );

my $regexp_daemon = App::Baphomet::Rules::Syslog->new(
	'name' => 'syslog/dovecot-ish',
	'def'  => {
		'daemons'        => ['//^dovecot(?:-auth)?$//'],
		'message_regexp' => ['bad thing from %%%SRC%%%'],
		'ban_var'        => ['SRC'],
	}
);
ok( $regexp_daemon->accepts_daemon('dovecot'),      'a //regexp// daemon entry is honored' );
ok( $regexp_daemon->accepts_daemon('dovecot-auth'), 'and matches its whole alternation' );
ok( !$regexp_daemon->accepts_daemon('dovecotd'),    'without matching what it should not' );

my $raw_rule = App::Baphomet::Rules::Raw->new(
	'name' => 'raw/anything',
	'def'  => { 'message_regexp' => ['bad thing from %%%SRC%%%'], 'ban_var' => ['SRC'] }
);
ok( $raw_rule->accepts_daemon(undef), 'a raw rule accepts a daemon-less line' );
is_deeply( $raw_rule->gate_discriminators, {}, 'and offers no gate discriminator... its gate is over captures' );

#
# gate_discriminators... the rule-side half for the types with no daemon.
# only the flat gate form contributes, and only its plain equalities
#

my $alert_scan = App::Baphomet::Rules::JSON->new(
	'name' => 'json/scan-ish',
	'def'  => {
		'gate' => [
			{ 'field' => 'event_type',     'values' => ['alert'] },
			{ 'field' => 'alert.category', 'values' => ['Detection of a Network Scan'] },
		],
		'ban_var' => ['src_ip'],
	}
);
is_deeply(
	$alert_scan->gate_discriminators,
	{ 'event_type' => { 'alert' => 1 }, 'alert.category' => { 'Detection of a Network Scan' => 1 } },
	'every plain equality of a gate list is a discriminator'
);
is( $alert_scan->gate_discriminators, $alert_scan->gate_discriminators, 'and the answer is built once and cached' );

my $multi = App::Baphomet::Rules::JSON->new(
	'name' => 'json/multi',
	'def'  =>
		{ 'gate' => [ { 'field' => 'event_type', 'values' => [ 'alert', 'anomaly' ] } ], 'ban_var' => ['src_ip'] }
);
is_deeply(
	$multi->gate_discriminators,
	{ 'event_type' => { 'alert' => 1, 'anomaly' => 1 } },
	'a values list pins each of its values'
);

my $regexp_gate = App::Baphomet::Rules::JSON->new(
	'name' => 'json/regexp-gate',
	'def'  => { 'gate' => [ { 'field' => 'event_type', 'values' => ['//^al//'] } ], 'ban_var' => ['src_ip'] }
);
is_deeply( $regexp_gate->gate_discriminators, {}, 'a //regexp// value pins nothing the index could enumerate' );

my $predicate_gate = App::Baphomet::Rules::JSON->new(
	'name' => 'json/predicate-gate',
	'def'  => {
		'gate'    => [ { 'field' => 'alert.severity', 'op' => 'lt', 'value' => 3 } ],
		'ban_var' => ['src_ip'],
	}
);
is_deeply( $predicate_gate->gate_discriminators, {}, 'a typed predicate pins no exact value' );

my $keyword_gate = App::Baphomet::Rules::JSON->new(
	'name' => 'json/keyword-gate',
	'def'  => { 'keywords' => ['bad'], 'ban_var' => ['src_ip'] }
);
is_deeply( $keyword_gate->gate_discriminators, {}, 'a keyword fan pins no one field' );

# selections may sit under an or in the condition, so no arm of one is
# mandatory and none may be indexed
my $selected = App::Baphomet::Rules::JSON->new(
	'name' => 'json/selections',
	'def'  => {
		'selections' => {
			'is_alert' => [ { 'field' => 'event_type', 'values' => ['alert'] } ],
			'is_flow'  => [ { 'field' => 'event_type', 'values' => ['flow'] } ],
		},
		'condition' => 'is_alert or is_flow',
		'ban_var'   => ['src_ip'],
	}
);
is_deeply( $selected->gate_discriminators, {}, 'a selections arm is not mandatory, so it is never indexed' );

# the contract's second clause... a rule with a path to a result that goes
# around its own gate offers nothing, however plain its gate looks
my $with_capture = App::Baphomet::Rules::JSON->new(
	'name' => 'json/with-capture',
	'def'  => {
		'gate'    => [ { 'field' => 'event_type', 'values' => ['alert'] } ],
		'capture' => [ { 'key'   => 'flow_id',    'gate'   => [ { 'field' => 'event_type', 'values' => ['flow'] } ] } ],
		'key'     => 'flow_id',
		'ban_var' => ['src_ip'],
	}
);
is_deeply( $with_capture->gate_discriminators, {}, 'a rule that harvests context offers no discriminator' );

my $with_ignore = App::Baphomet::Rules::JSON->new(
	'name' => 'json/with-ignore',
	'def'  => {
		'gate'    => [ { 'field' => 'event_type',      'values' => ['alert'] } ],
		'ignore'  => [ { 'field' => 'alert.signature', 'regexp' => 'TEST' } ],
		'ban_var' => ['src_ip'],
	}
);
is_deeply( $with_ignore->gate_discriminators, {}, 'and neither does one carrying an ignore' );

#
# _index_field... which field a watcher keys on
#

is( App::Baphomet::Galla::_index_field( [ $sshd, $regexp_daemon ] ),
	'%%%DAEMON%%%', 'a watcher whose rules gate on a daemon keys on the daemon' );
is( App::Baphomet::Galla::_index_field( [ $keyword_gate, $selected, $regexp_gate ] ),
	undef, 'a watcher whose rules pin nothing keys on nothing' );
is( App::Baphomet::Galla::_index_field( [ undef, undef ] ), undef, 'and rules that did not load elect nothing' );

# the election takes the most selective field, not the most popular one...
# both rules pin event_type, but between them they pin only the two values
# alert and anomaly, where the two alert.category values are one each. so
# event_type hands a line both rules and alert.category hands it one
{
	my $scan_two = App::Baphomet::Rules::JSON->new(
		'name' => 'json/scan-two',
		'def'  => {
			'gate' => [
				{ 'field' => 'event_type',     'values' => [ 'alert', 'anomaly' ] },
				{ 'field' => 'alert.category', 'values' => ['Attempted Administrator Privilege Gain'] },
			],
			'ban_var' => ['src_ip'],
		}
	);
	my $both = [ $alert_scan, $scan_two ];
	is( App::Baphomet::Galla::_index_field($both), 'alert.category', 'the most selective field wins the election' );

	# and it is really the values that decide... give the two rules the same
	# category and alert.category stops thinning anything, so event_type,
	# which still separates them, takes it
	my $same_category = App::Baphomet::Rules::JSON->new(
		'name' => 'json/same-category',
		'def'  => {
			'gate' => [
				{ 'field' => 'event_type',     'values' => ['anomaly'] },
				{ 'field' => 'alert.category', 'values' => ['Detection of a Network Scan'] },
			],
			'ban_var' => ['src_ip'],
		}
	);
	is( App::Baphomet::Galla::_index_field( [ $alert_scan, $same_category ] ),
		'event_type', 'a field every rule pins the same way thins nothing and loses' );
}

#
# _rule_candidates, the daemon half
#

my $syslog_watcher = {
	'rules'       => [ 'syslog/a', 'syslog/b',     'syslog/c' ],
	'rule_objs'   => [ $sshd,      $regexp_daemon, $sshd ],
	'index_field' => '%%%DAEMON%%%',
	'rule_index'  => {},
};

is_deeply(
	$galla->_rule_candidates( $syslog_watcher, syslog_record( 'sshd', 'x' ) ),
	[ 0, 2 ],
	'only the rules the daemon could match'
);
is_deeply( $galla->_rule_candidates( $syslog_watcher, syslog_record( 'dovecot', 'x' ) ),
	[1], 'the regexp-gated rule answers for its own' );
is_deeply( $galla->_rule_candidates( $syslog_watcher, syslog_record( 'nobody', 'x' ) ),
	[], 'a daemon no rule wants yields nothing to walk' );
is_deeply( $galla->_rule_candidates( $syslog_watcher, syslog_record( undef, 'x' ) ),
	[], 'and neither does a line with no daemon' );

# the config's rule order is what the overlap semantics rest on, so the
# candidates must come back ascending however the index was filled
my $ordered = App::Baphomet::Rules::Syslog->new(
	'name' => 'syslog/ordered',
	'def'  => {
		'daemons'        => ['shared'],
		'message_regexp' => ['bad thing from %%%SRC%%%'],
		'ban_var'        => ['SRC'],
	}
);
my $five = {
	'rules'       => [ map { 'syslog/r' . $_ } ( 0 .. 4 ) ],
	'rule_objs'   => [ $ordered, $sshd, $ordered, $sshd, $ordered ],
	'index_field' => '%%%DAEMON%%%',
	'rule_index'  => {},
};
is_deeply(
	$galla->_rule_candidates( $five, syslog_record( 'shared', 'x' ) ),
	[ 0, 2, 4 ],
	'candidates keep the config rule order'
);

# an undef rule obj (a rule that failed to load under a non-fatal warn) is
# never a candidate rather than a call on undef
my $holed = {
	'rules'       => [ 'syslog/a', 'syslog/gone' ],
	'rule_objs'   => [ $sshd,      undef ],
	'index_field' => '%%%DAEMON%%%',
	'rule_index'  => {},
};
is_deeply( $galla->_rule_candidates( $holed, syslog_record( 'sshd', 'x' ) ),
	[0], 'a rule that did not load is never a candidate' );

#
# _rule_candidates, the gate half
#

my $anomaly = App::Baphomet::Rules::JSON->new(
	'name' => 'json/anomaly',
	'def'  => { 'gate' => [ { 'field' => 'event_type', 'values' => ['anomaly'] } ], 'ban_var' => ['src_ip'] }
);
my $json_watcher = {
	'rules'       => [ 'json/scan', 'json/multi', 'json/anomaly', 'json/keyword' ],
	'rule_objs'   => [ $alert_scan, $multi,       $anomaly,       $keyword_gate ],
	'index_field' => 'event_type',
	'rule_index'  => {},
};

is_deeply(
	$galla->_rule_candidates( $json_watcher, json_record( 'event_type' => 'alert' ) ),
	[ 0, 1, 3 ],
	'an alert reaches the rules pinning alert, and the rule pinning nothing'
);
is_deeply(
	$galla->_rule_candidates( $json_watcher, json_record( 'event_type' => 'anomaly' ) ),
	[ 1, 2, 3 ],
	'a values list makes its rule a candidate for each value it names'
);
is_deeply( $galla->_rule_candidates( $json_watcher, json_record( 'event_type' => 'flow' ) ),
	[3], 'a flow reaches only the rule that pins no event_type at all' );
is_deeply( $galla->_rule_candidates( $json_watcher, json_record( 'src_ip' => '192.0.2.1' ) ),
	[3], 'and so does a record missing the indexed field entirely' );

# a watcher with nothing to index on walks every rule, as it always did
my $unindexed = {
	'rules'       => [ 'json/keyword', 'json/selections' ],
	'rule_objs'   => [ $keyword_gate,  $selected ],
	'index_field' => undef,
	'rule_index'  => {},
};
is_deeply(
	$galla->_rule_candidates( $unindexed, json_record( 'event_type' => 'alert' ) ),
	[ 0, 1 ],
	'a watcher with no index field offers every line to every rule'
);

#
# the index memoises, and is bounded... the value comes off the log line, so
# a hostile producer must not be able to grow it forever
#

my $memo = {
	'rules'       => ['syslog/a'],
	'rule_objs'   => [$sshd],
	'index_field' => '%%%DAEMON%%%',
	'rule_index'  => {},
};
my $first  = $galla->_rule_candidates( $memo, syslog_record( 'sshd', 'x' ) );
my $second = $galla->_rule_candidates( $memo, syslog_record( 'sshd', 'x' ) );
is( $second, $first, 'a repeat value is answered from the index, not rebuilt' );

for ( my $i = 0; $i < 1100; $i++ ) {
	$galla->_rule_candidates( $memo, syslog_record( 'daemon' . $i, 'x' ) );
}
cmp_ok( scalar( keys( %{ $memo->{rule_index} } ) ), '<=', 1024,
	'the index stays bounded under a fresh value per line' );
is_deeply( $galla->_rule_candidates( $memo, syslog_record( 'sshd', 'x' ) ),
	[0], 'and still answers correctly after being thrown away' );

#
# the whole point... walking the candidates and walking every rule reach the
# same verdict, which is the invariant both halves rest on
#

sub agrees {
	my ( $watcher, $parsed, $scope, $label ) = @_;

	my @every = grep { defined( $watcher->{rule_objs}[$_]->check( $parsed, $scope . '-every', {} ) ) }
		grep { defined( $watcher->{rule_objs}[$_] ) } ( 0 .. scalar( @{ $watcher->{rule_objs} } ) - 1 );
	my @indexed = grep { defined( $watcher->{rule_objs}[$_]->check( $parsed, $scope . '-indexed', {} ) ) }
		@{ $galla->_rule_candidates( $watcher, $parsed ) };
	is_deeply( \@indexed, \@every, 'the same rules fire for ' . $label );

	return;
} ## end sub agrees

agrees( $syslog_watcher, syslog_record( 'sshd',    'bad thing from 1.2.3.4' ), 'sy1', 'a sshd line' );
agrees( $syslog_watcher, syslog_record( 'dovecot', 'bad thing from 5.6.7.8' ), 'sy2', 'a dovecot line' );
agrees( $syslog_watcher, syslog_record( 'otherd',  'bad thing from 9.9.9.9' ), 'sy3', 'an unwanted daemon' );
agrees( $syslog_watcher, syslog_record( undef,     'bad thing from 8.8.8.8' ), 'sy4', 'a line with no daemon' );

agrees(
	$json_watcher,
	json_record(
		'event_type'     => 'alert',
		'src_ip'         => '192.0.2.5',
		'alert.category' => 'Detection of a Network Scan'
	),
	'js1',
	'a scan alert'
);
agrees( $json_watcher, json_record( 'event_type' => 'alert', 'src_ip' => '192.0.2.5', 'alert.category' => 'Other' ),
	'js2', 'an alert of another class' );
agrees( $json_watcher, json_record( 'event_type' => 'anomaly', 'src_ip' => '192.0.2.5' ), 'js3', 'an anomaly' );
agrees( $json_watcher, json_record( 'event_type' => 'flow',    'src_ip' => '192.0.2.5' ), 'js4', 'a flow' );
agrees( $json_watcher, json_record( 'src_ip' => '192.0.2.5' ), 'js5', 'a record with no event_type' );

done_testing();
