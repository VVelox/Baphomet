#!perl
# what a misshapen rule def dies with, key by key... every row of the shapes
# App::Baphomet::Rule and the gate classes vet a def against is fed a bad
# value here and the whole message compared, so the wording is pinned in one
# place and a row naming a kind that does not exist is caught by its own test
use 5.006;
use strict;
use warnings;
use Test::More;
use App::Baphomet::Rule ();

# the gates the least def of each type is made of, and the detection_var a
# case has in place of the ban_var... a case with a gate of its own lists
# them around it, so where the gate sits in the list, and so the entry the
# message names, is there to read
my $daemons    = { 'daemons'        => ['sshd'] };
my $matcher    = { 'message_regexp' => ['^bad thing from %%%%SRC%%%%'] };
my $ban_src    = { 'ban_var'        => ['SRC'] };
my $detect_src = { 'detection_var'  => ['SRC'] };
my $event_gate = { 'gate'           => [ { 'field' => 'event', 'values' => ['fail'] } ] };
my $ban_ip     = { 'ban_var'        => ['ip'] };
my $status     = { 'status'         => ['404'] };
my $ban_host   = { 'ban_var'        => ['host'] };

# the two gates that lead the list of a syslog case swapping neither out, so
# what a case lists right after them is entry 2
my @sshd = ( $daemons, $matcher );

# the least def each type loads, which each case below adds its keys to... a
# rule_gates a case has of its own is in place of the one here
my %base_defs = (
	'syslog' => { 'rule_gates' => [ @sshd,       $ban_src ] },
	'json'   => { 'rule_gates' => [ $event_gate, $ban_ip ] },
	'http'   => { 'rule_gates' => [ $status,     $ban_host ] },
);

# what building a rule of the type from its base def and the passed keys dies
# with, less the at-line tail perl adds, or undef when it loads
sub load_error {
	my ( $type, $keys ) = @_;

	my %def = ( %{ $base_defs{$type} }, %{$keys} );

	if ( eval { App::Baphomet::Rule->new( 'name' => $type . '/x', 'def' => \%def ); 1 } ) {
		return undef;
	}
	my $error = $@;
	$error =~ s/ at \S+ line \d+\.\n\z//;
	return $error;
} ## end sub load_error

my $name_says = 'a name matching /^[a-zA-Z0-9_\-]+$/';
my $strings   = 'a non-empty array of non-empty strings';
my $gate      = [ { 'field' => 'event', 'values' => ['login'] } ];
# the one stage the staged cases that are not about a stage are given
my $probe_stage = { 'message_regexp' => ['^probe from %%%%SRC%%%%'] };

# each case is the rule type, what the case is, the keys it adds to the base
# def, and the message the def dies with, or undef for a def that loads
my @cases = (
	#
	# the top level keys
	#
	[ 'syslog', 'a unknown key', { 'max_scroe' => 5 }, 'The rule "syslog/x" has the unknown key "max_scroe"' ],
	[
		'syslog',
		'a max_score that is a word',
		{ 'max_score' => 'abc' },
		'The rule "syslog/x" has a max_score that is not a positive int'
	],
	[
		'syslog',
		'a find_time of 0',
		{ 'find_time' => 0 },
		'The rule "syslog/x" has a find_time that is not a positive int'
	],
	[
		'syslog',
		'a negative ban_time',
		{ 'ban_time' => -1 },
		'The rule "syslog/x" has a ban_time that is not a non-negative int of seconds'
	],
	[ 'syslog', 'a ban_time of 0, which is eternal', { 'ban_time' => 0 }, undef ],
	[
		'syslog',
		'a weight of 0',
		{ 'weight' => 0 },
		'The rule "syslog/x" has a weight that is not a positive number'
	],
	[ 'syslog', 'a weight with a fraction', { 'weight' => '0.5' }, undef ],
	[
		'syslog',
		'a eve_only that is a array',
		{ 'eve_only' => [1] },
		'The rule "syslog/x" has a eve_only that is not a boolean'
	],
	[ 'syslog', 'a empty msg', { 'msg' => '' }, 'The rule "syslog/x" has a msg that is not a non-empty string' ],
	[
		'syslog',
		'a severity that is not a level',
		{ 'severity' => 'loud' },
		'The rule "syslog/x" has a severity that is not one of info/low/medium/high/critical'
	],
	[
		'syslog',
		'a classtype that is a array',
		{ 'classtype' => [] },
		'The rule "syslog/x" has a classtype that is not a non-empty string'
	],
	[
		'syslog',
		'a empty references',
		{ 'references' => [] },
		'The rule "syslog/x" has a references that is not ' . $strings
	],
	[
		'syslog',
		'a attack holding a empty string',
		{ 'attack' => [ 'T1110', '' ] },
		'The rule "syslog/x" has a attack that is not ' . $strings
	],
	[ 'syslog', 'a negative rev', { 'rev' => -1 }, 'The rule "syslog/x" has a rev that is not a non-negative int' ],
	[ 'syslog', 'a rev of 0, which is unversioned', { 'rev' => 0 }, undef ],
	[
		'syslog',
		'a empty src_ip_var',
		{ 'src_ip_var' => '' },
		'The rule "syslog/x" has a src_ip_var that is not a non-empty string'
	],
	[ 'syslog', 'a null src_ip_var, which is one not set', { 'src_ip_var' => undef }, undef ],
	[
		'syslog', 'a tests that is a array', { 'tests' => [] }, 'The rule "syslog/x" has a tests that is not a hash'
	],

	#
	# who is counted
	#
	[
		'syslog',
		'a ban_var holding a empty string',
		{ 'rule_gates' => [ @sshd, { 'ban_var' => [''] } ] },
		'The ban_var gate of the rule "syslog/x" (rule_gates entry 2) is not ' . $strings
	],
	[
		'syslog',
		'no ban_var at all',
		{ 'rule_gates' => [@sshd] },
		'The rule "syslog/x" has neither a ban_var nor a detection_var gate, '
			. 'so nothing says who a offense counts against'
	],
	[
		'syslog',
		'a second ban_var',
		{ 'rule_gates' => [ @sshd, $ban_src, $ban_src ] },
		'The ban_var gate of the rule "syslog/x" (rule_gates entry 3) comes after a ban_var, '
			. 'and a rule names who it counts against once'
	],
	[
		'syslog',
		'a second matcher',
		{ 'rule_gates' => [ @sshd, $matcher, $ban_src ] },
		'The message_regexp gate of the rule "syslog/x" (rule_gates entry 2) is the second message_regexp '
			. 'gate of the rule, which can have the one'
	],
	[
		'syslog',
		'a gate key at the top level',
		{ 'daemons' => ['sshd'] },
		'The rule "syslog/x" has "daemons" at its top level, which is a gate and goes under rule_gates'
	],
	[
		'syslog',
		'no daemons gate',
		{ 'rule_gates' => [ $matcher, $ban_src ] },
		'The rule "syslog/x" has no daemons gate, which a syslog rule has to have'
	],
	[
		'syslog',
		'a gate of another type of rule',
		{ 'rule_gates' => [ @sshd, $status, $ban_src ] },
		'The status gate of the rule "syslog/x" (rule_gates entry 2) is on a syslog rule, '
			. 'and only a http rule can have one'
	],
	[
		'syslog',
		'a detection_var holding a empty string',
		{ 'rule_gates' => [ @sshd, { 'detection_var' => [''] } ] },
		'The detection_var gate of the rule "syslog/x" (rule_gates entry 2) is not ' . $strings
	],
	[ 'syslog', 'a detection_var in place of the ban_var', { 'rule_gates' => [ @sshd, $detect_src ] }, undef ],
	[
		'syslog',
		'a empty mungers',
		{ 'rule_gates' => [ $daemons, { 'mungers' => [] }, $matcher, $ban_src ] },
		'The mungers gate of the rule "syslog/x" (rule_gates entry 1) is not ' . $strings
	],

	#
	# the marks
	#
	[
		'syslog',
		'a mark that is a array',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'mark' => [ { 'name' => 'brute', 'ttl' => 60 } ] } ] },
		'The mark gate of the rule "syslog/x" (rule_gates entry 3) is not a hash'
	],
	[
		'syslog',
		'a mark that is a string',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'mark' => 'brute' } ] },
		'The mark gate of the rule "syslog/x" (rule_gates entry 3) is not a hash'
	],
	[
		'syslog',
		'a mark with a unknown key',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'mark' => { 'name' => 'brute', 'ttl' => 60, 'tll' => 5 } } ] },
		'The mark gate of the rule "syslog/x" (rule_gates entry 3) has the unknown key "tll"'
	],
	[
		'syslog',
		'a mark with no name',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'mark' => { 'ttl' => 60 } } ] },
		'The mark gate of the rule "syslog/x" (rule_gates entry 3) lacks a name'
	],
	[
		'syslog',
		'a mark with no ttl',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'mark' => { 'name' => 'brute' } } ] },
		'The mark gate of the rule "syslog/x" (rule_gates entry 3) lacks a ttl'
	],
	[
		'syslog',
		'a mark name with a space',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'mark' => { 'name' => 'brute force', 'ttl' => 60 } } ] },
		'The mark gate of the rule "syslog/x" (rule_gates entry 3) has a name that is not ' . $name_says
	],
	[
		'syslog',
		'a mark ttl of 0',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'mark' => { 'name' => 'brute', 'ttl' => 0 } } ] },
		'The mark gate of the rule "syslog/x" (rule_gates entry 3) has a ttl that is not a positive int of seconds'
	],
	[
		'syslog',
		'a mark with a empty var',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'mark' => { 'name' => 'brute', 'ttl' => 60, 'var' => '' } } ] },
		'The mark gate of the rule "syslog/x" (rule_gates entry 3) has a var that is not a non-empty string'
	],
	[
		'syslog',
		'a mark with a null var, which is one not set',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'mark' => { 'name' => 'brute', 'ttl' => 60, 'var' => undef } } ] },
		undef
	],
	[
		'syslog',
		'a mark with a empty vars',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'mark' => { 'name' => 'brute', 'ttl' => 60, 'vars' => [] } } ] },
		'The mark gate of the rule "syslog/x" (rule_gates entry 3) has a vars that is not ' . $strings
	],
	[
		'syslog',
		'a mark with both var and vars',
		{
			'rule_gates' => [
				@sshd, $ban_src,
				{ 'mark' => { 'name' => 'brute', 'ttl' => 60, 'var' => 'USER', 'vars' => [ 'USER', 'SRC' ] } }
			]
		},
		'The mark gate of the rule "syslog/x" (rule_gates entry 3) has both var and vars'
	],
	[
		'syslog',
		'a second mark that is the bad one',
		{
			'rule_gates' => [
				@sshd, $ban_src,
				{ 'mark' => { 'name' => 'brute', 'ttl' => 60 } }, { 'mark' => { 'name' => 'spray' } }
			]
		},
		'The mark gate of the rule "syslog/x" (rule_gates entry 4) lacks a ttl'
	],
	[
		'syslog',
		'a unmark with a ttl',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'unmark' => { 'name' => 'brute', 'ttl' => 60 } } ] },
		'The unmark gate of the rule "syslog/x" (rule_gates entry 3) has the unknown key "ttl"'
	],
	[
		'syslog',
		'a marked with neither name nor names',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'marked' => { 'var' => 'USER' } } ] },
		'The marked gate of the rule "syslog/x" (rule_gates entry 3) has neither name nor names'
	],
	[
		'syslog',
		'a marked with both name and names',
		{
			'rule_gates' =>
				[ @sshd, $ban_src, { 'marked' => { 'name' => 'brute', 'names' => [ 'brute', 'spray' ] } } ]
		},
		'The marked gate of the rule "syslog/x" (rule_gates entry 3) has both name and names'
	],
	[
		'syslog',
		'a marked names holding what is not a name',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'marked' => { 'names' => [ 'brute', 'brute force' ] } } ] },
		'The marked gate of the rule "syslog/x" (rule_gates entry 3) has a names that is not a non-empty array, each '
			. $name_says
	],
	[
		'syslog',
		'a marked with both value_is and value_not',
		{
			'rule_gates' =>
				[ @sshd, $ban_src, { 'marked' => { 'name' => 'brute', 'value_is' => 'USER', 'value_not' => 'USER' } } ]
		},
		'The marked gate of the rule "syslog/x" (rule_gates entry 3) has both value_is and value_not'
	],
	[
		'syslog',
		'a marked holding on any of several names',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'marked' => { 'names' => [ 'brute', 'spray' ] } } ] }, undef
	],
	[
		'syslog',
		'a not_marked with names',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'not_marked' => { 'names' => ['brute'] } } ] },
		'The not_marked gate of the rule "syslog/x" (rule_gates entry 3) has the unknown key "names"'
	],
	[
		'syslog',
		'a sequence with no marks',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'sequence' => { 'var' => 'USER' } } ] },
		'The sequence gate of the rule "syslog/x" (rule_gates entry 3) lacks a marks'
	],
	[
		'syslog',
		'a sequence of one mark',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'sequence' => { 'marks' => ['probe'] } } ] },
		'The sequence gate of the rule "syslog/x" (rule_gates entry 3) has a marks that is not '
			. 'a array of at least two mark names'
	],
	[
		'syslog',
		'a sequence of two marks',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'sequence' => { 'marks' => [ 'probe', 'login' ] } } ] }, undef
	],

	#
	# distinct
	#
	[
		'syslog',
		'a distinct that is a string',
		{ 'distinct' => 'USER' },
		'The distinct of the rule "syslog/x" is not a hash'
	],
	[
		'syslog',
		'a distinct with no of',
		{ 'distinct' => { 'by' => 'SRC' } },
		'The distinct of the rule "syslog/x" lacks a of'
	],
	[
		'syslog',
		'a distinct with a empty by',
		{ 'distinct' => { 'of' => 'USER', 'by' => '' } },
		'The distinct of the rule "syslog/x" has a by that is not a non-empty string'
	],
	[
		'syslog',
		'a distinct with a unknown key',
		{ 'distinct' => { 'of' => 'USER', 'per' => 'SRC' } },
		'The distinct of the rule "syslog/x" has the unknown key "per"'
	],

	#
	# the tracked records
	#
	[
		'syslog',
		'a track with no key',
		{ 'rule_gates' => [ @sshd, { 'track' => { 'name' => 'mail-queue' } }, $ban_src ] },
		'The track gate of the rule "syslog/x" (rule_gates entry 2) lacks a key'
	],
	[
		'syslog',
		'a track with a empty key list',
		{
			'rule_gates' => [ @sshd, { 'track' => { 'name' => 'mail-queue', 'key' => [] } }, $ban_src ]
		},
		'The track gate of the rule "syslog/x" (rule_gates entry 2) has a key that is not '
			. 'a non-empty string or a non-empty array of them'
	],
	[
		'syslog',
		'a track with a fields that is a string',
		{
			'rule_gates' =>
				[ @sshd, { 'track' => { 'name' => 'mail-queue', 'key' => 'QID', 'fields' => 'SRC' } }, $ban_src ]
		},
		'The track gate of the rule "syslog/x" (rule_gates entry 2) has a fields that is not '
			. 'a array of non-empty strings'
	],
	[
		'syslog',
		'a track with a empty fields, which contributes nothing',
		{
			'rule_gates' =>
				[ @sshd, { 'track' => { 'name' => 'mail-queue', 'key' => 'QID', 'fields' => [] } }, $ban_src ]
		},
		undef
	],
	[
		'syslog',
		'a track with a ttl of 0',
		{
			'rule_gates' =>
				[ @sshd, { 'track' => { 'name' => 'mail-queue', 'key' => 'QID', 'ttl' => 0 } }, $ban_src ]
		},
		'The track gate of the rule "syslog/x" (rule_gates entry 2) has a ttl that is not a positive int of seconds'
	],
	[
		'syslog',
		'a tracked with a empty into',
		{
			'rule_gates' => [
				@sshd,
				{ 'tracked' => { 'name' => 'mail-queue', 'into' => [] } },
				{ 'track'   => { 'name' => 'mail-queue', 'key'  => 'QID' } }, $ban_src
			]
		},
		'The tracked gate of the rule "syslog/x" (rule_gates entry 2) has a into that is not ' . $strings
	],

	#
	# the rule_gates list, ahead of what any one gate vets of its own entry
	#
	[
		'syslog',
		'a rule_gates that is a hash',
		{ 'rule_gates' => { 'country' => { 'is' => 'US' } } },
		'The rule_gates of the rule "syslog/x" is not a non-empty array'
	],
	[
		'syslog',
		'a empty rule_gates',
		{ 'rule_gates' => [] },
		'The rule_gates of the rule "syslog/x" is not a non-empty array'
	],
	[
		'syslog',
		'a rule_gates entry that is a string',
		{ 'rule_gates' => [ @sshd, $ban_src, 'country' ] },
		'The rule_gates of the rule "syslog/x" entry 3 is not a hash of one key, the gate type'
	],
	[
		'syslog',
		'a rule_gates entry naming two gates',
		{
			'rule_gates' =>
				[ @sshd, $ban_src, { 'country' => { 'is' => 'US' }, 'marked' => { 'name' => 'brute' } } ]
		},
		'The rule_gates of the rule "syslog/x" entry 3 is not a hash of one key, the gate type'
	],
	[
		'syslog',
		'a rule_gates entry naming a gate there is none of',
		{
			'rule_gates' => [ @sshd, $ban_src, { 'country' => { 'is' => 'US' } }, { 'contry' => { 'is' => 'US' } } ]
		},
		'The rule_gates of the rule "syslog/x" entry 4 names the gate "contry", which is not a known gate type'
	],
	[
		'syslog',
		'a rule_gates entry naming what is not a gate type name',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'Country::Evil' => {} } ] },
		'The rule_gates of the rule "syslog/x" entry 3 names the gate "Country::Evil", which is not a gate type name'
	],
	[
		'syslog',
		'a gate named twice',
		{
			'rule_gates' => [
				@sshd, $ban_src,
				{ 'country' => { 'is' => 'US', 'vars' => 'SRC' } }, { 'country' => { 'isnot' => 'CN' } }
			]
		},
		undef
	],

	#
	# a gate keyed by the offender on a detection rule, which has no offender
	#
	(
		map {
			my ( $gate_type, $told ) = @{$_};
			[
				'syslog',
				'a ' . $gate_type . ' gate keyed by the offender on a detection rule',
				{ 'rule_gates' => [ @sshd, $detect_src, { $gate_type => $told } ] },
				'The '
					. $gate_type
					. ' gate of the rule "syslog/x" (rule_gates entry 3) keys on the offender, '
					. 'which a detection rule does not have... name a var for it to check'
			]
		} (
			[ 'marked',      { 'name'    => 'brute' } ],
			[ 'not_marked',  { 'name'    => 'brute' } ],
			[ 'sequence',    { 'marks'   => [ 'probe', 'login' ] } ],
			[ 'country',     { 'isnot'   => 'US' } ],
			[ 'namtar_list', { 'list'    => 'feed' } ],
			[ 'reverse_dns', { 'matches' => '\.example\.org$' } ],
		)
	),
	[
		'syslog',
		'a gate keyed by a var on a detection rule',
		{
			'rule_gates' => [ @sshd, $detect_src, { 'country' => { 'isnot' => 'US', 'vars' => 'SRC' } } ]
		},
		undef
	],
	[
		'syslog',
		'a active_time gate naming no var on a detection rule, as it keys on the clock',
		{ 'rule_gates' => [ @sshd, $detect_src, { 'active_time' => { 'is' => 'business' } } ] },
		undef
	],

	#
	# the gates the galla judges
	#
	[
		'syslog',
		'a namtar_list entry naming no list',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'namtar_list' => { 'var' => 'SRC' } } ] },
		'The namtar_list gate of the rule "syslog/x" (rule_gates entry 3) has neither list nor lists'
	],
	[
		'syslog',
		'a namtar_list entry with both list and lists',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'namtar_list' => { 'list' => 'feed', 'lists' => ['feed'] } } ] },
		'The namtar_list gate of the rule "syslog/x" (rule_gates entry 3) has both list and lists'
	],
	[
		'syslog',
		'a namtar_list list name with a space',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'namtar_list' => { 'list' => 'threat feed' } } ] },
		'The namtar_list gate of the rule "syslog/x" (rule_gates entry 3) has a list that is not '
			. $name_says
			. ' or a non-empty array of them'
	],
	[
		'syslog',
		'a namtar_list with a empty lists',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'namtar_list' => { 'lists' => [] } } ] },
		'The namtar_list gate of the rule "syslog/x" (rule_gates entry 3) has a lists that is not '
			. $name_says
			. ' or a non-empty array of them'
	],
	[
		'syslog',
		'a namtar_list entry with a empty var',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'namtar_list' => { 'list' => 'feed', 'var' => '' } } ] },
		'The namtar_list gate of the rule "syslog/x" (rule_gates entry 3) has a var that is not a non-empty string'
	],
	[
		'syslog',
		'a reverse_dns entry with nothing to compare against',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'reverse_dns' => { 'var' => 'SRC' } } ] },
		'The reverse_dns gate of the rule "syslog/x" (rule_gates entry 3) has neither matches nor matches_var'
	],
	[
		'syslog',
		'a reverse_dns entry with both matches and matches_var',
		{
			'rule_gates' =>
				[ @sshd, $ban_src, { 'reverse_dns' => { 'matches' => '\.example\.org$', 'matches_var' => 'HELO' } } ]
		},
		'The reverse_dns gate of the rule "syslog/x" (rule_gates entry 3) has both matches and matches_var'
	],
	[
		'syslog',
		'a reverse_dns on_nxdomain that is not a action',
		{
			'rule_gates' =>
				[ @sshd, $ban_src, { 'reverse_dns' => { 'matches' => '\.example\.org$', 'on_nxdomain' => 'drop' } } ]
		},
		'The reverse_dns gate of the rule "syslog/x" (rule_gates entry 3) has a on_nxdomain that is not '
			. 'one of pass, fail, or compare'
	],
	[
		'syslog',
		'a country that is a string',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'country' => 'US' } ] },
		'The country gate of the rule "syslog/x" (rule_gates entry 3) is not a hash'
	],
	[
		'syslog',
		'a country with both is and isnot',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'country' => { 'is' => ['US'], 'isnot' => ['CA'] } } ] },
		'The country gate of the rule "syslog/x" (rule_gates entry 3) has both is and isnot'
	],
	[
		'syslog',
		'a country with nothing to do',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'country' => { 'vars' => ['SRC'] } } ] },
		'The country gate of the rule "syslog/x" (rule_gates entry 3) has none of is, isnot, or into'
	],
	[
		'syslog',
		'a country into with no var',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'country' => { 'into' => 'COUNTRY' } } ] },
		'The country gate of the rule "syslog/x" (rule_gates entry 3) has a into, '
			. 'which needs exactly one var to lift the country of'
	],
	[
		'syslog',
		'a country into with two vars',
		{
			'rule_gates' =>
				[ @sshd, $ban_src, { 'country' => { 'is' => 'US', 'vars' => [ 'SRC', 'DEST' ], 'into' => 'COUNTRY' } } ]
		},
		'The country gate of the rule "syslog/x" (rule_gates entry 3) has a into, '
			. 'which needs exactly one var to lift the country of'
	],
	[
		'syslog',
		'a country that only lifts',
		{ 'rule_gates' => [ @sshd, { 'country' => { 'vars' => 'SRC', 'into' => 'COUNTRY' } }, $ban_src ] }, undef
	],
	[
		'syslog',
		'a country entry of three letters',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'country' => { 'is' => ['USA'] } } ] },
		'The country gate of the rule "syslog/x" (rule_gates entry 3) has a is that is not a 2-letter code or a '
			. '%%%country_codes{name}%%% import, or a non-empty array of them'
	],
	[
		'syslog',
		'a country vars holding a empty string',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'country' => { 'is' => 'US', 'vars' => [''] } } ] },
		'The country gate of the rule "syslog/x" (rule_gates entry 3) has a vars that is not '
			. 'a non-empty string or a non-empty array of them'
	],
	[
		'syslog',
		'a country naming one code and one var bare',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'country' => { 'is' => 'US', 'vars' => 'SRC' } } ] }, undef
	],

	#
	# asn
	#
	[
		'syslog',
		'a asn with two modes',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'asn' => { 'is' => 64496, 'org_isnot' => 'hosting' } } ] },
		'The asn gate of the rule "syslog/x" (rule_gates entry 3) has both is and org_isnot'
	],
	[
		'syslog',
		'a asn with nothing to do',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'asn' => { 'vars' => 'SRC' } } ] },
		'The asn gate of the rule "syslog/x" (rule_gates entry 3) has none of '
			. 'is, isnot, org_is, org_isnot, into, or org_into'
	],
	[
		'syslog',
		'a asn entry that is no number',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'asn' => { 'is' => ['AS-EXAMPLE'] } } ] },
		'The asn gate of the rule "syslog/x" (rule_gates entry 3) has a is that is not a AS number or a '
			. '%%%asn_lists{name}%%% import, or a non-empty array of them'
	],
	[
		'syslog',
		'a asn org_into with no var',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'asn' => { 'org_into' => 'ORG' } } ] },
		'The asn gate of the rule "syslog/x" (rule_gates entry 3) has a into or org_into, '
			. 'which needs exactly one var to lift the network of'
	],
	[
		'syslog',
		'a asn keyed by the offender with no ban_var above it',
		{ 'rule_gates' => [ @sshd, { 'asn' => { 'is' => 'AS64496' } }, $ban_src ] },
		'The asn gate of the rule "syslog/x" (rule_gates entry 2) keys on the offender, '
			. 'and no ban_var above it names one'
	],
	[
		'syslog',
		'a asn that judges and lifts',
		{
			'rule_gates' => [
				@sshd,
				{ 'asn' => { 'isnot' => [ 64496, '%%%asn_lists{office}%%%' ], 'vars' => 'SRC', 'into' => 'ASN' } },
				$ban_src
			]
		},
		undef
	],

	#
	# dnsbl
	#
	[
		'syslog',
		'a dnsbl with no zones',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'dnsbl' => { 'var' => 'SRC' } } ] },
		'The dnsbl gate of the rule "syslog/x" (rule_gates entry 3) lacks a zones'
	],
	[
		'syslog',
		'a dnsbl zone that is no host name',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'dnsbl' => { 'zones' => ['bl example org'] } } ] },
		'The dnsbl gate of the rule "syslog/x" (rule_gates entry 3) has a zones that is not '
			. 'a zone name or a non-empty array of them'
	],
	[
		'syslog',
		'a dnsbl code out of the listing range',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'dnsbl' => { 'zones' => 'bl.example.org', 'codes' => '10.0.0.2' } } ] },
		'The dnsbl gate of the rule "syslog/x" (rule_gates entry 3) has a codes that is not '
			. 'a address out of 127.0.0.0/8 or a non-empty array of them'
	],
	[
		'syslog',
		'a dnsbl on_servfail of compare',
		{
			'rule_gates' =>
				[ @sshd, $ban_src, { 'dnsbl' => { 'zones' => 'bl.example.org', 'on_servfail' => 'compare' } } ]
		},
		'The dnsbl gate of the rule "syslog/x" (rule_gates entry 3) has a on_servfail that is not one of pass or fail'
	],
	[
		'syslog',
		'a dnsbl of one zone and one code',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'dnsbl' => { 'zones' => 'bl.example.org', 'codes' => '127.0.0.2' } } ] },
		undef
	],

	#
	# account
	#
	[
		'syslog',
		'a account with no var',
		{ 'rule_gates' => [ @sshd, { 'account' => { 'exists' => 0 } }, $ban_src ] },
		'The account gate of the rule "syslog/x" (rule_gates entry 2) lacks a var'
	],
	[
		'syslog',
		'a account with a unknown key',
		{ 'rule_gates' => [ @sshd, { 'account' => { 'var' => 'USER', 'negate' => 1 } }, $ban_src ] },
		'The account gate of the rule "syslog/x" (rule_gates entry 2) has the unknown key "negate"'
	],
	[
		'syslog',
		'a account told to hold on none and to ask its shell',
		{ 'rule_gates' => [ @sshd, { 'account' => { 'var' => 'USER', 'exists' => 0, 'shell' => 'nologin' } }, $ban_src ] },
		'The account gate of the rule "syslog/x" (rule_gates entry 2) has a exists of false and a shell, '
			. 'and nothing can be asked of a account that is none'
	],
	[
		'syslog',
		'a account shell that is neither',
		{ 'rule_gates' => [ @sshd, { 'account' => { 'var' => 'USER', 'shell' => '/bin/sh' } }, $ban_src ] },
		'The account gate of the rule "syslog/x" (rule_gates entry 2) has a shell that is not one of nologin or login'
	],
	[
		'syslog',
		'a account asked everything',
		{
			'rule_gates' => [
				@sshd,
				{
					'account' => {
						'var' => 'USER', 'shell' => 'login', 'system' => 0, 'system_below' => 500, 'group' => [ 'wheel', 'sudo' ]
					}
				},
				$ban_src
			]
		},
		undef
	],
	[
		'syslog',
		'a account above the ban_var',
		{ 'rule_gates' => [ @sshd, { 'account' => { 'var' => 'USER', 'exists' => 0 } }, $ban_src ] }, undef
	],

	#
	# limit
	#
	[
		'syslog',
		'a limit with no by',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'limit' => { 'seconds' => 60 } } ] },
		'The limit gate of the rule "syslog/x" (rule_gates entry 3) lacks a by'
	],
	[
		'syslog',
		'a limit with no seconds',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'limit' => { 'by' => 'SRC' } } ] },
		'The limit gate of the rule "syslog/x" (rule_gates entry 3) lacks a seconds'
	],
	[
		'syslog',
		'a limit count of zero',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'limit' => { 'by' => 'SRC', 'seconds' => 60, 'count' => 0 } } ] },
		'The limit gate of the rule "syslog/x" (rule_gates entry 3) has a count that is not a positive int'
	],
	[
		'syslog',
		'a limit above the ban_var',
		{ 'rule_gates' => [ @sshd, { 'limit' => { 'by' => [ 'SRC', 'USER' ], 'seconds' => 60 } }, $ban_src ] }, undef
	],

	#
	# after
	#
	[
		'syslog',
		'a after with no count',
		{ 'rule_gates' => [ @sshd, { 'after' => { 'by' => 'USER', 'seconds' => 600 } }, $ban_src ] },
		'The after gate of the rule "syslog/x" (rule_gates entry 2) lacks a count'
	],
	[
		'syslog',
		'a after count of one',
		{ 'rule_gates' => [ @sshd, { 'after' => { 'by' => 'USER', 'count' => 1, 'seconds' => 600 } }, $ban_src ] },
		'The after gate of the rule "syslog/x" (rule_gates entry 2) has a count that is not a int of two or more'
	],
	[
		'syslog',
		'a after above the ban_var',
		{ 'rule_gates' => [ @sshd, { 'after' => { 'by' => 'USER', 'count' => 20, 'seconds' => 600 } }, $ban_src ] },
		undef
	],

	#
	# network and sum
	#
	[
		'syslog',
		'a network with no into',
		{ 'rule_gates' => [ @sshd, { 'network' => { 'var' => 'SRC' } }, $ban_src ] },
		'The network gate of the rule "syslog/x" (rule_gates entry 2) lacks a into'
	],
	[
		'syslog',
		'a network v4 past what a IPv4 address has bits for',
		{ 'rule_gates' => [ @sshd, { 'network' => { 'var' => 'SRC', 'into' => 'NET', 'v4' => 48 } }, $ban_src ] },
		'The network gate of the rule "syslog/x" (rule_gates entry 2) has a v4 that is not a prefix length of 1 to 32'
	],
	[
		'syslog',
		'a network above a after that counts by it',
		{
			'rule_gates' => [
				@sshd,
				{ 'network' => { 'var' => 'SRC', 'into'  => 'NET', 'v4' => 16, 'v6' => 48 } },
				{ 'after'   => { 'by'  => 'NET', 'count' => 30,    'seconds' => 600 } },
				$ban_src
			]
		},
		undef
	],
	[
		'syslog',
		'a sum with no of',
		{ 'rule_gates' => [ @sshd, { 'sum' => { 'by' => 'SRC', 'above' => 1000, 'seconds' => 60 } }, $ban_src ] },
		'The sum gate of the rule "syslog/x" (rule_gates entry 2) lacks a of'
	],
	[
		'syslog',
		'a sum above of nothing',
		{
			'rule_gates' =>
				[ @sshd, { 'sum' => { 'by' => 'SRC', 'of' => 'bytes', 'above' => 0, 'seconds' => 60 } }, $ban_src ]
		},
		'The sum gate of the rule "syslog/x" (rule_gates entry 2) has a above that is not a positive number'
	],
	[
		'syslog',
		'a sum above the ban_var',
		{
			'rule_gates' =>
				[ @sshd, { 'sum' => { 'by' => 'SRC', 'of' => 'bytes', 'above' => 1000.5, 'seconds' => 60 } }, $ban_src ]
		},
		undef
	],

	#
	# what more a marked may ask, and a track's tally
	#
	[
		'syslog',
		'a marked hosts of nothing',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'marked' => { 'name' => 'recon', 'hosts' => 0 } } ] },
		'The marked gate of the rule "syslog/x" (rule_gates entry 3) has a hosts that is not a positive int'
	],
	[
		'syslog',
		'a marked newer_than that is no number',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'marked' => { 'name' => 'recon', 'newer_than' => 'soon' } } ] },
		'The marked gate of the rule "syslog/x" (rule_gates entry 3) has a newer_than that is not a positive int of seconds'
	],
	[
		'syslog',
		'a marked asking the age and the hosts',
		{
			'rule_gates' => [
				@sshd, $ban_src,
				{ 'marked' => { 'name' => 'recon', 'older_than' => 60, 'newer_than' => 3600, 'hosts' => 3 } }
			]
		},
		undef
	],
	[
		'syslog',
		'a track count that is no name',
		{ 'rule_gates' => [ @sshd, { 'track' => { 'name' => 'client', 'key' => 'SRC', 'count' => [] } }, $ban_src ] },
		'The track gate of the rule "syslog/x" (rule_gates entry 2) has a count that is not a non-empty string'
	],

	#
	# epoch, fresh, novel, and banished
	#
	[
		'syslog',
		'a epoch with neither a var nor a into',
		{ 'rule_gates' => [ { 'epoch' => { 'format' => 'auto' } }, @sshd, $ban_src ] },
		'The epoch gate of the rule "syslog/x" (rule_gates entry 0) has neither a var nor a into, '
			. 'and the line\'s own timestamp is no field to convert where it is'
	],
	[
		'syslog',
		'a epoch zone that is a place',
		{ 'rule_gates' => [ { 'epoch' => { 'into' => 'WHEN', 'zone' => 'Europe/Paris' } }, @sshd, $ban_src ] },
		'The epoch gate of the rule "syslog/x" (rule_gates entry 0) has a zone that is not local, utc, or a offset as +02:00'
	],
	[
		'syslog',
		'a fresh with no within',
		{ 'rule_gates' => [ { 'epoch' => { 'into' => 'WHEN' } }, { 'fresh' => { 'var' => 'WHEN' } }, @sshd, $ban_src ] },
		'The fresh gate of the rule "syslog/x" (rule_gates entry 1) lacks a within'
	],
	[
		'syslog',
		'a epoch and a fresh ahead of the matcher',
		{
			'rule_gates' => [
				{ 'epoch' => { 'into' => 'WHEN', 'format' => '%b %d %H:%M:%S', 'zone' => '-05:00' } },
				{ 'fresh' => { 'var'  => 'WHEN', 'within' => 300, 'on_unparsed' => 'pass' } },
				@sshd, $ban_src
			]
		},
		undef
	],
	[
		'syslog',
		'a novel with no of',
		{ 'rule_gates' => [ @sshd, { 'novel' => { 'name' => 'seen', 'by' => 'USER' } }, $ban_src ] },
		'The novel gate of the rule "syslog/x" (rule_gates entry 2) lacks a of'
	],
	[
		'syslog',
		'a novel on a detection rule',
		{
			'rule_gates' => [
				@sshd,
				{ 'novel' => { 'name' => 'seen', 'by' => [ 'USER', 'SRC' ], 'of' => 'USER', 'ttl' => 60, 'after_seen' => 1 } },
				$detect_src
			]
		},
		undef
	],
	[
		'syslog',
		'a banished that asks nothing',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'banished' => { 'var' => 'SRC' } } ] },
		'The banished gate of the rule "syslog/x" (rule_gates entry 3) has neither now nor times'
	],
	[
		'syslog',
		'a banished of the offender on a detection rule',
		{ 'rule_gates' => [ @sshd, $detect_src, { 'banished' => { 'now' => 1 } } ] },
		'The banished gate of the rule "syslog/x" (rule_gates entry 3) keys on the offender, '
			. 'which a detection rule does not have... name a var for it to check'
	],
	[
		'syslog',
		'a banished asking both',
		{
			'rule_gates' =>
				[ @sshd, $ban_src, { 'banished' => { 'now' => 0, 'times' => 3, 'within' => 2592000 } } ]
		},
		undef
	],
	[
		'syslog',
		'a pressure by what is usual',
		{
			'rule_gates' =>
				[ { 'pressure' => { 'times' => 5, 'above' => 20, 'seconds' => 60, 'baseline' => 3600 } }, @sshd, $ban_src ]
		},
		undef
	],
	[
		'syslog',
		'a pressure times with no baseline',
		{ 'rule_gates' => [ { 'pressure' => { 'times' => 5, 'seconds' => 60 } }, @sshd, $ban_src ] },
		'The pressure gate of the rule "syslog/x" (rule_gates entry 0) has a times with out a baseline, '
			. 'or a baseline with out a times'
	],

	#
	# address, beacon, sample, account near, and the epoch lifts
	#
	[
		'syslog',
		'a address of a kind there is none of',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'address' => { 'is' => 'reserved' } } ] },
		'The address gate of the rule "syslog/x" (rule_gates entry 3) has a is that is not one of '
			. 'bogon, cgnat, documentation, link_local, loopback, multicast, private, or a non-empty array of them'
	],
	[
		'syslog',
		'a address of the offender with no ban_var above it',
		{ 'rule_gates' => [ @sshd, { 'address' => { 'isnot' => 'bogon' } }, $ban_src ] },
		'The address gate of the rule "syslog/x" (rule_gates entry 2) keys on the offender, '
			. 'and no ban_var above it names one'
	],
	[
		'syslog',
		'a address by a var above the ban_var',
		{ 'rule_gates' => [ @sshd, { 'address' => { 'var' => 'SRC', 'is' => [ 'bogon', 'cgnat' ] } }, $ban_src ] }, undef
	],
	[
		'syslog',
		'a beacon count of one',
		{ 'rule_gates' => [ @sshd, { 'beacon' => { 'by' => 'SRC', 'count' => 1 } }, $ban_src ] },
		'The beacon gate of the rule "syslog/x" (rule_gates entry 2) has a count that is not a int of two or more'
	],
	[
		'syslog',
		'a beacon on a detection rule',
		{
			'rule_gates' => [
				@sshd,
				{ 'beacon' => { 'by' => [ 'SRC', 'USER' ], 'count' => 10, 'jitter' => 0.05, 'min_interval' => 60, 'max_interval' => 7200 } },
				$detect_src
			]
		},
		undef
	],
	[
		'syslog',
		'a sample with no every',
		{ 'rule_gates' => [ @sshd, $detect_src, { 'sample' => {} } ] },
		'The sample gate of the rule "syslog/x" (rule_gates entry 3) lacks a every'
	],
	[
		'syslog',
		'a sample on a detection rule',
		{ 'rule_gates' => [ @sshd, $detect_src, { 'sample' => { 'every' => 100 } } ] }, undef
	],
	[
		'syslog',
		'a account near beside a exists of true',
		{ 'rule_gates' => [ @sshd, { 'account' => { 'var' => 'USER', 'near' => 1 } }, $ban_src ] },
		'The account gate of the rule "syslog/x" (rule_gates entry 2) has a near with out a exists of false, '
			. 'a name near a account being one that is none'
	],
	[
		'syslog',
		'a account near beside a exists of false',
		{ 'rule_gates' => [ @sshd, { 'account' => { 'var' => 'USER', 'exists' => 0, 'near' => 2 } }, $ban_src ] }, undef
	],
	[
		'syslog',
		'a epoch lifting only the hour and the day',
		{ 'rule_gates' => [ @sshd, { 'epoch' => { 'hour_into' => 'HOUR', 'weekday_into' => 'DAY' } }, $ban_src ] }, undef
	],

	#
	# extract, forwarded, concurrent, digest, and eve_line
	#
	[
		'json',
		'a extract with no named capture',
		{ 'rule_gates' => [ $event_gate, { 'extract' => { 'var' => 'user', 'regexp' => '@.+$' } }, $ban_ip ] },
		'The extract gate of the rule "json/x" (rule_gates entry 1) has a regexp with no named capture, which would lift nothing'
	],
	[
		'json',
		'a extract on_miss that is neither',
		{ 'rule_gates' => [ $event_gate, { 'extract' => { 'var' => 'user', 'regexp' => '(?<D>.+)', 'on_miss' => 'drop' } }, $ban_ip ] },
		'The extract gate of the rule "json/x" (rule_gates entry 1) has a on_miss that is not one of pass or fail'
	],
	[
		'json',
		'a extract above the gate',
		{ 'rule_gates' => [ { 'extract' => { 'var' => 'user', 'regexp' => '@(?<D>.+)$', 'on_miss' => 'fail' } }, $event_gate, $ban_ip ] },
		undef
	],
	[
		'json',
		'a forwarded with a trusted that is no CIDR',
		{ 'rule_gates' => [ $event_gate, { 'forwarded' => { 'var' => 'xff', 'peer' => 'host', 'trusted' => 'the lb', 'into' => 'C' } }, $ban_ip ] },
		'The forwarded gate of the rule "json/x" (rule_gates entry 1) trusted entry "the lb" is not a IPv4 or IPv6 address or CIDR'
	],
	[
		'json',
		'a forwarded above the ban_var it feeds',
		{
			'rule_gates' => [
				$event_gate,
				{ 'forwarded' => { 'var' => 'xff', 'peer' => 'host', 'trusted' => [ '10.0.0.0/8', 'fd00::/8' ], 'into' => 'CLIENT', 'max_hops' => 4 } },
				{ 'ban_var'   => ['CLIENT'] }
			]
		},
		undef
	],
	[
		'json',
		'a concurrent with no of',
		{ 'rule_gates' => [ $event_gate, { 'concurrent' => { 'by' => 'user', 'more_than' => 2, 'seconds' => 600 } }, $ban_ip ] },
		'The concurrent gate of the rule "json/x" (rule_gates entry 1) lacks a of'
	],
	[
		'json',
		'a digest of what a ban_var names',
		{ 'rule_gates' => [ $event_gate, { 'digest' => { 'var' => 'ip' } }, $ban_ip ] },
		'The digest gate of the rule "json/x" (rule_gates entry 1) hashes ip, which a ban_var names, and a ban has to be of the address itself'
	],
	[
		'json',
		'a digest in place of what a account reads',
		{ 'rule_gates' => [ $event_gate, { 'digest' => { 'var' => 'user' } }, { 'account' => { 'var' => 'user', 'exists' => 0 } }, $ban_ip ] },
		'The digest gate of the rule "json/x" (rule_gates entry 1) hashes user where it is, and the account gate that reads it '
			. 'would only ever see the hash... give it a into'
	],
	[
		'json',
		'a digest into beside a account',
		{
			'eve_line'   => 0,
			'rule_gates' => [
				$event_gate,
				{ 'digest'  => { 'var' => 'user', 'into' => 'USER_ID' } },
				{ 'account' => { 'var' => 'user', 'exists' => 0 } },
				{ 'concurrent' => { 'by' => 'USER_ID', 'of' => 'ip', 'more_than' => 2, 'seconds' => 600 } },
				$ban_ip
			]
		},
		undef
	],
	[
		'json',
		'a eve_line that is no boolean',
		{ 'eve_line' => [], 'rule_gates' => [ $event_gate, $ban_ip ] },
		'The rule "json/x" has a eve_line that is not a boolean'
	],

	#
	# scored and startup
	#
	[
		'syslog',
		'a scored of the offender with no ban_var above it',
		{ 'rule_gates' => [ @sshd, { 'scored' => { 'above' => 8 } }, $ban_src ] },
		'The scored gate of the rule "syslog/x" (rule_gates entry 2) keys on the offender, and no ban_var above it names one'
	],
	[
		'syslog',
		'a scored by a var on a detection rule',
		{ 'rule_gates' => [ @sshd, { 'scored' => { 'above' => 2.5, 'seconds' => 600, 'var' => 'SRC' } }, $detect_src ] }, undef
	],
	[
		'syslog',
		'a startup with no grace',
		{ 'rule_gates' => [ { 'startup' => {} }, @sshd, $ban_src ] },
		'The startup gate of the rule "syslog/x" (rule_gates entry 0) lacks a grace'
	],
	[
		'syslog',
		'a startup leading the list',
		{ 'rule_gates' => [ { 'startup' => { 'grace' => 120 } }, @sshd, $ban_src ] }, undef
	],

	#
	# normalize
	#
	[
		'http',
		'a normalize with no ops',
		{ 'rule_gates' => [ $status, { 'normalize' => { 'var' => 'path', 'into' => 'PATH' } }, $ban_host ] },
		'The normalize gate of the rule "http/x" (rule_gates entry 1) lacks a ops'
	],
	[
		'http',
		'a normalize with both kinds of dot_segment',
		{ 'rule_gates' => [ $status, { 'normalize' => { 'var' => 'path', 'into' => 'PATH', 'ops' => [ 'dot_segment', 'dot_segment_below' ] } }, $ban_host ] },
		'The normalize gate of the rule "http/x" (rule_gates entry 1) names both dot_segment and dot_segment_below, '
			. 'which resolve a .. above / two ways'
	],
	[
		'http',
		'a normalize ahead of a match on what it lifts',
		{
			'rule_gates' => [
				$status,
				{ 'normalize' => { 'var' => 'path', 'into' => 'PATH', 'ops' => [ 'lower', 'url', 'dot_segment_below', 'params', 'nul' ] } },
				{ 'match' => [ { 'field' => 'PATH', 'regexp' => '^/\.\./' } ] },
				$ban_host
			]
		},
		undef
	],

	#
	# breadth and weigh
	#
	[
		'syslog',
		'a breadth of one rule',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'breadth' => { 'rules' => 1, 'seconds' => 3600 } } ] },
		'The breadth gate of the rule "syslog/x" (rule_gates entry 3) has a rules that is not a int of two or more'
	],
	[
		'syslog',
		'a breadth of the offender with no ban_var above it',
		{ 'rule_gates' => [ @sshd, { 'breadth' => { 'rules' => 3, 'seconds' => 3600 } }, $ban_src ] },
		'The breadth gate of the rule "syslog/x" (rule_gates entry 2) keys on the offender, and no ban_var above it names one'
	],
	[
		'syslog',
		'a breadth of some rules by a var',
		{
			'rule_gates' =>
				[ @sshd, { 'breadth' => { 'rules' => 2, 'seconds' => 3600, 'var' => 'SRC', 'of' => [ 'syslog/vsftpd', 'http/scan' ] } }, $detect_src ]
		},
		undef
	],
	[
		'syslog',
		'a weigh with both times and by',
		{ 'rule_gates' => [ @sshd, { 'weigh' => { 'times' => 2, 'by' => 'score' } }, $ban_src ] },
		'The weigh gate of the rule "syslog/x" (rule_gates entry 2) has both times and by'
	],
	[
		'syslog',
		'a weigh with a when',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'weigh' => { 'times' => 2.5, 'when' => [ { 'field' => 'USER', 'op' => 'eq', 'value' => 'root' } ] } } ] },
		undef
	],

	#
	# travel
	#
	[
		'syslog',
		'a travel with no speed',
		{ 'rule_gates' => [ @sshd, { 'travel' => { 'name' => 'last-login', 'by' => 'USER', 'var' => 'SRC' } }, $ban_src ] },
		'The travel gate of the rule "syslog/x" (rule_gates entry 2) lacks a faster_than_kmh'
	],
	[
		'syslog',
		'a travel speed of nothing',
		{
			'rule_gates' => [
				@sshd,
				{ 'travel' => { 'name' => 'last-login', 'by' => 'USER', 'var' => 'SRC', 'faster_than_kmh' => 0 } },
				$ban_src
			]
		},
		'The travel gate of the rule "syslog/x" (rule_gates entry 2) has a faster_than_kmh that is not a positive number'
	],
	[
		'syslog',
		'a travel name with a space',
		{
			'rule_gates' => [
				@sshd,
				{ 'travel' => { 'name' => 'last login', 'by' => 'USER', 'var' => 'SRC', 'faster_than_kmh' => 900 } },
				$ban_src
			]
		},
		'The travel gate of the rule "syslog/x" (rule_gates entry 2) has a name that is not ' . $name_says
	],
	[
		'syslog',
		'a travel on a detection rule',
		{
			'rule_gates' => [
				@sshd,
				{
					'travel' => {
						'name'            => 'last-login',
						'by'              => [ 'USER', 'SRC' ],
						'var'             => 'SRC',
						'faster_than_kmh' => 900.5,
						'min_km'          => 250,
						'km_into'         => 'KM'
					}
				},
				$detect_src
			]
		},
		undef
	],

	#
	# forgive
	#
	[
		'syslog',
		'a forgive with no rules',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'forgive' => { 'same' => 'USER' } } ] },
		'The forgive gate of the rule "syslog/x" (rule_gates entry 3) lacks a rules'
	],
	[
		'syslog',
		'a forgive naming a group',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'forgive' => { 'rules' => ['%syslog/sshd%'] } } ] },
		'The forgive gate of the rule "syslog/x" (rule_gates entry 3) has a rules that is not '
			. 'a rule name or a non-empty array of them'
	],
	[
		'syslog',
		'a forgive of the offender with no ban_var above it',
		{ 'rule_gates' => [ @sshd, { 'forgive' => { 'rules' => 'syslog/sshd' } }, $ban_src ] },
		'The forgive gate of the rule "syslog/x" (rule_gates entry 2) keys on the offender, '
			. 'and no ban_var above it names one'
	],
	[
		'syslog',
		'a forgive of the offender on a detection rule',
		{ 'rule_gates' => [ @sshd, $detect_src, { 'forgive' => { 'rules' => 'syslog/sshd' } } ] },
		'The forgive gate of the rule "syslog/x" (rule_gates entry 3) keys on the offender, '
			. 'which a detection rule does not have... name a var for it to check'
	],
	[
		'syslog',
		'a forgive by a var on a detection rule',
		{
			'rule_gates' =>
				[ @sshd, { 'forgive' => { 'rules' => 'syslog/sshd', 'var' => 'SRC', 'same' => 'USER' } }, $detect_src ]
		},
		undef
	],

	#
	# pressure
	#
	[
		'syslog',
		'a pressure with no above',
		{ 'rule_gates' => [ { 'pressure' => { 'seconds' => 60 } }, @sshd, $ban_src ] },
		'The pressure gate of the rule "syslog/x" (rule_gates entry 0) has neither above nor times'
	],
	[
		'syslog',
		'a pressure scope that is no scope',
		{ 'rule_gates' => [ { 'pressure' => { 'above' => 200, 'seconds' => 60, 'scope' => 'kur' } }, @sshd, $ban_src ] },
		'The pressure gate of the rule "syslog/x" (rule_gates entry 0) has a scope that is not one of watcher or galla'
	],
	[
		'syslog',
		'a pressure leading the list',
		{ 'rule_gates' => [ { 'pressure' => { 'above' => 200, 'seconds' => 60, 'hold' => 300 } }, @sshd, $ban_src ] },
		undef
	],
	[
		'json',
		'a pressure on a json rule, below the gate',
		{ 'rule_gates' => [ $event_gate, { 'pressure' => { 'above' => 200, 'seconds' => 60 } }, $ban_ip ] }, undef
	],
	[
		'syslog',
		'a active_time window name with a space',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'active_time' => { 'is' => ['business hours'] } } ] },
		'The active_time gate of the rule "syslog/x" (rule_gates entry 3) has a is that is not '
			. $name_says
			. ' or a non-empty array of them'
	],

	#
	# the regexp matchers of the syslog and raw types
	#
	[
		'syslog',
		'a keyed message_regexp entry with a unknown key',
		{
			'rule_gates' => [
				$daemons,
				{ 'message_regexp' => [ { 'regexp' => '^conn(?<KEY>\d+) failed', 'key' => 'KEY', 'defre' => 5 } ] },
				$ban_src
			]
		},
		'The message_regexp gate of the rule "syslog/x" (rule_gates entry 1) entry 0 has the unknown key "defre"'
	],
	[
		'syslog',
		'a hash message_regexp entry with no key',
		{
			'rule_gates' =>
				[ $daemons, { 'message_regexp' => [ { 'regexp' => '^conn(?<KEY>\d+) failed' } ] }, $ban_src ]
		},
		'The message_regexp gate of the rule "syslog/x" (rule_gates entry 1) entry 0 lacks a key'
	],
	[
		'syslog',
		'a hash message_regexp entry with no regexp',
		{ 'rule_gates' => [ $daemons, { 'message_regexp' => [ { 'key' => 'KEY' } ] }, $ban_src ] },
		'The message_regexp gate of the rule "syslog/x" (rule_gates entry 1) entry 0 lacks a regexp'
	],
	[
		'syslog',
		'a hash message_regexp entry whose regexp is a array',
		{
			'rule_gates' =>
				[ $daemons, { 'message_regexp' => [ { 'regexp' => ['^conn'], 'key' => 'KEY' } ] }, $ban_src ]
		},
		'The message_regexp gate of the rule "syslog/x" (rule_gates entry 1) entry 0 has a regexp that is not a string'
	],
	[
		'syslog',
		'a message_regexp entry with a defer of 0',
		{
			'rule_gates' => [
				$daemons,
				{ 'message_regexp' => [ { 'regexp' => '^conn(?<KEY>\d+) failed', 'key' => 'KEY', 'defer' => 0 } ] },
				$ban_src
			]
		},
		'The message_regexp gate of the rule "syslog/x" (rule_gates entry 1) entry 0 has a defer that is not '
			. 'a positive int of seconds'
	],
	[
		'syslog',
		'a message_regexp entry that is a array',
		{
			'rule_gates' =>
				[ $daemons, { 'message_regexp' => [ '^bad thing from %%%%SRC%%%%', ['^worse'] ] }, $ban_src ]
		},
		'The message_regexp gate of the rule "syslog/x" (rule_gates entry 1) entry 1 is not a string or a hash'
	],
	[
		'syslog',
		'a capture_regexp that is a hash',
		{
			'rule_gates' => [
				$daemons,
				{ 'capture_regexp' => { 'regexp' => '^conn(?<KEY>\d+) from %%%%SRC%%%%', 'key' => 'KEY' } },
				$matcher, $ban_src
			]
		},
		'The capture_regexp gate of the rule "syslog/x" (rule_gates entry 1) is not a non-empty array'
	],
	[
		'syslog',
		'a capture_regexp entry with no key',
		{
			'rule_gates' => [
				$daemons, { 'capture_regexp' => [ { 'regexp' => '^conn(?<KEY>\d+) from %%%%SRC%%%%' } ] },
				$matcher, $ban_src
			]
		},
		'The capture_regexp gate of the rule "syslog/x" (rule_gates entry 1) entry 0 lacks a key'
	],
	[
		'syslog',
		'a capture_regexp entry with a ttl of 0',
		{
			'rule_gates' => [
				$daemons,
				{
					'capture_regexp' =>
						[ { 'regexp' => '^conn(?<KEY>\d+) from %%%%SRC%%%%', 'key' => 'KEY', 'ttl' => 0 } ]
				},
				$matcher, $ban_src
			]
		},
		'The capture_regexp gate of the rule "syslog/x" (rule_gates entry 1) entry 0 has a ttl that is not '
			. 'a positive int of seconds'
	],
	[
		'syslog',
		'a capture_regexp entry whose regexp is a hash',
		{
			'rule_gates' => [
				$daemons, { 'capture_regexp' => [ { 'regexp' => { 'pattern' => '^conn' }, 'key' => 'KEY' } ] },
				$matcher, $ban_src
			]
		},
		'The capture_regexp gate of the rule "syslog/x" (rule_gates entry 1) entry 0 has a regexp that is not a string'
	],
	[
		'syslog',
		'a stages that is the bare list of them',
		{
			'rule_gates' =>
				[ $daemons, { 'stages' => [ { 'message_regexp' => ['^probe from %%%%SRC%%%%'] } ] }, $ban_src ]
		},
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) is not a hash'
	],
	[
		'syslog',
		'a stages with a per and no stages',
		{ 'rule_gates' => [ $daemons, { 'stages' => { 'per' => 'SRC' } }, $ban_src ] },
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) lacks a stages'
	],
	[
		'syslog',
		'a stages with a unknown key',
		{ 'rule_gates' => [ $daemons, { 'stages' => { 'stages' => [$probe_stage], 'pre' => 'SRC' } }, $ban_src ] },
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) has the unknown key "pre"'
	],
	[
		'syslog',
		'a stages whose stages is a hash',
		{ 'rule_gates' => [ $daemons, { 'stages' => { 'stages' => $probe_stage } }, $ban_src ] },
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) stages is not a non-empty array'
	],
	[
		'syslog',
		'a stages with a per that is a empty array',
		{ 'rule_gates' => [ $daemons, { 'stages' => { 'stages' => [$probe_stage], 'per' => [] } }, $ban_src ] },
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) per has a empty key array'
	],
	[
		'syslog',
		'a stages with a per and its stages',
		{ 'rule_gates' => [ $daemons, { 'stages' => { 'stages' => [$probe_stage], 'per' => 'SRC' } }, $ban_src ] },
		undef
	],
	[
		'syslog',
		'a stage with no message_regexp',
		{ 'rule_gates' => [ $daemons, { 'stages' => { 'stages' => [ { 'count' => 2 } ] } }, $ban_src ] },
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) stages entry 0 lacks a message_regexp'
	],
	[
		'syslog',
		'a stage with a empty message_regexp',
		{ 'rule_gates' => [ $daemons, { 'stages' => { 'stages' => [ { 'message_regexp' => [] } ] } }, $ban_src ] },
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) stages entry 0 has a message_regexp '
			. 'that is not a non-empty array of regexp strings'
	],
	[
		'syslog',
		'a stage with a count of 0',
		{
			'rule_gates' =>
				[ $daemons, { 'stages' => { 'stages' => [ { %{$probe_stage}, 'count' => 0 } ] } }, $ban_src ]
		},
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) stages entry 0 has a count '
			. 'that is not a positive int'
	],
	[
		'syslog',
		'a stage with a unknown key',
		{
			'rule_gates' =>
				[ $daemons, { 'stages' => { 'stages' => [ { %{$probe_stage}, 'withn' => 5 } ] } }, $ban_src ]
		},
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) stages entry 0 has the unknown key "withn"'
	],

	#
	# keywords
	#
	[
		'syslog',
		'a keywords with a empty in',
		{
			'rule_gates' => [ @sshd, { 'keywords' => { 'in' => '', 'values' => ['denied'] } }, $ban_src ]
		},
		'The keywords gate of the rule "syslog/x" (rule_gates entry 2) has a in that is not a non-empty string'
	],
	[
		'syslog',
		'a keywords with a unknown key',
		{
			'rule_gates' => [ @sshd, { 'keywords' => { 'inn' => 'MESSAGE', 'values' => ['denied'] } }, $ban_src ]
		},
		'The keywords gate of the rule "syslog/x" (rule_gates entry 2) has the unknown key "inn"'
	],

	#
	# the json type's correlation layer and the match and ignore entries it
	# shares with the http type
	#
	[
		'json',
		'a capture with neither gate nor match',
		{ 'rule_gates' => [ { 'capture' => [ { 'key' => 'session' } ] }, $event_gate, $ban_ip ] },
		'The capture gate of the rule "json/x" (rule_gates entry 0) entry 0 has neither gate nor match, '
			. 'so it would harvest every line'
	],
	[
		'json',
		'a capture with no key',
		{ 'rule_gates' => [ { 'capture' => [ { 'gate' => $gate } ] }, $event_gate, $ban_ip ] },
		'The capture gate of the rule "json/x" (rule_gates entry 0) entry 0 lacks a key'
	],
	[
		'json',
		'a capture with a ttl that is a word',
		{
			'rule_gates' =>
				[ { 'capture' => [ { 'key' => 'session', 'gate' => $gate, 'ttl' => 'soon' } ] }, $event_gate, $ban_ip ]
		},
		'The capture gate of the rule "json/x" (rule_gates entry 0) entry 0 has a ttl that is not '
			. 'a positive int of seconds'
	],
	[
		'json',
		'a capture match entry with no regexp',
		{
			'rule_gates' => [
				{ 'capture' => [ { 'key' => 'session', 'match' => [ { 'field' => 'msg' } ] } ] },
				$event_gate, $ban_ip
			]
		},
		'The capture gate of the rule "json/x" (rule_gates entry 0) entry 0 match entry 0 lacks a regexp'
	],
	[
		'json',
		'a capture match entry whose regexp is a array',
		{
			'rule_gates' => [
				{
					'capture' =>
						[ { 'key' => 'session', 'match' => [ { 'field' => 'msg', 'regexp' => ['^login'] } ] } ]
				},
				$event_gate,
				$ban_ip
			]
		},
		'The capture gate of the rule "json/x" (rule_gates entry 0) entry 0 match entry 0 '
			. 'has a regexp that is not a string'
	],
	[
		'json',
		'a defer of 0',
		{ 'rule_gates' => [ $event_gate, { 'key' => { 'key' => 'session', 'defer' => 0 } }, $ban_ip ] },
		'The key gate of the rule "json/x" (rule_gates entry 1) has a defer that is not a positive int of seconds'
	],
	[
		'json',
		'a match entry with no regexp',
		{ 'rule_gates' => [ $event_gate, { 'match' => [ { 'field' => 'msg' } ] }, $ban_ip ] },
		'The match gate of the rule "json/x" (rule_gates entry 1) entry 0 lacks a regexp'
	],
	[
		'json',
		'a ignore that is a hash',
		{
			'rule_gates' =>
				[ { 'ignore' => { 'field' => 'msg', 'regexp' => '^healthcheck' } }, $event_gate, $ban_ip ]
		},
		'The ignore gate of the rule "json/x" (rule_gates entry 0) is not a non-empty array'
	],
	[
		'http',
		'a match entry whose regexp is a hash',
		{
			'rule_gates' => [
				$status, { 'match' => [ { 'field' => 'request', 'regexp' => { 'pattern' => '^/wp-login' } } ] },
				$ban_host
			]
		},
		'The match gate of the rule "http/x" (rule_gates entry 1) entry 0 has a regexp that is not a string'
	],
	[
		'http',
		'a match entry with a unknown key',
		{
			'rule_gates' => [
				$status, { 'match' => [ { 'field' => 'request', 'regexp' => '^/wp-login', 'nocase' => 1 } ] },
				$ban_host
			]
		},
		'The match gate of the rule "http/x" (rule_gates entry 1) entry 0 has the unknown key "nocase"'
	],
);

foreach my $case (@cases) {
	my ( $type, $description, $keys, $expected ) = @{$case};
	is( load_error( $type, $keys ), $expected, $description );
}

# a def that is no hash at all, which no case above can build
my $not_a_hash = eval { App::Baphomet::Rule->new( 'name' => 'syslog/x', 'def' => ['daemons'] ); 1 } ? '' : $@;
like( $not_a_hash, qr/^The rule "syslog\/x" is not a hash at /, 'a def that is a array' );

done_testing;
