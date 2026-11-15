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
		'a country with neither is nor isnot',
		{ 'rule_gates' => [ @sshd, $ban_src, { 'country' => { 'vars' => ['SRC'] } } ] },
		'The country gate of the rule "syslog/x" (rule_gates entry 3) has neither is nor isnot'
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
		'a stages that is a hash',
		{
			'rule_gates' =>
				[ $daemons, { 'stages' => { 'message_regexp' => ['^probe from %%%%SRC%%%%'] } }, $ban_src ]
		},
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) is not a non-empty array'
	],
	[
		'syslog',
		'a stage with no message_regexp',
		{ 'rule_gates' => [ $daemons, { 'stages' => [ { 'count' => 2 } ] }, $ban_src ] },
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) entry 0 lacks a message_regexp'
	],
	[
		'syslog',
		'a stage with a empty message_regexp',
		{ 'rule_gates' => [ $daemons, { 'stages' => [ { 'message_regexp' => [] } ] }, $ban_src ] },
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) entry 0 has a message_regexp that is not '
			. 'a non-empty array of regexp strings'
	],
	[
		'syslog',
		'a stage with a count of 0',
		{
			'rule_gates' => [
				$daemons, { 'stages' => [ { 'message_regexp' => ['^probe from %%%%SRC%%%%'], 'count' => 0 } ] },
				$ban_src
			]
		},
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) entry 0 has a count that is not a positive int'
	],
	[
		'syslog',
		'a stage with a unknown key',
		{
			'rule_gates' => [
				$daemons, { 'stages' => [ { 'message_regexp' => ['^probe from %%%%SRC%%%%'], 'withn' => 5 } ] },
				$ban_src
			]
		},
		'The stages gate of the rule "syslog/x" (rule_gates entry 1) entry 0 has the unknown key "withn"'
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
		'json', 'a defer of 0',
		{ 'rule_gates' => [ $event_gate, { 'key' => 'session' }, { 'defer' => 0 }, $ban_ip ] },
		'The defer gate of the rule "json/x" (rule_gates entry 2) is not a positive int of seconds'
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
