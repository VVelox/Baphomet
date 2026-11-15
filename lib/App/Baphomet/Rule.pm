package App::Baphomet::Rule;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util                  qw( is_plain_hashref );
use Digest::MD5                qw( md5 );
use List::Util                 qw( any uniqstr );
use App::Baphomet::Correlation qw( correlation_prune correlation_restore );
use App::Baphomet::Shape       qw( check_hash );
use App::Baphomet::Gate        qw( gate_class compile_rule_gates line_walk_of stand );
# run_tests takes the rule as its first argument, so importing it here is what
# makes it a method of every rule... $rule->run_tests
use App::Baphomet::Rules::SelfTest qw( run_tests );

=pod

=head1 NAME

App::Baphomet::Rule - A Baphomet rule, the gates a line goes down and how what gets by is counted.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Rule;

    my $rule = App::Baphomet::Rule->new( 'name' => 'syslog/sshd', 'def' => $def );

    my $found = $rule->check($parsed);
    if ( defined($found) ) {
        print 'offense from ' . $found->{data}{SRC} . "\n";
    }

=head1 DESCRIPTION

A rule is a YAML hash of two sorts of key. C<rule_gates> is everything the
rule matches with, a list of gates a line goes down in the order written,
each a L<App::Baphomet::Gate> type. The rest is about the rule and not the
line... how a offense is counted, what a event says of it, and the tests
that prove it.

    rev: 1
    msg: "sshd login failure"
    max_score: 5
    rule_gates:
      - daemons: [ sshd ]
      - message_regexp:
          - '^Invalid user .*? from %%%%SRC%%%%'
      - ban_var: [ SRC ]

A rule's type is the first part of its name, the directory its file is in,
and is what parser its lines come from and so what its gates have to read.

    - syslog :: A syslog line, its message matched by regexp. It has to
          have a C<daemons> gate.

    - raw :: A line of no known format, the whole of it the message.

    - http :: A access log line, matched on its fields.

    - http_error :: A apache or nginx error log line, matched on its
          message and fields. It has to have a C<message_regexp> gate.

    - json :: A JSON record, matched on its flattened fields.

A gate refuses a rule of a type that does not have what it reads, when the
rule loads. Every rule has to name who a offense counts against, with a
C<ban_var> or a C<detection_var> gate, and has to have something that makes
a offense of a line or judges one.

The keys of a rule and every gate type are documented in F<docs/rules.md>,
which ships in the dist and reads online at
L<https://github.com/LilithSec/Baphomet/blob/main/docs/rules.md>, and each
gate type in its own class, L<App::Baphomet::Gate::daemons> and the like.

=head1 METHODS

=head2 new

Initiates the object, compiling the passed rule def. Will die on a invalid
or uncompilable def.

    - name :: The rule name, the type and then the name with in it.
        Default :: unnamed

    - def :: The rule def hash, as parsed from the YAML.
        Default :: undef

    - type :: The rule's type, for a rule whose name does not lead with it.
        Default :: the part of the name ahead of the first /

    my $rule = App::Baphomet::Rule->new( 'name' => 'syslog/sshd', 'def' => $def );

=cut

# what a line of each type is, and what a rule of the type defaults to...
#   must_have       :: the parsed fields a line has to have to be of the type
#   message         :: true when the gates read its message
#   fields          :: true when its parser hands over the field space
#   build_fields    :: what builds the field space of a type whose parser
#                      does not, handed the parsed line
#   known_fields    :: the fields a line can have, for a type with a fixed set
#   envelope_fields :: the envelope fields a correlation key may name
#   test_parser     :: the parser of a embedded test that names none
#   src_ip_var      :: the found var a event's src_ip is read from when the
#                      rule names none
my %HTTP_FIELDS = map { $_ => 1 } (
	'host',   'ident', 'user',    'time',       'request', 'method', 'path', 'protocol',
	'status', 'bytes', 'referer', 'user_agent', 'format'
);
my %TYPES = (
	'syslog' => {
		'must_have'       => ['message'],
		'message'         => 1,
		'envelope_fields' => { 'syslog.daemon' => 1, 'syslog.host' => 1, 'syslog.pid' => 1 },
		'test_parser'     => 'bsd_syslog',
		'src_ip_var'      => 'src_ip',
	},
	'raw'  => { 'must_have' => ['message'], 'message' => 1, 'test_parser' => 'raw', 'src_ip_var' => 'src_ip' },
	'http' => {
		'must_have' => [ 'host', 'status' ],
		# the parsed access log fields the type knows, those the line has
		'build_fields' => sub {
			my ($parsed) = @_;
			return { map { $_ => $parsed->{$_} } grep { defined( $parsed->{$_} ) } keys(%HTTP_FIELDS) };
		},
		'known_fields' => \%HTTP_FIELDS,
		'test_parser'  => 'http_access',
		'src_ip_var'   => 'host',
	},
	'http_error' => {
		'must_have' => [ 'client', 'message' ],
		# every defined scalar field the parser gave the line, the message
		# included
		'build_fields' => sub {
			my ($parsed) = @_;
			return {
				map  { $_ => $parsed->{$_} }
				grep { defined( $parsed->{$_} ) && ref( $parsed->{$_} ) eq '' } keys( %{$parsed} )
			};
		},
		'test_parser' => 'apache_error',
		'src_ip_var'  => 'client',
	},
	'json' => { 'must_have' => ['fields'], 'fields' => 1, 'test_parser' => 'json', 'src_ip_var' => 'src_ip' },
);

# the keys of a rule that are about the rule and not the line, each against
# the kind it must be... everything it matches with is a gate under rule_gates
my %RULE_KEYS = (
	'rule_gates' => 'any',
	# how it is counted... a ban_time of 0 is eternal
	'max_score'  => 'positive_int',
	'find_time'  => 'positive_int',
	'ban_time'   => 'seconds_or_zero',
	'weight'     => 'positive_number',
	'eve_only'   => 'boolean',
	'distinct'   => 'any',
	'mark_only'  => 'any',
	'track_only' => 'any',
	# what a event says of it... a rev of 0 is unversioned
	'msg'           => 'string',
	'severity'      => 'severity',
	'classtype'     => 'string',
	'references'    => 'strings',
	'attack'        => 'strings',
	'rev'           => 'non_negative_int',
	'src_ip_var'    => 'string',
	'src_port_var'  => 'string',
	'dest_ip_var'   => 'string',
	'dest_port_var' => 'string',
	'user_var'      => 'string',
	# the embedded tests
	'tests'       => 'hash',
	'test_parser' => 'any',
);

sub new {
	my ( $class, %opts ) = @_;

	my $name  = $opts{name} // 'unnamed';
	my $def   = $opts{def};
	my $where = 'The rule "' . $name . '"';

	my $type = $opts{type};
	if ( !defined($type) && $name =~ m{^([^/]+)/} ) {
		$type = $1;
	}
	if ( !defined($type) ) {
		die( $where . ' is of no type, its name having none ahead of a /' );
	}
	if ( !defined( $TYPES{$type} ) ) {
		die( $where . ' is of the type "' . $type . '", which is not a rule type' );
	}

	# a key that is a gate was a key of the rule itself once, and reads as a
	# typo when all that is said of it is that it is unknown
	foreach my $key ( is_plain_hashref($def) ? sort( keys( %{$def} ) ) : () ) {
		if ( !defined( $RULE_KEYS{$key} ) && defined( eval { gate_class( $key, $where ) } ) ) {
			die( $where . ' has "' . $key . '" at its top level, which is a gate and goes under rule_gates' );
		}
	}
	check_hash( $def, { 'optional' => \%RULE_KEYS }, $where );
	# of names the found var whose distinct values the galla counts, by the
	# one it groups them under
	if ( defined( $def->{distinct} ) ) {
		check_hash(
			$def->{distinct},
			{ 'required' => { 'of' => 'string' }, 'optional' => { 'by' => 'string' } },
			'The distinct of the rule "' . $name . '"'
		);
	}
	if ( !defined( $def->{rule_gates} ) ) {
		die( $where . ' has no rule_gates, and so nothing to match with' );
	}

	my $self = bless(
		{
			'name' => $name,
			'def'  => $def,
			'type' => $type,
			# the correlation store, context and deferred offenses per scope...
			# what the gates that correlate keep between lines, and what
			# dump_state hands the galla for the context tablet
			'correlation' => { 'context' => {}, 'pending' => {} },
			# a stable 31-bit unsigned integer from the name, the top four bytes
			# of its MD5... masked to stay a positive value that survives tools
			# treating a sid as a signed 32-bit int
			'sid' => unpack( 'N', substr( md5($name), 0, 4 ) ) & 0x7fffffff,
		}
	);
	$self->{rule_gates} = compile_rule_gates( $def->{rule_gates}, $self, $name );

	# what only the list as a whole can be asked... a gate told to do nothing
	# is not counted as there
	my @asked = grep { !$_->idle } @{ $self->{rule_gates} };
	my %has   = map  { $_->{type} => 1 } @asked;
	if ( !$has{ban_var} && !$has{detection_var} ) {
		die( $where . ' has neither a ban_var nor a detection_var gate, so nothing says who a offense counts against' );
	}
	if ( $type eq 'syslog' && !$has{daemons} ) {
		die( $where . ' has no daemons gate, which a syslog rule has to have' );
	}
	if ( $type eq 'http_error' && !$has{message_regexp} ) {
		die( $where . ' has no message_regexp gate, which a http_error rule has to have' );
	}
	my $makes  = any { $has{$_} } qw( message_regexp stages match );
	my $judges = any { $has{$_} } qw( gate keywords condition status method level module );
	if ( !$makes && !$judges ) {
		die( $where . ' has no gate that makes a offense of a line or judges one, so it would banish on every line' );
	}
	# a message has no fields till something reads them out of it
	if ( !$makes && $TYPES{$type}{message} && !$has{message_json} && !$has{mungers} ) {
		die(      $where
				. ' has no message_regexp or stages gate, and no message_json or mungers gate to give the others'
				. ' fields to judge' );
	}
	if ( $def->{track_only} && !$has{track} ) {
		die( $where . ' is track_only but has no track gate' );
	}

	# what the rule is to a line, the passage's rule... the type's line and
	# if the line's fields are the offense, nothing in the list making one,
	# and if anything in the list harvests
	$self->{lines}     = { %{ $TYPES{$type} }, 'implicit' => $makes ? 0 : 1, 'harvests' => $has{track} ? 1 : 0 };
	$self->{line_walk} = line_walk_of( $self->{rule_gates} );

	# the views of the rule the galla asks for on every match, built once
	# now that the def is known sound... the thresholds the def sets, the
	# track gates, and the def less its tests for the EVE rule field, which
	# the tests would bloat for no value
	$self->{is_detection} = $has{detection_var} ? 1 : 0;
	$self->{tracks}       = [ grep { $_->{type} eq 'track' } @asked ];
	$self->{thresholds}
		= { map { $_ => $def->{$_} } grep { defined( $def->{$_} ) } ( 'max_score', 'find_time', 'ban_time' ) };
	my %def_less_tests = %{$def};
	delete( $def_less_tests{tests} );
	$self->{info} = { 'name' => $name, 'def' => \%def_less_tests };

	# what the galla indexes a watcher's rules by. the daemons gates that
	# lead the list, where a line one turns away has had nothing done with it
	# and nothing kept of it... one further down is still asked, of every line
	my $leading = $self->{line_walk};
	$self->{daemon_gates}
		= [ grep { $_->{type} eq 'daemons' } @{ $leading->{line} }[ 0 .. $leading->{early} - 1 ] ];

	# and the field values a json record has to have. only where no gate of
	# the rule does or keeps anything for a record the pinning gate refuses...
	# a capture stands a waiting offense on its own judgment, a track
	# harvests whatever the line came to, and a ignore and a key are left out
	# with them so the rule stays one sentence long
	$self->{gate_discriminators} = {};
	if ( $type eq 'json' && !any { $has{$_} } qw( capture ignore key track ) ) {
		foreach my $gate ( grep { $_->{type} eq 'gate' } @asked ) {
			my $pins = $gate->pins;
			foreach my $field ( keys( %{$pins} ) ) {
				my $held = $self->{gate_discriminators}{$field};
				if ( !defined($held) ) {
					$self->{gate_discriminators}{$field} = $pins->{$field};
					next;
				}
				# every gate is ANDed, so two pinning the one field pin only
				# the values in both
				foreach my $value ( keys( %{$held} ) ) {
					if ( !defined( $pins->{$field}{$value} ) ) {
						delete( $held->{$value} );
					}
				}
			} ## end foreach my $field ( keys( %{$pins} ) )
		} ## end foreach my $gate ( grep { $_->{type} eq 'gate' ...})
	} ## end if ( $type eq 'json' && !any { $has{$_} } ...)

	return $self;
} ## end sub new

=head2 type

Returns the rule's type... C<syslog>, C<raw>, C<http>, C<http_error>, or
C<json>. It is what parser feeds the rule, and so what its lines have for a
gate to read.

    my $type = $rule->type;

=cut

sub type {
	my ($self) = @_;

	return $self->{type};
}

=head2 known_fields

Returns a hash ref of the fields a line of the rule's type can have, for a
gate that names one to be checked against, or undef for a type whose lines
have whatever fields they have.

    my $known_fields = $rule->known_fields;

=cut

sub known_fields {
	my ($self) = @_;

	return $TYPES{ $self->{type} }{known_fields};
}

=head2 envelope_fields

Returns a hash ref of the envelope fields a correlation key of the rule may
name beside the captures, the reserved C<syslog.*> ones of a syslog rule, or
undef for a type whose lines have no envelope.

    my $envelope_fields = $rule->envelope_fields;

=cut

sub envelope_fields {
	my ($self) = @_;

	return $TYPES{ $self->{type} }{envelope_fields};
}

=head2 correlation

Returns the rule's correlation store, the context and the deferred offenses
its gates keep between lines.

    my $store = $rule->correlation;

=cut

sub correlation {
	my ($self) = @_;

	return $self->{correlation};
}

=head2 default_test_parser

Returns the parser a embedded test of the rule is read with when neither it
nor the rule's C<test_parser> names one... C<bsd_syslog>, C<raw>,
C<http_access>, C<apache_error>, or C<json>, going by the rule's type.

    my $parser = $rule->default_test_parser;

=cut

sub default_test_parser {
	my ($self) = @_;

	return $TYPES{ $self->{type} }{test_parser};
}

=head2 walk_line

Takes a line down the rule's gates of the line phase, in the order the rule
wrote them, making the L<passage|App::Baphomet::Gate/THE PASSAGE> each is
handed. Returns the array ref of the offenses left standing, the line's own
first and then any a earlier line left waiting on this one. A empty one for
a line that is not of the rule's type, one a gate turned away outright, and
one that made no offense.

    - bound :: The rule's gates bound for a watcher, as
          L<App::Baphomet::Gate/bind_rule_gates> returns, or as they are,
          as L<App::Baphomet::Gate/line_walk_of> returns.

    - parsed :: The parsed line, as L<App::Baphomet::Parser> returns.

    - scope :: The correlation scope, the watcher name.

    - line_ctx :: Hash ref of the line context, the clock, the line's
          sequence and source, and the tracked store, or undef.

    foreach my $offense ( @{ $rule->walk_line( $bound, $parsed, $scope, $line_ctx ) } ) { ... }

=cut

sub walk_line {
	my ( $self, $bound, $parsed, $scope, $line_ctx ) = @_;

	# a line that is not of the rule's type makes no offense
	if ( !is_plain_hashref($parsed) ) {
		return [];
	}
	my $lines = $self->{lines};
	foreach my $must_have ( @{ $lines->{must_have} } ) {
		if ( !defined( $parsed->{$must_have} ) ) {
			return [];
		}
	}

	# the gates leading the list that read nothing but the parsed line and
	# only turn it away are asked of a passage holding only that... most
	# lines a rule is offered go no further, and need no more made for them
	my $gates = $bound->{line};
	my $early = $bound->{early};
	if ($early) {
		my $glimpse = { 'parsed' => $parsed };
		foreach my $gate_int ( 0 .. $early - 1 ) {
			if ( !$gates->[$gate_int]->ask($glimpse) ) {
				return [];
			}
		}
	}

	# a missing line context reads as a empty one
	if ( !is_plain_hashref($line_ctx) ) {
		$line_ctx = {};
	}
	my $passage = {
		'parsed'   => $parsed,
		'scope'    => $scope // '',
		'line_ctx' => $line_ctx,
		'now'      => $line_ctx->{now} // time,
		'rule'     => $lines,
	};
	if ( $lines->{message} ) {
		$passage->{message} = $parsed->{message};
	} elsif ( $lines->{fields} ) {
		$passage->{fields} = $parsed->{fields};
	}

	my $last_always = $bound->{last_always};
	foreach my $gate_int ( $early .. $#{$gates} ) {
		if ( !$gates->[$gate_int]->ask($passage) ) {
			return [];
		}
		# nothing standing and nothing to come, so only a gate that is asked
		# regardless is worth going on for
		if (   $passage->{refused}
			&& $gate_int >= $last_always
			&& !( defined( $passage->{results} ) && @{ $passage->{results} } ) )
		{
			return [];
		}
	} ## end foreach my $gate_int ( $early .. $#{$gates} )

	return stand($passage);
} ## end sub walk_line

=head2 check

Checks a parsed line against the rule with no watcher behind it, taking it
down the gates of the line phase as L</walk_line> does. Returns undef for no
match. For a match, returns the offense the line made, a hash as below, with
any further offenses a earlier line left waiting on this one under C<more>.
The gates of the offense phase are not asked.

    { 'data' => { 'SRC' => '1.2.3.4' }, 'regexp' => 0 }

    my $found = $rule->check( $parsed, $scope, $line_ctx );

=cut

sub check {
	my ( $self, $parsed, $scope, $line_ctx ) = @_;

	my ( $found, @more ) = @{ $self->walk_line( $self->{line_walk}, $parsed, $scope, $line_ctx ) };
	if ( defined($found) && @more ) {
		$found->{more} = \@more;
	}

	return $found;
} ## end sub check

=head2 accepts_daemon

Returns true when a line logged by the named daemon could get by the
C<daemons> gates that lead the rule's list. It is what the galla indexes a
watcher's rules by, so a line is only offered to the rules that name its
daemon. Always true for a rule with out such a gate.

Only the gates that lead the list are asked, as only there has a line one
turns away had nothing done with it and nothing kept of it, which is what
makes not offering the line the same as offering it.

    if ( $rule->accepts_daemon($daemon) ) { ... }

=cut

sub accepts_daemon {
	my ( $self, $daemon ) = @_;

	foreach my $gate ( @{ $self->{daemon_gates} } ) {
		if ( !$gate->accepts($daemon) ) {
			return 0;
		}
	}

	return 1;
} ## end sub accepts_daemon

=head2 gate_discriminators

Returns the field values a record has to have for the rule's C<gate> gates
to hold, a hash of field to the set of values it may be, a empty one for a
rule offering none. The other half of L</accepts_daemon>, for a watcher of
JSON records... a rule whose gate wants C<event_type> to be C<alert> can not
match a record whose C<event_type> is C<flow>, which is knowable with out
asking the rule.

    { 'event_type' => { 'alert' => 1 } }

Only a json rule offers any, the fields of the other types not being the
record's own. And only one with no C<capture>, C<ignore>, C<key>, or
C<track> gate, each of those doing or keeping something for a record the
C<gate> refuses, so nothing is indexed that can fire around what it is
indexed on.

    my $discriminators = $rule->gate_discriminators;

=cut

sub gate_discriminators {
	my ($self) = @_;

	return $self->{gate_discriminators};
}

=head2 sweep_state

Drops expired correlation context and pending deferred offenses. A no-op
for rules with out any. The galla calls this from its sweeper so expiry
does not depend on traffic.

    $rule->sweep_state($now);

=cut

sub sweep_state {
	my ( $self, $now ) = @_;

	$now //= time;
	correlation_prune( $self->{correlation}, $now );
	foreach my $gate ( @{ $self->{rule_gates} } ) {
		$gate->sweep_state($now);
	}

	return;
} ## end sub sweep_state

=head2 thresholds

Returns a hash of the rule's own threshold overrides, max_score,
find_time, and ban_time, holding only the keys the def actually sets...
a empty hash for a rule carrying none. The galla is what has the watcher
settings and decides if these are honored, per its
C<allow_per_rule_thresholds>... this just exposes the def keys.

    my $thresholds = $rule->thresholds;
    if ( %{$thresholds} ) { ... }

=cut

sub thresholds {
	my ($self) = @_;

	return $self->{thresholds};
}

=head2 weight

Returns the rule's weight, a positive number defaulting to 1... what a match
contributes to the offender's accumulated score toward a ban, so a dangerous
signature can weigh more and a noisy one less. Honored by the galla only when
the watcher's C<allow_per_rule_thresholds> is on, like the thresholds, so a
shipped rule can not quietly reshape an operator's tuning.

    my $weight = $rule->weight;

=cut

sub weight {
	my ($self) = @_;

	return defined( $self->{def}{weight} ) ? $self->{def}{weight} + 0 : 1;
}

=head2 eve_only

Returns the rule's own C<eve_only> as 0 or 1, or undef when the rule does not
set it... undef meaning inherit the watcher-resolved setting. When in force
the rule is in observe mode: its matches are written to EVE but never count
toward a real ban, and a would-be banish surfaces as an alert instead.

    my $eve_only = $rule->eve_only;   # undef, 0, or 1

=cut

sub eve_only {
	my ($self) = @_;

	if ( !exists( $self->{def}{eve_only} ) ) {
		return undef;
	}

	return $self->{def}{eve_only} ? 1 : 0;
}

=head2 is_detection

Returns 1 when the rule is detection-only, its C<rule_gates> naming who a
offense counts against with a C<detection_var>, else 0. Such a rule is
matched, counted, and held to its threshold like any other, but never
banishes... it counts by its subject into the shadow buckets, writes
C<sighting> per match and C<sighted> when a subject crosses the threshold,
and sends nothing to Kur.

    if ( $rule->is_detection ) { ... }

=cut

sub is_detection {
	my ($self) = @_;

	return $self->{is_detection};
}

=head2 msg

Returns the rule's msg, the human-readable signature naming what it detects,
Sagan/Suricata style (C<[TAG] description>). Falls back to the rule's name
when the def sets none, so the EVE msg field is always present and meaningful,
the way Suricata always has a signature.

    my $msg = $rule->msg;

=cut

sub msg {
	my ($self) = @_;

	if ( defined( $self->{def}{msg} ) ) {
		return $self->{def}{msg};
	}

	return $self->{name};
}

=head2 severity

Returns the rule's own severity (one of info/low/medium/high/critical), or
undef when the def sets none... undef meaning inherit the watcher-resolved
C<default_severity>. Triage metadata, inert to matching.

    my $severity = $rule->severity;   # undef or a level name

=cut

sub severity {
	my ($self) = @_;

	return $self->{def}{severity};
}

=head2 classtype

Returns the rule's classtype, the short class slug in the Snort/Sagan/Suricata
sense, or undef when unset. What reaches EVE is L</category>, this put into
words.

    my $classtype = $rule->classtype;

=cut

sub classtype {
	my ($self) = @_;

	return $self->{def}{classtype};
}

# the human-readable description of each classtype, which is what Suricata and
# Snort put in a event's category field... their rules carry the short slug and
# their classification.config holds the prose, so a consumer never sees the
# slug. Baphomet has no classification.config to read, so the table is here.
#
# the Snort and Suricata entries are their canonical wording, so a Baphomet
# event and a Suricata event of the same class read identically in one SIEM.
# the rest are classtypes Baphomet adds for things a network IDS has no reason
# to name... a log monitor sees configuration changes and program errors where
# Suricata sees packets. anything absent falls to a title-cased slug, so a site
# inventing its own classtype gets a sensible category with no edit here
my %classtype_category = (
	# Snort, priority 1
	'attempted-admin'        => 'Attempted Administrator Privilege Gain',
	'attempted-user'         => 'Attempted User Privilege Gain',
	'inappropriate-content'  => 'Inappropriate Content was Detected',
	'policy-violation'       => 'Potential Corporate Privacy Violation',
	'shellcode-detect'       => 'Executable code was detected',
	'successful-admin'       => 'Successful Administrator Privilege Gain',
	'successful-user'        => 'Successful User Privilege Gain',
	'trojan-activity'        => 'A Network Trojan was detected',
	'unsuccessful-user'      => 'Unsuccessful User Privilege Gain',
	'web-application-attack' => 'Web Application Attack',
	# Snort, priority 2
	'attempted-dos'                  => 'Attempted Denial of Service',
	'attempted-recon'                => 'Attempted Information Leak',
	'bad-unknown'                    => 'Potentially Bad Traffic',
	'default-login-attempt'          => 'Attempt to login by a default username and password',
	'denial-of-service'              => 'Detection of a Denial of Service Attack',
	'misc-attack'                    => 'Misc Attack',
	'non-standard-protocol'          => 'Detection of a non-standard protocol or event',
	'rpc-portmap-decode'             => 'Decode of an RPC Query',
	'successful-dos'                 => 'Denial of Service',
	'successful-recon-largescale'    => 'Large Scale Information Leak',
	'successful-recon-limited'       => 'Information Leak',
	'suspicious-filename-detect'     => 'A suspicious filename was detected',
	'suspicious-login'               => 'An attempted login using a suspicious username was detected',
	'system-call-detect'             => 'A system call was detected',
	'unusual-client-port-connection' => 'A client was using an unusual port',
	'web-application-activity'       => 'Access to a potentially vulnerable web application',
	# Snort, priority 3
	'icmp-event'              => 'Generic ICMP event',
	'misc-activity'           => 'Misc activity',
	'network-scan'            => 'Detection of a Network Scan',
	'not-suspicious'          => 'Not Suspicious Traffic',
	'protocol-command-decode' => 'Generic Protocol Command Decode',
	'string-detect'           => 'A suspicious string was detected',
	'unknown'                 => 'Unknown Traffic',
	# Snort, priority 4
	'tcp-connection' => 'A TCP connection was detected',
	# Suricata's own additions, as the ET ruleset uses them
	'coin-mining'         => 'Crypto Currency Mining Activity Detected',
	'command-and-control' => 'Malware Command and Control Activity Detected',
	'credential-theft'    => 'Successful Credential Theft Detected',
	'domain-c2'           => 'Domain Observed Used for C2 Detected',
	'exploit-kit'         => 'Exploit Kit Activity Detected',
	'external-ip-check'   => 'Device Retrieving External IP Address Detected',
	'pup-activity'        => 'Possibly Unwanted Program Detected',
	'social-engineering'  => 'Possible Social Engineering Attempted',
	'targeted-activity'   => 'Targeted Malicious Activity was Detected',
	# Baphomet's own, for what a log says and a packet does not
	'blocked'              => 'Traffic the Sensor Blocked',
	'brute-force'          => 'Brute Force Attack',
	'configuration-change' => 'Configuration Change',
	'correlated-attack'    => 'Correlated Attack',
	'exploit-attempt'      => 'Exploit Attempt',
	'malware'              => 'Malware Activity Detected',
	'network-event'        => 'Network Event',
	'program-error'        => 'Program Error',
	'suspicious-traffic'   => 'Suspicious Traffic',
	'system-error'         => 'System Error',
	'system-event'         => 'System Event',
	'unsuccessful-admin'   => 'Unsuccessful Administrator Privilege Gain',
);

=head2 category

Returns the rule's classtype as the human-readable description Suricata and
Snort write to an event's C<category>, or undef when the rule sets no
classtype.

The rule file carries the short slug, the way a Snort or Suricata rule does,
and the event carries the prose their C<classification.config> would have
supplied... so C<classtype: misc-attack> reads as C<"category" : "Misc Attack">
downstream and sorts alongside a Suricata event of the same class. A classtype
the table does not know, a site's own, becomes its slug title-cased with the
hyphens taken out, so it is still readable and still needs no code change.

    my $category = $rule->category;

=cut

sub category {
	my ($self) = @_;

	my $classtype = $self->{def}{classtype};
	if ( !defined($classtype) ) {
		return undef;
	}

	if ( defined( $classtype_category{$classtype} ) ) {
		return $classtype_category{$classtype};
	}

	return join( ' ', map { ucfirst($_) } split( /-+/, $classtype ) );
} ## end sub category

=head2 references

Returns the rule's references (an array of URLs, CVE ids, or doc links) as an
array ref, or undef when the def sets none.

    my $references = $rule->references;

=cut

sub references {
	my ($self) = @_;

	return $self->{def}{references};
}

=head2 attack

Returns the rule's MITRE ATT&CK technique ids as an array ref, or undef when
the def sets none.

    my $attack = $rule->attack;

=cut

sub attack {
	my ($self) = @_;

	return $self->{def}{attack};
}

=head2 gid

Returns the rule's EVE group id, the Suricata C<alert.gid> analogue... C<0>
when the rule was loaded from the shipped rules dir, C<1> from the site
override dir. Set by the loader with L</set_gid>; C<0> until then, so a rule
built with out the loader reads as shipped.

    my $gid = $rule->gid;

=cut

sub gid {
	my ($self) = @_;

	return $self->{gid} // 0;
}

=head2 set_gid

Records which dir the rule came from for L</gid>... C<0> shipped, C<1>
override. Called once by the loader, right after construction.

    $rule->set_gid(1);

=cut

sub set_gid {
	my ( $self, $gid ) = @_;

	$self->{gid} = $gid;

	return;
}

=head2 sid

Returns the rule's EVE signature id, the Suricata C<alert.signature_id>
analogue... a stable positive integer derived from the rule name, so
C<syslog/sshd> always hashes to the same value.

    my $sid = $rule->sid;

=cut

sub sid {
	my ($self) = @_;

	return $self->{sid};
}

=head2 rev

Returns the rule's revision, the Suricata C<alert.rev> analogue, from the
def's C<rev> key... undef when unset or C<0>, a zero revision meaning
unversioned. EVE renders the undef as C<0>, so the field is always an
integer there.

    my $rev = $rule->rev;   # undef or a positive integer

=cut

sub rev {
	my ($self) = @_;

	return ( defined( $self->{def}{rev} ) && $self->{def}{rev} ) ? $self->{def}{rev} + 0 : undef;
}

=head2 rule_gates

Returns the rule's gates, a array ref of L<App::Baphomet::Gate> objects in
the order its C<rule_gates> names them, compiled but not yet bound to a
watcher... a empty array for a rule with out any. A found result only counts
if every one of them holds, and what binds and asks them is the galla, or
C<run_tests> over a rule's own fixtures.

    my $bound = bind_rule_gates( $rule->rule_gates, \%context, $where );

=cut

sub rule_gates {
	my ($self) = @_;

	return $self->{rule_gates};
}

=head2 mark_only

Returns true if the rule only brands and gates, never counting toward a
ban... and a mark_only rule does not consume the line either, so matching
falls through to the watcher's later rules.

    if ( $rule->mark_only ) { ... }

=cut

sub mark_only {
	my ($self) = @_;

	return $self->{def}{mark_only} ? 1 : 0;
}

=head2 tracks

Returns the rule's C<track> gates as a array ref, possibly empty, each a
L<App::Baphomet::Gate::track> holding the record's C<name>, its C<key>, the
C<fields> it takes, and its C<ttl>.

    foreach my $track ( @{ $rule->tracks } ) { ... }

=cut

sub tracks {
	my ($self) = @_;

	return $self->{tracks};
}

=head2 track_only

Returns true if the rule only harvests tracked records, never counting toward
a ban... and a track_only rule does not consume the line either, so matching
falls through to the watcher's later rules. C<mark_only>'s sibling.

    if ( $rule->track_only ) { ... }

=cut

sub track_only {
	my ($self) = @_;

	return $self->{def}{track_only} ? 1 : 0;
}

=head2 distinct

Returns the rule's distinct-cardinality spec, a hash naming C<of> (the found
var whose distinct values are counted per offender), or undef when the rule
counts hits the usual way. The galla is what does the counting... this just
exposes the def key.

    my $distinct = $rule->distinct;   # undef or { of => 'USER' }

=cut

sub distinct {
	my ($self) = @_;

	return ( is_plain_hashref( $self->{def}{distinct} ) ) ? $self->{def}{distinct} : undef;
}

=head2 src_ip_var

Returns the name of the found var holding the flow's source IP, promoted to
the EVE event's top-level C<src_ip>. When the def names none it is C<host>
for a http rule and C<client> for a http_error one, the offender of each,
and C<src_ip> for the rest.

    my $src_ip_var = $rule->src_ip_var;

=cut

sub src_ip_var {
	my ($self) = @_;

	return $self->{def}{src_ip_var} // $TYPES{ $self->{type} }{src_ip_var};
}

=head2 dest_ip_var

Returns the name of the found var holding the flow's destination IP, defaulting
to C<dest_ip> when the def names none. The parallel of L</src_ip_var>, promoted
to the EVE event's top-level C<dest_ip>.

    my $dest_ip_var = $rule->dest_ip_var;   # 'dest_ip' or the named var

=cut

sub dest_ip_var {
	my ($self) = @_;

	return $self->{def}{dest_ip_var} // 'dest_ip';
}

=head2 src_port_var

Returns the name of the found var holding the flow's source port, defaulting to
C<src_port> when the def names none. The port twin of L</src_ip_var>, promoted
to the EVE event's top-level C<src_port>. The galla writes it as a number where
it reads as one, so a capture arriving as the string C<"22"> and a JSON schema's
native integer land in the one field as the one type.

    my $src_port_var = $rule->src_port_var;   # 'src_port' or the named var

=cut

sub src_port_var {
	my ($self) = @_;

	return $self->{def}{src_port_var} // 'src_port';
}

=head2 dest_port_var

Returns the name of the found var holding the flow's destination port,
defaulting to C<dest_port> when the def names none. The parallel of
L</src_port_var>, promoted to the EVE event's top-level C<dest_port>.

    my $dest_port_var = $rule->dest_port_var;   # 'dest_port' or the named var

=cut

sub dest_port_var {
	my ($self) = @_;

	return $self->{def}{dest_port_var} // 'dest_port';
}

=head2 user_var

Returns the name of the found var holding the account the line is about,
defaulting to C<user> when the def names none. Promoted to the EVE event's
top-level C<user>, so who was being logged in as reads beside the address it
came from without going through C<found>. The shipped regexp rules capture the
account as C<USER> and name it, while the http access parse and the JSON
schemas already call it C<user> and need no override.

    my $user_var = $rule->user_var;   # 'user' or the named var

=cut

sub user_var {
	my ($self) = @_;

	return $self->{def}{user_var} // 'user';
}

=head2 mungers

Returns the list of the Log-Munger sets the rule's C<mungers> gates name,
each once, or a empty list for a rule with out one.

    my @mungers = $rule->mungers;    # ('postfix')

=cut

sub mungers {
	my ($self) = @_;

	return uniqstr( map { @{ $_->{set} } } grep { $_->{type} eq 'mungers' } @{ $self->{rule_gates} } );
}

=head2 info

Returns the rule's name and def with the embedded tests stripped, for the
EVE log's rule field... the tests would bloat every event for no value.

    my $info = $rule->info;

=cut

sub info {
	my ($self) = @_;

	return $self->{info};
}

=head2 dump_state

Returns the live correlation state, context and pendings, as a plain data
structure for persisting... undef when there is none. The galla writes
this to a tablet so a restart does not forget a half correlated offense.

    my $state = $rule->dump_state;

=cut

sub dump_state {
	my ($self) = @_;

	my $store = $self->{correlation};
	if ( !%{ $store->{context} } && !%{ $store->{pending} } ) {
		return undef;
	}

	# a copy of the top level, so nothing a caller adds to what it was handed
	# lands in the live store
	return { %{$store} };
} ## end sub dump_state

=head2 restore_state

Restores correlation state from what L</dump_state> returned, dropping
anything already expired as of $now. Merges into whatever is present
rather than replacing, so it is safe to call at start.

    $rule->restore_state( $state, $now );

=cut

sub restore_state {
	my ( $self, $state, $now ) = @_;

	correlation_restore( $self->{correlation}, $state, $now // time );

	return;
}

=head2 run_tests

Runs the tests embedded in the rule, returning a hash of C<pass>, C<fail>,
and C<failures>. Does not die on test failures... that is the caller's call
to make. The runner is L<App::Baphomet::Rules::SelfTest/run_tests>, imported
here so it is a method of every rule, and what it does per test entry is
documented there.

    my $results = $rule->run_tests;

=cut

1;
