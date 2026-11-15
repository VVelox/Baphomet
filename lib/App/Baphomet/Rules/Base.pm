package App::Baphomet::Rules::Base;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util                  qw( is_plain_arrayref is_plain_hashref );
use Digest::MD5                qw( md5 );
use List::Util                 qw( uniqstr );
use App::Baphomet::Correlation qw( correlation_prune correlation_restore );
use App::Baphomet::Shape       qw( check_hash check_entries check_value );
use App::Baphomet::Gate        qw( compile_rule_gates );
use App::Baphomet::Tracks      qw( track_key track_get track_put );
use App::Baphomet::Rules::Gates
	qw( compile_matchers matchers_hit compile_gates gates_pass compile_condition eval_condition );
# run_tests takes the rule as its first argument, so importing it here is what
# makes it a method of every rule... $rule->run_tests
use App::Baphomet::Rules::SelfTest qw( run_tests );

=pod

=head1 NAME

App::Baphomet::Rules::Base - Shared plumbing for the Baphomet rule handlers.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

The bits common to every rule handler... the def checks, the getters the
galla reads a rule through, and the mungers, the boolean, and the tracked
records the types share. The def checks are written as shapes for
L<App::Baphomet::Shape>, the gate vocabulary is
L<App::Baphomet::Rules::Gates>, the C<%%%%TOKEN%%%%> regexps
L<App::Baphomet::Rules::Tokens>, the correlation store
L<App::Baphomet::Correlation>, and the embedded test runner
L<App::Baphomet::Rules::SelfTest>. The regexp and staged matching of the
syslog and raw types is L<App::Baphomet::Rules::MessageRegexp>. Not usable
on its own... see L<App::Baphomet::Rules::Syslog> and
L<App::Baphomet::Rules::HTTP> for the handlers.

A handler is expected to provide C<_compile>, which L</new> calls to check
and compile the def, and C<check>, taking a parsed line and returning undef
or a hash with a C<data> hash of what got captured, and to override L</default_test_parser> if C<bsd_syslog> is not the right default
for its tests.

A rule def may carry a top level C<test_parser> key, which sets the
parser for all of its embedded tests that do not name one themselves,
overriding the handler default... handy for a rule whose tests are all in
a non-default format, like a nginx rule of the http_error type.

=head1 RULE FORMAT

Every rule, whatever its type, is a YAML hash. What its keys are and what
each one means is documented in F<docs/rules.md>, which ships in the dist
and reads online at
L<https://github.com/LilithSec/Baphomet/blob/main/docs/rules.md>. That is
the one reference for the format... the keys common to every type and each
type's own alike... so none of it is repeated here.

The common keys are under its sections on naming the offender, how it is
counted, triage metadata, tests, refining a match with the gates, and
enriching a match with mungers. The matcher keys, the part that differs by
type, are under each type's own section there and summarized in the
handlers: L<App::Baphomet::Rules::Syslog>, L<App::Baphomet::Rules::Raw>,
L<App::Baphomet::Rules::HTTP>, L<App::Baphomet::Rules::HTTPError>, and
L<App::Baphomet::Rules::JSON>.

=head1 METHODS

=head2 new

Initiates the object and compiles the passed rule def. Every handler
inherits this, and provides the C<_compile> it calls to check and compile
the def the way its type reads one. Will die on a invalid or uncompilable
def.

    - name :: The rule name, for error messages.
        Default :: unnamed

    - def :: The rule def hash, as parsed from the YAML.
        Default :: undef

    my $rule = App::Baphomet::Rules::Syslog->new( 'name' => 'syslog/sshd', 'def' => $def );

=cut

sub new {
	my ( $class, %opts ) = @_;

	# mungers and gates start empty rather than absent, every type being
	# asked for its mungers and every type carrying the boolean, though only
	# some rules set either
	my $name = $opts{name} // 'unnamed';
	my $self = bless(
		{
			'name'    => $name,
			'def'     => $opts{def},
			'mungers' => [],
			'gates'   => [],
			# the correlation store, context and deferred offenses per scope...
			# empty for a rule that never correlates, and what dump_state hands
			# the galla for the context tablet
			'correlation' => { 'context' => {}, 'pending' => {} },
			# a stable 31-bit unsigned integer from the name, the top four bytes
			# of its MD5... masked to stay a positive value that survives tools
			# treating a sid as a signed 32-bit int
			'sid' => unpack( 'N', substr( md5($name), 0, 4 ) ) & 0x7fffffff,
		},
		ref($class) || $class
	);

	$self->_compile;

	return $self;
} ## end sub new

=head2 default_test_parser

The parser used for embedded tests that do not name one.

    my $parser = $rule->default_test_parser;

=cut

sub default_test_parser {
	return 'bsd_syslog';
}

=head2 accepts_daemon

Returns true when a line logged by the named daemon could possibly match
this rule... the cheap veto the galla indexes its watchers on, so a line
is only offered to the rules that could want it rather than to every rule
on the watcher in turn.

The base answer is always true, which is the honest one for every rule
type that has no daemon to gate on (http, http_error, json, raw)... those
watchers index to the whole rule list and behave exactly as they did
before. L<App::Baphomet::Rules::Syslog> overrides it with its daemons
list, which is what makes the index worth having.

The contract this rests on: a rule that answers false here must run
nothing and remember nothing for that line. A syslog rule's daemon gate
is the first thing C<check> does and it returns before touching any
correlation state, so skipping the call and making the call are the same
thing. A rule type whose C<check> harvests context before it could veto
must not override this.

    if ( $rule->accepts_daemon($daemon) ) { ... }

=cut

sub accepts_daemon {
	return 1;
}

=head2 gate_discriminators

Returns the rule's mandatory field equalities as a hash of field name to
the set of values that field may hold, C<{}> for a rule offering none.
The other half of the same idea as L</accepts_daemon>, for the rule types
that have no daemon: a rule whose gate demands C<event_type> be C<alert>
can not match a line whose C<event_type> is C<flow>, and that is knowable
from the line without running the rule.

    { 'event_type' => { 'alert' => 1 } }

The base answer is C<{}>, which offers nothing and indexes to always-try.
Only L<App::Baphomet::Rules::JSON> overrides it, and only that type could:
a json rule's gate is a pre-filter over the parsed fields of the line,
where a syslog or raw rule's gate is a post-match refinement over the
captures its regexps produced. A capture name is not a line field, so
there is nothing there to prefilter a line on.

The contract, which is L</accepts_daemon>'s with one more clause. A rule
offering a discriminator must, for a line the discriminator rejects,

=over 4

=item * run nothing and remember nothing, exactly as for the daemon gate; and

=item * have no path to a match that goes around the gate.

=back

The second is why a json rule offering one must carry no C<capture>,
C<ignore>, or C<key>: a capture entry harvests context and completes
deferred offenses on its own gates, not the rule's, so such a rule can
still return a result on a line its own gate refuses. Nothing may be
indexed that can fire around the thing being indexed on.

    my $discriminators = $rule->gate_discriminators;

=cut

sub gate_discriminators {
	return {};
}

=head2 sweep_state

Drops expired correlation context and pending deferred offenses. A no-op
for rules with out any. The galla calls this from its sweeper so expiry
does not depend on traffic.

    $rule->sweep_state($now);

=cut

sub sweep_state {
	my ( $self, $now ) = @_;

	correlation_prune( $self->{correlation}, $now // time );

	return;
}

=head2 ban_not_internal

Returns true if the rule wants only the found IPs that are not internal
banished, for rules like the Suricata ones where the offender may be the
src or the dest of a flow. The galla is what has the internal list and
does the filtering... this just exposes the rule's C<ban_not_internal>
def key. A rule type that does not allow the key never sees it set, so
this is false there.

    if ( $rule->ban_not_internal ) { ... }

=cut

sub ban_not_internal {
	my ($self) = @_;

	return $self->{def}{ban_not_internal} ? 1 : 0;
}

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

=head2 detection_var

Returns the list of capture or field names a detection-only rule counts by,
or the empty list for a ordinary banning rule. It is the parallel of
L</ban_var>, but under no obligation to name a address... a username, a
hostname, a URI, a service, or a IP when that is what is wanted. A rule names
C<ban_var> or C<detection_var>, never both, and the presence of the latter is
what makes it detection-only.

    my @detection_var = $rule->detection_var;

=cut

sub detection_var {
	my ($self) = @_;

	if ( !is_plain_arrayref( $self->{def}{detection_var} ) ) {
		return ();
	}

	return @{ $self->{def}{detection_var} };
}

=head2 is_detection

Returns 1 when the rule is detection-only (it carries a C<detection_var>), 0
otherwise. A detection-only rule runs the whole match/count/threshold path
like any other, but never banishes... it counts by its detection_var subject
into the shadow buckets, writes C<sighting> per match and C<sighted> when a
subject crosses the threshold, and sends nothing to Kur.

    if ( $rule->is_detection ) { ... }

=cut

sub is_detection {
	my ($self) = @_;

	return scalar( $self->detection_var ) ? 1 : 0;
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

=head2 marks

Returns the array of marks the rule sets on match, each a hash of C<name>,
C<ttl>, and optionally C<var> (key by this capture instead of the offender
IP), C<vars> (key by these captures joined into one compound key... never
beside C<var>), and C<value_var> (store this capture as the mark's
value)... a empty array for a rule setting none. The galla is what has the
marks store and does the branding, this just exposes the def key.

    foreach my $mark ( @{ $rule->marks } ) { ... }

=cut

sub marks {
	my ($self) = @_;

	return is_plain_arrayref( $self->{def}{mark} ) ? $self->{def}{mark} : [];
}

=head2 unmarks

Returns the array of marks the rule lifts on match, each a hash of C<name>
and optionally C<var> or C<vars>... a empty array for a rule lifting none.

    foreach my $unmark ( @{ $rule->unmarks } ) { ... }

=cut

sub unmarks {
	my ($self) = @_;

	return is_plain_arrayref( $self->{def}{unmark} ) ? $self->{def}{unmark} : [];
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

Returns the rule's compiled C<track> declarations as a array ref, possibly
empty. Each entry is a hash of C<name>, C<key> (always a array ref of found
var names, a single key being a list of one), C<fields> (a array ref of the
found vars to contribute, or undef meaning everything found), and C<ttl> in
seconds. This is what the harvest walks.

    foreach my $track ( @{ $rule->tracks } ) { ... }

=cut

sub tracks {
	my ($self) = @_;

	return $self->{tracks} // [];
}

=head2 track_gates

Returns the rule's tracked-record gates as a hash of two arrays, C<tracked>
and C<not_tracked>, either possibly empty. Each entry carries the C<name> and
the C<key> lifted from the C<track> that declared it; a tracked entry also
carries its compiled C<where> gates and its C<into> list, either possibly
undef. Evaluated as a clause of the rule's own boolean rather than galla
side, so what C<into> lifts is readable by C<gate> and C<keywords>.

    my $gates = $rule->track_gates;
    foreach my $gate ( @{ $gates->{tracked} } ) { ... }

=cut

sub track_gates {
	my ($self) = @_;

	# a rule with no gates gets a fresh empty pair, never one stored on the
	# object... a defined track_gates is what the per-line paths read as "this
	# rule has gates", so storing one here would have every rule that ever
	# fired run the tracked and boolean passes for nothing
	if ( defined( $self->{track_gates} ) ) {
		return $self->{track_gates};
	}
	return { 'tracked' => [], 'not_tracked' => [] };
} ## end sub track_gates

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

=head2 _check_detection_var

Validates a rule's C<detection_var>, if any, and reports whether the rule is
detection-only. When present it must be a non-empty array of non-empty
strings, and it may not sit beside C<ban_var>... a rule bans or is
detection-only, not both.
Each rule type calls this and makes its own C<ban_var> requirement conditional
on the return, so a detection rule need not name a offender it will never
banish. Returns 1 for a detection rule, 0 otherwise. Dies on a malformed def.

    my $is_detection = $self->_check_detection_var;

=cut

sub _check_detection_var {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	if ( !exists( $def->{detection_var} ) ) {
		return 0;
	}

	check_value( $def->{detection_var}, 'strings', 'The detection_var of the rule "' . $name . '"' );
	if ( exists( $def->{ban_var} ) ) {
		die(      'The rule "'
				. $name
				. '" sets both ban_var and detection_var... a rule banishes or is detection-only, not both' );
	}

	return 1;
} ## end sub _check_detection_var

# the def keys every rule type allows, each against the kind it must be... a
# type adds only its own matcher keys to these. a key of the kind any is
# either a flag read only for its truth or a structure of its own, vetted by
# the entry shapes below or by the compile that reads it
my %COMMON_DEF_KEYS = (
	# the boolean
	'gate'       => 'any',
	'selections' => 'any',
	'condition'  => 'any',
	'keywords'   => 'any',
	# naming the offender
	'detection_var'    => 'any',
	'ban_not_internal' => 'any',
	'src_ip_var'       => 'string',
	'src_port_var'     => 'string',
	'dest_ip_var'      => 'string',
	'dest_port_var'    => 'string',
	'user_var'         => 'string',
	# how it is counted... a ban_time of 0 is eternal
	'max_score' => 'positive_int',
	'find_time' => 'positive_int',
	'ban_time'  => 'seconds_or_zero',
	'weight'    => 'positive_number',
	'eve_only'  => 'boolean',
	'distinct'  => 'any',
	# triage metadata... a rev of 0 is unversioned
	'msg'        => 'string',
	'severity'   => 'severity',
	'classtype'  => 'string',
	'references' => 'strings',
	'attack'     => 'strings',
	'rev'        => 'non_negative_int',
	# marks
	'mark'      => 'any',
	'unmark'    => 'any',
	'mark_only' => 'any',
	# tracked records
	'track'       => 'any',
	'tracked'     => 'any',
	'not_tracked' => 'any',
	'track_only'  => 'any',
	# the gates the galla judges, each entry vetted by its own gate type
	'rule_gates' => 'any',
	# the embedded tests
	'tests'       => 'hash',
	'test_parser' => 'any',
);

# what each entry of a def's list keys must look like, read by check_entries...
# a mark name is constrained like a rule name so it rides tablets and commands
# cleanly, and vars is a compound key, several captures joined into one, and
# never beside the single var
my %ENTRY_SHAPES = (
	'mark' => {
		'required' => { 'name' => 'name',   'ttl'  => 'seconds' },
		'optional' => { 'var'  => 'string', 'vars' => 'strings', 'value_var' => 'string' },
		'not_both' => [ [ 'var', 'vars' ] ],
	},
	'unmark' => {
		'required' => { 'name' => 'name' },
		'optional' => { 'var'  => 'string', 'vars' => 'strings' },
		'not_both' => [ [ 'var', 'vars' ] ],
	},
	# fields absent means everything found is contributed, which is not the
	# same as a empty list, which means nothing is... the second is how a rule
	# that only reads a record declares itself
	'track' => {
		'required' => { 'name'   => 'name',        'key' => 'string_or_strings' },
		'optional' => { 'fields' => 'string_list', 'ttl' => 'seconds' },
	},
	# a tracked entry with neither where nor into would do nothing, which is
	# worth saying out loud
	'tracked' => {
		'required' => { 'name'  => 'name' },
		'optional' => { 'where' => 'any', 'into' => 'strings' },
		'any_of'   => [ [ 'where', 'into', 'so it does nothing' ] ],
	},
	'not_tracked' => { 'required' => { 'name' => 'name' } },
);

# the def checks every handler runs, one call so a new key or gate check can
# not be forgotten in one type... that the def is a hash naming only the
# common keys and the type's own, each common one of the kind
# %COMMON_DEF_KEYS holds it to, then the mark lists and distinct against
# their shapes, and last the compiles of what the galla judges, the tracks and
# the rule_gates, each of which vets its part of the def as it compiles it.
#
# args:
#   $type_keys :: arrayref of the def keys this type allows past the common
#                 ones, its matcher keys, which the type vets itself
#
# returns nothing, dying on the first problem found. a sound def also leaves
# thresholds, rule_gates, and info on the object, the views of it their
# getters hand the galla.
#
#   $self->_check_common( [ 'status', 'method', 'match', 'ignore' ] );
sub _check_common {
	my ( $self, $type_keys ) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	check_hash(
		$def,
		{ 'optional' => { %COMMON_DEF_KEYS, map { $_ => 'any' } @{$type_keys} } },
		'The rule "' . $name . '"'
	);

	foreach my $list_key ( 'mark', 'unmark' ) {
		if ( defined( $def->{$list_key} ) ) {
			check_entries(
				$def->{$list_key},
				$ENTRY_SHAPES{$list_key},
				'The ' . $list_key . ' of the rule "' . $name . '"'
			);
		}
	}
	# the distinct-cardinality spec... of names the found var whose distinct
	# values the galla counts, by the one it groups them under
	if ( defined( $def->{distinct} ) ) {
		check_hash(
			$def->{distinct},
			{ 'required' => { 'of' => 'string' }, 'optional' => { 'by' => 'string' } },
			'The distinct of the rule "' . $name . '"'
		);
	}

	$self->_compile_tracks;
	$self->{rule_gates} = compile_rule_gates( $def->{rule_gates}, $self, $name );

	# the views of the def the galla asks for on every match, built once now
	# that the def is known sound rather than on each asking... the threshold
	# overrides the def actually sets, and the def less its tests for the EVE
	# rule field, which the tests would bloat for no value
	$self->{thresholds}
		= { map { $_ => $def->{$_} } grep { defined( $def->{$_} ) } ( 'max_score', 'find_time', 'ban_time' ) };
	my %def_less_tests = %{$def};
	delete( $def_less_tests{tests} );
	$self->{info} = { 'name' => $name, 'def' => \%def_less_tests };

	return;
} ## end sub _check_common

# validates the ban_var of a def unless the rule is detection-only, and
# says which it was... shared by the types with a free-form ban_var (the
# http pair chisel theirs to a fixed field).
#
# takes nothing. returns 1 for a detection-only rule, which needs no ban_var,
# else 0. dies on a detection_var that is unusable, and for a rule that is not
# detection-only on a ban_var that is not a non-empty array of non-empty
# strings.
#
#   my $is_detection = $self->_check_ban_var;
sub _check_ban_var {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	if ( $self->_check_detection_var ) {
		return 1;
	}

	check_value( $def->{ban_var}, 'strings', 'The ban_var of the rule "' . $name . '"' );

	return 0;
} ## end sub _check_ban_var

=head2 ban_var

Returns the ban_var list of the rule... the vars whose values are the
offenders. The http types override this with their fixed field.

    my @ban_var = $rule->ban_var;

=cut

sub ban_var {
	my ($self) = @_;

	return @{ $self->{def}{ban_var} };
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

Returns the name of the found var holding the flow's source IP, defaulting to
C<src_ip> when the def names none. The galla reads this var out of the found
data and promotes its value to the EVE event's top-level C<src_ip>, so a hit
carries the source address beside the offender no matter how the rule captured
or flattened it. Naming the var, C<flow.src_ip> say, points it at whatever
dotted path a schema puts the source under.

    my $src_ip_var = $rule->src_ip_var;   # 'src_ip' or the named var

=cut

sub src_ip_var {
	my ($self) = @_;

	return $self->{def}{src_ip_var} // 'src_ip';
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

Returns the array of Log-Munger rule-file names this rule applies for
enrichment (its C<mungers> key), or an empty list for a rule declaring none.
Each entry is a leaf munger... a Log::Munger rule file whose own dependencies
(C<base> and any others) resolve themselves, so only the relevant munger is
named, never C<base>. The parsed line is run through them before the rule's
own C<message_regexp>, and the fields they decode are laid down under the
offense... a C<message_regexp> capture of the same name overwrites, that
divergence being deliberate (a looser parse than the munger had).

    my @mungers = $rule->mungers;   # ('postfix')

=cut

sub mungers {
	my ($self) = @_;

	return @{ $self->{mungers} };
}

# validates and stores the mungers key... a non-empty array of non-empty
# rule-file names, deduped and sorted so a set shares one memoized processor
# whatever the order named. dies on a malformed key. the processor is built
# lazily on first use (or prewarmed by the galla), so a rule declaring none
# never so much as loads Log::Munger
sub _compile_mungers {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	if ( !defined( $def->{mungers} ) ) {
		return;
	}
	check_value( $def->{mungers}, 'strings', 'The mungers of the rule "' . $name . '"' );
	$self->{mungers} = [ sort( uniqstr( @{ $def->{mungers} } ) ) ];

	return;
} ## end sub _compile_mungers

# the memoized Log::Munger::LogProcessor for this rule's munger-set, shared
# across every rule naming the same set (keyed on the sorted list). built on
# first use... a Log::Munger that is not loadable, or a munger file that will
# not resolve, is fatal per the feature's contract, surfaced as a die the
# loader (or the galla's prewarm) turns into a log_drek error. undef for a
# rule declaring no mungers
my %munge_processor_cache;

sub _munge_processor {
	my ($self) = @_;

	if ( !@{ $self->{mungers} } ) {
		return undef;
	}

	my $key = join( "\x1f", @{ $self->{mungers} } );
	if ( exists( $munge_processor_cache{$key} ) ) {
		return $munge_processor_cache{$key};
	}

	try {
		require Log::Munger::LogProcessor;
	} catch ($caught) {
		die(      'The rule "'
				. $self->{name}
				. '" names mungers ('
				. join( ', ', @{ $self->{mungers} } )
				. ') but Log::Munger is not loadable... '
				. $caught );
	}

	my $processor;
	eval { $processor = Log::Munger::LogProcessor->new( 'rules' => [ @{ $self->{mungers} } ] ); };
	if ( $@ || !defined($processor) ) {
		die(      'The rule "'
				. $self->{name}
				. '" names mungers ('
				. join( ', ', @{ $self->{mungers} } )
				. ') that could not be loaded... '
				. ( $@ ? $@ : 'Log::Munger::LogProcessor->new returned undef' ) );
	}

	$munge_processor_cache{$key} = $processor;

	return $processor;
} ## end sub _munge_processor

# runs the parsed line through the rule's mungers and returns the decoded
# fields as a hash ref, or undef when the rule names none, the line carries no
# message, or nothing matched. the syslog envelope maps onto Log-Munger's own
# field names... daemon is the PROGRAM gate, level the PRIORITY, facility the
# FACILITY. process_item never dies, so a non-match is simply undef, never a
# error... a munger that could not load already died at load or prewarm
#
# The decode is memoised on the parsed line, under the munger-set that produced
# it, exactly as _message_json_extra memoises its flatten. It is the same work
# for every rule naming that set and only ever read, so one decode serves them
# all... which matters because a watcher listing a whole appliance family runs
# one munger-driven rule per event class over each line, and without this each
# would re-decode. Measured on the eight fortinet rules, the pass is around
# 97us where the rule's own matching is nearer 40, so the saving is most of the
# cost of the family. The parsed hash lives exactly as long as the line, so the
# cache needs no invalidating; a undef decode is memoised too, so a line the
# mungers do not match is not retried per rule.
sub _munge_enrich {
	my ( $self, $parsed ) = @_;

	if ( !@{ $self->{mungers} } || !is_plain_hashref($parsed) ) {
		return undef;
	}
	if ( !defined( $parsed->{message} ) ) {
		return undef;
	}

	# keyed by the set, since two rules on one watcher may name different
	# mungers and must not be handed each other's fields
	my $set_key = join( "\x1f", @{ $self->{mungers} } );
	if ( is_plain_hashref( $parsed->{_munge_fields} ) && exists( $parsed->{_munge_fields}{$set_key} ) ) {
		return $parsed->{_munge_fields}{$set_key};
	}

	my $processor = $self->_munge_processor;
	if ( !defined($processor) ) {
		return undef;
	}

	my %feed = ( 'message' => $parsed->{message} );
	$feed{program}  = $parsed->{daemon}   if ( defined( $parsed->{daemon} ) );
	$feed{priority} = $parsed->{level}    if ( defined( $parsed->{level} ) );
	$feed{facility} = $parsed->{facility} if ( defined( $parsed->{facility} ) );

	my $fields;
	eval { $fields = $processor->process_item(%feed); };
	if ( $@ || !is_plain_hashref($fields) ) {
		$parsed->{_munge_fields}{$set_key} = undef;
		return undef;
	}

	$parsed->{_munge_fields}{$set_key} = $fields;

	return $fields;
} ## end sub _munge_enrich

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

# compiles the def's track keys, track, tracked, not_tracked, and track_only,
# onto the object, dying on anything unusable... the entry shapes vet what
# each entry holds, and this what a shape can not see. A track_only rule must
# declare a track, a track declared twice leaves its key ambiguous, and a
# tracked or not_tracked naming a record the rule declared no track for will
# not load, the declaration being what the read is a read of.
#
# takes nothing. returns nothing, leaving tracks (a array ref of
# { name, key, fields, ttl }) and track_gates ({ tracked, not_tracked }) on
# the object, each entry of the latter carrying the key its declaration gave
# so the runtime never has to look one up.
#
#   $self->_compile_tracks;
#   # $self->{tracks} is [ { 'name' => 'mail-queue', 'key' => ['QUEUE_ID'], 'fields' => undef, 'ttl' => 3600 } ]
sub _compile_tracks {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	if ( !defined( $def->{track} ) && !defined( $def->{tracked} ) && !defined( $def->{not_tracked} ) ) {
		if ( $def->{track_only} ) {
			die( 'The rule "' . $name . '" is track_only but declares no track' );
		}
		return;
	}

	# the declarations first, as the gates below are checked against them
	my %declared;
	if ( defined( $def->{track} ) ) {
		my $where = 'The track of the rule "' . $name . '"';
		check_entries( $def->{track}, $ENTRY_SHAPES{track}, $where );

		my @tracks;
		foreach my $entry ( @{ $def->{track} } ) {
			if ( defined( $declared{ $entry->{name} } ) ) {
				die( $where . ' declares "' . $entry->{name} . '" twice, which leaves its key ambiguous' );
			}
			my $track = {
				'name' => $entry->{name},
				# a list of one is the same thing as the plain string, so both
				# compile to a list and the runtime has one shape to resolve
				'key'    => is_plain_arrayref( $entry->{key} ) ? [ @{ $entry->{key} } ]    : [ $entry->{key} ],
				'fields' => defined( $entry->{fields} )        ? [ @{ $entry->{fields} } ] : undef,
				'ttl'    => $entry->{ttl} // 3600,
			};
			$declared{ $entry->{name} } = $track;
			push( @tracks, $track );
		} ## end foreach my $entry ( @{ $def->{track} } )
		$self->{tracks} = \@tracks;
	} ## end if ( defined( $def->{track} ) )

	my $gates = { 'tracked' => [], 'not_tracked' => [] };
	foreach my $key ( 'tracked', 'not_tracked' ) {
		if ( !defined( $def->{$key} ) ) {
			next;
		}
		my $where = 'The ' . $key . ' of the rule "' . $name . '"';
		check_entries( $def->{$key}, $ENTRY_SHAPES{$key}, $where );

		foreach my $entry ( @{ $def->{$key} } ) {
			if ( !defined( $declared{ $entry->{name} } ) ) {
				die( $where . ' entry "' . $entry->{name} . '" names a record the rule declares no track for' );
			}

			my $gate = { 'name' => $entry->{name}, 'key' => $declared{ $entry->{name} }{key} };
			if ( defined( $entry->{where} ) ) {
				# the ordinary gate vocabulary, judged against the stored record
				# rather than the line... so a undef stored value already fails
				# every operator but exists
				$gate->{where} = compile_gates( $entry->{where}, $where . ' entry "' . $entry->{name} . '" where' );
			}
			if ( defined( $entry->{into} ) ) {
				$gate->{into} = [ @{ $entry->{into} } ];
			}
			push( @{ $gates->{$key} }, $gate );
		} ## end foreach my $entry ( @{ $def->{$key} } )
	} ## end foreach my $key ( 'tracked', 'not_tracked' )

	if ( @{ $gates->{tracked} } || @{ $gates->{not_tracked} } ) {
		$self->{track_gates} = $gates;
	}

	return;
} ## end sub _compile_tracks

# validates a correlation key... a non-empty string or a non-empty array of
# them, each component either a regexp capture name or a reserved envelope
# field the type declared in envelope_key_fields... returns the components
# as a array ref and notes on the object when the envelope is wanted, so
# check only builds it for rules that key on it
sub _correlation_key_components {
	my ( $self, $key, $where ) = @_;

	my @components;
	if ( is_plain_arrayref($key) ) {
		@components = @{$key};
	} elsif ( ref($key) eq '' ) {
		@components = ($key);
	} else {
		die( $where . ' has a key that is not a string or a array' );
	}
	if ( !@components ) {
		die( $where . ' has a empty key array' );
	}
	foreach my $component (@components) {
		if ( !defined($component) || ref($component) ne '' || $component eq '' ) {
			die( $where . ' has a key component that is not a non-empty string' );
		}
		if ( $component =~ /^syslog\./ ) {
			if ( !is_plain_hashref( $self->{envelope_key_fields} ) || !$self->{envelope_key_fields}{$component} ) {
				die( $where . ' keys on "' . $component . '", which is not a envelope field this rule type carries' );
			}
			$self->{wants_envelope} = 1;
		}
	} ## end foreach my $component (@components)

	return \@components;
} ## end sub _correlation_key_components

# the tracked/not_tracked clause of the rule's boolean, run first among them
# so that whatever a into lifts is readable by the gate and keywords that
# follow. reading here rather than galla side is the decision the whole
# feature rests on... galla side it could only AND after the rule had already
# matched, so a record could veto a offense but never help decide what the
# offense was.
#
# takes the found data hash ref for one offense (mutated in place by a into)
# and the line context, whose tracked key holds the galla's live store (or a
# throwaway one under run_tests). a caller threading no store is read as a
# store holding nothing, which vetoes a where and passes a not_tracked, the
# same fail-closed reading a genuinely empty store gets.
#
# returns 1 when every entry holds, 0 on the first veto. the four states a
# read can find are documented under "Tracked records" above.
sub _tracked_pass {
	my ( $self, $data, $line_ctx ) = @_;

	my $gates = $self->{track_gates};
	if ( !defined($gates) ) {
		return 1;
	}

	# a missing line context reads as a empty one, and a missing store as a
	# empty store
	if ( !is_plain_hashref($line_ctx) ) {
		$line_ctx = {};
	}
	my $store = is_plain_hashref( $line_ctx->{tracked} ) ? $line_ctx->{tracked} : {};
	my $now   = $line_ctx->{now} // time;

	foreach my $gate ( @{ $gates->{tracked} } ) {
		my $key = track_key( $gate, $data );
		if ( !defined($key) ) {
			# the line is not part of a tracked transaction, which is not
			# evidence of anything... a postfix NOQUEUE reject carries no
			# queue id and must sail through
			next;
		}

		my $record = track_get( $store, $gate->{name}, $key, $now );
		if ( !defined($record) ) {
			# a where asserts something about the history, and no history
			# leaves the assertion unproven... fail closed, the way country,
			# namtar_list, and reverse_dns all do. a into-only entry has
			# nothing to assert, so it simply lifts nothing
			if ( defined( $gate->{where} ) ) {
				return 0;
			}
			next;
		} ## end if ( !defined($record) )

		if ( defined( $gate->{where} ) && !gates_pass( $gate->{where}, $record, undef ) ) {
			return 0;
		}

		# the lift lands underneath this line's own fields, exactly as the
		# munger fields do, so a capture of the same name always wins
		if ( defined( $gate->{into} ) ) {
			foreach my $field ( @{ $gate->{into} } ) {
				if ( defined( $record->{$field} ) && !exists( $data->{$field} ) ) {
					$data->{$field} = $record->{$field};
				}
			}
		}
	} ## end foreach my $gate ( @{ $gates->{tracked} } )

	foreach my $gate ( @{ $gates->{not_tracked} } ) {
		my $key = track_key( $gate, $data );
		if ( !defined($key) ) {
			next;
		}
		if ( defined( track_get( $store, $gate->{name}, $key, $now ) ) ) {
			return 0;
		}
	}

	return 1;
} ## end sub _tracked_pass

# the rule's whole boolean for one offense... the tracked clause and then the
# keywords/gate/selections, in that order so a lifted field is readable by the
# rest. split out because the tracked clause has to run whether or not the
# rule carries a boolean of its own, a rule gating purely on a record being a
# legal and useful thing to write.
#
# takes the found data hash ref, the message (for the MESSAGE pseudo-field),
# and the line context. returns 1 when the offense stands, 0 when it does not.
sub _offense_boolean_pass {
	my ( $self, $data, $message, $line_ctx ) = @_;

	if ( !$self->_tracked_pass( $data, $line_ctx ) ) {
		return 0;
	}
	if ( $self->{has_boolean} && !$self->_boolean_pass( $data, $message ) ) {
		return 0;
	}

	return 1;
} ## end sub _offense_boolean_pass

# the track sweep, the harvest. reads each declared track's fields out of a
# line's found vars and lays them over the record, newest winning.
#
# it does not care whether the message regexps hit or whether the boolean
# passed, a record being a record of the transaction rather than of offenses.
# the caller hands it the field spaces to sweep, which is why it is given
# refs taken BEFORE the boolean could drop them... gating the harvest on "did
# this line look bannable" is exactly the conflation the feature exists to
# undo. only the type gate and a ignore hit stop it, and both do so by
# returning before this is ever reached.
#
# runs after the read at _tracked_pass and never before it. write first and
# the gate would judge a record it just made... not_tracked could never pass,
# and a where would degenerate into a plain field check the gate already does.
#
# takes a array ref of found data hash refs to harvest from (one per offense,
# or a single base field space on a line that matched nothing) and the line
# context carrying the store and the clock. returns nothing.
sub _track_sweep {
	my ( $self, $sources, $line_ctx ) = @_;

	my $tracks = $self->{tracks};
	if ( !defined($tracks) ) {
		return;
	}

	# nothing to harvest into with out a line context carrying a store
	if ( !is_plain_hashref($line_ctx) || !is_plain_hashref( $line_ctx->{tracked} ) ) {
		return;
	}
	my $store = $line_ctx->{tracked};
	my $now   = $line_ctx->{now} // time;

	foreach my $data ( @{$sources} ) {
		foreach my $track ( @{$tracks} ) {
			my $key = track_key( $track, $data );
			if ( !defined($key) ) {
				next;
			}

			# a fields list contributes what it names, absent contributes
			# everything found, and a empty list contributes nothing at all...
			# how a rule that only reads a record declares itself. the ttl
			# refreshes either way, sighting the key being evidence enough
			# that the transaction is alive
			my %fields;
			foreach my $field ( defined( $track->{fields} ) ? @{ $track->{fields} } : keys( %{$data} ) ) {
				if ( defined( $data->{$field} ) ) {
					$fields{$field} = $data->{$field};
				}
			}

			track_put( $store, $track->{name}, $key, \%fields, $track->{ttl}, $now );
		} ## end foreach my $track ( @{$tracks} )
	} ## end foreach my $data ( @{$sources} )

	return;
} ## end sub _track_sweep

# compiles a def's match and ignore arrays onto matches and ignores, vetting
# the field-and-regexp shape the two share... the per-entry compile differs by
# type, tokened for json, plain and field-checked for http, so the caller
# hands one in.
#
# args:
#   $compile_entry :: code ref taking a entry, a hash ref of field and regexp,
#                     and the lead in for its die messages, and returning the
#                     compiled entry
#
# returns nothing, dying on anything unusable. matches and ignores each gain
# what the code ref returned for each of their entries, in the def's order.
#
#   $self->_compile_match_ignore( sub { my ( $entry, $where ) = @_; ...; return $compiled; } );
sub _compile_match_ignore {
	my ( $self, $compile_entry ) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	foreach my $list_key ( 'match', 'ignore' ) {
		if ( !defined( $def->{$list_key} ) ) {
			next;
		}
		my $where = 'The ' . $list_key . ' of the rule "' . $name . '"';
		check_entries( $def->{$list_key}, { 'required' => { 'field' => 'scalar', 'regexp' => 'scalar' } }, $where );

		foreach my ( $entry_int, $entry ) ( indexed @{ $def->{$list_key} } ) {
			push(
				@{ $self->{ $list_key eq 'match' ? 'matches' : 'ignores' } },
				$compile_entry->( $entry, $where . ' entry ' . $entry_int )
			);
		}
	} ## end foreach my $list_key ( 'match', 'ignore' )

	return;
} ## end sub _compile_match_ignore

# compiles a rule's boolean matcher, the flat gate or the selections+condition
# form, onto the object... they are mutually exclusive, a condition needs
# selections and the reverse. shared by every type that carries a gate, so json,
# syslog, and raw all get the operators, decode, and the boolean form uniformly
sub _compile_boolean {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	if ( defined( $def->{gate} ) && defined( $def->{selections} ) ) {
		die( 'The rule "' . $name . '" has both a gate and selections, which are two forms of the same thing' );
	}

	if ( defined( $def->{gate} ) ) {
		$self->{gates} = compile_gates( $def->{gate}, 'The gate of the rule "' . $name . '"' );
	}

	if ( defined( $def->{selections} ) ) {
		if ( !defined( $def->{condition} ) ) {
			die( 'The rule "' . $name . '" has selections but no condition' );
		}
		if ( !is_plain_hashref( $def->{selections} ) || !%{ $def->{selections} } ) {
			die( 'The selections of the rule "' . $name . '" is not a non-empty table' );
		}
		my %compiled;
		foreach my $sel_name ( keys( %{ $def->{selections} } ) ) {
			if ( $sel_name !~ /^[A-Za-z_][A-Za-z0-9_]*$/ || $sel_name =~ /^(?:and|or|not|of|them|all)$/i ) {
				die( 'The selection name "' . $sel_name . '" of the rule "' . $name . '" is not a plain identifier' );
			}
			$compiled{$sel_name} = compile_gates( $def->{selections}{$sel_name},
				'The selection "' . $sel_name . '" of the rule "' . $name . '"' );
		}
		$self->{selections} = \%compiled;
		$self->{condition_ast}
			= compile_condition( $def->{condition}, \%compiled, 'The condition of the rule "' . $name . '"' );
	} elsif ( defined( $def->{condition} ) ) {
		die( 'The rule "' . $name . '" has a condition but no selections' );
	}

	$self->_compile_keywords;

	# whether any boolean filter exists at all, judged once here... the one
	# answer to it. the per-line paths read it to skip building the field
	# space for a rule with none, and each type's new reads it to refuse a
	# rule that would match everything or nothing
	my $has_gates    = is_plain_arrayref( $self->{gates} )         && @{ $self->{gates} };
	my $has_keywords = is_plain_arrayref( $self->{keyword_gates} ) && @{ $self->{keyword_gates} };
	$self->{has_boolean} = ( $has_gates || $has_keywords || defined( $self->{condition_ast} ) ) ? 1 : 0;

	# the whole-rule fast path... a rule whose boolean is nothing but a gate
	# list, every entry of which compiled to a code ref, is run by walking
	# those code refs and nothing else. set only when that holds, so
	# _boolean_pass tests one defined and is otherwise untouched. a rule with
	# keywords, a condition, or any gate shape that did not compile leaves it
	# undef and takes the general path as before
	$self->{gate_code} = undef;
	if ( $has_gates && !$has_keywords && !defined( $self->{condition_ast} ) ) {
		my @code;
		foreach my $gate ( @{ $self->{gates} } ) {
			if ( !defined( $gate->{code} ) ) {
				@code = ();
				last;
			}
			push( @code, $gate->{code} );
		}
		if (@code) {
			$self->{gate_code} = \@code;
		}
	} ## end if ( $has_gates && !$has_keywords && !defined...)

	return;
} ## end sub _compile_boolean

# compiles the fixed-field gates of the http and http_error types... each gate
# key the def sets becomes a matcher set that the parsed field of the same name
# must hit.
#
# args:
#   $fields :: arrayref of the def keys that are field gates, each named for
#              the parsed field it gates, as status and method are
#
# returns nothing. the compiled gates land in $self->{field_gates}, keyed by
# field. a gate key that is set but is not a non-empty array dies.
#
#   $self->_compile_field_gates( [ 'status', 'method' ] );
sub _compile_field_gates {
	my ( $self, $fields ) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	foreach my $field ( @{$fields} ) {
		if ( !defined( $def->{$field} ) ) {
			next;
		}
		if ( !is_plain_arrayref( $def->{$field} ) || !@{ $def->{$field} } ) {
			die( 'The ' . $field . ' of the rule "' . $name . '" is not a array or is empty' );
		}
		$self->{field_gates}{$field}
			= compile_matchers( $def->{$field}, 'The ' . $field . ' of the rule "' . $name . '"' );
	} ## end foreach my $field ( @{$fields} )

	return;
} ## end sub _compile_field_gates

# whether a parsed line passes the fixed-field gates _compile_field_gates
# built... every gate's field must hit one of its matchers.
#
# args:
#   $parsed :: the parsed line's hash
#
# returns 1 when every gate holds, which it does with none, else 0.
#
#   if ( !$self->_field_gates_pass($parsed) ) { return undef; }
sub _field_gates_pass {
	my ( $self, $parsed ) = @_;

	foreach my $field ( keys( %{ $self->{field_gates} } ) ) {
		if ( !matchers_hit( $self->{field_gates}{$field}, $parsed->{$field} ) ) {
			return 0;
		}
	}

	return 1;
} ## end sub _field_gates_pass

# the shared middle of the http and http_error checks... the tracked clause and
# the generic gate, selections, or keywords over the line's field space, then
# the track harvest, which runs whether or not the line passed. the field space
# is the type's own _field_space of the line, and is only built here when the
# boolean, a tracked gate, or a harvest needs it.
#
# args:
#   $parsed   :: the parsed line's hash
#   $line_ctx :: the line context, for the tracked store and the clock
#
# returns the two item list ( $passed, $field_space )... passed 1 when the
# boolean holds or there is none, else 0, and field_space the hash ref built,
# or undef when nothing here needed it, for the caller to build once the line
# has matched.
#
#   my ( $passed, $field_space ) = $self->_boolean_and_harvest( $parsed, $line_ctx );
sub _boolean_and_harvest {
	my ( $self, $parsed, $line_ctx ) = @_;

	my $field_space;
	if ( $self->{has_boolean} || defined( $self->{tracks} ) || defined( $self->{track_gates} ) ) {
		$field_space = $self->_field_space($parsed);
	}

	# held rather than returned on, as the harvest below runs either way
	my $passed = 1;
	if ( $self->{has_boolean} || defined( $self->{track_gates} ) ) {
		$passed = $self->_offense_boolean_pass( $field_space, undef, $line_ctx ) ? 1 : 0;
	}

	if ( defined( $self->{tracks} ) ) {
		$self->_track_sweep( [$field_space], $line_ctx );
	}

	return ( $passed, $field_space );
} ## end sub _boolean_and_harvest

# compiles the keywords shorthand into a keyword gate list, ANDed ahead of the
# gate or selections by _boolean_pass. a plain list searches every field via
# %%%ANY%%%; the { in, values } form searches a named path, a %%%ANY:prefix%%%
# subtree, or %%%ANY%%%, so a rule can scope the search when it knows the path
sub _compile_keywords {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	if ( !defined( $def->{keywords} ) ) {
		return;
	}
	my $where = 'The keywords of the rule "' . $name . '"';
	my $kw    = $def->{keywords};

	my ( $in, $values );
	if ( is_plain_arrayref($kw) ) {
		$in     = '%%%ANY%%%';
		$values = $kw;
	} elsif ( is_plain_hashref($kw) ) {
		check_hash( $kw, { 'optional' => { 'in' => 'string', 'values' => 'any' } }, $where );
		$in     = $kw->{in} // '%%%ANY%%%';
		$values = $kw->{values};
	} else {
		die( $where . ' is not a list of strings or a table' );
	}

	if ( !is_plain_arrayref($values) || !@{$values} ) {
		die( $where . ' lacks a non-empty values list' );
	}

	# one contains-predicate gate over the chosen field, reusing the whole
	# operator/decode/keyword machinery
	$self->{keyword_gates}
		= compile_gates( [ { 'field' => $in, 'op' => 'contains', 'values' => $values } ], $where );

	return;
} ## end sub _compile_keywords

# runs a rule's boolean matcher over a data hash, true when it passes... the
# selections folded by their condition when the rule has them, else the flat
# gate, else true (no boolean filter). the one entry point for json's pre-filter
# and the syslog/raw post-match refinement alike
sub _boolean_pass {
	my ( $self, $data, $message ) = @_;

	# the common rule... a gate list and nothing else, every entry of it
	# compiled to a code ref that does only what that one gate needs. walking
	# the code refs is the whole judgment, so the keyword, condition, and
	# gate-shape questions below are not asked per line and gates_pass, with
	# the general per-gate test behind it, is never entered
	if ( defined( $self->{gate_code} ) ) {
		foreach my $code ( @{ $self->{gate_code} } ) {
			if ( !$code->($data) ) {
				return 0;
			}
		}
		return 1;
	}

	# the keywords shorthand, ANDed ahead of the gate or selections so it
	# composes with either or stands alone
	if ( is_plain_arrayref( $self->{keyword_gates} ) && @{ $self->{keyword_gates} } ) {
		if ( !gates_pass( $self->{keyword_gates}, $data, $message ) ) {
			return 0;
		}
	}

	if ( defined( $self->{condition_ast} ) ) {
		# selections evaluate lazily and memoized, so a condition that
		# short-circuits (a failed and-arm, a satisfied or-arm) never pays
		# for the selections it did not need
		my %results;
		my $eval_sel = sub {
			my ($sel_name) = @_;
			if ( !exists( $results{$sel_name} ) ) {
				$results{$sel_name} = gates_pass( $self->{selections}{$sel_name}, $data, $message );
			}
			return $results{$sel_name};
		};
		return eval_condition( $self->{condition_ast}, $eval_sel );
	} ## end if ( defined( $self->{condition_ast} ) )

	if ( is_plain_arrayref( $self->{gates} ) && @{ $self->{gates} } ) {
		return gates_pass( $self->{gates}, $data, $message );
	}

	return 1;
} ## end sub _boolean_pass

1;
