package App::Baphomet::Rules::Base;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util             qw( is_plain_arrayref is_plain_hashref );
use Digest::MD5           qw( md5 );
use List::Util            qw( uniqstr );
use App::Baphomet::Parser ();
use App::Baphomet::Marks  ();
use App::Baphomet::Tracks qw( track_key track_get track_put );
use App::Baphomet::Rules::Gates
	qw( compile_matchers matchers_hit compile_gates gates_pass compile_condition eval_condition );
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp match_tokened );
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
galla reads a rule through, and the regexp, staged, correlated, and tracked
matching the types share. The gate vocabulary is
L<App::Baphomet::Rules::Gates>, the C<%%%%TOKEN%%%%> regexps
L<App::Baphomet::Rules::Tokens>, and the embedded test runner
L<App::Baphomet::Rules::SelfTest>. Not usable on its own... see
L<App::Baphomet::Rules::Syslog> and L<App::Baphomet::Rules::HTTP> for the
handlers.

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

	$now //= time;

	# correlation context and staged rule slots are kept the same way, per
	# scope and key with a expires, so the one walk drops the dead of either...
	# for a staged slot that is a sequence nothing has fed since its stage's
	# within, or the default hold
	foreach my $store_name ( 'context', 'stage_state' ) {
		my $store = $self->{$store_name};
		foreach my $scope ( keys( %{$store} ) ) {
			foreach my $key ( keys( %{ $store->{$scope} } ) ) {
				if ( $store->{$scope}{$key}{expires} <= $now ) {
					delete( $store->{$scope}{$key} );
				}
			}
			if ( !%{ $store->{$scope} } ) {
				delete( $store->{$scope} );
			}
		} ## end foreach my $scope ( keys( %{$store} ) )
	} ## end foreach my $store_name ( 'context', 'stage_state')

	foreach my $scope ( keys( %{ $self->{pending} } ) ) {
		foreach my $key ( keys( %{ $self->{pending}{$scope} } ) ) {
			my @live = grep { $_->{expires} > $now } @{ $self->{pending}{$scope}{$key} };
			if (@live) {
				$self->{pending}{$scope}{$key} = \@live;
			} else {
				delete( $self->{pending}{$scope}{$key} );
			}
		}
		if ( !keys( %{ $self->{pending}{$scope} } ) ) {
			delete( $self->{pending}{$scope} );
		}
	} ## end foreach my $scope ( keys( %{ $self->{pending} }...))

	return;
} ## end sub sweep_state

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

=head2 mark_gates

Returns the rule's mark gates as a hash of three arrays, C<marked>,
C<not_marked>, and C<sequence>, any possibly empty. Each marked or
not_marked entry keys by C<var> or the
compound C<vars>, or var-less by the offender IP. A marked entry names its
brand with C<name>, or with C<names> holds on any of a list, and either
kind of entry may carry one of C<value_is> or C<value_not>, naming a
capture the stored value must equal or differ from... on a not_marked
entry the compare narrows the veto to a brand carrying that value. The
galla evaluates these against its marks store... a found result only
counts if every gate holds.

    my $gates = $rule->mark_gates;
    foreach my $gate ( @{ $gates->{marked} } ) { ... }

=cut

sub mark_gates {
	my ($self) = @_;

	return $self->{mark_gates};
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
detection-only. When present it must be a non-empty array of strings, and it
may not sit beside C<ban_var>... a rule bans or is detection-only, not both.
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

	if ( !is_plain_arrayref( $def->{detection_var} ) || !@{ $def->{detection_var} } ) {
		die( 'The rule "' . $name . '" has a detection_var that is not a non-empty array' );
	}
	foreach my $item ( @{ $def->{detection_var} } ) {
		if ( !defined($item) || ref($item) ne '' ) {
			die( 'The detection_var of the rule "' . $name . '" contains a non-string entry' );
		}
	}
	if ( exists( $def->{ban_var} ) ) {
		die(      'The rule "'
				. $name
				. '" sets both ban_var and detection_var... a rule banishes or is detection-only, not both' );
	}

	return 1;
} ## end sub _check_detection_var

# what the name of a mark, a tracked record, a namtar list, or a active_time
# window must look like... the alphabet of a rule name, so one rides tablets,
# commands, and config tables cleanly
my $NAME_RE = qr/^[a-zA-Z0-9_\-]+$/;

# the def keys every rule type allows, the ones _check_common goes on to
# vet... a type adds only its own matcher keys to these
my @COMMON_DEF_KEYS = qw(
	gate selections condition keywords
	detection_var ban_not_internal src_ip_var src_port_var dest_ip_var dest_port_var user_var
	max_score find_time ban_time weight eve_only distinct
	msg severity classtype references attack rev
	mark unmark marked not_marked mark_only sequence
	track tracked not_tracked track_only
	country namtar_list active_time reverse_dns
	tests test_parser
);

# the def checks every handler runs, one call so a new key or gate check can
# not be forgotten in one type... that the def is a hash, that it names only
# the common keys and the type's own, then the scoring and triage keys, the
# gate family, and the tests shape. the _check_ steps only validate, while the
# _compile_ ones, the tracks and the country, namtar_list, active_time, and
# reverse_dns gates, also compile what they vet onto the object.
#
# args:
#   $type_keys :: arrayref of the def keys this type allows past the common
#                 ones, its matcher keys
#
# returns nothing, dying on the first problem found. a sound def also leaves
# thresholds, mark_gates, and info on the object, the views of it their
# getters hand the galla.
#
#   $self->_check_common( [ 'status', 'method', 'match', 'ignore' ] );
sub _check_common {
	my ( $self, $type_keys ) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	if ( !is_plain_hashref($def) ) {
		die( 'The def for the rule "' . $name . '" is not a hash' );
	}
	$self->_check_keys( $def, [ @COMMON_DEF_KEYS, @{$type_keys} ], 'The rule "' . $name . '" has' );

	$self->_check_scoring_and_triage;
	$self->_check_marks;
	$self->_compile_tracks;
	$self->_compile_is_isnot_gate('country');
	$self->_compile_namtar;
	$self->_compile_is_isnot_gate('active_time');
	$self->_compile_reverse_dns;
	$self->_check_distinct;
	$self->_check_promoted_vars;

	if ( defined( $def->{tests} ) && !is_plain_hashref( $def->{tests} ) ) {
		die( 'The tests of the rule "' . $name . '" is not a hash' );
	}

	# the views of the def the galla asks for on every match, built once now
	# that the def is known sound rather than on each asking... the threshold
	# overrides the def actually sets, the mark gates each as a array however
	# few the def carries, and the def less its tests for the EVE rule field,
	# which the tests would bloat for no value
	$self->{thresholds}
		= { map { $_ => $def->{$_} } grep { defined( $def->{$_} ) } ( 'max_score', 'find_time', 'ban_time' ) };
	$self->{mark_gates} = { map { $_ => $def->{$_} // [] } ( 'marked', 'not_marked', 'sequence' ) };
	my %def_less_tests = %{$def};
	delete( $def_less_tests{tests} );
	$self->{info} = { 'name' => $name, 'def' => \%def_less_tests };

	return;
} ## end sub _check_common

# validates the ban_var of a def unless the rule is detection-only, and
# says which it was... shared by the types with a free-form ban_var (the
# http pair chisel theirs to a fixed field)
sub _check_ban_var {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	if ( $self->_check_detection_var ) {
		return 1;
	}

	if ( !is_plain_arrayref( $def->{ban_var} ) || !@{ $def->{ban_var} } ) {
		die( 'The rule "' . $name . '" lacks a ban_var array or it is empty' );
	}
	foreach my $item ( @{ $def->{ban_var} } ) {
		if ( !defined($item) || ref($item) ne '' ) {
			die( 'The ban_var of the rule "' . $name . '" contains a non-string entry' );
		}
	}

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

# the is/isnot gates, which share one shape... is xor isnot, each a entry or a
# array of them, and vars an optional found var or list of them to check in
# place of the offender or the clock. per gate, what its die messages call it,
# the key its getter lists the entries under, and what a entry must look like
my %IS_ISNOT_GATES = (
	'country' => {
		'label'       => 'country',
		'list_key'    => 'entries',
		'entry_re'    => qr/^(?:[A-Za-z]{2}|%%%country_codes\{[a-zA-Z0-9_\-]+\}%%%)$/,
		'entry_noun'  => 'entry',
		'entry_shape' => 'a 2-letter code or a %%%country_codes{name}%%% import',
	},
	'active_time' => {
		'label'       => 'active_time',
		'list_key'    => 'windows',
		'entry_re'    => $NAME_RE,
		'entry_noun'  => 'window name',
		'entry_shape' => 'a /^[a-zA-Z0-9_\-]+$/ string',
	},
);

=head2 country

Returns the rule's country gate normalized, or undef when it has none. The
gate is a hash of C<mode> (C<is> or C<isnot>), C<entries> (the raw list, 2-
letter codes and C<%%%country_codes{name}%%%> imports still unexpanded, as
the config to expand against is the galla's per watcher), and C<vars> (the
found vars to check the country of, or undef to check the offender IP). The
galla resolves the imports and does the lookups.

    my $country = $rule->country;

=cut

sub country {
	my ($self) = @_;

	return $self->{country_gate};
}

=head2 reverse_dns

Returns the rule's reverse_dns gate compiled, or undef when it has none...
a array of entries, each a hash of C<var> (the found var holding the
address, or undef for the offender), C<regexp> (the compiled matches) or
C<matches_var>, C<negate>, and C<forward_confirm>. The galla does the
lookups.

    my $reverse_dns = $rule->reverse_dns;

=cut

sub reverse_dns {
	my ($self) = @_;

	return $self->{reverse_dns_gate};
}

=head2 namtar_list

Returns the rule's namtar_list gate normalized, or undef when it has none.
The gate is a array of entries, each a hash of C<lists> (the named list
references, still unresolved as the config to resolve against is the
galla's per watcher) and C<var> (the found var to check, or undef for the
offender IP). The galla resolves the list names to files and does the
membership tests.

    foreach my $entry ( @{ $rule->namtar_list } ) { ... }

=cut

sub namtar_list {
	my ($self) = @_;

	return $self->{namtar_gate};
}

=head2 active_time

Returns the rule's active_time gate normalized, or undef when it has none.
The gate is a hash of C<mode> (C<is> or C<isnot>), C<windows> (the named
window references, still unresolved as the config to resolve against is the
galla's per watcher), and C<vars> (the found vars holding the times to
check, or undef to check the current time). The galla resolves the window
names to specs and does the time tests.

    my $active = $rule->active_time;

=cut

sub active_time {
	my ($self) = @_;

	return $self->{active_time_gate};
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
	if ( !is_plain_arrayref( $def->{mungers} ) || !@{ $def->{mungers} } ) {
		die( 'The mungers of the rule "' . $name . '" is not a non-empty array' );
	}
	foreach my $munger ( @{ $def->{mungers} } ) {
		if ( !defined($munger) || ref($munger) ne '' || $munger eq '' ) {
			die( 'The mungers of the rule "' . $name . '" contains a entry that is not a non-empty string' );
		}
	}
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

	if ( !( $self->{context} && %{ $self->{context} } ) && !( $self->{pending} && %{ $self->{pending} } ) ) {
		return undef;
	}

	return {
		'context' => $self->{context},
		'pending' => $self->{pending},
	};
} ## end sub dump_state

=head2 restore_state

Restores correlation state from what L</dump_state> returned, dropping
anything already expired as of $now. Merges into whatever is present
rather than replacing, so it is safe to call at start.

    $rule->restore_state( $state, $now );

=cut

sub restore_state {
	my ( $self, $state, $now ) = @_;

	if ( !is_plain_hashref($state) ) {
		return;
	}
	$now //= time;

	if ( is_plain_hashref( $state->{context} ) ) {
		foreach my $scope ( keys( %{ $state->{context} } ) ) {
			foreach my ( $key, $entry ) ( %{ $state->{context}{$scope} } ) {
				if ( is_plain_hashref($entry) && defined( $entry->{expires} ) && $entry->{expires} > $now ) {
					$self->{context}{$scope}{$key} = $entry;
				}
			}
		}
	}

	if ( is_plain_hashref( $state->{pending} ) ) {
		foreach my $scope ( keys( %{ $state->{pending} } ) ) {
			foreach my $key ( keys( %{ $state->{pending}{$scope} } ) ) {
				my @live = grep { is_plain_hashref($_) && defined( $_->{expires} ) && $_->{expires} > $now }
					@{ $state->{pending}{$scope}{$key} };
				if (@live) {
					push( @{ $self->{pending}{$scope}{$key} }, @live );
				}
			}
		}
	} ## end if ( is_plain_hashref( $state->{pending} ))

	return;
} ## end sub restore_state

=head2 run_tests

Runs the tests embedded in the rule, returning a hash of C<pass>, C<fail>,
and C<failures>. Does not die on test failures... that is the caller's call
to make. The runner is L<App::Baphomet::Rules::SelfTest/run_tests>, imported
here so it is a method of every rule, and what it does per test entry is
documented there.

    my $results = $rule->run_tests;

=cut

# the severity scale, worst last... the ordinal is unused for now but keeps
# the order canonical if anything ever wants to sort or compare
our %SEVERITY = ( 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4 );

# dies if a hash of a def carries a key it should not... the typo guard, a
# misspelled key otherwise being a setting that silently never applies. the
# keys are walked sorted, so of several unknown keys the one named is always
# the same, rather than whichever the hash happened to hand back first.
#
# args:
#   $hash    :: the hash ref to check, a def or one entry of a def list
#   $allowed :: arrayref of the keys the hash may carry
#   $prefix  :: the start of the die message, naming the rule and what the
#               hash is, up to and including its verb, such as 'The track of
#               the rule "syslog/sshd" has a entry with'... the message goes
#               on with ' the unknown key "<key>"'
#
# returns nothing, dying on the first unknown key.
#
#   $self->_check_keys( $entry, [qw( name key fields ttl )], $where . ' has a entry with' );
sub _check_keys {
	my ( $self, $hash, $allowed, $prefix ) = @_;

	my %allowed_keys = map { $_ => 1 } @{$allowed};
	foreach my $key ( sort( keys( %{$hash} ) ) ) {
		if ( !$allowed_keys{$key} ) {
			die( $prefix . ' the unknown key "' . $key . '"' );
		}
	}

	return;
} ## end sub _check_keys

# dies unless a def value is a non-empty array whose every entry is a
# defined, plain, non-empty string... the shape of references, attack, a mark
# or sequence entry's vars, and a tracked gate's into.
#
# args:
#   $value  :: the def value as the rule file wrote it
#   $prefix :: the start of the die message, naming the rule and the key, such
#              as 'The rule "syslog/sshd" has a references'... the message goes
#              on with " that is not a non-empty array" for a bad list, or
#              " entry that is not a non-empty string" for a bad entry
#
# returns nothing, dying on the first problem found.
#
#   _check_string_list( $def->{references}, 'The rule "' . $name . '" has a references' );
sub _check_string_list {
	my ( $value, $prefix ) = @_;

	if ( !is_plain_arrayref($value) || !@{$value} ) {
		die( $prefix . ' that is not a non-empty array' );
	}
	foreach my $item ( @{$value} ) {
		if ( !defined($item) || ref($item) ne '' || $item eq '' ) {
			die( $prefix . ' entry that is not a non-empty string' );
		}
	}

	return;
} ## end sub _check_string_list

# dies if the def's scoring knobs or triage metadata hold unusable values...
# the scoring knobs being the threshold overrides, positive ints for
# max_score and find_time and a non-negative one for ban_time (0 meaning
# eternal), a positive number for weight, and a boolean for eve_only, and the
# triage metadata a non-empty msg and classtype, a known severity, a
# non-negative int rev, and references and attack as lists of non-empty
# strings... called by every handler's new, as the keys are legal on every
# type
sub _check_scoring_and_triage {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	foreach my $item ( 'max_score', 'find_time' ) {
		if ( defined( $def->{$item} )
			&& ( ref( $def->{$item} ) ne '' || $def->{$item} !~ /^[0-9]+$/ || !$def->{$item} ) )
		{
			die( 'The rule "' . $name . '" has a ' . $item . ', "' . $def->{$item} . '", that is not a positive int' );
		}
	}
	if ( defined( $def->{ban_time} ) && ( ref( $def->{ban_time} ) ne '' || $def->{ban_time} !~ /^[0-9]+$/ ) ) {
		die(      'The rule "'
				. $name
				. '" has a ban_time, "'
				. $def->{ban_time}
				. '", that is not a non-negative int of seconds' );
	}
	if (
		defined( $def->{weight} )
		&& (   ref( $def->{weight} ) ne ''
			|| $def->{weight} !~ /^[0-9]+(?:\.[0-9]+)?$/
			|| $def->{weight} + 0 <= 0 )
		)
	{
		die( 'The rule "' . $name . '" has a weight, "' . $def->{weight} . '", that is not a positive number' );
	}
	if ( defined( $def->{eve_only} ) && ref( $def->{eve_only} ) ne '' ) {
		die( 'The rule "' . $name . '" has a eve_only that is not a boolean' );
	}
	if ( defined( $def->{msg} ) && ( ref( $def->{msg} ) ne '' || $def->{msg} eq '' ) ) {
		die( 'The rule "' . $name . '" has a msg that is not a non-empty string' );
	}
	if ( defined( $def->{severity} ) && ( ref( $def->{severity} ) ne '' || !exists( $SEVERITY{ $def->{severity} } ) ) )
	{
		die( 'The rule "' . $name . '" has a severity that is not one of info/low/medium/high/critical' );
	}
	if ( defined( $def->{classtype} ) && ( ref( $def->{classtype} ) ne '' || $def->{classtype} eq '' ) ) {
		die( 'The rule "' . $name . '" has a classtype that is not a non-empty string' );
	}
	# the EVE rev... a non-negative integer, 0 the unversioned default
	if ( defined( $def->{rev} ) && ( ref( $def->{rev} ) ne '' || $def->{rev} !~ /^\d+$/ ) ) {
		die( 'The rule "' . $name . '" has a rev that is not a non-negative integer' );
	}
	foreach my $listkey ( 'references', 'attack' ) {
		if ( defined( $def->{$listkey} ) ) {
			_check_string_list( $def->{$listkey}, 'The rule "' . $name . '" has a ' . $listkey );
		}
	}

	return;
} ## end sub _check_scoring_and_triage

# dies if the def's mark keys, mark, unmark, marked, not_marked, and
# mark_only, hold unusable values... called by every handler's new, as the
# keys are legal on every type. Names are constrained like rule names so
# they ride tablets and commands cleanly.
sub _check_marks {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	my %shapes = (
		'mark' =>
			{ 'name' => 'required', 'ttl' => 'ttl', 'var' => 'string', 'vars' => 'vars', 'value_var' => 'string' },
		'unmark' => { 'name' => 'required', 'var' => 'string', 'vars' => 'vars' },
		'marked' => {
			'name'      => 'required',
			'names'     => 'names',
			'var'       => 'string',
			'vars'      => 'vars',
			'value_is'  => 'string',
			'value_not' => 'string'
		},
		'not_marked' => {
			'name'      => 'required',
			'var'       => 'string',
			'vars'      => 'vars',
			'value_is'  => 'string',
			'value_not' => 'string'
		},
	);

	foreach my $key ( keys(%shapes) ) {
		if ( !defined( $def->{$key} ) ) {
			next;
		}
		my $where = 'The ' . $key . ' of the rule "' . $name . '"';
		if ( !is_plain_arrayref( $def->{$key} ) || !@{ $def->{$key} } ) {
			die( $where . ' is not a non-empty array' );
		}
		foreach my $entry ( @{ $def->{$key} } ) {
			if ( !is_plain_hashref($entry) ) {
				die( $where . ' contains a entry that is not a hash' );
			}
			$self->_check_keys( $entry, [ keys( %{ $shapes{$key} } ) ], $where . ' has a entry with' );
			# a marked entry may carry names, a any-of list, in place of its
			# one name... everything else requires the one
			if ( defined( $shapes{$key}{names} ) && defined( $entry->{names} ) ) {
				if ( defined( $entry->{name} ) ) {
					die( $where . ' has a entry carrying both name and names' );
				}
				if ( !is_plain_arrayref( $entry->{names} ) || !@{ $entry->{names} } ) {
					die( $where . ' has a entry whose names is not a non-empty array' );
				}
				foreach my $mark_name ( @{ $entry->{names} } ) {
					if ( !defined($mark_name) || ref($mark_name) ne '' || $mark_name !~ $NAME_RE ) {
						die( $where . ' has a entry with a names entry not matching /^[a-zA-Z0-9_\-]+$/' );
					}
				}
			} elsif ( !defined( $entry->{name} )
				|| ref( $entry->{name} ) ne ''
				|| $entry->{name} !~ $NAME_RE )
			{
				die( $where . ' has a entry lacking a name matching /^[a-zA-Z0-9_\-]+$/' );
			}
			my $entry_name = $entry->{name} // join( '|', @{ $entry->{names} } );
			if (
				defined( $shapes{$key}{ttl} )
				&& (  !defined( $entry->{ttl} )
					|| ref( $entry->{ttl} ) ne ''
					|| $entry->{ttl} !~ /^[0-9]+$/
					|| !$entry->{ttl} )
				)
			{
				die( $where . ' entry "' . $entry_name . '" lacks a ttl that is a positive int of seconds' );
			} ## end if ( defined( $shapes{$key}{ttl} ) && ( !defined...))
			# vars, a compound key... two or more captures joined into one
			# brandable key, and never beside the single var
			if ( defined( $entry->{vars} ) ) {
				if ( defined( $entry->{var} ) ) {
					die( $where . ' entry "' . $entry_name . '" carries both var and vars' );
				}
				_check_string_list( $entry->{vars}, $where . ' entry "' . $entry_name . '" has a vars' );
			}
			foreach my $string_key (
				grep { defined( $shapes{$key}{$_} ) && $shapes{$key}{$_} eq 'string' }
				keys( %{$entry} )
				)
			{
				if (  !defined( $entry->{$string_key} )
					|| ref( $entry->{$string_key} ) ne ''
					|| $entry->{$string_key} eq '' )
				{
					die(      $where
							. ' entry "'
							. $entry_name
							. '" has a '
							. $string_key
							. ' that is not a non-empty string' );
				} ## end if ( !defined( $entry->{$string_key} ) || ...)
			} ## end foreach my $string_key ( grep { defined( $shapes...)})
			if ( defined( $entry->{value_is} ) && defined( $entry->{value_not} ) ) {
				die( $where . ' entry "' . $entry_name . '" carries both value_is and value_not' );
			}
		} ## end foreach my $entry ( @{ $def->{$key} } )
	} ## end foreach my $key ( keys(%shapes) )

	# the sequence gate... ordered temporal correlation, a list of mark names
	# that must all be set for the key and in the listed order by set time
	if ( defined( $def->{sequence} ) ) {
		my $where = 'The sequence of the rule "' . $name . '"';
		if ( !is_plain_arrayref( $def->{sequence} ) || !@{ $def->{sequence} } ) {
			die( $where . ' is not a non-empty array' );
		}
		foreach my $entry ( @{ $def->{sequence} } ) {
			if ( !is_plain_hashref($entry) ) {
				die( $where . ' contains a entry that is not a hash' );
			}
			$self->_check_keys( $entry, [qw( marks var vars )], $where . ' has a entry with' );
			if ( !is_plain_arrayref( $entry->{marks} ) || scalar( @{ $entry->{marks} } ) < 2 ) {
				die( $where . ' entry lacks a marks array of at least two mark names' );
			}
			foreach my $mark_name ( @{ $entry->{marks} } ) {
				if ( !defined($mark_name) || ref($mark_name) ne '' || $mark_name !~ $NAME_RE ) {
					die( $where . ' entry has a mark name not matching /^[a-zA-Z0-9_\-]+$/' );
				}
			}
			if ( defined( $entry->{var} ) && ( ref( $entry->{var} ) ne '' || $entry->{var} eq '' ) ) {
				die( $where . ' entry has a var that is not a non-empty string' );
			}
			if ( defined( $entry->{vars} ) ) {
				if ( defined( $entry->{var} ) ) {
					die( $where . ' entry carries both var and vars' );
				}
				_check_string_list( $entry->{vars}, $where . ' entry has a vars' );
			}
		} ## end foreach my $entry ( @{ $def->{sequence} } )
	} ## end if ( defined( $def->{sequence} ) )

	return;
} ## end sub _check_marks

# dies if the def's track keys, track, tracked, not_tracked, and track_only,
# hold unusable values, compiling the usable ones onto the object... called by
# every handler's new, as the keys are legal on every type. Names are
# constrained like mark names so they ride tablets and commands cleanly.
#
# takes nothing. returns nothing, leaving tracks (a array ref of
# { name, key, fields, ttl }) and track_gates ({ tracked, not_tracked }) on
# the object, each entry of the latter carrying the key its declaration gave
# so the runtime never has to look one up.
#
# two rulings are enforced here rather than left to surprise a operator at
# three in the morning. A tracked or not_tracked naming a record the rule
# declared no track for will not load, the declaration being what the read is
# a read of. And a tracked entry carrying neither where nor into will not
# load, doing nothing being worth saying out loud.
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
		if ( !is_plain_arrayref( $def->{track} ) || !@{ $def->{track} } ) {
			die( $where . ' is not a non-empty array' );
		}
		my @tracks;
		foreach my $entry ( @{ $def->{track} } ) {
			if ( !is_plain_hashref($entry) ) {
				die( $where . ' contains a entry that is not a hash' );
			}
			$self->_check_keys( $entry, [qw( name key fields ttl )], $where . ' has a entry with' );
			if ( !defined( $entry->{name} ) || ref( $entry->{name} ) ne '' || $entry->{name} !~ $NAME_RE ) {
				die( $where . ' has a entry lacking a name matching /^[a-zA-Z0-9_\-]+$/' );
			}
			if ( defined( $declared{ $entry->{name} } ) ) {
				die( $where . ' declares "' . $entry->{name} . '" twice, which leaves its key ambiguous' );
			}

			# the key, a found var or a compound list of them. a list of one is
			# the same thing as the plain string, so both compile to a list and
			# the runtime has one shape to resolve
			my @components;
			if ( is_plain_arrayref( $entry->{key} ) ) {
				if ( !@{ $entry->{key} } ) {
					die( $where . ' entry "' . $entry->{name} . '" has a key that is a empty array' );
				}
				@components = @{ $entry->{key} };
			} else {
				@components = ( $entry->{key} );
			}
			foreach my $component (@components) {
				if ( !defined($component) || ref($component) ne '' || $component eq '' ) {
					die( $where . ' entry "' . $entry->{name} . '" has a key that is not a non-empty found var' );
				}
			}

			# fields absent means everything found is contributed, which is not
			# the same as a empty list, which means nothing is... the second is
			# how a rule that only reads a record declares itself
			my $fields;
			if ( defined( $entry->{fields} ) ) {
				if ( !is_plain_arrayref( $entry->{fields} ) ) {
					die( $where . ' entry "' . $entry->{name} . '" has a fields that is not a array' );
				}
				foreach my $field ( @{ $entry->{fields} } ) {
					if ( !defined($field) || ref($field) ne '' || $field eq '' ) {
						die(      $where
								. ' entry "'
								. $entry->{name}
								. '" has a fields entry that is not a non-empty string' );
					}
				}
				$fields = [ @{ $entry->{fields} } ];
			} ## end if ( defined( $entry->{fields} ) )

			my $ttl = 3600;
			if ( defined( $entry->{ttl} ) ) {
				if ( ref( $entry->{ttl} ) ne '' || $entry->{ttl} !~ /^[0-9]+$/ || !$entry->{ttl} ) {
					die( $where . ' entry "' . $entry->{name} . '" has a ttl that is not a positive int of seconds' );
				}
				$ttl = $entry->{ttl};
			}

			my $track = {
				'name'   => $entry->{name},
				'key'    => \@components,
				'fields' => $fields,
				'ttl'    => $ttl
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
		if ( !is_plain_arrayref( $def->{$key} ) || !@{ $def->{$key} } ) {
			die( $where . ' is not a non-empty array' );
		}
		foreach my $entry ( @{ $def->{$key} } ) {
			if ( !is_plain_hashref($entry) ) {
				die( $where . ' contains a entry that is not a hash' );
			}
			$self->_check_keys(
				$entry,
				$key eq 'tracked' ? [qw( name where into )] : ['name'],
				$where . ' has a entry with'
			);
			if ( !defined( $entry->{name} ) || ref( $entry->{name} ) ne '' || $entry->{name} !~ $NAME_RE ) {
				die( $where . ' has a entry lacking a name matching /^[a-zA-Z0-9_\-]+$/' );
			}
			if ( !defined( $declared{ $entry->{name} } ) ) {
				die( $where . ' entry "' . $entry->{name} . '" names a record the rule declares no track for' );
			}

			my $gate = { 'name' => $entry->{name}, 'key' => $declared{ $entry->{name} }{key} };

			if ( $key eq 'tracked' ) {
				if ( !defined( $entry->{where} ) && !defined( $entry->{into} ) ) {
					die(      $where
							. ' entry "'
							. $entry->{name}
							. '" carries neither where nor into, so it does nothing' );
				}
				if ( defined( $entry->{where} ) ) {
					# the ordinary gate vocabulary, judged against the stored
					# record rather than the line... so a undef stored value
					# already fails every operator but exists
					$gate->{where}
						= compile_gates( $entry->{where}, $where . ' entry "' . $entry->{name} . '" where' );
				}
				if ( defined( $entry->{into} ) ) {
					_check_string_list( $entry->{into}, $where . ' entry "' . $entry->{name} . '" has a into' );
					$gate->{into} = [ @{ $entry->{into} } ];
				}
			} ## end if ( $key eq 'tracked' )

			push( @{ $gates->{$key} }, $gate );
		} ## end foreach my $entry ( @{ $def->{$key} } )
	} ## end foreach my $key ( 'tracked', 'not_tracked' )

	if ( @{ $gates->{tracked} } || @{ $gates->{not_tracked} } ) {
		$self->{track_gates} = $gates;
	}

	return;
} ## end sub _compile_tracks

# dies if the def's is/isnot gate of the named kind is malformed, and leaves a
# sound one normalized on the object for its getter... the mode, its entries
# as a list however the def wrote them, and vars as a list or undef. the token
# and window names are resolved against the config later, by the galla, per
# watcher.
#
# args:
#   $gate_key :: the gate's def key, a key of %IS_ISNOT_GATES, country or
#                active_time
#
# returns nothing, dying on the first problem found. a def without the gate
# passes and leaves nothing. otherwise the gate lands under its key with _gate
# on the end, country_gate or active_time_gate, a hash ref of mode (is or
# isnot), the gate's list key (entries or windows) holding the arrayref of its
# entries, and vars, a arrayref of the found vars to check or undef to check
# the offender or the clock.
#
#   $self->_compile_is_isnot_gate('country');
#   # $self->{country_gate} is { 'mode' => 'is', 'entries' => [ 'US' ], 'vars' => undef }
sub _compile_is_isnot_gate {
	my ( $self, $gate_key ) = @_;

	my $gate_def = $self->{def}{$gate_key};
	if ( !defined($gate_def) ) {
		return;
	}

	my $shape = $IS_ISNOT_GATES{$gate_key};
	my $where = 'The ' . $shape->{label} . ' gate of the rule "' . $self->{name} . '"';

	if ( !is_plain_hashref($gate_def) ) {
		die( $where . ' is not a hash' );
	}
	$self->_check_keys( $gate_def, [qw( is isnot vars )], $where . ' has' );
	if ( defined( $gate_def->{is} ) && defined( $gate_def->{isnot} ) ) {
		die( $where . ' carries both is and isnot' );
	}
	if ( !defined( $gate_def->{is} ) && !defined( $gate_def->{isnot} ) ) {
		die( $where . ' has neither is nor isnot' );
	}

	my $mode = defined( $gate_def->{is} ) ? 'is' : 'isnot';

	my @entries = is_plain_arrayref( $gate_def->{$mode} ) ? @{ $gate_def->{$mode} } : ( $gate_def->{$mode} );
	if ( !@entries ) {
		die( $where . ' ' . $mode . ' is empty' );
	}
	foreach my $entry (@entries) {
		if ( !defined($entry) || ref($entry) ne '' || $entry !~ $shape->{entry_re} ) {
			die( $where . ' ' . $mode . ' has a ' . $shape->{entry_noun} . ' that is not ' . $shape->{entry_shape} );
		}
	}

	my $vars;
	if ( defined( $gate_def->{vars} ) ) {
		my @vars = is_plain_arrayref( $gate_def->{vars} ) ? @{ $gate_def->{vars} } : ( $gate_def->{vars} );
		if ( !@vars ) {
			die( $where . ' vars is empty' );
		}
		foreach my $var (@vars) {
			if ( !defined($var) || ref($var) ne '' || $var eq '' ) {
				die( $where . ' vars has a entry that is not a non-empty string' );
			}
		}
		$vars = \@vars;
	} ## end if ( defined( $gate_def->{vars} ) )

	$self->{ $gate_key . '_gate' } = { 'mode' => $mode, $shape->{list_key} => \@entries, 'vars' => $vars };

	return;
} ## end sub _compile_is_isnot_gate

# dies if the def's reverse_dns gate is malformed, compiling it onto the
# object... a array of entries, each comparing the PTR names of an address
# (a named found var, or var-less the offender) against a regexp (matches)
# or another found value (matches_var), optionally negated, with forward
# confirmation on unless refused. the galla owns the lookups and the
# fail-closed rules, this only the shape
sub _compile_reverse_dns {
	my ($self) = @_;

	my $def = $self->{def};

	if ( !defined( $def->{reverse_dns} ) ) {
		return;
	}

	my $name  = $self->{name};
	my $where = 'The reverse_dns gate of the rule "' . $name . '"';

	if ( !is_plain_arrayref( $def->{reverse_dns} ) || !@{ $def->{reverse_dns} } ) {
		die( $where . ' is not a array or is empty' );
	}

	my @compiled;
	foreach my ( $entry_int, $entry ) ( indexed @{ $def->{reverse_dns} } ) {
		my $entry_where = $where . ' entry ' . $entry_int;
		if ( !is_plain_hashref($entry) ) {
			die( $entry_where . ' is not a hash' );
		}
		$self->_check_keys(
			$entry,
			[qw( var matches matches_var negate forward_confirm on_nxdomain on_servfail )],
			$entry_where . ' has'
		);
		if ( defined( $entry->{matches} ) && defined( $entry->{matches_var} ) ) {
			die( $entry_where . ' carries both matches and matches_var' );
		}
		if ( !defined( $entry->{matches} ) && !defined( $entry->{matches_var} ) ) {
			die( $entry_where . ' has neither matches nor matches_var' );
		}
		foreach my $key ( 'var', 'matches', 'matches_var' ) {
			if ( defined( $entry->{$key} ) && ( ref( $entry->{$key} ) ne '' || $entry->{$key} eq '' ) ) {
				die( $entry_where . ' has a ' . $key . ' that is not a non-empty string' );
			}
		}
		foreach my $key ( 'on_nxdomain', 'on_servfail' ) {
			if ( defined( $entry->{$key} )
				&& ( ref( $entry->{$key} ) ne '' || $entry->{$key} !~ /^(?:pass|fail|compare)$/ ) )
			{
				die( $entry_where . ' has a ' . $key . ' that is not one of pass, fail, or compare' );
			}
		}

		my $compiled_entry = {
			'var'             => $entry->{var},
			'matches_var'     => $entry->{matches_var},
			'negate'          => $entry->{negate}                                                       ? 1 : 0,
			'forward_confirm' => ( defined( $entry->{forward_confirm} ) && !$entry->{forward_confirm} ) ? 0 : 1,
			'on_nxdomain'     => defined( $entry->{on_nxdomain} ) ? $entry->{on_nxdomain}                   : 'compare',
			'on_servfail'     => defined( $entry->{on_servfail} ) ? $entry->{on_servfail}                   : 'fail',
		};
		if ( defined( $entry->{matches} ) ) {
			my $regexp = $entry->{matches};
			try {
				$compiled_entry->{regexp} = qr/$regexp/;
			} catch ($caught) {
				die( $entry_where . ' matches does not compile... ' . $caught );
			}
		}
		push( @compiled, $compiled_entry );
	} ## end foreach my ( $entry_int, $entry ) ( indexed @{ ...})
	$self->{reverse_dns_gate} = \@compiled;

	return;
} ## end sub _compile_reverse_dns

# dies if the def's namtar_list gate is malformed, and leaves a sound one
# normalized on the object for its getter... a array of entries, each naming
# one or more lists (list or lists) and a optional var to check instead of
# the offender. the list names are resolved against the config later, by the
# galla, per watcher.
#
# takes nothing. returns nothing, dying on the first problem found. a def
# without the gate passes and leaves nothing. otherwise namtar_gate holds a
# arrayref of entries, each a hash ref of lists, the arrayref of list names
# whichever of list or lists the def used, and var, the found var to check or
# undef for the offender.
#
#   $self->_compile_namtar;
#   # $self->{namtar_gate} is [ { 'lists' => [ 'threatfeed' ], 'var' => 'SRC' } ]
sub _compile_namtar {
	my ($self) = @_;

	my $def = $self->{def};

	if ( !defined( $def->{namtar_list} ) ) {
		return;
	}

	my $name  = $self->{name};
	my $where = 'The namtar_list gate of the rule "' . $name . '"';

	if ( !is_plain_arrayref( $def->{namtar_list} ) || !@{ $def->{namtar_list} } ) {
		die( $where . ' is not a non-empty array' );
	}
	my @compiled;
	foreach my $entry ( @{ $def->{namtar_list} } ) {
		if ( !is_plain_hashref($entry) ) {
			die( $where . ' has a entry that is not a hash' );
		}
		$self->_check_keys( $entry, [qw( list lists var )], $where . ' has a entry with' );
		if ( defined( $entry->{list} ) && defined( $entry->{lists} ) ) {
			die( $where . ' has a entry carrying both list and lists' );
		}
		my $lists = $entry->{lists} // $entry->{list};
		if ( !defined($lists) ) {
			die( $where . ' has a entry lacking a list or lists' );
		}
		my @lists = is_plain_arrayref($lists) ? @{$lists} : ($lists);
		if ( !@lists ) {
			die( $where . ' has a entry with a empty lists' );
		}
		foreach my $list (@lists) {
			if ( !defined($list) || ref($list) ne '' || $list !~ $NAME_RE ) {
				die( $where . ' has a list name that is not a /^[a-zA-Z0-9_\-]+$/ string' );
			}
		}
		if ( defined( $entry->{var} ) && ( ref( $entry->{var} ) ne '' || $entry->{var} eq '' ) ) {
			die( $where . ' has a var that is not a non-empty string' );
		}
		push( @compiled, { 'lists' => \@lists, 'var' => $entry->{var} } );
	} ## end foreach my $entry ( @{ $def->{namtar_list} } )
	$self->{namtar_gate} = \@compiled;

	return;
} ## end sub _compile_namtar

# checks the distinct-cardinality spec, dieing on anything unusable... a table
# with a of naming the found var whose distinct values the galla counts
sub _check_distinct {
	my ($self) = @_;

	my $def = $self->{def};

	if ( !defined( $def->{distinct} ) ) {
		return;
	}
	my $name = $self->{name};
	my $spec = $def->{distinct};

	if ( !is_plain_hashref($spec) ) {
		die( 'The distinct of the rule "' . $name . '" is not a table' );
	}
	$self->_check_keys( $spec, [qw( of by )], 'The distinct of the rule "' . $name . '" has' );
	if ( !defined( $spec->{of} ) || ref( $spec->{of} ) ne '' || $spec->{of} eq '' ) {
		die(      'The distinct of the rule "'
				. $name
				. '" lacks a non-empty of naming the field to count distinct values of' );
	}
	if ( defined( $spec->{by} ) && ( ref( $spec->{by} ) ne '' || $spec->{by} eq '' ) ) {
		die(      'The distinct of the rule "'
				. $name
				. '" has a by that is not a non-empty string naming the grouping field' );
	}

	return;
} ## end sub _check_distinct

# dies if any of the def's promoted-var keys is set to anything but a
# non-empty string... each names the found var whose value the galla
# promotes to the EVE top level. absent is fine, they default to the
# literal src_ip, dest_ip, src_port, dest_port, and user fields
sub _check_promoted_vars {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};
	foreach my $item ( 'src_ip_var', 'dest_ip_var', 'src_port_var', 'dest_port_var', 'user_var' ) {
		if ( !exists( $def->{$item} ) ) {
			next;
		}
		if ( !defined( $def->{$item} ) || ref( $def->{$item} ) ne '' || $def->{$item} eq '' ) {
			die( 'The ' . $item . ' of the rule "' . $name . '" is not a non-empty string' );
		}
	}

	return;
} ## end sub _check_promoted_vars

# Names the first message_regexp whose shape leaves the offender open to being
# chosen by whoever wrote the line, or undef when none does. Sets
# needs_injection_test, which run_tests turns into a warning when the rule
# carries no tests.injection to answer it... a warning and not a failure,
# because the shape alone does not make a rule exploitable.
#
# The shape is a LAZY unbounded wildcard between the head of the pattern and the
# offender token, with nothing anchoring the token's tail. Lazy takes the first
# candidate it reaches, so wherever the log lets a client write text ahead of the
# real field... an account name, a mail subject, a user agent... the client picks
# the ban target by planting a copy of the delimiter. Every real instance of this
# found in the shipped set had exactly this shape.
#
# Greedy is deliberately NOT flagged. It takes the LAST candidate, and a forgery
# can only ever be planted ahead of the field the daemon writes, so the ordering
# is itself the defence.
#
# This is a shape and nothing more. Whether a client can actually reach that
# wildcard is a property of the log format, which no amount of reading the
# pattern will settle: the two raw/palo-alto rules are the same shape and
# opposite verdicts, one writing the account before the address and one after.
# So this does not judge the pattern, and must not refuse it... it points at a
# question only a test can answer, and the answer may well be "safe here".
sub _detect_injection_shape {
	my ($self) = @_;

	my $def = $self->{def};

	$self->{needs_injection_test} = undef;

	foreach my $item ( @{ $def->{message_regexp} || [] } ) {
		my $re = is_plain_hashref($item) ? $item->{regexp} : $item;
		next if ( !defined($re) || ref($re) ne '' );

		my ( $pre, $token, $post ) = $re =~ /^(.*?)%%%%(SRC|DEST|ADDR|HOST|IP4|IP6|SUBNET)%%%%(.*)$/s;
		next if ( !defined($token) );

		# an unbounded run that yields the shortest match... ".*?", "\S+?" and
		# the like. a bounded one ("[^"]*", "{0,3}") cannot cross a delimiter
		next if ( $pre !~ /(?:\.|\\S|\\w|\\d|\\D|\\W)[*+]\?/ );

		# peel the tail down to whatever really has to be there... an all
		# optional group, a trailing space run, and a word boundary each anchor
		# nothing at all
		my $tail    = $post;
		my $peeling = 1;
		while ($peeling) {
			$peeling = 0;
			$peeling = 1 if ( $tail =~ s/\((?:\?:)?[^()]*\)[?*]// );
			$peeling = 1 if ( $tail =~ s/\\s\*// );
			$peeling = 1 if ( $tail =~ s/\\b// );
		}
		next if ( $tail =~ /\S/ );

		$self->{needs_injection_test} = 'the offender of "' . $re . '"';
		return;
	} ## end foreach my $item ( @{ $def->{message_regexp} ||...})

	return;
} ## end sub _detect_injection_shape

# compiles the matcher of the syslog and raw types, which is one of two
# things... a staged rule, whose stages are the whole matcher, or the
# per-line message_regexp with its capture_regexp correlation, and either way
# the ignore_regexp and the boolean. shared by the two types so a change to
# what a regexp rule may carry lands once.
#
# message_regexp may be left off when something else does the matching...
# message_json, whose decoded fields the gate tests, or mungers, whose
# decomposed fields it tests the same way, which is what lets an appliance
# rule name a parsed field as its offender instead of scanning the line for
# an address. either makes the gate the matcher, so such a rule must carry
# one.
#
# takes nothing, reading the def, the mungers, and message_json, which only
# the syslog type sets, off the object... so it is called after those are
# settled. returns nothing, dying on stages beside the per-line matchers, a
# per with no stages, anything the compiles it calls refuse, or a rule that
# would regard every line it decodes as a offense.
#
#   $self->_compile_message_matchers;
sub _compile_message_matchers {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	# a staged rule... its stages are the whole matcher, exclusive with the
	# per-line matchers and the keyed correlation
	if ( defined( $def->{stages} ) ) {
		my @beside = grep { defined( $def->{$_} ) } ( 'message_regexp', 'capture_regexp' );
		if ( $self->{message_json} ) {
			push( @beside, 'message_json' );
		}
		if (@beside) {
			die(      'The rule "'
					. $name
					. '" has stages beside '
					. join( ', ', @beside )
					. '... stages are the whole matcher' );
		}
		$self->_compile_ignore_regexps;
		$self->_compile_stages;
		$self->_compile_boolean;
		return;
	} ## end if ( defined( $def->{stages} ) )
	if ( defined( $def->{per} ) ) {
		die( 'The rule "' . $name . '" has a per but no stages for it to key' );
	}

	my $gate_may_match = ( $self->{message_json} || @{ $self->{mungers} } ) ? 1 : 0;
	$self->_compile_message_regexps($gate_may_match);
	$self->_compile_capture_regexps;

	# an optional gate or selections+condition refines the match on its
	# captures, and on the message_json or munger fields too... operators and
	# decode over the extracted vars, those fields, and the reserved MESSAGE
	$self->_compile_boolean;

	# a message_json or munger rule with no message_regexp must match on
	# something, else it would regard every line it decodes as a offense
	if ( $gate_may_match && !@{ $self->{regexps} } && !$self->{has_boolean} ) {
		die(      'The rule "'
				. $name . '" is '
				. ( $self->{message_json} ? 'message_json' : 'munger driven' )
				. ' with no message_regexp and no gate, selections, or keywords, so it would banish every line' );
	}

	return;
} ## end sub _compile_message_matchers

# compiles the def's message_regexp and ignore_regexp, expanding
# %%%%TOKEN%%%% tokens into named captures, and populates regexps and
# ignore_regexps on the object... shared by the handlers whose matching is
# regexps against a message with something to extract. takes whether a
# missing message_regexp is allowed, something else doing the matching
sub _compile_message_regexps {
	my ( $self, $allow_empty ) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	$self->{regexps} = [];

	# does any pattern leave the offender open to being chosen by whoever wrote
	# the line? run_tests turns a yes into a demand for a tests.injection entry
	$self->_detect_injection_shape;

	# a message_json rule may have no message_regexp, the json fields being
	# what it matches on, so the caller can allow an empty list. a missing key
	# is fine then; a present but malformed one is still an error
	if ( !defined( $def->{message_regexp} ) && $allow_empty ) {
		$self->_compile_ignore_regexps;
		return;
	}
	if ( !is_plain_arrayref( $def->{message_regexp} ) || !@{ $def->{message_regexp} } ) {
		die( 'The rule "' . $name . '" lacks a message_regexp array or it is empty' );
	}
	foreach my $item ( @{ $def->{message_regexp} } ) {
		if ( !defined($item) || ( ref($item) ne '' && !is_plain_hashref($item) ) ) {
			die( 'The message_regexp of the rule "' . $name . '" contains a entry that is not a string or a hash' );
		}
		if ( is_plain_hashref($item) ) {
			$self->_check_keys( $item, [qw( regexp key defer )],
				'A message_regexp entry of the rule "' . $name . '" has' );
			if ( !defined( $item->{regexp} ) || ref( $item->{regexp} ) ne '' ) {
				die( 'A message_regexp entry of the rule "' . $name . '" lacks a regexp string' );
			}
			if ( !defined( $item->{key} ) ) {
				die( 'A message_regexp hash entry of the rule "' . $name . '" lacks a key' );
			}
			$self->_correlation_key_components( $item->{key}, 'A message_regexp entry of the rule "' . $name . '"' );
			if ( defined( $item->{defer} ) && ( $item->{defer} !~ /^[0-9]+$/ || !$item->{defer} ) ) {
				die(      'The defer of a message_regexp entry of the rule "'
						. $name
						. '" is not a positive int of seconds' );
			}
		} ## end if ( is_plain_hashref($item) )
	} ## end foreach my $item ( @{ $def->{message_regexp} } )

	$self->_compile_ignore_regexps;

	foreach my ( $entry_int, $item ) ( indexed @{ $def->{message_regexp} } ) {
		my $regexp   = is_plain_hashref($item) ? $item->{regexp} : $item;
		my $compiled = compile_tokened_regexp( $regexp,
			'The message_regexp entry ' . $entry_int . ' of the rule "' . $name . '"' );
		if ( is_plain_hashref($item) ) {
			$compiled->{key} = $self->_correlation_key_components( $item->{key},
				'The message_regexp entry ' . $entry_int . ' of the rule "' . $name . '"' );
			$compiled->{defer} = $item->{defer};
		}
		push( @{ $self->{regexps} }, $compiled );
	} ## end foreach my ( $entry_int, $item ) ( indexed @{ $def...})

	return;
} ## end sub _compile_message_regexps

# compiles the def's ignore_regexp onto the object... tokens
# work here too, but nothing is captured from them, so the aliases are
# just thrown away. shared by the message_regexp and stages matchers
sub _compile_ignore_regexps {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	$self->{ignore_regexps} = [];

	if ( !defined( $def->{ignore_regexp} ) ) {
		return;
	}
	if ( !is_plain_arrayref( $def->{ignore_regexp} ) ) {
		die( 'The ignore_regexp of the rule "' . $name . '" is not a array' );
	}
	foreach my $item ( @{ $def->{ignore_regexp} } ) {
		if ( !defined($item) || ref($item) ne '' ) {
			die( 'The ignore_regexp of the rule "' . $name . '" contains a non-string entry' );
		}
	}

	foreach my ( $ignore_int, $regexp ) ( indexed @{ $def->{ignore_regexp} } ) {
		my $entry = compile_tokened_regexp( $regexp,
			'The ignore_regexp entry ' . $ignore_int . ' of the rule "' . $name . '"' );
		push( @{ $self->{ignore_regexps} }, $entry->{regexp} );
	}

	return;
} ## end sub _compile_ignore_regexps

# compiles the stages of a staged rule... ordered matchers with counted
# hits and gap bounds, the in-rule temporal correlation. the per key
# components ride the correlation key machinery, so envelope fields work
# where the type carries them
sub _compile_stages {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	if ( !is_plain_arrayref( $def->{stages} ) || !@{ $def->{stages} } ) {
		die( 'The stages of the rule "' . $name . '" is not a array or is empty' );
	}

	my @compiled_stages;
	foreach my ( $stage_int, $stage ) ( indexed @{ $def->{stages} } ) {
		my $where = 'The stage ' . $stage_int . ' of the rule "' . $name . '"';
		if ( !is_plain_hashref($stage) ) {
			die( $where . ' is not a hash' );
		}
		$self->_check_keys( $stage, [qw( message_regexp count within skip )], $where . ' has' );
		if ( !is_plain_arrayref( $stage->{message_regexp} ) || !@{ $stage->{message_regexp} } ) {
			die( $where . ' lacks a message_regexp array or it is empty' );
		}
		foreach my $item ( 'count', 'within', 'skip' ) {
			if ( defined( $stage->{$item} )
				&& ( ref( $stage->{$item} ) ne '' || $stage->{$item} !~ /^[0-9]+$/ || !$stage->{$item} ) )
			{
				die( $where . ' has a ' . $item . ' that is not a positive int' );
			}
		}

		my @matchers;
		foreach my ( $entry_int, $regexp ) ( indexed @{ $stage->{message_regexp} } ) {
			if ( !defined($regexp) || ref($regexp) ne '' ) {
				die( $where . ' has a message_regexp entry that is not a string' );
			}
			push( @matchers, compile_tokened_regexp( $regexp, $where . ' message_regexp entry ' . $entry_int ) );
		}

		push(
			@compiled_stages,
			{
				'matchers' => \@matchers,
				'count'    => defined( $stage->{count} )  ? $stage->{count} + 0  : 1,
				'within'   => defined( $stage->{within} ) ? $stage->{within} + 0 : undef,
				'skip'     => defined( $stage->{skip} )   ? $stage->{skip} + 0   : undef,
			}
		);
	} ## end foreach my ( $stage_int, $stage ) ( indexed @{ ...})
	$self->{stages} = \@compiled_stages;

	if ( defined( $def->{per} ) ) {
		$self->{per_key} = $self->_correlation_key_components( $def->{per}, 'The per of the rule "' . $name . '"' );
	}

	return;
} ## end sub _compile_stages

# checks a message against a staged rule... ordered stages, counted hits,
# and gap bounds, the state per (scope, per key) and memory only. returns
# undef until the final stage completes, then the found carrying the
# merged captures and the stage hits
sub _check_stages {
	my ( $self, $message, $scope, $line_ctx, $envelope, $munge ) = @_;

	if ( !defined($message) ) {
		return undef;
	}

	# 1.5, and lifted above the core so it stops the harvest too... a ignore
	# hit is the operator saying this line is not evidence, which no amount of
	# wanting a complete record overrides
	foreach my $ignore ( @{ $self->{ignore_regexps} } ) {
		if ( $message =~ $ignore ) {
			return undef;
		}
	}

	my $found = $self->_check_stages_core( $message, $scope, $line_ctx, $envelope, $munge );

	# the harvest runs on every line of a sequence, not only the one that
	# completed it... the completing line's whole accumulated field space when
	# there is one, this line's munger enrichment when there is not
	if ( defined( $self->{tracks} ) ) {
		my $source
			= defined($found)          ? $found->{data}
			: is_plain_hashref($munge) ? $munge
			:                            {};
		$self->_track_sweep( [$source], $line_ctx );
	}

	return $found;
} ## end sub _check_stages

# how long, in seconds, a staged slot waits for its next stage when that stage
# names no within of its own... also the life of a slot just opened
my $STAGE_DEFAULT_WITHIN = 600;

# the staged matcher proper, wrapped by _check_stages so the ignore veto and
# the track sweep sit either side of it. returns undef until the final stage
# completes, then the found carrying the merged captures and the stage hits
sub _check_stages_core {
	my ( $self, $message, $scope, $line_ctx, $envelope, $munge ) = @_;

	$scope //= '';
	# a missing line context reads as a empty one
	if ( !is_plain_hashref($line_ctx) ) {
		$line_ctx = {};
	}
	my $now = $line_ctx->{now} // time;
	my $seq = $line_ctx->{seq};

	my $stages = $self->{stages};
	my $store  = $self->{stage_state}{$scope};
	$store //= $self->{stage_state}{$scope} = {};

	# which stages this line hits, tried lazily and remembered
	my @stage_caps;
	my $stage_match = sub {
		my ($stage_int) = @_;
		if ( !exists( $stage_caps[$stage_int] ) ) {
			my $caps;
			foreach my $matcher ( @{ $stages->[$stage_int]{matchers} } ) {
				$caps = match_tokened( $matcher, $message );
				if ( defined($caps) ) {
					last;
				}
			}
			$stage_caps[$stage_int] = $caps;
		} ## end if ( !exists( $stage_caps[$stage_int] ) )
		return $stage_caps[$stage_int];
	}; ## end $stage_match = sub

	# the slot key... the per components off this line's captures and the
	# envelope, or the source for the keyless adjacency form
	my $slot_key = sub {
		my ($caps) = @_;
		if ( !defined( $self->{per_key} ) ) {
			return $line_ctx->{source} // '';
		}
		return $self->_correlation_key_value( { 'key' => $self->{per_key} }, $caps, $envelope );
	};

	# a hit on the stage a slot is awaiting advances it, gap bounds
	# permitting... too late or too far kills the sequence, and the line
	# may then head a fresh one below
	foreach my ( $stage_int, $stage ) ( indexed @{$stages} ) {
		my $caps = $stage_match->($stage_int);
		if ( !defined($caps) ) {
			next;
		}
		my $key_value = $slot_key->($caps);
		if ( !defined($key_value) ) {
			next;
		}
		my $slot = $store->{$key_value};
		if ( !defined($slot) || $slot->{stage} != $stage_int ) {
			next;
		}
		# a slot past its expiry is dead even if the sweeper has not gotten
		# to it yet, same as the context and pending stores judge at read
		if ( $slot->{expires} <= $now ) {
			delete( $store->{$key_value} );
			next;
		}

		my $gap_ok = 1;
		if ( defined( $stage->{within} ) && ( $now - $slot->{last_time} ) > $stage->{within} ) {
			$gap_ok = 0;
		}
		if (   $gap_ok
			&& defined( $stage->{skip} )
			&& defined($seq)
			&& defined( $slot->{last_seq} )
			&& ( $seq - $slot->{last_seq} - 1 ) > $stage->{skip} )
		{
			$gap_ok = 0;
		}
		if ( !$gap_ok ) {
			delete( $store->{$key_value} );
			last;
		}

		return $self->_stage_hit( $store, $key_value, $stage_int, $caps, $message, $now, $seq, $munge, $line_ctx );
	} ## end foreach my ( $stage_int, $stage ) ( indexed @{$stages...})

	# no slot advanced... a line matching the first stage heads a fresh
	# sequence, but never tramples one already in flight for its key
	my $caps = $stage_match->(0);
	if ( !defined($caps) ) {
		return undef;
	}
	my $key_value = $slot_key->($caps);
	if ( !defined($key_value) || defined( $store->{$key_value} ) ) {
		return undef;
	}
	# a fresh slot awaiting the first stage, the per scope slot count bounded
	# the way the correlation context is bounded
	App::Baphomet::Marks::bound_expiring_store( $store, $key_value, $now );
	$store->{$key_value} = {
		'stage'     => 0,
		'count'     => 0,
		'data'      => {},
		'hits'      => [],
		'last_time' => $now,
		'last_seq'  => undef,
		'expires'   => $now + $STAGE_DEFAULT_WITHIN,
	};

	return $self->_stage_hit( $store, $key_value, 0, $caps, $message, $now, $seq, $munge, $line_ctx );
} ## end sub _check_stages_core

# lands a hit on a slot's awaited stage... counts, merges captures later
# stages authoritative, and fires the found when the final stage completes
sub _stage_hit {
	my ( $self, $store, $key_value, $stage_int, $caps, $message, $now, $seq, $munge, $line_ctx ) = @_;

	my $slot  = $store->{$key_value};
	my $stage = $self->{stages}[$stage_int];

	$slot->{count}++;
	$slot->{data} = { %{ $slot->{data} }, %{$caps} };
	push( @{ $slot->{hits} }, { 'stage' => $stage_int, 'time' => $now, 'line' => $message } );
	$slot->{last_time} = $now;
	$slot->{last_seq}  = $seq;

	if ( $slot->{count} < $stage->{count} ) {
		$slot->{expires} = $now + ( $stage->{within} // $STAGE_DEFAULT_WITHIN );
		return undef;
	}

	# the final stage completing is the found... the rule's boolean matcher
	# filters the completed sequence like any other found
	if ( $stage_int == scalar( @{ $self->{stages} } ) - 1 ) {
		delete( $store->{$key_value} );
		# the completing line's munger enrichment rides under the sequence's
		# accumulated captures, which win on a clash... the same precedence a
		# non-staged rule gives, and the completing line is what EVE records
		my $data = $slot->{data};
		if ( is_plain_hashref($munge) && %{$munge} ) {
			$data = { %{$munge}, %{ $slot->{data} } };
		}
		my $found = { 'data' => $data, 'regexp' => undef, 'stages' => $slot->{hits} };
		if ( $self->{has_boolean} || defined( $self->{track_gates} ) ) {
			if ( !$self->_offense_boolean_pass( $found->{data}, $message, $line_ctx ) ) {
				return undef;
			}
		}
		return $found;
	} ## end if ( $stage_int == scalar( @{ $self->{stages...}}))

	$slot->{stage}++;
	$slot->{count} = 0;
	my $next_stage = $self->{stages}[ $slot->{stage} ];
	$slot->{expires} = $now + ( $next_stage->{within} // $STAGE_DEFAULT_WITHIN );

	return undef;
} ## end sub _stage_hit

# compiles the def's capture_regexp onto the object... entries harvest
# correlation context rather than being offenses, each a hash of a
# tokened regexp, the capture name serving as the correlation key, and a
# ttl for how long the harvested captures live
sub _compile_capture_regexps {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	$self->{capture_regexps} = [];

	if ( !defined( $def->{capture_regexp} ) ) {
		return;
	}
	if ( !is_plain_arrayref( $def->{capture_regexp} ) || !@{ $def->{capture_regexp} } ) {
		die( 'The capture_regexp of the rule "' . $name . '" is not a array or is empty' );
	}

	foreach my ( $entry_int, $item ) ( indexed @{ $def->{capture_regexp} } ) {
		my $where = 'The capture_regexp entry ' . $entry_int . ' of the rule "' . $name . '"';
		if ( !is_plain_hashref($item) || !defined( $item->{regexp} ) || !defined( $item->{key} ) ) {
			die( $where . ' is not a hash with a regexp and a key' );
		}
		$self->_check_keys( $item, [qw( regexp key ttl )], $where . ' has' );
		if ( defined( $item->{ttl} ) && ( $item->{ttl} !~ /^[0-9]+$/ || !$item->{ttl} ) ) {
			die( $where . ' has a ttl that is not a positive int of seconds' );
		}

		my $compiled = compile_tokened_regexp( $item->{regexp}, $where );
		$compiled->{key} = $self->_correlation_key_components( $item->{key}, $where );
		$compiled->{ttl} = $item->{ttl} // 60;

		push( @{ $self->{capture_regexps} }, $compiled );
	} ## end foreach my ( $entry_int, $item ) ( indexed @{ $def...})

	return;
} ## end sub _compile_capture_regexps

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

# resolves a compiled entry's correlation key against the folded captures
# and the parsed envelope, captures never clashing with the syslog. names...
# undef when any component is missing, several components joining under a
# separator no log value can carry
sub _correlation_key_value {
	my ( $self, $entry, $caps, $envelope ) = @_;

	my @values;
	foreach my $component ( @{ $entry->{key} } ) {
		my $value;
		if ( $component =~ /^syslog\./ ) {
			$value = defined($envelope) ? $envelope->{$component} : undef;
		} else {
			$value = $caps->{$component};
		}
		if ( !defined($value) ) {
			return undef;
		}
		push( @values, $value );
	} ## end foreach my $component ( @{ $entry->{key} } )

	return join( "\x00", @values );
} ## end sub _correlation_key_value

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

# the most deferred offenses held per correlation key... past it the oldest
# is dropped, so a key whose capture line never comes can not grow forever
my $PENDING_PER_KEY_MAX = 100;

# completes the offenses deferred under a key, now that a capture line has
# brought its context... the pendings come off the key whether or not they
# complete, a expired one simply being dropped.
#
# args:
#   $scope     :: the correlation scope, the watcher name
#   $key_value :: the joined correlation key the capture line produced
#   $context   :: hash ref of the capture line's data, which each completion
#                 takes beneath the deferred offense's own, those winning
#   $now       :: the current time, against which the pendings expire
#
# returns a list of completions, each a found hash of data and regexp, the
# regexp being what the deferred offense carried. empty when nothing was
# waiting or all of it had expired.
#
#   push( @completions, $self->_complete_pendings( $scope, $key_value, $caps, $now ) );
sub _complete_pendings {
	my ( $self, $scope, $key_value, $context, $now ) = @_;

	my $pendings = delete( $self->{pending}{$scope}{$key_value} );
	if ( !defined($pendings) ) {
		return ();
	}

	my @completions;
	foreach my $pending ( @{$pendings} ) {
		if ( $pending->{expires} <= $now ) {
			next;
		}
		push( @completions, { 'data' => { %{$context}, %{ $pending->{caps} } }, 'regexp' => $pending->{regexp} } );
	}

	return @completions;
} ## end sub _complete_pendings

# parks a offense that can not be resolved yet under its correlation key, to
# await a capture line with the same key... the line was a offense, just one
# whose context has not arrived.
#
# args:
#   $scope     :: the correlation scope, the watcher name
#   $key_value :: the joined correlation key the offense produced
#   $caps      :: hash ref of the offense's data, authoritative on completion
#   $regexp    :: the index of the entry that matched, or undef for a json
#                 rule with no match entries
#   $defer     :: the seconds the offense waits before it is dropped
#   $now       :: the current time
#
# returns nothing. at most $PENDING_PER_KEY_MAX wait per key, the oldest
# dropped to make room.
#
#   $self->_park_pending( $scope, $key_value, $caps, 0, 60, $now );
sub _park_pending {
	my ( $self, $scope, $key_value, $caps, $regexp, $defer, $now ) = @_;

	$self->{pending}{$scope}{$key_value} //= [];
	my $pendings = $self->{pending}{$scope}{$key_value};
	push( @{$pendings}, { 'caps' => $caps, 'regexp' => $regexp, 'expires' => $now + $defer } );
	if ( scalar( @{$pendings} ) > $PENDING_PER_KEY_MAX ) {
		shift( @{$pendings} );
	}

	return;
} ## end sub _park_pending

# folds a line's own offense and the completions its capture lines brought
# into the one found a check returns... the offense leads, else the first
# completion does, and the rest ride in its more.
#
# args:
#   $found       :: the line's own found hash, or undef when it was not one
#   $completions :: arrayref of completion found hashes, left untouched
#
# returns the leading found hash, carrying a more arrayref of the others when
# there are any, or undef when there was neither.
#
#   return $self->_primary_found( $found, \@completions );
sub _primary_found {
	my ( $self, $found, $completions ) = @_;

	my @rest    = @{$completions};
	my $primary = $found // shift(@rest);
	if ( defined($primary) && @rest ) {
		$primary->{more} = \@rest;
	}

	return $primary;
} ## end sub _primary_found

# checks a message against the compiled capture, ignore, and message
# regexps... returns undef or a found hash with the folded captures,
# possibly carrying a more array of further completions when a capture
# line resolved deferred offenses
sub _check_message {
	my ( $self, $message, $scope, $extra, $envelope, $line_ctx ) = @_;

	if ( !defined($message) ) {
		return undef;
	}
	$scope //= '';
	# a missing line context reads as a empty one
	if ( !is_plain_hashref($line_ctx) ) {
		$line_ctx = {};
	}
	my $now = $line_ctx->{now} // time;

	# a ignore_regexp match vetoes the line entirely
	foreach my $ignore ( @{ $self->{ignore_regexps} } ) {
		if ( $message =~ $ignore ) {
			return undef;
		}
	}

	# capture lines harvest context and may complete deferred offenses
	my @completions;
	foreach my $capture ( @{ $self->{capture_regexps} } ) {
		my $caps = match_tokened( $capture, $message );
		if ( !defined($caps) ) {
			next;
		}
		my $key_value = $self->_correlation_key_value( $capture, $caps, $envelope );
		if ( !defined($key_value) ) {
			next;
		}

		$self->_context_store( $scope, $key_value, $caps, $capture->{ttl}, $now );
		push( @completions, $self->_complete_pendings( $scope, $key_value, $caps, $now ) );
	} ## end foreach my $capture ( @{ $self->{capture_regexps...}})

	my $found;
	foreach my ( $entry_int, $entry ) ( indexed @{ $self->{regexps} } ) {
		my $caps = match_tokened( $entry, $message );
		if ( !defined($caps) ) {
			next;
		}

		# a entry with no key, or a key component that did not participate,
		# has nothing to correlate, so it is the offense as it stands
		my $key_value = defined( $entry->{key} ) ? $self->_correlation_key_value( $entry, $caps, $envelope ) : undef;
		if ( !defined($key_value) ) {
			$found = { 'data' => $caps, 'regexp' => $entry_int };
			last;
		}

		my $stored = $self->{context}{$scope}{$key_value};
		if ( defined($stored) && $stored->{expires} > $now ) {
			my %data = ( %{ $stored->{data} }, %{$caps} );
			$found = { 'data' => \%data, 'regexp' => $entry_int };
			last;
		}

		if ( $entry->{defer} ) {
			# park it awaiting a capture line with this key... it was the
			# offense, so further entries are not tried
			$self->_park_pending( $scope, $key_value, $caps, $entry_int, $entry->{defer}, $now );
			last;
		}

		# unresolved and undeferred, so this entry is not a offense here...
		# fall through to the remaining entries
	} ## end foreach my ( $entry_int, $entry ) ( indexed @{ ...})

	# message_json... with no message_regexp the offense is the extra fields
	# themselves (the json body and syslog envelope), synthesized here so the
	# gate below decides on them. with message_regexp present the regexp stays
	# the matcher, so nothing is synthesized when it did not fire
	if ( defined($extra) && !defined($found) && !@completions && !@{ $self->{regexps} } ) {
		$found = { 'data' => {}, 'regexp' => undef };
	}

	# merge the extra json+envelope fields into the field space, the line's
	# own captures winning on a clash, so the gate and ban_var see both
	if ( defined($extra) ) {
		if ( defined($found) ) {
			$found->{data} = { %{$extra}, %{ $found->{data} } };
		}
		foreach my $completion (@completions) {
			$completion->{data} = { %{$extra}, %{ $completion->{data} } };
		}
	}

	# the field spaces the track sweep will harvest, taken here because the
	# boolean below may drop the very records holding them and the harvest
	# does not care whether the line was a offense. a line that matched
	# nothing still contributes what the mungers and the JSON body gave it
	my @sweep;
	if ( defined( $self->{tracks} ) ) {
		@sweep = map { $_->{data} }
			grep { defined($_) } ( $found, @completions );
		if ( !@sweep ) {
			@sweep = ( $extra // {} );
		}
	}

	# the rule's boolean matcher (the tracked clause, then the keywords, the
	# gate, or the selections+condition, over the captures, and the json
	# fields when message_json) filters the offense and each completion,
	# dropping those that do not pass... none skips this
	if ( $self->{has_boolean} || defined( $self->{track_gates} ) ) {
		if ( defined($found) && !$self->_offense_boolean_pass( $found->{data}, $message, $line_ctx ) ) {
			$found = undef;
		}
		@completions = grep { $self->_offense_boolean_pass( $_->{data}, $message, $line_ctx ) } @completions;
	}

	# the harvest, after the read above and never before it
	if (@sweep) {
		$self->_track_sweep( \@sweep, $line_ctx );
	}

	return $self->_primary_found( $found, \@completions );
} ## end sub _check_message

# flattens a message that is a JSON object into dotted-path fields, reusing
# the json parser's flattener... a message that is not a JSON object gives
# undef, so a message_json rule can refuse the line outright rather than
# matching raw text it was told would be JSON
sub _flatten_json_message {
	my ( $self, $message ) = @_;

	if ( !defined($message) ) {
		return undef;
	}
	my $parsed;
	eval { $parsed = App::Baphomet::Parser::parse( 'json', $message ); };
	if ( is_plain_hashref($parsed) && is_plain_hashref( $parsed->{fields} ) ) {
		return $parsed->{fields};
	}

	return undef;
} ## end sub _flatten_json_message

# stores harvested captures under (scope, key), bounding the per scope
# key count... on hitting the cap expired entries are pruned first and
# then the soonest to expire is evicted
sub _context_store {
	my ( $self, $scope, $key_value, $caps, $ttl, $now ) = @_;

	my $context = $self->{context}{$scope};
	$context //= $self->{context}{$scope} = {};

	App::Baphomet::Marks::bound_expiring_store( $context, $key_value, $now );

	$context->{$key_value} = { 'data' => $caps, 'expires' => $now + $ttl };

	return;
} ## end sub _context_store

# compiles a def's match and ignore arrays onto matches and ignores,
# validating the shared field-and-regexp shape... the per-entry compile
# differs by type (tokened for json, plain and field-checked for http), so
# the caller hands one in
sub _compile_match_ignore {
	my ( $self, $compile_entry ) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	foreach my $sort ( 'match', 'ignore' ) {
		if ( !defined( $def->{$sort} ) ) {
			next;
		}
		if ( !is_plain_arrayref( $def->{$sort} ) || !@{ $def->{$sort} } ) {
			die( 'The ' . $sort . ' of the rule "' . $name . '" is not a array or is empty' );
		}

		foreach my ( $entry_int, $entry ) ( indexed @{ $def->{$sort} } ) {
			my $where = 'The ' . $sort . ' entry ' . $entry_int . ' of the rule "' . $name . '"';
			if ( !is_plain_hashref($entry) || !defined( $entry->{field} ) || !defined( $entry->{regexp} ) ) {
				die( $where . ' is not a hash with a field and a regexp' );
			}
			$self->_check_keys( $entry, [qw( field regexp )], $where . ' has' );

			push( @{ $self->{ $sort eq 'match' ? 'matches' : 'ignores' } }, $compile_entry->( $entry, $where ) );
		}
	} ## end foreach my $sort ( 'match', 'ignore' )

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
		$self->_check_keys( $kw, [qw( in values )], $where . ' has' );
		$in = $kw->{in} // '%%%ANY%%%';
		if ( ref($in) ne '' || $in eq '' ) {
			die( $where . ' in is not a non-empty string naming a field, a %%%ANY:prefix%%%, or %%%ANY%%%' );
		}
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
