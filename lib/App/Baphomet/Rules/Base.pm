package App::Baphomet::Rules::Base;

use 5.006;
use strict;
use warnings;
use Regexp::IPv4          qw( $IPv4_re );
use Regexp::IPv6          qw( $IPv6_re );
use MIME::Base64          qw( decode_base64 );
use Digest::MD5           qw( md5 );
use Encode                ();
use App::Baphomet::Parser ();
use App::Baphomet::Config qw( compile_ignore_ips ip_ignored );

=pod

=head1 NAME

App::Baphomet::Rules::Base - Shared plumbing for the Baphomet rule handlers.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

The bits common to every rule handler... the embedded test runner and the
string-or-C<//regexp//> matcher lists. Not usable on its own... see
L<App::Baphomet::Rules::Syslog> and L<App::Baphomet::Rules::HTTP> for the
handlers.

A handler is expected to provide C<check>, taking a parsed line and
returning undef or a hash with a C<data> hash of what got captured, and to
override L</default_test_parser> if C<bsd_syslog> is not the right default
for its tests.

A rule def may carry a top level C<test_parser> key, which sets the
parser for all of its embedded tests that do not name one themselves,
overriding the handler default... handy for a rule whose tests are all in
a non-default format, like a nginx rule of the http_error type.

=head1 RULE FORMAT

Every rule, whatever its type, is a YAML hash, and most of its keys are
common to all types and documented here. The C<check> matcher... how a raw
line becomes a match, and where the offender is dug from... is the
type-specific part, documented in each handler:
L<App::Baphomet::Rules::Syslog>, L<App::Baphomet::Rules::Raw>,
L<App::Baphomet::Rules::HTTP>, L<App::Baphomet::Rules::HTTPError>, and
L<App::Baphomet::Rules::JSON>.

A rule matches a line, names the offender it is counted against, says how it
is counted and when it bans, carries triage metadata, and proves itself with
embedded tests. Optional gates... marks, geography, blocklists, time... can
refine a match after the fact.

Where a key names a found var (C<ban_var>, a mark's C<var>, a gate's
C<vars>), it resolves against the matched line's data: a regexp capture on
the syslog, raw, and json types, or a flattened dotted field path on json, so
C<SRC> and C<request.client_ip> are both legal names for whatever they
name.

=head2 Naming the offender

=head3 ban_var

The captures or fields whose value is the offender... the thing a hit is
registered against and, at the threshold, handed to Ereshkigal to banish.
Usually just C<SRC>. Each name that a matched line carries a value for is
counted. The http and http_error types do not use C<ban_var>, their offender
being the parsed C<host> / C<client>; the syslog, raw, and json types require
it (or C<detection_var>). A rule names one or the other, never both.

=head3 detection_var

The parallel of C<ban_var> for a B<detection-only rule>, named in place of
it. The captures or fields to count by, under no obligation to be a
address... a username, a hostname, a URI, a service, or a IP when that is
what you want. Its presence makes the rule detection-only: it runs the whole
match/count/threshold path like any other, but never banishes. Each match
writes a C<sighting> to the EVE log and a subject crossing C<max_score>
within C<find_time> writes a C<sighted> naming it, nothing going to Kur.
Counting rides the shadow buckets, so a detection rule can never tip a real
ban over its threshold, and C<ignore_ips> does not apply. Loading one forces
C<eve_enable> on, so it is never a silent no-op. On the http and http_error
types a C<detection_var> overrides the default C<host> / C<client> counting.

=head3 ban_not_internal

When true, an offender that is one of your own hosts is spared the ban... the
C<internal> config field, which defaults to C<ignore_ips>. With more than one
C<ban_var> this bans only the external ends of a flow: the external src of an
inbound attack, the external dest of an outbound callout, both ends of a
transit flow, neither of a host-to-host one. With a single offender... one
C<ban_var>, or the http/http_error fixed C<host>/C<client>... it simply skips
the ban when that offender is internal. Legal on every type, since any of them
can produce an IP to banish; set C<internal> wider than C<ignore_ips> to spare
internal offenders from a rule without globally ignoring them.

=head2 How it is counted

=head3 max_score / find_time / ban_time / weight

The rule's own word on how it is counted and how long the ban runs, the first
four honored only when the watcher's C<allow_per_rule_thresholds> config
setting is on, at which point the layering is rule over watcher over kur over
global. A rule overriding C<max_score> or C<find_time> is counted in its own
bucket, apart from the shared per-IP count, while a C<ban_time>-only override
counts in the shared bucket and just bans with its own duration.

C<max_score> is the accumulated score at which an offender is banished, not a
plain retry count... each match deposits the rule's C<weight> (a positive
number, default 1), so a heavy signature bans faster and several rules
against one IP sum toward the one judgment. With every weight 1 the score is
just the hit count, as before.

=head3 eve_only

A boolean putting the rule in B<observe mode>, honored whatever the consent
setting and layering over the watcher's own C<eve_only>. Its matches are
written to EVE but never counted toward a real ban... a would-be banish
surfaces as an C<alert> event and each match as C<noted> rather than
C<found>. Set it false to opt one rule back in to real banning under a
watcher or kur that is observing. Distinct from a detection rule: observe
mode is a real rule held back, still keyed to a offender IP, while a
detection rule never bans and counts any subject.

=head3 distinct

Switches counting from summing hits to counting the distinct values of a
field, the SIEM distinct-count and value_count. A table of C<of> (the found
field whose distinct values are counted) and optional C<by> (the grouping
field, default the offender IP). The score is the size of the distinct set
within C<find_time>, banning at C<max_score>. With no C<by> the set is keyed
by the offender and the offender is banished... N distinct users from one
source is credential stuffing, C<distinct: { of: USER }>. With a C<by> the
set is keyed by that field and the I<current offender> is banished instead,
since the key may not be bannable... N distinct sources against one account
is distributed spray, C<distinct: { of: SRC, by: USER }> with
C<ban_var: [ SRC ]>. An offender-keyed set resets on firing; a by-keyed one
does not, catching every further source while the key stays over threshold.
Pairs with C<eve_only> for detect-without-banning.

=head2 Triage metadata

=head3 msg

A short human-readable signature naming what the rule detects, the
Sagan/Suricata C<msg> convention... a C<[TAG] description> line. It is written
to every EVE event the rule produces as the top-level C<msg> field (Suricata's
C<alert.signature>, promoted), so tooling reads what tripped without decoding
the raw line. When a rule sets none it falls back to the rule's name, so the
field is always present. Inert to matching.

=head3 severity / classtype / references / attack

Triage metadata, all inert to matching and all written to EVE beside C<msg>
when set:

    - severity :: One of info, low, medium, high, or critical. Emitted as the
          top-level EVE C<severity>. When the rule sets none the config's
          C<default_severity> (global/kur/watcher) fills in, and absent that
          too the field is omitted.

    - classtype :: A category string, the Snort/Sagan/Suricata classtype...
          emitted as EVE C<classtype>. Free-form; the shipped suricata rules
          carry their Suricata class here.

    - references :: An array of URLs, CVE ids, or doc links. Emitted as EVE
          C<references>.

    - attack :: An array of MITRE ATT&CK technique ids. Emitted as EVE
          C<attack>.

Together with C<msg> these are the Suricata/Sagan C<alert> metadata set,
flattened to top-level EVE fields for triage.

=head2 The predicate gate

A boolean refinement over a line's fields or captures, ANDed ahead of the
type's own matching. Every type has it. What a C<field> names depends on the
type... a capture (syslog, raw), a flattened dotted path (json), or a parsed
access/error-log field (http, http_error). The reserved C<%%%ANY%%%> fans a
predicate over every field value (and, on syslog/raw, the message), and
C<%%%ANY:E<lt>prefixE<gt>%%%> over just the fields at or under C<prefix>. On
syslog and raw, the reserved C<MESSAGE> names the whole message.

=head3 gate

Optional, ANDed. Each entry names a field and the values it must have...
values entries starting and ending with C<//> are regexps, everything else is
string equality. A field the line does not carry never matches a gate.

An entry may instead use the typed operator form, opt-in and detected by the
presence of an C<op>, C<value>, C<all>, C<negate>, C<nocase>, C<fieldref>, or
C<decode> key (a plain C<field>/C<values> entry stays the legacy
equality/regexp form above):

    gate:
      - { field: event,     op: eq,       value: auth_fail }
      - { field: bytes_out, op: gt,       value: 1000000 }
      - { field: src,       op: cidr,     values: [ 10.0.0.0/8, 2001:db8::/32 ] }
      - { field: cmd,       op: contains, values: [ psexec, mimikatz ], all: false }
      - { field: user,      op: eq,       value: healthcheck, negate: true }

    - op :: eq (default), contains, startswith, endswith, re (a tokened
          regexp), gt/lt/ge/le (numeric, the field coerced, a non-number
          missing), cidr (v4/v6 membership), or exists (the field is present,
          any value... Sigma's C<|exists>, taking no value; with C<negate> it
          is the field-absent test).
    - value / values :: one scalar or a non-empty list, matching if any holds,
          or all when C<all> is true.
    - fieldref :: names another field to compare against instead of a literal,
          its value the needle resolved from the line at match time, Sigma's
          C<|fieldref>... so a rule can say two fields must (with C<negate>,
          must not) agree, C<{ field: auth_user, op: eq, fieldref: cert_user }>.
          Stands in for value/values (a error to set both), and only the string
          ops eq/contains/startswith/endswith take it. A absent referenced field
          is a non-match. Folds under C<nocase> and decodes the source under
          C<decode> like any other compare.
    - all :: require every value to match rather than any. Default false.
    - negate :: invert the entry. A negated entry holds when the field is
          absent, matching Sigma's field-absent semantics.
    - nocase :: case-fold the compare, so the match is case-insensitive.
          Default off, since Baphomet matches case-sensitively... this is
          Sigma's default-insensitive matching, and a Sigma C<|cased> field is
          just the default. Applies to the string ops and C<re> (baked in as
          C<(?i)>); a error on the numeric and cidr ops, where it is meaningless.
    - decode :: a list of transforms run left to right over the field value
          before the operator, so an obfuscated payload is compared decoded...
          base64, base64offset (the three alignment candidates), utf16le /
          utf16be / utf16 (wide an alias for utf16le), windash, url, lower,
          upper. A transform that can not decode drops that candidate, so a
          bad decode simply does not match. C<decode: [ base64, utf16le ]>
          with C<op: contains> is the PowerShell -enc shape.

=head3 keywords

Optional, shorthand for a C<contains> over the keyword field. A plain list
searches every field:

    keywords: [ mimikatz, sekurlsa, "Invoke-Mimikatz" ]

or the table form scopes it with C<in>, a field path, a C<%%%ANY:prefix%%%>
subtree, or C<%%%ANY%%%> (the default)... so nothing unrelated is searched
when the path is known:

    keywords:
      in: process.command_line
      values: [ mimikatz ]

Keywords are ANDed ahead of any L</gate> or L</selections / condition>, and
may stand alone as the whole matcher.

=head3 selections / condition

Optional, the boolean form and an alternative to L</gate> (a rule may not
carry both). C<selections> is a table of named selections, each a list of
gate entries (the same predicate and legacy forms) ANDed together.
C<condition> is a string composing the selections with C<and>, C<or>, C<not>,
parens, and the quantifiers C<all of them>, C<1 of them>, and
C<N of E<lt>prefixE<gt>_*>. It is the pre-filter, ANDed ahead of the matches,
and gives the OR, arbitrary nesting, and N-of-M the flat gate can not... the
Sigma detection model.

    selections:
      auth:  [ { field: event, op: eq, value: authFailure } ]
      admin: [ { field: user,  op: eq, values: [ root, admin ] } ]
      trust: [ { field: src,   op: cidr, value: 10.0.0.0/8 } ]
    condition: "auth and admin and not trust"

A selection referenced but not defined, an unbalanced paren, or a stray token
is a load-time error, as is a condition without selections or the two present
together.

=head2 Marks... cross-rule state

=head3 mark / unmark / marked / not_marked / mark_only

Marks are a galla wide, expiring, named store one rule brands and another
gates on, so rules can carry state across each other the way correlation
carries it across lines... Sagan's xbits and flexbits. The key defaults to
the offender IP but any capture or field can be it (C<var>), and a value can
be harvested from the line too (C<value_var>).

    - mark :: Array of brands to set on match, each a hash of C<name> and
          C<ttl>, and optionally C<var> (key by this capture instead of the
          offender IP) and C<value_var> (store this capture on the brand).

    - unmark :: Array of brands to lift on match, each C<name> and optionally
          C<var>.

    - marked :: Gate array, ANDed... the result only counts if every named
          brand is set. Each a hash of C<name>, optionally C<var>, and at most
          one of C<value_is> or C<value_not> naming a capture the stored value
          must equal or differ from. A var entry is checked against the line's
          captures, a var-less one against each offender.

    - not_marked :: The inverse gate... the result only counts if none of the
          named brands is set.

    - mark_only :: When true the rule only brands and gates, never counting
          toward a ban, and does not consume the line, so matching falls
          through to the later rules.

A rule whose mark gates veto, like a mark_only rule, falls through rather than
consuming the line, so the brander and the gater can both fire on it. Marks
live per galla, cross watchers and rules but not kurs, survive a restart, and
are visible with C<baphomet marked>. The ignored are never branded. See
C<syslog/sshd-mark-users> and C<syslog/sshd-spray> for a shipped pair.

=head3 sequence

Ordered temporal correlation, an array of entries each naming a list of
C<marks> that must all be set for the key and in the listed order by when each
first fired, and optionally a C<var> keying the correlation (its capture, or
var-less the offender). So a rule watching several stages... one mark_only
rule branding each... fires only when they happened in sequence.

    sequence:
      - marks: [ recon, foothold, exfil ]
        var: HOST

A stage that is missing, expired, or out of order fails the gate. Marks carry
a first-seen time the ordering compares; two stages in the same instant count
as in order. The set time survives a restart and rides the fleet mark sync
bus, so a fleet-shared sequence correlates stages seen on different machines.
Unordered correlation (all stages present, any order) is the plain C<marked>
gate over the same brands.

=head2 The geography, blocklist, time, and reverse DNS gates

=head3 country

A gate that only lets a match count when a IP is in, or not in, a set of
countries, needing the C<geoip_db> config setting and the optional
IP::Geolocation::MMDB module. A hash of:

    - is / isnot :: Exactly one. A list of ISO 3166 2-letter codes and
          C<%%%country_codes{name}%%%> imports of named lists from the config
          (resolved per watcher). A bare string is a one-element list. is
          counts only IPs in the set, isnot only those not in it.

    - vars :: Optional. Found vars to check the country of instead of the
          offender. Without it the gate is offender-keyed, checked per ban_var
          candidate in the ban loop. With it the gate is data-keyed, checked
          once per result against those vars and vetoing the whole result on a
          failure... so a rule can gate on the geography of a value it is not
          banning.

The gate fails closed: a IP that does not locate, or a missing database,
blocks the count rather than risking a wrong ban. A galla with country gated
rules and no database says so loudly at start.

=head3 namtar_list

A gate that only lets a match count when a value is on a named blocklist, the
inverse of ignore_ips. The lists are named in the config's C<namtar_lists>,
layered per watcher and reloaded on mtime change. Each list is a cidr list
matched by address containment, or a string list matched by exact (optionally
case-folded) equality, so the gate reaches beyond the offender IP to any
captured field. The flavor is set on the list in the config, not the rule. A
array of entries, each:

    - list / lists :: One or more named lists to check against. A value on any
          of them (union) satisfies the entry, even across flavors.

    - var :: Optional. The found var to check. With it the entry is data-keyed
          and vets the whole result, without it the entry is offender-keyed
          and filters candidates... so a rule can gate on a captured field it
          is not banning.

Every entry must hold. The gate fails closed: a value on no list, or a list
whose file is unreadable, blocks the count. ignore_ips still wins, so a
ignored IP is never banished even when blocklisted.

=head3 active_time

A gate that only lets a match count when a time is in, or not in, named
windows from the config's C<active_time>, resolved per watcher. A hash of:

    - is / isnot :: Exactly one. A window name or a list of them. Multiple are
          unioned. is counts only when the time is in a window, isnot only
          when in none.

    - vars :: Optional. Found vars holding the time to check, read as a epoch
          or a ISO 8601 datetime. Without it the gate checks the current time.
          A value that does not parse fails closed.

Unlike the other gates active_time is never per-offender... time is a property
of the line, so it is checked once per result and vetoes the whole result.
Times are local.

=head3 reverse_dns

A gate comparing the PTR names of an address against a regexp or another
found value, negatable... behind the galla's C<enable_rdns> consent (on by
default) and the optional Net::DNS module. A array of entries, all
required to hold:

    reverse_dns:
      - matches: '\.google(?:bot)?\.com$'
        negate: true
      - var: SRC
        matches_var: CLAIM
        forward_confirm: false

    - var :: The found value holding the address to reverse. With out it
          the gate checks each offender in the ban loop; with it, once
          per result, vetoing the whole result.

    - matches / matches_var :: Exactly one. A Perl regexp any PTR name
          must satisfy, or another found value the PTR must equal
          (case-folded, trailing dots stripped).

    - negate :: Invert the comparison.

    - forward_confirm :: On by default... a PTR name only participates
          when it resolves back to the address, a spoofed PTR being as
          good as absent.

    - on_nxdomain / on_servfail :: What an authoritative empty PTR set
          (on_nxdomain, default C<compare>) or a lookup failure anywhere
          in the entry (on_servfail, default C<fail>) becomes...
          C<compare> runs the comparison over whatever names there are,
          C<pass> satisfies the entry outright, C<fail> vetoes outright.
          pass and fail are terminal verdicts... negate never touches
          them. A servfail during forward confirmation under C<compare>
          leaves that one name unconfirmed and carries on.

Under the defaults, authoritative absence is data... an empty PTR set
compares false, so negate counts the client with no reverse DNS... while
a lookup failure vetoes regardless of negate. Everything else always
fails closed... no resolver, a non-address value, a missing matches_var.
Beware C<on_servfail: pass> or C<compare> on a negated gate... it means
a DNS outage counts everyone, the trade being coverage over the
outage-can-not-misaim guarantee. Lookups are per match, bounded and
cached galla-side, so a rule's embedded tests can not exercise this
gate.

=head2 tests

Positive and negative tests for verifying the rule works. These are ran at
load time and a rule failing its own tests refuses to load. Each test is a
hash with the keys below. A top level C<test_parser> key sets the default
parser for all of them.

    - message :: The full log line to test with. Either this or messages is
          required.

    - messages :: A array of lines fed through in order, for testing
          correlation... each test entry runs in its own throwaway scope,
          found is the expected count of found results across the sequence,
          and data asserts against the last of them.

    - parser :: The parser to parse it with. Defaults to the handler's own
          (C<bsd_syslog> for syslog, C<http_access> for http, and so on).

    - found :: If the rule should match the line or not, 1 or 0. Defaults to 1
          for positive, 0 for negative.

    - data :: For positive tests, a hash of capture names to the values they
          should of captured.

    - undefed :: For negative tests, a array of capture names that should not
          be defined.

=head1 METHODS

=head2 default_test_parser

The parser used for embedded tests that do not name one.

    my $parser = $rule->default_test_parser;

=cut

sub default_test_parser {
	return 'bsd_syslog';
}

=head2 sweep_state

Drops expired correlation context and pending deferred offenses. A no-op
for rules with out any. The galla calls this from its sweeper so expiry
does not depend on traffic.

    $rule->sweep_state($now);

=cut

sub sweep_state {
	my ( $self, $now ) = @_;

	if ( !defined($now) ) {
		$now = time;
	}

	foreach my $scope ( keys( %{ $self->{context} } ) ) {
		foreach my $key ( keys( %{ $self->{context}{$scope} } ) ) {
			if ( $self->{context}{$scope}{$key}{expires} <= $now ) {
				delete( $self->{context}{$scope}{$key} );
			}
		}
		if ( !keys( %{ $self->{context}{$scope} } ) ) {
			delete( $self->{context}{$scope} );
		}
	} ## end foreach my $scope ( keys( %{ $self->{context} }...))

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

	# staged rule slots... a sequence nothing has fed since its stage's
	# within (or the default hold) is dead
	foreach my $scope ( keys( %{ $self->{stage_state} } ) ) {
		foreach my $key ( keys( %{ $self->{stage_state}{$scope} } ) ) {
			if ( $self->{stage_state}{$scope}{$key}{expires} <= $now ) {
				delete( $self->{stage_state}{$scope}{$key} );
			}
		}
		if ( !keys( %{ $self->{stage_state}{$scope} } ) ) {
			delete( $self->{stage_state}{$scope} );
		}
	} ## end foreach my $scope ( keys( %{ $self->{stage_state...}}))

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
C<allow_per_rule_thresholds>... this just exposes the def keys. Cached,
as the def does not change.

    my $thresholds = $rule->thresholds;
    if ( %{$thresholds} ) { ... }

=cut

sub thresholds {
	my ($self) = @_;

	if ( !defined( $self->{thresholds} ) ) {
		my $thresholds = {};
		foreach my $item ( 'max_score', 'find_time', 'ban_time' ) {
			if ( defined( $self->{def}{$item} ) ) {
				$thresholds->{$item} = $self->{def}{$item};
			}
		}
		$self->{thresholds} = $thresholds;
	}

	return $self->{thresholds};
} ## end sub thresholds

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

	if ( ref( $self->{def}{detection_var} ) ne 'ARRAY' ) {
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

Returns the rule's classtype, a category string in the Snort/Sagan/Suricata
sense, or undef when unset. Emitted to EVE as-is.

    my $classtype = $rule->classtype;

=cut

sub classtype {
	my ($self) = @_;

	return $self->{def}{classtype};
}

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

	return defined( $self->{gid} ) ? $self->{gid} : 0;
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
C<syslog/sshd> always hashes to the same value. Built once and cached.

    my $sid = $rule->sid;

=cut

sub sid {
	my ($self) = @_;

	if ( !defined( $self->{sid} ) ) {
		# a stable 31-bit unsigned integer from the name, the top four bytes
		# of its MD5... masked to stay a positive value that survives tools
		# treating a sid as a signed 32-bit int
		$self->{sid} = unpack( 'N', substr( md5( $self->{name} ), 0, 4 ) ) & 0x7fffffff;
	}

	return $self->{sid};
} ## end sub sid

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
IP) and C<value_var> (store this capture as the mark's value)... a empty
array for a rule setting none. The galla is what has the marks store and
does the branding, this just exposes the def key.

    foreach my $mark ( @{ $rule->marks } ) { ... }

=cut

sub marks {
	my ($self) = @_;

	return ref( $self->{def}{mark} ) eq 'ARRAY' ? $self->{def}{mark} : [];
}

=head2 unmarks

Returns the array of marks the rule lifts on match, each a hash of C<name>
and optionally C<var>... a empty array for a rule lifting none.

    foreach my $unmark ( @{ $rule->unmarks } ) { ... }

=cut

sub unmarks {
	my ($self) = @_;

	return ref( $self->{def}{unmark} ) eq 'ARRAY' ? $self->{def}{unmark} : [];
}

=head2 mark_gates

Returns the rule's mark gates as a hash of two arrays, C<marked> and
C<not_marked>, either possibly empty. Each entry is a hash of C<name> and
optionally C<var>, and marked entries may also carry one of C<value_is> or
C<value_not>, naming a capture the stored value must equal or differ from.
The galla evaluates these against its marks store... a found result only
counts if every gate holds.

    my $gates = $rule->mark_gates;
    foreach my $gate ( @{ $gates->{marked} } ) { ... }

=cut

sub mark_gates {
	my ($self) = @_;

	# pure rule data, so built once... this is asked for on every match
	if ( !defined( $self->{_mark_gates} ) ) {
		$self->{_mark_gates} = {
			'marked'     => ref( $self->{def}{marked} ) eq 'ARRAY'     ? $self->{def}{marked}     : [],
			'not_marked' => ref( $self->{def}{not_marked} ) eq 'ARRAY' ? $self->{def}{not_marked} : [],
			'sequence'   => ref( $self->{def}{sequence} ) eq 'ARRAY'   ? $self->{def}{sequence}   : [],
		};
	}

	return $self->{_mark_gates};
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

=head2 _check_detection_var

Validates a rule's C<detection_var>, if any, and reports whether the rule is
detection-only. When present it must be a non-empty array of strings, and it
may not sit beside C<ban_var>... a rule bans or is detection-only, not both.
Each rule type calls this and makes its own C<ban_var> requirement conditional
on the return, so a detection rule need not name a offender it will never
banish. Returns 1 for a detection rule, 0 otherwise. Dies on a malformed def.

    my $is_detection = $self->_check_detection_var( $def, $name );

=cut

sub _check_detection_var {
	my ( $self, $def, $name ) = @_;

	if ( !exists( $def->{detection_var} ) ) {
		return 0;
	}

	if ( ref( $def->{detection_var} ) ne 'ARRAY' || !@{ $def->{detection_var} } ) {
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

# the def checks every handler runs... the gate family, the thresholds,
# and the tests shape, one call so a new gate check can not be forgotten
# in one type
sub _check_common {
	my ( $self, $def, $name ) = @_;

	$self->_check_thresholds($def);
	$self->_check_marks($def);
	$self->_check_country($def);
	$self->_check_namtar($def);
	$self->_check_active_time($def);
	$self->_check_reverse_dns($def);
	$self->_check_distinct($def);
	$self->_check_ip_vars($def);

	if ( defined( $def->{tests} ) && ref( $def->{tests} ) ne 'HASH' ) {
		die( 'The tests of the rule "' . $name . '" is not a hash' );
	}

	return;
} ## end sub _check_common

# validates the ban_var of a def unless the rule is detection-only, and
# says which it was... shared by the types with a free-form ban_var (the
# http pair chisel theirs to a fixed field)
sub _check_ban_var {
	my ( $self, $def, $name ) = @_;

	if ( $self->_check_detection_var( $def, $name ) ) {
		return 1;
	}

	if ( ref( $def->{ban_var} ) ne 'ARRAY' || !@{ $def->{ban_var} } ) {
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

=head2 country

Returns the rule's country gate normalized, or undef when it has none. The
gate is a hash of C<mode> (C<is> or C<isnot>), C<entries> (the raw list, 2-
letter codes and C<%%%country_codes{name}%%%> imports still unexpanded, as
the config to expand against is the galla's per watcher), and C<vars> (the
found vars to check the country of, or undef to check the offender IP). The
galla resolves the imports and does the lookups. Cached.

    my $country = $rule->country;

=cut

sub country {
	my ($self) = @_;

	if ( !exists( $self->{country_parsed} ) ) {
		my $def = $self->{def}{country};
		if ( ref($def) ne 'HASH' ) {
			$self->{country_parsed} = undef;
		} else {
			my $mode = defined( $def->{is} ) ? 'is' : 'isnot';
			$self->{country_parsed} = {
				'mode'    => $mode,
				'entries' => [ ref( $def->{$mode} ) eq 'ARRAY' ? @{ $def->{$mode} } : ( $def->{$mode} ) ],
				'vars'    => ref( $def->{vars} ) eq 'ARRAY' ? $def->{vars}
				: defined( $def->{vars} ) ? [ $def->{vars} ]
				:                           undef,
			};
		} ## end else [ if ( ref($def) ne 'HASH' ) ]
	} ## end if ( !exists( $self->{country_parsed} ) )

	return $self->{country_parsed};
} ## end sub country

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
membership tests. Cached.

    foreach my $entry ( @{ $rule->namtar_list } ) { ... }

=cut

sub namtar_list {
	my ($self) = @_;

	if ( !exists( $self->{namtar_parsed} ) ) {
		my $def = $self->{def}{namtar_list};
		if ( ref($def) ne 'ARRAY' ) {
			$self->{namtar_parsed} = undef;
		} else {
			my @entries;
			foreach my $entry ( @{$def} ) {
				my $lists = defined( $entry->{lists} ) ? $entry->{lists} : $entry->{list};
				push(
					@entries,
					{
						'lists' => [ ref($lists) eq 'ARRAY' ? @{$lists} : ($lists) ],
						'var'   => $entry->{var},
					}
				);
			} ## end foreach my $entry ( @{$def} )
			$self->{namtar_parsed} = \@entries;
		} ## end else [ if ( ref($def) ne 'ARRAY' ) ]
	} ## end if ( !exists( $self->{namtar_parsed} ) )

	return $self->{namtar_parsed};
} ## end sub namtar_list

=head2 active_time

Returns the rule's active_time gate normalized, or undef when it has none.
The gate is a hash of C<mode> (C<is> or C<isnot>), C<windows> (the named
window references, still unresolved as the config to resolve against is the
galla's per watcher), and C<vars> (the found vars holding the times to
check, or undef to check the current time). The galla resolves the window
names to specs and does the time tests. Cached.

    my $active = $rule->active_time;

=cut

sub active_time {
	my ($self) = @_;

	if ( !exists( $self->{active_parsed} ) ) {
		my $def = $self->{def}{active_time};
		if ( ref($def) ne 'HASH' ) {
			$self->{active_parsed} = undef;
		} else {
			my $mode = defined( $def->{is} ) ? 'is' : 'isnot';
			$self->{active_parsed} = {
				'mode'    => $mode,
				'windows' => [ ref( $def->{$mode} ) eq 'ARRAY' ? @{ $def->{$mode} } : ( $def->{$mode} ) ],
				'vars'    => ref( $def->{vars} ) eq 'ARRAY' ? $def->{vars}
				: defined( $def->{vars} ) ? [ $def->{vars} ]
				:                           undef,
			};
		} ## end else [ if ( ref($def) ne 'HASH' ) ]
	} ## end if ( !exists( $self->{active_parsed} ) )

	return $self->{active_parsed};
} ## end sub active_time

=head2 distinct

Returns the rule's distinct-cardinality spec, a hash naming C<of> (the found
var whose distinct values are counted per offender), or undef when the rule
counts hits the usual way. The galla is what does the counting... this just
exposes the def key.

    my $distinct = $rule->distinct;   # undef or { of => 'USER' }

=cut

sub distinct {
	my ($self) = @_;

	return ( ref( $self->{def}{distinct} ) eq 'HASH' ) ? $self->{def}{distinct} : undef;
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

	return defined( $self->{def}{src_ip_var} ) ? $self->{def}{src_ip_var} : 'src_ip';
}

=head2 dest_ip_var

Returns the name of the found var holding the flow's destination IP, defaulting
to C<dest_ip> when the def names none. The parallel of L</src_ip_var>, promoted
to the EVE event's top-level C<dest_ip>.

    my $dest_ip_var = $rule->dest_ip_var;   # 'dest_ip' or the named var

=cut

sub dest_ip_var {
	my ($self) = @_;

	return defined( $self->{def}{dest_ip_var} ) ? $self->{def}{dest_ip_var} : 'dest_ip';
}

=head2 info

Returns the rule's name and def with the embedded tests stripped, for the
EVE log's rule field... the tests would bloat every event for no value.
Cached, as the def does not change.

    my $info = $rule->info;

=cut

sub info {
	my ($self) = @_;

	if ( !defined( $self->{info} ) ) {
		my %def = %{ $self->{def} };
		delete( $def{tests} );
		$self->{info} = { 'name' => $self->{name}, 'def' => \%def };
	}

	return $self->{info};
} ## end sub info

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

	if ( ref($state) ne 'HASH' ) {
		return;
	}
	if ( !defined($now) ) {
		$now = time;
	}

	if ( ref( $state->{context} ) eq 'HASH' ) {
		foreach my $scope ( keys( %{ $state->{context} } ) ) {
			foreach my $key ( keys( %{ $state->{context}{$scope} } ) ) {
				my $entry = $state->{context}{$scope}{$key};
				if ( ref($entry) eq 'HASH' && defined( $entry->{expires} ) && $entry->{expires} > $now ) {
					$self->{context}{$scope}{$key} = $entry;
				}
			}
		}
	} ## end if ( ref( $state->{context} ) eq 'HASH' )

	if ( ref( $state->{pending} ) eq 'HASH' ) {
		foreach my $scope ( keys( %{ $state->{pending} } ) ) {
			foreach my $key ( keys( %{ $state->{pending}{$scope} } ) ) {
				my @live = grep { ref($_) eq 'HASH' && defined( $_->{expires} ) && $_->{expires} > $now }
					@{ $state->{pending}{$scope}{$key} };
				if (@live) {
					push( @{ $self->{pending}{$scope}{$key} }, @live );
				}
			}
		}
	} ## end if ( ref( $state->{pending} ) eq 'HASH' )

	return;
} ## end sub restore_state

=head2 run_tests

Runs the tests embedded in the rule. Returns a hash as below. Does not die
on test failures... that is the caller's call to make.

    {
        'pass'     => 3,
        'fail'     => 0,
        'failures' => [],
    }

    my $results = $rule->run_tests;

=cut

sub run_tests {
	my ($self) = @_;

	my $results = {
		'pass'     => 0,
		'fail'     => 0,
		'failures' => [],
	};

	my $tests = $self->{def}{tests};
	if ( ref($tests) ne 'HASH' ) {
		return $results;
	}

	# a typo'd section name would otherwise mean zero tests and a clean
	# load, quietly defeating the prove-itself-at-load design
	foreach my $section ( keys( %{$tests} ) ) {
		if ( $section !~ /^(?:positive|negative)$/ ) {
			$results->{fail}++;
			push( @{ $results->{failures} }, 'unknown tests section "' . $section . '"' );
		}
	}

	foreach my $sort ( 'positive', 'negative' ) {
		if ( !defined( $tests->{$sort} ) ) {
			next;
		}
		if ( ref( $tests->{$sort} ) ne 'ARRAY' ) {
			$results->{fail}++;
			push( @{ $results->{failures} }, $sort . ' tests is not a array' );
			next;
		}

		my $test_int = 0;
		foreach my $test ( @{ $tests->{$sort} } ) {
			my $where = $sort . ' test ' . $test_int;
			$test_int++;

			if ( ref($test) ne 'HASH' || ( !defined( $test->{message} ) && ref( $test->{messages} ) ne 'ARRAY' ) ) {
				$results->{fail}++;
				push( @{ $results->{failures} }, $where . ' is not a hash with a message or a messages array' );
				next;
			}

			my @messages = defined( $test->{message} ) ? ( $test->{message} ) : @{ $test->{messages} };

			my $parser
				= defined( $test->{parser} )           ? $test->{parser}
				: defined( $self->{def}{test_parser} ) ? $self->{def}{test_parser}
				:                                        $self->default_test_parser;

			# each test entry gets a throwaway correlation scope of its own
			my $test_scope = 'run_tests ' . $where;

			my @found_all;
			my $parse_failed = 0;
			my $message_int  = 0;
			foreach my $message (@messages) {
				my $parsed;
				eval { $parsed = App::Baphomet::Parser::parse( $parser, $message ); };
				if ($@) {
					$results->{fail}++;
					push( @{ $results->{failures} }, $where . ' has a unusable parser... ' . $@ );
					$parse_failed = 1;
					last;
				}
				if ( !defined($parsed) ) {
					$results->{fail}++;
					push(
						@{ $results->{failures} },
						$where . ' message did not parse via ' . $parser . '... "' . $message . '"'
					);
					$parse_failed = 1;
					last;
				}

				# the line context a staged rule's skip bound reads... the
				# message index is the sequence with in the test entry
				my $found = $self->check( $parsed, $test_scope, { 'seq' => $message_int, 'source' => '' } );
				$message_int++;
				if ( defined($found) ) {
					push( @found_all, $found );
					if ( ref( $found->{more} ) eq 'ARRAY' ) {
						push( @found_all, @{ $found->{more} } );
					}
				}
			} ## end foreach my $message (@messages)
			if ($parse_failed) {
				next;
			}

			my $expected_found = defined( $test->{found} ) ? $test->{found} : ( $sort eq 'positive' ? 1 : 0 );
			my $got_found      = scalar(@found_all);

			if ( $got_found != $expected_found ) {
				$results->{fail}++;
				push(
					@{ $results->{failures} },
					$where
						. ' expected found='
						. $expected_found
						. ' but got found='
						. $got_found
						. ' for "'
						. $messages[-1] . '"'
				);
				next;
			} ## end if ( $got_found != $expected_found )

			my $found = @found_all ? $found_all[-1] : undef;

			my $data_failed = 0;
			if ( defined( $test->{data} ) && ref( $test->{data} ) eq 'HASH' ) {
				foreach my $key ( sort( keys( %{ $test->{data} } ) ) ) {
					my $got = defined($found) ? $found->{data}{$key} : undef;
					if ( !defined($got) || $got ne $test->{data}{$key} ) {
						$results->{fail}++;
						push(
							@{ $results->{failures} },
							$where
								. ' expected data.'
								. $key . '="'
								. $test->{data}{$key}
								. '" but got '
								. ( defined($got) ? '"' . $got . '"' : 'undef' )
						);
						$data_failed = 1;
						last;
					} ## end if ( !defined($got) || $got ne $test->{data...})
				} ## end foreach my $key ( sort( keys( %{ $test->{data} ...})))
			} ## end if ( defined( $test->{data} ) && ref( $test...))

			if ( defined( $test->{undefed} ) && ref( $test->{undefed} ) eq 'ARRAY' && !$data_failed ) {
				foreach my $key ( @{ $test->{undefed} } ) {
					my $got = defined($found) ? $found->{data}{$key} : undef;
					if ( defined($got) ) {
						$results->{fail}++;
						push(
							@{ $results->{failures} },
							$where . ' expected ' . $key . ' to be undef but got "' . $got . '"'
						);
						$data_failed = 1;
						last;
					}
				} ## end foreach my $key ( @{ $test->{undefed} } )
			} ## end if ( defined( $test->{undefed} ) && ref( $test...))

			if ( !$data_failed ) {
				$results->{pass}++;
			}
		} ## end foreach my $test ( @{ $tests->{$sort} } )
	} ## end foreach my $sort ( 'positive', 'negative' )

	return $results;
} ## end sub run_tests

# the TLD atom, like the label atoms ahead of it, may not end on a hyphen
my $dns_re = qr/(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?/;

my %tokens = (
	'IP4'    => qr/$IPv4_re/,
	'IP6'    => qr/$IPv6_re/,
	'ADDR'   => qr/(?:$IPv4_re|$IPv6_re)/,
	'DNS'    => $dns_re,
	'HOST'   => qr/(?:$IPv4_re|$IPv6_re|$dns_re)/,
	'SUBNET' => qr/(?:$IPv4_re|$IPv6_re)(?:\/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])(?![0-9]))?/,
	'SRC'    => qr/(?:$IPv4_re|$IPv6_re)/,
	'DEST'   => qr/(?:$IPv4_re|$IPv6_re)/,
);

# the severity scale, worst last... the ordinal is unused for now but keeps
# the order canonical if anything ever wants to sort or compare
our %SEVERITY = ( 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4 );

# dies if the def's threshold overrides, max_score, find_time, and
# ban_time, or its weight or eve_only, hold unusable values... positive ints
# for the thresholds (non-negative ban_time, 0 meaning eternal), a positive
# number for weight, a boolean for eve_only... called by every handler's new,
# as the keys are legal on every type
sub _check_thresholds {
	my ( $self, $def ) = @_;

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
		if ( !defined( $def->{$listkey} ) ) {
			next;
		}
		if ( ref( $def->{$listkey} ) ne 'ARRAY' || !@{ $def->{$listkey} } ) {
			die( 'The rule "' . $name . '" has a ' . $listkey . ' that is not a non-empty array' );
		}
		foreach my $item ( @{ $def->{$listkey} } ) {
			if ( !defined($item) || ref($item) ne '' || $item eq '' ) {
				die( 'The rule "' . $name . '" has a ' . $listkey . ' entry that is not a non-empty string' );
			}
		}
	} ## end foreach my $listkey ( 'references', 'attack' )

	return;
} ## end sub _check_thresholds

# dies if the def's mark keys, mark, unmark, marked, not_marked, and
# mark_only, hold unusable values... called by every handler's new, as the
# keys are legal on every type. Names are constrained like rule names so
# they ride tablets and commands cleanly.
sub _check_marks {
	my ( $self, $def ) = @_;

	my $name = $self->{name};

	my %shapes = (
		'mark'       => { 'name' => 'required', 'ttl' => 'ttl', 'var' => 'string', 'value_var' => 'string' },
		'unmark'     => { 'name' => 'required', 'var' => 'string' },
		'marked'     => { 'name' => 'required', 'var' => 'string', 'value_is' => 'string', 'value_not' => 'string' },
		'not_marked' => { 'name' => 'required', 'var' => 'string' },
	);

	foreach my $key ( keys(%shapes) ) {
		if ( !defined( $def->{$key} ) ) {
			next;
		}
		my $where = 'The ' . $key . ' of the rule "' . $name . '"';
		if ( ref( $def->{$key} ) ne 'ARRAY' || !@{ $def->{$key} } ) {
			die( $where . ' is not a non-empty array' );
		}
		foreach my $entry ( @{ $def->{$key} } ) {
			if ( ref($entry) ne 'HASH' ) {
				die( $where . ' contains a entry that is not a hash' );
			}
			foreach my $entry_key ( keys( %{$entry} ) ) {
				if ( !defined( $shapes{$key}{$entry_key} ) ) {
					die( $where . ' has a entry with the unknown key "' . $entry_key . '"' );
				}
			}
			if ( !defined( $entry->{name} ) || ref( $entry->{name} ) ne '' || $entry->{name} !~ /^[a-zA-Z0-9_\-]+$/ ) {
				die( $where . ' has a entry lacking a name matching /^[a-zA-Z0-9_\-]+$/' );
			}
			if (
				defined( $shapes{$key}{ttl} )
				&& (  !defined( $entry->{ttl} )
					|| ref( $entry->{ttl} ) ne ''
					|| $entry->{ttl} !~ /^[0-9]+$/
					|| !$entry->{ttl} )
				)
			{
				die( $where . ' entry "' . $entry->{name} . '" lacks a ttl that is a positive int of seconds' );
			} ## end if ( defined( $shapes{$key}{ttl} ) && ( !defined...))
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
							. $entry->{name}
							. '" has a '
							. $string_key
							. ' that is not a non-empty string' );
				} ## end if ( !defined( $entry->{$string_key} ) || ...)
			} ## end foreach my $string_key ( grep { defined( $shapes...)})
			if ( defined( $entry->{value_is} ) && defined( $entry->{value_not} ) ) {
				die( $where . ' entry "' . $entry->{name} . '" carries both value_is and value_not' );
			}
		} ## end foreach my $entry ( @{ $def->{$key} } )
	} ## end foreach my $key ( keys(%shapes) )

	# the sequence gate... ordered temporal correlation, a list of mark names
	# that must all be set for the key and in the listed order by set time
	if ( defined( $def->{sequence} ) ) {
		my $where = 'The sequence of the rule "' . $name . '"';
		if ( ref( $def->{sequence} ) ne 'ARRAY' || !@{ $def->{sequence} } ) {
			die( $where . ' is not a non-empty array' );
		}
		foreach my $entry ( @{ $def->{sequence} } ) {
			if ( ref($entry) ne 'HASH' ) {
				die( $where . ' contains a entry that is not a hash' );
			}
			foreach my $entry_key ( keys( %{$entry} ) ) {
				if ( $entry_key !~ /^(?:marks|var)$/ ) {
					die( $where . ' has a entry with the unknown key "' . $entry_key . '"' );
				}
			}
			if ( ref( $entry->{marks} ) ne 'ARRAY' || scalar( @{ $entry->{marks} } ) < 2 ) {
				die( $where . ' entry lacks a marks array of at least two mark names' );
			}
			foreach my $mark_name ( @{ $entry->{marks} } ) {
				if ( !defined($mark_name) || ref($mark_name) ne '' || $mark_name !~ /^[a-zA-Z0-9_\-]+$/ ) {
					die( $where . ' entry has a mark name not matching /^[a-zA-Z0-9_\-]+$/' );
				}
			}
			if ( defined( $entry->{var} ) && ( ref( $entry->{var} ) ne '' || $entry->{var} eq '' ) ) {
				die( $where . ' entry has a var that is not a non-empty string' );
			}
		} ## end foreach my $entry ( @{ $def->{sequence} } )
	} ## end if ( defined( $def->{sequence} ) )

	return;
} ## end sub _check_marks

# dies if the def's country gate is malformed... is xor isnot, each a 2-
# letter code or a %%%country_codes{name}%%% import, vars an optional list
# of found vars to check instead of the offender. the token names are
# resolved against the config later, by the galla, per watcher
sub _check_country {
	my ( $self, $def ) = @_;

	if ( !defined( $def->{country} ) ) {
		return;
	}

	my $name  = $self->{name};
	my $where = 'The country gate of the rule "' . $name . '"';
	my $c     = $def->{country};

	if ( ref($c) ne 'HASH' ) {
		die( $where . ' is not a hash' );
	}
	foreach my $key ( keys( %{$c} ) ) {
		if ( $key !~ /^(?:is|isnot|vars)$/ ) {
			die( $where . ' has the unknown key "' . $key . '"' );
		}
	}
	if ( defined( $c->{is} ) && defined( $c->{isnot} ) ) {
		die( $where . ' carries both is and isnot' );
	}
	if ( !defined( $c->{is} ) && !defined( $c->{isnot} ) ) {
		die( $where . ' has neither is nor isnot' );
	}

	my $mode    = defined( $c->{is} )           ? 'is'             : 'isnot';
	my @entries = ref( $c->{$mode} ) eq 'ARRAY' ? @{ $c->{$mode} } : ( $c->{$mode} );
	if ( !@entries ) {
		die( $where . ' ' . $mode . ' is empty' );
	}
	foreach my $entry (@entries) {
		if (  !defined($entry)
			|| ref($entry) ne ''
			|| $entry !~ /^(?:[A-Za-z]{2}|%%%country_codes\{[a-zA-Z0-9_\-]+\}%%%)$/ )
		{
			die(      $where . ' '
					. $mode
					. ' has a entry that is not a 2-letter code or a %%%country_codes{name}%%% import' );
		}
	} ## end foreach my $entry (@entries)

	if ( defined( $c->{vars} ) ) {
		my @vars = ref( $c->{vars} ) eq 'ARRAY' ? @{ $c->{vars} } : ( $c->{vars} );
		if ( !@vars ) {
			die( $where . ' vars is empty' );
		}
		foreach my $var (@vars) {
			if ( !defined($var) || ref($var) ne '' || $var eq '' ) {
				die( $where . ' vars has a entry that is not a non-empty string' );
			}
		}
	} ## end if ( defined( $c->{vars} ) )

	return;
} ## end sub _check_country

# dies if the def's reverse_dns gate is malformed, compiling it onto the
# object... a array of entries, each comparing the PTR names of an address
# (a named found var, or var-less the offender) against a regexp (matches)
# or another found value (matches_var), optionally negated, with forward
# confirmation on unless refused. the galla owns the lookups and the
# fail-closed rules, this only the shape
sub _check_reverse_dns {
	my ( $self, $def ) = @_;

	if ( !defined( $def->{reverse_dns} ) ) {
		return;
	}

	my $name  = $self->{name};
	my $where = 'The reverse_dns gate of the rule "' . $name . '"';

	if ( ref( $def->{reverse_dns} ) ne 'ARRAY' || !@{ $def->{reverse_dns} } ) {
		die( $where . ' is not a array or is empty' );
	}

	my @compiled;
	my $entry_int = 0;
	foreach my $entry ( @{ $def->{reverse_dns} } ) {
		my $entry_where = $where . ' entry ' . $entry_int;
		if ( ref($entry) ne 'HASH' ) {
			die( $entry_where . ' is not a hash' );
		}
		foreach my $key ( keys( %{$entry} ) ) {
			if ( $key !~ /^(?:var|matches|matches_var|negate|forward_confirm|on_nxdomain|on_servfail)$/ ) {
				die( $entry_where . ' has the unknown key "' . $key . '"' );
			}
		}
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
			eval { $compiled_entry->{regexp} = qr/$regexp/; };
			if ($@) {
				die( $entry_where . ' matches does not compile... ' . $@ );
			}
		}
		push( @compiled, $compiled_entry );
		$entry_int++;
	} ## end foreach my $entry ( @{ $def->{reverse_dns} } )
	$self->{reverse_dns_gate} = \@compiled;

	return;
} ## end sub _check_reverse_dns

# dies if the def's namtar_list gate is malformed... a array of entries,
# each naming one or more lists (list or lists) and a optional var to check
# instead of the offender. the list names are resolved against the config
# later, by the galla, per watcher
sub _check_namtar {
	my ( $self, $def ) = @_;

	if ( !defined( $def->{namtar_list} ) ) {
		return;
	}

	my $name  = $self->{name};
	my $where = 'The namtar_list gate of the rule "' . $name . '"';

	if ( ref( $def->{namtar_list} ) ne 'ARRAY' || !@{ $def->{namtar_list} } ) {
		die( $where . ' is not a non-empty array' );
	}
	foreach my $entry ( @{ $def->{namtar_list} } ) {
		if ( ref($entry) ne 'HASH' ) {
			die( $where . ' has a entry that is not a hash' );
		}
		foreach my $key ( keys( %{$entry} ) ) {
			if ( $key !~ /^(?:list|lists|var)$/ ) {
				die( $where . ' has a entry with the unknown key "' . $key . '"' );
			}
		}
		if ( defined( $entry->{list} ) && defined( $entry->{lists} ) ) {
			die( $where . ' has a entry carrying both list and lists' );
		}
		my $lists = defined( $entry->{lists} ) ? $entry->{lists} : $entry->{list};
		if ( !defined($lists) ) {
			die( $where . ' has a entry lacking a list or lists' );
		}
		my @lists = ref($lists) eq 'ARRAY' ? @{$lists} : ($lists);
		if ( !@lists ) {
			die( $where . ' has a entry with a empty lists' );
		}
		foreach my $list (@lists) {
			if ( !defined($list) || ref($list) ne '' || $list !~ /^[a-zA-Z0-9_\-]+$/ ) {
				die( $where . ' has a list name that is not a /^[a-zA-Z0-9_\-]+$/ string' );
			}
		}
		if ( defined( $entry->{var} ) && ( ref( $entry->{var} ) ne '' || $entry->{var} eq '' ) ) {
			die( $where . ' has a var that is not a non-empty string' );
		}
	} ## end foreach my $entry ( @{ $def->{namtar_list} } )

	return;
} ## end sub _check_namtar

# dies if the def's active_time gate is malformed... is xor isnot, each a
# window name or a array of them, vars an optional list of found vars whose
# times to check instead of now. the window names are resolved against the
# config later, by the galla, per watcher
sub _check_active_time {
	my ( $self, $def ) = @_;

	if ( !defined( $def->{active_time} ) ) {
		return;
	}

	my $name  = $self->{name};
	my $where = 'The active_time gate of the rule "' . $name . '"';
	my $a     = $def->{active_time};

	if ( ref($a) ne 'HASH' ) {
		die( $where . ' is not a hash' );
	}
	foreach my $key ( keys( %{$a} ) ) {
		if ( $key !~ /^(?:is|isnot|vars)$/ ) {
			die( $where . ' has the unknown key "' . $key . '"' );
		}
	}
	if ( defined( $a->{is} ) && defined( $a->{isnot} ) ) {
		die( $where . ' carries both is and isnot' );
	}
	if ( !defined( $a->{is} ) && !defined( $a->{isnot} ) ) {
		die( $where . ' has neither is nor isnot' );
	}

	my $mode    = defined( $a->{is} )           ? 'is'             : 'isnot';
	my @windows = ref( $a->{$mode} ) eq 'ARRAY' ? @{ $a->{$mode} } : ( $a->{$mode} );
	if ( !@windows ) {
		die( $where . ' ' . $mode . ' is empty' );
	}
	foreach my $window (@windows) {
		if ( !defined($window) || ref($window) ne '' || $window !~ /^[a-zA-Z0-9_\-]+$/ ) {
			die( $where . ' ' . $mode . ' has a window name that is not a /^[a-zA-Z0-9_\-]+$/ string' );
		}
	}

	if ( defined( $a->{vars} ) ) {
		my @vars = ref( $a->{vars} ) eq 'ARRAY' ? @{ $a->{vars} } : ( $a->{vars} );
		if ( !@vars ) {
			die( $where . ' vars is empty' );
		}
		foreach my $var (@vars) {
			if ( !defined($var) || ref($var) ne '' || $var eq '' ) {
				die( $where . ' vars has a entry that is not a non-empty string' );
			}
		}
	} ## end if ( defined( $a->{vars} ) )

	return;
} ## end sub _check_active_time

# checks the distinct-cardinality spec, dieing on anything unusable... a table
# with a of naming the found var whose distinct values the galla counts
sub _check_distinct {
	my ( $self, $def ) = @_;

	if ( !defined( $def->{distinct} ) ) {
		return;
	}
	my $name = $self->{name};
	my $spec = $def->{distinct};

	if ( ref($spec) ne 'HASH' ) {
		die( 'The distinct of the rule "' . $name . '" is not a table' );
	}
	foreach my $key ( keys( %{$spec} ) ) {
		if ( $key !~ /^(?:of|by)$/ ) {
			die( 'The distinct of the rule "' . $name . '" has the unknown key "' . $key . '"' );
		}
	}
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

# dies if the def's src_ip_var or dest_ip_var is set to anything but a
# non-empty string... each names the found var whose value the galla
# promotes to the EVE top level. absent is fine, they default to the
# literal src_ip and dest_ip fields
sub _check_ip_vars {
	my ( $self, $def ) = @_;

	my $name = $self->{name};
	foreach my $item ( 'src_ip_var', 'dest_ip_var' ) {
		if ( !exists( $def->{$item} ) ) {
			next;
		}
		if ( !defined( $def->{$item} ) || ref( $def->{$item} ) ne '' || $def->{$item} eq '' ) {
			die( 'The ' . $item . ' of the rule "' . $name . '" is not a non-empty string' );
		}
	}

	return;
} ## end sub _check_ip_vars

# compiles the message_regexp and ignore_regexp of the passed def,
# expanding %%%%TOKEN%%%% tokens into named captures, and populates
# regexps and ignore_regexps on the object... shared by the handlers
# whose matching is regexps against a message with something to extract
sub _compile_message_regexps {
	my ( $self, $def, $allow_empty ) = @_;

	my $name = $self->{name};

	$self->{regexps} = [];

	# a message_json rule may have no message_regexp, the json fields being
	# what it matches on, so the caller can allow an empty list. a missing key
	# is fine then; a present but malformed one is still an error
	if ( !defined( $def->{message_regexp} ) && $allow_empty ) {
		$self->_compile_ignore_regexps($def);
		return;
	}
	if ( ref( $def->{message_regexp} ) ne 'ARRAY' || !@{ $def->{message_regexp} } ) {
		die( 'The rule "' . $name . '" lacks a message_regexp array or it is empty' );
	}
	foreach my $item ( @{ $def->{message_regexp} } ) {
		if ( !defined($item) || ( ref($item) ne '' && ref($item) ne 'HASH' ) ) {
			die( 'The message_regexp of the rule "' . $name . '" contains a entry that is not a string or a hash' );
		}
		if ( ref($item) eq 'HASH' ) {
			foreach my $key ( keys( %{$item} ) ) {
				if ( $key !~ /^(?:regexp|key|defer)$/ ) {
					die( 'A message_regexp entry of the rule "' . $name . '" has the unknown key "' . $key . '"' );
				}
			}
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
		} ## end if ( ref($item) eq 'HASH' )
	} ## end foreach my $item ( @{ $def->{message_regexp} } )

	$self->_compile_ignore_regexps($def);

	my $entry_int = 0;
	foreach my $item ( @{ $def->{message_regexp} } ) {
		my $regexp   = ref($item) eq 'HASH' ? $item->{regexp} : $item;
		my $compiled = $self->_compile_tokened_regexp( $regexp,
			'The message_regexp entry ' . $entry_int . ' of the rule "' . $name . '"' );
		if ( ref($item) eq 'HASH' ) {
			$compiled->{key} = $self->_correlation_key_components( $item->{key},
				'The message_regexp entry ' . $entry_int . ' of the rule "' . $name . '"' );
			$compiled->{defer} = $item->{defer};
		}
		push( @{ $self->{regexps} }, $compiled );
		$entry_int++;
	} ## end foreach my $item ( @{ $def->{message_regexp} } )

	return;
} ## end sub _compile_message_regexps

# compiles the ignore_regexp of the passed def onto the object... tokens
# work here too, but nothing is captured from them, so the aliases are
# just thrown away. shared by the message_regexp and stages matchers
sub _compile_ignore_regexps {
	my ( $self, $def ) = @_;

	my $name = $self->{name};

	$self->{ignore_regexps} = [];

	if ( !defined( $def->{ignore_regexp} ) ) {
		return;
	}
	if ( ref( $def->{ignore_regexp} ) ne 'ARRAY' ) {
		die( 'The ignore_regexp of the rule "' . $name . '" is not a array' );
	}
	foreach my $item ( @{ $def->{ignore_regexp} } ) {
		if ( !defined($item) || ref($item) ne '' ) {
			die( 'The ignore_regexp of the rule "' . $name . '" contains a non-string entry' );
		}
	}

	my $ignore_int = 0;
	foreach my $regexp ( @{ $def->{ignore_regexp} } ) {
		my $entry = $self->_compile_tokened_regexp( $regexp,
			'The ignore_regexp entry ' . $ignore_int . ' of the rule "' . $name . '"' );
		push( @{ $self->{ignore_regexps} }, $entry->{regexp} );
		$ignore_int++;
	}

	return;
} ## end sub _compile_ignore_regexps

# compiles the stages of a staged rule... ordered matchers with counted
# hits and gap bounds, the in-rule temporal correlation. the per key
# components ride the correlation key machinery, so envelope fields work
# where the type carries them
sub _compile_stages {
	my ( $self, $def ) = @_;

	my $name = $self->{name};

	if ( ref( $def->{stages} ) ne 'ARRAY' || !@{ $def->{stages} } ) {
		die( 'The stages of the rule "' . $name . '" is not a array or is empty' );
	}

	my @compiled_stages;
	my $stage_int = 0;
	foreach my $stage ( @{ $def->{stages} } ) {
		my $where = 'The stage ' . $stage_int . ' of the rule "' . $name . '"';
		if ( ref($stage) ne 'HASH' ) {
			die( $where . ' is not a hash' );
		}
		foreach my $key ( keys( %{$stage} ) ) {
			if ( $key !~ /^(?:message_regexp|count|within|skip)$/ ) {
				die( $where . ' has the unknown key "' . $key . '"' );
			}
		}
		if ( ref( $stage->{message_regexp} ) ne 'ARRAY' || !@{ $stage->{message_regexp} } ) {
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
		my $entry_int = 0;
		foreach my $regexp ( @{ $stage->{message_regexp} } ) {
			if ( !defined($regexp) || ref($regexp) ne '' ) {
				die( $where . ' has a message_regexp entry that is not a string' );
			}
			push( @matchers,
				$self->_compile_tokened_regexp( $regexp, $where . ' message_regexp entry ' . $entry_int ) );
			$entry_int++;
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
		$stage_int++;
	} ## end foreach my $stage ( @{ $def->{stages} } )
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
	my ( $self, $message, $scope, $line_ctx, $envelope ) = @_;

	if ( !defined($message) ) {
		return undef;
	}
	if ( !defined($scope) ) {
		$scope = '';
	}
	my $now = ( ref($line_ctx) eq 'HASH' && defined( $line_ctx->{now} ) ) ? $line_ctx->{now} : time;
	my $seq = ref($line_ctx) eq 'HASH' && defined( $line_ctx->{seq} ) ? $line_ctx->{seq} : undef;

	foreach my $ignore ( @{ $self->{ignore_regexps} } ) {
		if ( $message =~ $ignore ) {
			return undef;
		}
	}

	my $stages = $self->{stages};
	my $store  = $self->{stage_state}{$scope};
	if ( !defined($store) ) {
		$store = $self->{stage_state}{$scope} = {};
	}

	# which stages this line hits, tried lazily and remembered
	my @stage_caps;
	my $stage_match = sub {
		my ($stage_int) = @_;
		if ( !exists( $stage_caps[$stage_int] ) ) {
			my $caps;
			foreach my $matcher ( @{ $stages->[$stage_int]{matchers} } ) {
				$caps = $self->_match_tokened( $matcher, $message );
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
			return ref($line_ctx) eq 'HASH' && defined( $line_ctx->{source} ) ? $line_ctx->{source} : '';
		}
		return $self->_correlation_key_value( { 'key' => $self->{per_key} }, $caps, $envelope );
	};

	# a hit on the stage a slot is awaiting advances it, gap bounds
	# permitting... too late or too far kills the sequence, and the line
	# may then head a fresh one below
	for ( my $stage_int = 0; $stage_int < scalar( @{$stages} ); $stage_int++ ) {
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

		my $stage  = $stages->[$stage_int];
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

		return $self->_stage_hit( $store, $key_value, $stage_int, $caps, $message, $now, $seq );
	} ## end for ( my $stage_int = 0; $stage_int < scalar...)

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
	$self->_stage_slot_new( $store, $key_value, $now );

	return $self->_stage_hit( $store, $key_value, 0, $caps, $message, $now, $seq );
} ## end sub _check_stages

# lands a hit on a slot's awaited stage... counts, merges captures later
# stages authoritative, and fires the found when the final stage completes
sub _stage_hit {
	my ( $self, $store, $key_value, $stage_int, $caps, $message, $now, $seq ) = @_;

	my $slot  = $store->{$key_value};
	my $stage = $self->{stages}[$stage_int];

	$slot->{count}++;
	$slot->{data} = { %{ $slot->{data} }, %{$caps} };
	push( @{ $slot->{hits} }, { 'stage' => $stage_int, 'time' => $now, 'line' => $message } );
	$slot->{last_time} = $now;
	$slot->{last_seq}  = $seq;

	if ( $slot->{count} < $stage->{count} ) {
		$slot->{expires} = $now + ( defined( $stage->{within} ) ? $stage->{within} : 600 );
		return undef;
	}

	# the final stage completing is the found... the rule's boolean matcher
	# filters the completed sequence like any other found
	if ( $stage_int == scalar( @{ $self->{stages} } ) - 1 ) {
		delete( $store->{$key_value} );
		my $found = { 'data' => $slot->{data}, 'regexp' => undef, 'stages' => $slot->{hits} };
		if ( $self->{has_boolean} ) {
			if ( !$self->_boolean_pass( $found->{data}, $message ) ) {
				return undef;
			}
		}
		return $found;
	} ## end if ( $stage_int == scalar( @{ $self->{stages...}}))

	$slot->{stage}++;
	$slot->{count} = 0;
	my $next_stage = $self->{stages}[ $slot->{stage} ];
	$slot->{expires} = $now + ( defined( $next_stage->{within} ) ? $next_stage->{within} : 600 );

	return undef;
} ## end sub _stage_hit

# bounds a store of expiring entries at the shared 10000 cap ahead of
# inserting a new key... expired entries are pruned first, then the soonest
# to expire is evicted, found by a linear min-scan rather than a sort, as
# this can run per line under a deliberate key flood
sub _bound_expiring_store {
	my ( $self, $store, $key_value, $now ) = @_;

	if ( defined( $store->{$key_value} ) || scalar( keys( %{$store} ) ) < 10000 ) {
		return;
	}

	foreach my $key ( keys( %{$store} ) ) {
		if ( $store->{$key}{expires} <= $now ) {
			delete( $store->{$key} );
		}
	}
	if ( scalar( keys( %{$store} ) ) >= 10000 ) {
		my $soonest;
		foreach my $key ( keys( %{$store} ) ) {
			if ( !defined($soonest) || $store->{$key}{expires} < $store->{$soonest}{expires} ) {
				$soonest = $key;
			}
		}
		delete( $store->{$soonest} );
	}

	return;
} ## end sub _bound_expiring_store

# creates a fresh slot awaiting the first stage, bounding the per scope
# slot count the way the correlation context is bounded
sub _stage_slot_new {
	my ( $self, $store, $key_value, $now ) = @_;

	$self->_bound_expiring_store( $store, $key_value, $now );

	$store->{$key_value} = {
		'stage'     => 0,
		'count'     => 0,
		'data'      => {},
		'hits'      => [],
		'last_time' => $now,
		'last_seq'  => undef,
		'expires'   => $now + 600,
	};

	return;
} ## end sub _stage_slot_new

# compiles the capture_regexp of the passed def... entries harvest
# correlation context rather than being offenses, each a hash of a
# tokened regexp, the capture name serving as the correlation key, and a
# ttl for how long the harvested captures live
sub _compile_capture_regexps {
	my ( $self, $def ) = @_;

	my $name = $self->{name};

	$self->{capture_regexps} = [];

	if ( !defined( $def->{capture_regexp} ) ) {
		return;
	}
	if ( ref( $def->{capture_regexp} ) ne 'ARRAY' || !@{ $def->{capture_regexp} } ) {
		die( 'The capture_regexp of the rule "' . $name . '" is not a array or is empty' );
	}

	my $entry_int = 0;
	foreach my $item ( @{ $def->{capture_regexp} } ) {
		my $where = 'The capture_regexp entry ' . $entry_int . ' of the rule "' . $name . '"';
		if ( ref($item) ne 'HASH' || !defined( $item->{regexp} ) || !defined( $item->{key} ) ) {
			die( $where . ' is not a hash with a regexp and a key' );
		}
		foreach my $key ( keys( %{$item} ) ) {
			if ( $key !~ /^(?:regexp|key|ttl)$/ ) {
				die( $where . ' has the unknown key "' . $key . '"' );
			}
		}
		if ( defined( $item->{ttl} ) && ( $item->{ttl} !~ /^[0-9]+$/ || !$item->{ttl} ) ) {
			die( $where . ' has a ttl that is not a positive int of seconds' );
		}

		my $compiled = $self->_compile_tokened_regexp( $item->{regexp}, $where );
		$compiled->{key} = $self->_correlation_key_components( $item->{key}, $where );
		$compiled->{ttl} = defined( $item->{ttl} ) ? $item->{ttl} : 60;

		push( @{ $self->{capture_regexps} }, $compiled );
		$entry_int++;
	} ## end foreach my $item ( @{ $def->{capture_regexp} } )

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
	if ( ref($key) eq 'ARRAY' ) {
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
			if ( ref( $self->{envelope_key_fields} ) ne 'HASH' || !$self->{envelope_key_fields}{$component} ) {
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

# compiles a single regexp string, expanding %%%%TOKEN%%%% tokens into
# named captures... returns a hash of the compiled regexp, the original,
# the alias map for folding, and whether SRC and DEST are paired in it...
# $where is the lead in for error messages
sub _compile_tokened_regexp {
	my ( $self, $regexp, $where ) = @_;

	my %aliases;
	my $expanded = $regexp;
	$expanded =~ s/%%%%([A-Z0-9]+)%%%%/$self->_expand_token( $1, \%aliases, $where, $regexp )/ge;

	my $compiled;
	eval { $compiled = qr/$expanded/; };
	if ($@) {
		die( $where . ', "' . $regexp . '", does not compile... ' . $@ );
	}

	return {
		'regexp'   => $compiled,
		'original' => $regexp,
		'aliases'  => \%aliases,
		'paired'   => ( defined( $aliases{SRC} ) && defined( $aliases{DEST} ) ) ? 1 : 0,
	};
} ## end sub _compile_tokened_regexp

# expands a single token occurrence into a named capture group, numbering
# the capture name if the token has already been seen in this entry given
# perl does not allow duplicate capture names in a single regexp
sub _expand_token {
	my ( $self, $token, $aliases, $where, $original ) = @_;

	if ( !defined( $tokens{$token} ) ) {
		die( $where . ', "' . $original . '", uses the unknown token "' . $token . '"' );
	}

	if ( !defined( $aliases->{$token} ) ) {
		$aliases->{$token} = [$token];
		return '(?<' . $token . '>' . $tokens{$token} . ')';
	}

	my $alias = $token . '_' . ( scalar( @{ $aliases->{$token} } ) + 1 );
	push( @{ $aliases->{$token} }, $alias );

	return '(?<' . $alias . '>' . $tokens{$token} . ')';
} ## end sub _expand_token

# checks a message against the compiled capture, ignore, and message
# regexps... returns undef or a found hash with the folded captures,
# possibly carrying a more array of further completions when a capture
# line resolved deferred offenses
sub _check_message {
	my ( $self, $message, $scope, $extra, $envelope, $line_ctx ) = @_;

	if ( !defined($message) ) {
		return undef;
	}
	if ( !defined($scope) ) {
		$scope = '';
	}
	my $now = ( ref($line_ctx) eq 'HASH' && defined( $line_ctx->{now} ) ) ? $line_ctx->{now} : time;

	# a ignore_regexp match vetoes the line entirely
	foreach my $ignore ( @{ $self->{ignore_regexps} } ) {
		if ( $message =~ $ignore ) {
			return undef;
		}
	}

	# capture lines harvest context and may complete deferred offenses
	my @completions;
	foreach my $capture ( @{ $self->{capture_regexps} } ) {
		my $caps = $self->_match_tokened( $capture, $message );
		if ( !defined($caps) ) {
			next;
		}
		my $key_value = $self->_correlation_key_value( $capture, $caps, $envelope );
		if ( !defined($key_value) ) {
			next;
		}

		$self->_context_store( $scope, $key_value, $caps, $capture->{ttl}, $now );

		my $pendings = delete( $self->{pending}{$scope}{$key_value} );
		if ( defined($pendings) ) {
			foreach my $pending ( @{$pendings} ) {
				if ( $pending->{expires} <= $now ) {
					next;
				}
				# the offense's own captures are authoritative
				my %data = ( %{$caps}, %{ $pending->{caps} } );
				push( @completions, { 'data' => \%data, 'regexp' => $pending->{regexp} } );
			}
		} ## end if ( defined($pendings) )
	} ## end foreach my $capture ( @{ $self->{capture_regexps...}})

	my $found;
	my $entry_int = 0;
	foreach my $entry ( @{ $self->{regexps} } ) {
		my $caps = $self->_match_tokened( $entry, $message );
		if ( !defined($caps) ) {
			$entry_int++;
			next;
		}

		if ( !defined( $entry->{key} ) ) {
			$found = { 'data' => $caps, 'regexp' => $entry_int };
			last;
		}

		my $key_value = $self->_correlation_key_value( $entry, $caps, $envelope );
		if ( !defined($key_value) ) {
			# a key component did not participate, so nothing to correlate
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
			# park it awaiting a capture line with this key... the line was
			# a offense, just one that can not be resolved yet, so further
			# entries are not tried
			my $pendings = $self->{pending}{$scope}{$key_value};
			if ( !defined($pendings) ) {
				$pendings = $self->{pending}{$scope}{$key_value} = [];
			}
			push( @{$pendings}, { 'caps' => $caps, 'regexp' => $entry_int, 'expires' => $now + $entry->{defer} } );
			# bound runaway pendings per key
			if ( scalar( @{$pendings} ) > 100 ) {
				shift( @{$pendings} );
			}
			last;
		} ## end if ( $entry->{defer} )

		# unresolved and undeferred, so this entry is not a offense here...
		# fall through to the remaining entries
		$entry_int++;
	} ## end foreach my $entry ( @{ $self->{regexps} } )

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

	# the rule's boolean matcher (the keywords, the gate, or the
	# selections+condition, over the captures, and the json fields when
	# message_json) filters the offense and each completion, dropping those
	# that do not pass... none skips this
	if ( $self->{has_boolean} ) {
		if ( defined($found) && !$self->_boolean_pass( $found->{data}, $message ) ) {
			$found = undef;
		}
		@completions = grep { $self->_boolean_pass( $_->{data}, $message ) } @completions;
	}

	my $primary = $found;
	if ( !defined($primary) && @completions ) {
		$primary = shift(@completions);
	}
	if ( defined($primary) && @completions ) {
		$primary->{more} = \@completions;
	}

	return $primary;
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
	if ( ref($parsed) eq 'HASH' && ref( $parsed->{fields} ) eq 'HASH' ) {
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
	if ( !defined($context) ) {
		$context = $self->{context}{$scope} = {};
	}

	$self->_bound_expiring_store( $context, $key_value, $now );

	$context->{$key_value} = { 'data' => $caps, 'expires' => $now + $ttl };

	return;
} ## end sub _context_store

# checks a value against a single compiled tokened entry... returns undef
# for no match, or the captures hash with numbered token occurrences
# folded back under the plain token name... a SRC/DEST paired entry with
# only one of the two captured is not regarded as matched
sub _match_tokened {
	my ( $self, $entry, $value ) = @_;

	if ( !defined($value) || $value !~ $entry->{regexp} ) {
		return undef;
	}

	my %caps = %+;

	foreach my $token ( keys( %{ $entry->{aliases} } ) ) {
		foreach my $alias ( @{ $entry->{aliases}{$token} } ) {
			if ( defined( $caps{$alias} ) && !defined( $caps{$token} ) ) {
				$caps{$token} = $caps{$alias};
			}
			if ( $alias ne $token ) {
				delete( $caps{$alias} );
			}
		}
	} ## end foreach my $token ( keys( %{ $entry->{aliases} ...}))

	# SRC/DEST only regard as being found if matched together
	if ( $entry->{paired} && ( !defined( $caps{SRC} ) || !defined( $caps{DEST} ) ) ) {
		return undef;
	}

	return \%caps;
} ## end sub _match_tokened

# compiles a list of string-or-//regexp// entries into a matcher hash...
# entries starting and ending with // are regexps, the rest are string
# equality checks... $where is for error messages
sub _compile_matchers {
	my ( $self, $list, $where ) = @_;

	my $matchers = {
		'strings' => {},
		'regexps' => [],
	};

	foreach my $item ( @{$list} ) {
		if ( !defined($item) || ref($item) ne '' ) {
			die( $where . ' contains a non-string entry' );
		}
		if ( $item =~ /^\/\/(.*)\/\/$/ ) {
			my $regexp = $1;
			my $compiled;
			eval { $compiled = qr/$regexp/; };
			if ($@) {
				die( $where . ' entry "' . $item . '" does not compile... ' . $@ );
			}
			push( @{ $matchers->{regexps} }, $compiled );
		} else {
			$matchers->{strings}{$item} = 1;
		}
	} ## end foreach my $item ( @{$list} )

	return $matchers;
} ## end sub _compile_matchers

# compiles a def's match and ignore arrays onto matches and ignores,
# validating the shared field-and-regexp shape... the per-entry compile
# differs by type (tokened for json, plain and field-checked for http), so
# the caller hands one in
sub _compile_match_ignore {
	my ( $self, $def, $name, $compile_entry ) = @_;

	foreach my $sort ( 'match', 'ignore' ) {
		if ( !defined( $def->{$sort} ) ) {
			next;
		}
		if ( ref( $def->{$sort} ) ne 'ARRAY' || !@{ $def->{$sort} } ) {
			die( 'The ' . $sort . ' of the rule "' . $name . '" is not a array or is empty' );
		}

		my $entry_int = 0;
		foreach my $entry ( @{ $def->{$sort} } ) {
			my $where = 'The ' . $sort . ' entry ' . $entry_int . ' of the rule "' . $name . '"';
			if ( ref($entry) ne 'HASH' || !defined( $entry->{field} ) || !defined( $entry->{regexp} ) ) {
				die( $where . ' is not a hash with a field and a regexp' );
			}
			foreach my $key ( keys( %{$entry} ) ) {
				if ( $key !~ /^(?:field|regexp)$/ ) {
					die( $where . ' has the unknown key "' . $key . '"' );
				}
			}

			push( @{ $self->{ $sort eq 'match' ? 'matches' : 'ignores' } }, $compile_entry->( $entry, $where ) );
			$entry_int++;
		} ## end foreach my $entry ( @{ $def->{$sort} } )
	} ## end foreach my $sort ( 'match', 'ignore' )

	return;
} ## end sub _compile_match_ignore

# checks a value against a matcher hash from _compile_matchers... a undef
# value never matches
sub _matchers_hit {
	my ( $self, $matchers, $value ) = @_;

	if ( !defined($value) ) {
		return 0;
	}

	if ( defined( $matchers->{strings}{$value} ) ) {
		return 1;
	}

	foreach my $regexp ( @{ $matchers->{regexps} } ) {
		if ( $value =~ $regexp ) {
			return 1;
		}
	}

	return 0;
} ## end sub _matchers_hit

# the typed field operators, the opt-in richer form of a gate entry. legacy
# entries (field + values, equality or //regex//) are untouched and never reach
# here... this only fires for an entry carrying op/value/all/negate
our %PREDICATE_OPS = map { $_ => 1 } qw( eq contains startswith endswith re gt lt ge le cidr exists );

# the comparators, resolved once at compile time onto the predicate as
# op_code so the per-line path dispatches straight to a static code ref
# instead of re-matching the op name per candidate
my %PREDICATE_NUM_OPS = (
	'gt' => sub { return ( $_[0] > $_[1] ) ? 1 : 0; },
	'lt' => sub { return ( $_[0] < $_[1] ) ? 1 : 0; },
	'ge' => sub { return ( $_[0] >= $_[1] ) ? 1 : 0; },
	'le' => sub { return ( $_[0] <= $_[1] ) ? 1 : 0; },
);
my %PREDICATE_STR_OPS = (
	'eq'         => sub { return ( $_[0] eq $_[1] )              ? 1 : 0; },
	'contains'   => sub { return ( index( $_[0], $_[1] ) >= 0 )  ? 1 : 0; },
	'startswith' => sub { return ( substr( $_[0], 0, length( $_[1] ) ) eq $_[1] ) ? 1 : 0; },
	'endswith'   => sub {
		return ( length( $_[1] ) <= length( $_[0] )
				&& substr( $_[0], length( $_[0] ) - length( $_[1] ) ) eq $_[1] ) ? 1 : 0;
	},
);

# the decode transforms, each string -> zero or more candidate strings, run
# left to right over a field value before the operator so an obfuscated payload
# is compared decoded. a transform that can not decode yields no candidate and
# that branch drops. base64offset yields the three alignment candidates
our %PREDICATE_TRANSFORMS = (
	'lower' => sub { return ( lc( $_[0] ) ); },
	'upper' => sub { return ( uc( $_[0] ) ); },
	'url'   => sub {
		my $string = $_[0];
		$string =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
		return ($string);
	},
	'windash' => sub {
		my $string = $_[0];
		# the unicode dash variants a Windows flag accepts, folded to ascii -
		$string =~ s/[\x{2010}\x{2011}\x{2012}\x{2013}\x{2014}\x{2015}]/-/g;
		return ($string);
	},
	'base64' => sub {
		my $decoded;
		eval { $decoded = decode_base64( $_[0] ); };
		return ( defined($decoded) && $decoded ne '' ) ? ($decoded) : ();
	},
	'base64offset' => sub {
		my $string = $_[0];
		my @out;
		foreach my $offset ( 0, 1, 2 ) {
			my $slice = substr( $string, $offset );
			my $trim  = length($slice) - ( length($slice) % 4 );
			if ( $trim <= 0 ) {
				next;
			}
			my $decoded;
			eval { $decoded = decode_base64( substr( $slice, 0, $trim ) ); };
			if ( defined($decoded) && $decoded ne '' ) {
				push( @out, $decoded );
			}
		} ## end foreach my $offset ( 0, 1, 2 )
		return @out;
	},
	'utf16le' => sub {
		my $d;
		eval { $d = Encode::decode( 'UTF-16LE', $_[0], Encode::FB_CROAK() ); };
		return defined($d) ? ($d) : ();
	},
	'utf16be' => sub {
		my $d;
		eval { $d = Encode::decode( 'UTF-16BE', $_[0], Encode::FB_CROAK() ); };
		return defined($d) ? ($d) : ();
	},
	'utf16' => sub {
		my $d;
		eval { $d = Encode::decode( 'UTF-16', $_[0], Encode::FB_CROAK() ); };
		return defined($d) ? ($d) : ();
	},
);
# wide is a Sigma alias for utf16le
$PREDICATE_TRANSFORMS{wide} = $PREDICATE_TRANSFORMS{utf16le};

# true if a gate entry is the predicate form rather than the legacy
# field/values form, so the compiler can branch and leave the old path alone
sub _is_predicate {
	my ( $self, $entry ) = @_;

	return (
		ref($entry) eq 'HASH' && ( exists( $entry->{op} )
			|| exists( $entry->{value} )
			|| exists( $entry->{all} )
			|| exists( $entry->{negate} )
			|| exists( $entry->{nocase} )
			|| exists( $entry->{fieldref} )
			|| exists( $entry->{decode} ) )
		)
		? 1
		: 0;
} ## end sub _is_predicate

# compiles a predicate entry into a runnable form, dieing on anything
# unusable. shape: { field, op (default eq), value | values, all, negate }.
# op eq/contains/startswith/endswith are string tests, re a regexp (tokened),
# gt/lt/ge/le numeric, cidr a v4/v6 membership reusing the ignore-list machine
sub _compile_predicate {
	my ( $self, $entry, $where ) = @_;

	foreach my $key ( keys( %{$entry} ) ) {
		if ( $key !~ /^(?:field|op|value|values|all|negate|nocase|fieldref|decode)$/ ) {
			die( $where . ' has the unknown key "' . $key . '"' );
		}
	}

	my $op = defined( $entry->{op} ) ? $entry->{op} : 'eq';
	if ( ref($op) ne '' || !$PREDICATE_OPS{$op} ) {
		die( $where . ' has the unknown op "' . ( ref($op) ? ref($op) : $op ) . '"' );
	}

	# nocase case-folds the string and re comparisons... meaningless on the
	# numeric and cidr ops, so a set there is a mistake worth naming
	my $nocase = $entry->{nocase} ? 1 : 0;
	if ( $nocase && ( $op eq 'cidr' || $op =~ /^(?:gt|lt|ge|le)$/ ) ) {
		die( $where . ' nocase does not apply to the ' . $op . ' op' );
	}

	# fieldref names another field to compare against, its value the needle
	# resolved from the line at match time rather than a literal. it stands in
	# for value/values and only the string ops, which compare a needle, take it
	my $fieldref = $entry->{fieldref};
	if ( defined($fieldref) ) {
		if ( ref($fieldref) ne '' || $fieldref eq '' ) {
			die( $where . ' fieldref is not a non-empty field name' );
		}
		if ( exists( $entry->{value} ) || exists( $entry->{values} ) ) {
			die( $where . ' sets both fieldref and a literal value' );
		}
		if ( $op !~ /^(?:eq|contains|startswith|endswith)$/ ) {
			die( $where . ' fieldref works only with the eq, contains, startswith, and endswith ops' );
		}
	} ## end if ( defined($fieldref) )

	# exists tests only whether the field is present, so it takes no needle...
	# negate turns it into the field-absent test, Sigma's C<|exists: false>
	if ( $op eq 'exists' ) {
		if (   exists( $entry->{value} )
			|| exists( $entry->{values} )
			|| defined($fieldref)
			|| exists( $entry->{decode} )
			|| $nocase
			|| $entry->{all} )
		{
			die( $where . ' the exists op takes no value, fieldref, decode, nocase, or all' );
		}
		return {
			'field'  => $entry->{field},
			'op'     => 'exists',
			'negate' => $entry->{negate} ? 1 : 0,
		};
	} ## end if ( $op eq 'exists' )

	my @values;
	if ( defined($fieldref) ) {
		# no literal needle... the referenced field is resolved at match time
	} elsif ( exists( $entry->{values} ) ) {
		if ( ref( $entry->{values} ) ne 'ARRAY' || !@{ $entry->{values} } ) {
			die( $where . ' values is not a non-empty array' );
		}
		@values = @{ $entry->{values} };
	} elsif ( exists( $entry->{value} ) ) {
		@values = ( $entry->{value} );
	} else {
		die( $where . ' lacks a value or values' );
	}
	foreach my $v (@values) {
		if ( !defined($v) || ref($v) ne '' ) {
			die( $where . ' has a non-scalar value' );
		}
	}

	my $predicate = {
		'field'    => $entry->{field},
		'op'       => $op,
		'all'      => $entry->{all}    ? 1 : 0,
		'negate'   => $entry->{negate} ? 1 : 0,
		'nocase'   => $nocase,
		'fieldref' => $fieldref,
	};

	if ( exists( $entry->{decode} ) ) {
		if ( ref( $entry->{decode} ) ne 'ARRAY' || !@{ $entry->{decode} } ) {
			die( $where . ' decode is not a non-empty array' );
		}
		foreach my $transform ( @{ $entry->{decode} } ) {
			if ( !defined($transform) || ref($transform) ne '' || !$PREDICATE_TRANSFORMS{$transform} ) {
				die(      $where
						. ' has the unknown decode transform "'
						. ( defined($transform) ? ( ref($transform) ? ref($transform) : $transform ) : 'undef' )
						. '"' );
			}
		}
		$predicate->{decode} = [ @{ $entry->{decode} } ];
	} ## end if ( exists( $entry->{decode} ) )

	if ( $op eq 're' ) {
		my @regexps;
		foreach my $v (@values) {
			# a leading (?i) applies to the whole pattern, token expansions
			# and all, so nocase folds a re without touching the tokens
			my $pat = $nocase ? '(?i)' . $v : $v;
			push( @regexps, $self->_compile_tokened_regexp( $pat, $where )->{regexp} );
		}
		$predicate->{regexps} = \@regexps;
		$predicate->{kind}    = 're';
	} elsif ( defined( $PREDICATE_NUM_OPS{$op} ) ) {
		my @numbers;
		foreach my $v (@values) {
			if ( $v !~ /^-?[0-9]+(?:\.[0-9]+)?$/ ) {
				die( $where . ' op ' . $op . ' needs numeric values, got "' . $v . '"' );
			}
			push( @numbers, $v + 0 );
		}
		$predicate->{numbers} = \@numbers;
		$predicate->{kind}    = 'num';
		$predicate->{op_code} = $PREDICATE_NUM_OPS{$op};
	} elsif ( $op eq 'cidr' ) {
		# dies on a bad CIDR, exactly as the ignore/namtar lists do
		$predicate->{cidr} = compile_ignore_ips( \@values, $where );
		$predicate->{kind} = 'cidr';
	} elsif ( defined($fieldref) ) {
		# the needle is the referenced field, injected at match time, so there
		# are no static strings to compile
		$predicate->{kind}    = 'string';
		$predicate->{op_code} = $PREDICATE_STR_OPS{$op};
	} else {
		# nocase folds the needles once here, the candidate folded to match at
		# test time, so a case-insensitive compare costs no per-hit lc of these
		$predicate->{strings} = $nocase ? [ map { lc } @values ] : \@values;
		$predicate->{kind}    = 'string';
		$predicate->{op_code} = $PREDICATE_STR_OPS{$op};
	}

	return $predicate;
} ## end sub _compile_predicate

# runs a compiled predicate against a field value, honoring negate. a missing
# field is a false core, so a plain predicate misses and a negated one holds,
# matching Sigma's "field absent" semantics
sub _predicate_hit {
	my ( $self, $predicate, $value, $ref ) = @_;

	my $core = $self->_predicate_core( $predicate, $value, $ref );
	if ( $predicate->{negate} ) {
		return $core ? 0 : 1;
	}
	return $core;
}

sub _predicate_core {
	my ( $self, $predicate, $value, $ref ) = @_;

	# exists tests presence, so it must see undef rather than short-circuit on
	# it... negate (applied by the caller) flips it to the field-absent test
	if ( $predicate->{op} eq 'exists' ) {
		return defined($value) ? 1 : 0;
	}

	if ( !defined($value) ) {
		return 0;
	}

	# the field value, run through any decode chain into one or more candidate
	# strings, the operator matching if any candidate satisfies it. with no
	# decode the candidate is just the value, so this is the plain path. $ref is
	# the referenced field's value for a fieldref predicate, the dynamic needle
	foreach my $candidate ( $self->_decode_candidates( $predicate->{decode}, "$value" ) ) {
		if ( $self->_predicate_test_one( $predicate, $candidate, $ref ) ) {
			return 1;
		}
	}

	return 0;
} ## end sub _predicate_core

# applies a predicate's decode chain to a value, fanning out... each transform
# maps every current candidate to zero or more, so base64offset widens and a
# failed decode narrows. no decode chain is the value unchanged
sub _decode_candidates {
	my ( $self, $decode, $value ) = @_;

	if ( !defined($decode) ) {
		return ($value);
	}

	my @candidates = ($value);
	foreach my $transform ( @{$decode} ) {
		my @next;
		foreach my $candidate (@candidates) {
			push( @next, $PREDICATE_TRANSFORMS{$transform}->($candidate) );
		}
		@candidates = @next;
		if ( !@candidates ) {
			return ();
		}
	} ## end foreach my $transform ( @{$decode} )

	return @candidates;
} ## end sub _decode_candidates

# tests one candidate string against a predicate's operator and values. $ref,
# the referenced field's value, is the dynamic needle for a fieldref predicate.
# the operator was resolved to kind and op_code at compile time and the any/all
# folds are inlined, as this is the innermost per-line call
sub _predicate_test_one {
	my ( $self, $predicate, $value, $ref ) = @_;

	my $kind = $predicate->{kind};

	# the string ops... eq/contains/startswith/endswith. under nocase the
	# needle was folded at compile time, so folding the candidate here makes
	# the compare case-insensitive
	if ( $kind eq 'string' ) {
		my $candidate = $predicate->{nocase} ? lc($value) : $value;

		# a fieldref predicate compares against another field's live value,
		# injected as the needle here, folded to match under nocase since it
		# was not folded at compile time... an absent referenced field is a
		# non-match
		my $needles = $predicate->{strings};
		if ( defined( $predicate->{fieldref} ) ) {
			if ( !defined($ref) ) {
				return 0;
			}
			$needles = [ $predicate->{nocase} ? lc($ref) : $ref ];
		}

		my $test = $predicate->{op_code};
		if ( $predicate->{all} ) {
			foreach my $needle ( @{$needles} ) {
				if ( !$test->( $candidate, $needle ) ) {
					return 0;
				}
			}
			return 1;
		}
		foreach my $needle ( @{$needles} ) {
			if ( $test->( $candidate, $needle ) ) {
				return 1;
			}
		}
		return 0;
	} ## end if ( $kind eq 'string' )

	if ( $kind eq 're' ) {
		if ( $predicate->{all} ) {
			foreach my $regexp ( @{ $predicate->{regexps} } ) {
				if ( $value !~ $regexp ) {
					return 0;
				}
			}
			return 1;
		}
		foreach my $regexp ( @{ $predicate->{regexps} } ) {
			if ( $value =~ $regexp ) {
				return 1;
			}
		}
		return 0;
	} ## end if ( $kind eq 're' )

	if ( $kind eq 'num' ) {
		if ( $value !~ /^-?[0-9]+(?:\.[0-9]+)?$/ ) {
			return 0;
		}
		my $number = $value + 0;
		my $test   = $predicate->{op_code};
		if ( $predicate->{all} ) {
			foreach my $threshold ( @{ $predicate->{numbers} } ) {
				if ( !$test->( $number, $threshold ) ) {
					return 0;
				}
			}
			return 1;
		}
		foreach my $threshold ( @{ $predicate->{numbers} } ) {
			if ( $test->( $number, $threshold ) ) {
				return 1;
			}
		}
		return 0;
	} ## end if ( $kind eq 'num' )

	# cidr
	return ip_ignored( $predicate->{cidr}, $value ) ? 1 : 0;
} ## end sub _predicate_test_one

# compiles a rule's gate array into runnable entries, each either a legacy
# field/values matcher set or a typed predicate. shared by every type that
# carries a gate... json runs it as a pre-filter over parsed fields, syslog and
# raw as a post-match refinement over the captures, and a selection is one such
# gate list too. $where_prefix names it in errors, so a selection reads clearly
sub _compile_gates {
	my ( $self, $gate_def, $where_prefix ) = @_;

	if ( ref($gate_def) ne 'ARRAY' || !@{$gate_def} ) {
		die( $where_prefix . ' is not a array or is empty' );
	}

	my @gates;
	my $entry_int = 0;
	foreach my $entry ( @{$gate_def} ) {
		my $where = $where_prefix . ' entry ' . $entry_int;
		if ( ref($entry) ne 'HASH' || !defined( $entry->{field} ) ) {
			die( $where . ' is not a hash with a field' );
		}
		my $gate;
		if ( $self->_is_predicate($entry) ) {
			$gate = { 'field' => $entry->{field}, 'predicate' => $self->_compile_predicate( $entry, $where ) };
		} else {
			if ( ref( $entry->{values} ) ne 'ARRAY' ) {
				die( $where . ' is not a hash with a field and a values array' );
			}
			foreach my $key ( keys( %{$entry} ) ) {
				if ( $key !~ /^(?:field|values)$/ ) {
					die( $where . ' has the unknown key "' . $key . '"' );
				}
			}
			$gate = { 'field' => $entry->{field}, 'matchers' => $self->_compile_matchers( $entry->{values}, $where ) };
		} ## end else [ if ( $self->_is_predicate($entry) ) ]

		# the reserved keyword fields, flagged at compile so the runtime fans
		# the predicate over many values... %%%ANY%%% every field, %%%ANY:pre%%%
		# the subtree at or under `pre`, so a keyword can search everything or
		# just a known branch without touching the rest
		if ( $entry->{field} eq '%%%ANY%%%' ) {
			$gate->{keyword} = 1;
		} elsif ( $entry->{field} =~ /^%%%ANY:(.+)%%%$/ ) {
			$gate->{keyword} = 1;
			$gate->{prefix}  = $1;
		}
		# the keyword fan carries no referenced value, so a fieldref under it
		# would compile and then silently never match
		if ( $gate->{keyword} && defined( $gate->{predicate} ) && defined( $gate->{predicate}{fieldref} ) ) {
			die( $where . ' pairs fieldref with a keyword field, which can never match' );
		}
		push( @gates, $gate );
		$entry_int++;
	} ## end foreach my $entry ( @{$gate_def} )

	return \@gates;
} ## end sub _compile_gates

# compiles a rule's boolean matcher, the flat gate or the selections+condition
# form, onto the object... they are mutually exclusive, a condition needs
# selections and the reverse. shared by every type that carries a gate, so json,
# syslog, and raw all get the operators, decode, and the boolean form uniformly
sub _compile_boolean {
	my ( $self, $def, $name ) = @_;

	if ( defined( $def->{gate} ) && defined( $def->{selections} ) ) {
		die( 'The rule "' . $name . '" has both a gate and selections, which are two forms of the same thing' );
	}

	if ( defined( $def->{gate} ) ) {
		$self->{gates} = $self->_compile_gates( $def->{gate}, 'The gate of the rule "' . $name . '"' );
	}

	if ( defined( $def->{selections} ) ) {
		if ( !defined( $def->{condition} ) ) {
			die( 'The rule "' . $name . '" has selections but no condition' );
		}
		if ( ref( $def->{selections} ) ne 'HASH' || !%{ $def->{selections} } ) {
			die( 'The selections of the rule "' . $name . '" is not a non-empty table' );
		}
		my %compiled;
		foreach my $sel_name ( keys( %{ $def->{selections} } ) ) {
			if ( $sel_name !~ /^[A-Za-z_][A-Za-z0-9_]*$/ || $sel_name =~ /^(?:and|or|not|of|them|all)$/i ) {
				die( 'The selection name "' . $sel_name . '" of the rule "' . $name . '" is not a plain identifier' );
			}
			$compiled{$sel_name} = $self->_compile_gates( $def->{selections}{$sel_name},
				'The selection "' . $sel_name . '" of the rule "' . $name . '"' );
		}
		$self->{selections} = \%compiled;
		$self->{condition_ast}
			= $self->_compile_condition( $def->{condition}, \%compiled, 'The condition of the rule "' . $name . '"' );
	} elsif ( defined( $def->{condition} ) ) {
		die( 'The rule "' . $name . '" has a condition but no selections' );
	}

	$self->_compile_keywords( $def, $name );

	# whether any boolean filter exists at all, judged once here so the
	# per-line paths can skip building the field space for a rule with none
	$self->{has_boolean}
		= (    ( ref( $self->{gates} ) eq 'ARRAY' && @{ $self->{gates} } )
			|| ( ref( $self->{keyword_gates} ) eq 'ARRAY' && @{ $self->{keyword_gates} } )
			|| defined( $self->{condition_ast} ) ) ? 1 : 0;

	return;
} ## end sub _compile_boolean

# compiles the keywords shorthand into a keyword gate list, ANDed ahead of the
# gate or selections by _boolean_pass. a plain list searches every field via
# %%%ANY%%%; the { in, values } form searches a named path, a %%%ANY:prefix%%%
# subtree, or %%%ANY%%%, so a rule can scope the search when it knows the path
sub _compile_keywords {
	my ( $self, $def, $name ) = @_;

	if ( !defined( $def->{keywords} ) ) {
		return;
	}
	my $where = 'The keywords of the rule "' . $name . '"';
	my $kw    = $def->{keywords};

	my ( $in, $values );
	if ( ref($kw) eq 'ARRAY' ) {
		$in     = '%%%ANY%%%';
		$values = $kw;
	} elsif ( ref($kw) eq 'HASH' ) {
		foreach my $key ( keys( %{$kw} ) ) {
			if ( $key !~ /^(?:in|values)$/ ) {
				die( $where . ' has the unknown key "' . $key . '"' );
			}
		}
		$in = defined( $kw->{in} ) ? $kw->{in} : '%%%ANY%%%';
		if ( ref($in) ne '' || $in eq '' ) {
			die( $where . ' in is not a non-empty string naming a field, a %%%ANY:prefix%%%, or %%%ANY%%%' );
		}
		$values = $kw->{values};
	} else {
		die( $where . ' is not a list of strings or a table' );
	}

	if ( ref($values) ne 'ARRAY' || !@{$values} ) {
		die( $where . ' lacks a non-empty values list' );
	}

	# one contains-predicate gate over the chosen field, reusing the whole
	# operator/decode/keyword machinery
	$self->{keyword_gates}
		= $self->_compile_gates( [ { 'field' => $in, 'op' => 'contains', 'values' => $values } ], $where );

	return;
} ## end sub _compile_keywords

# runs a rule's boolean matcher over a data hash, true when it passes... the
# selections folded by their condition when the rule has them, else the flat
# gate, else true (no boolean filter). the one entry point for json's pre-filter
# and the syslog/raw post-match refinement alike
sub _boolean_pass {
	my ( $self, $data, $message ) = @_;

	# the keywords shorthand, ANDed ahead of the gate or selections so it
	# composes with either or stands alone
	if ( ref( $self->{keyword_gates} ) eq 'ARRAY' && @{ $self->{keyword_gates} } ) {
		if ( !$self->_gates_pass( $self->{keyword_gates}, $data, $message ) ) {
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
				$results{$sel_name} = $self->_gates_pass( $self->{selections}{$sel_name}, $data, $message );
			}
			return $results{$sel_name};
		};
		return $self->_eval_condition( $self->{condition_ast}, $eval_sel );
	} ## end if ( defined( $self->{condition_ast} ) )

	if ( ref( $self->{gates} ) eq 'ARRAY' && @{ $self->{gates} } ) {
		return $self->_gates_pass( $self->{gates}, $data, $message );
	}

	return 1;
} ## end sub _boolean_pass

# the core... runs a given gate list (ANDed) over a data hash, true when all
# pass. shared by the rule gate and by each selection of the boolean form
sub _gates_pass {
	my ( $self, $gates, $data, $message ) = @_;

	foreach my $gate ( @{$gates} ) {
		if ( !$self->_gate_hit( $gate, $data, $message ) ) {
			return 0;
		}
	}

	return 1;
} ## end sub _gates_pass

# tests one gate against a data hash, true when it holds. an ordinary gate reads
# its one field (MESSAGE reaching the whole message); a keyword gate fans its
# predicate over many field values, matching if any hits, so a string can be
# searched across every field or a subtree
sub _gate_hit {
	my ( $self, $gate, $data, $message ) = @_;

	if ( $gate->{keyword} ) {
		my @values = $self->_keyword_values( $data, $message, $gate->{prefix} );
		my $hit    = 0;
		foreach my $value (@values) {
			# the predicate core, no negate, so the fan is a clean OR
			my $core
				= defined( $gate->{predicate} )
				? $self->_predicate_core( $gate->{predicate}, $value )
				: $self->_matchers_hit( $gate->{matchers}, $value );
			if ($core) {
				$hit = 1;
				last;
			}
		} ## end foreach my $value (@values)
		# a negated keyword means no field matched, so negate the whole fan once
		if ( defined( $gate->{predicate} ) && $gate->{predicate}{negate} ) {
			$hit = $hit ? 0 : 1;
		}
		return $hit;
	} ## end if ( $gate->{keyword} )

	my $value
		= ( $gate->{field} eq 'MESSAGE' && defined($message) && !exists( $data->{MESSAGE} ) )
		? $message
		: $data->{ $gate->{field} };
	if ( !defined( $gate->{predicate} ) ) {
		return $self->_matchers_hit( $gate->{matchers}, $value );
	}

	# a fieldref predicate's needle is another field's live value, resolved
	# here where the data hash is in hand and threaded into the compare
	my $ref;
	if ( defined( $gate->{predicate}{fieldref} ) ) {
		$ref = $data->{ $gate->{predicate}{fieldref} };
	}
	return $self->_predicate_hit( $gate->{predicate}, $value, $ref );
} ## end sub _gate_hit

# the values a keyword gate fans over... every field value plus the message for
# a bare %%%ANY%%%, or the values whose flattened path is the prefix or under it
# for a scoped %%%ANY:prefix%%%, so nothing unrelated is searched
sub _keyword_values {
	my ( $self, $data, $message, $prefix ) = @_;

	if ( defined($prefix) ) {
		my @values;
		my $under = $prefix . '.';
		foreach my $field ( keys( %{$data} ) ) {
			if ( $field eq $prefix || index( $field, $under ) == 0 ) {
				push( @values, $data->{$field} );
			}
		}
		return @values;
	} ## end if ( defined($prefix) )

	my @values = values( %{$data} );
	if ( defined($message) ) {
		push( @values, $message );
	}
	return @values;
} ## end sub _keyword_values

# parses a Sigma-style condition string over the named selections into an AST,
# dieing on a syntax error or a reference to a unknown selection. the grammar
# is or > and > not > primary, primary being a paren group, a selection name,
# or a quantifier... "all of them", "1 of them", "N of <prefix>_*"
sub _compile_condition {
	my ( $self, $string, $selections, $where ) = @_;

	if ( !defined($string) || ref($string) ne '' || $string !~ /\S/ ) {
		die( $where . ' is not a non-empty string' );
	}

	my @tokens;
	while ( $string =~ /\G\s*([()]|[^\s()]+)/gc ) {
		push( @tokens, $1 );
	}

	my $pos  = 0;
	my $peek = sub { return $pos < scalar(@tokens) ? $tokens[$pos] : undef; };
	my $next = sub { return $tokens[ $pos++ ]; };

	my ( $parse_or, $parse_and, $parse_not, $parse_primary );

	$parse_primary = sub {
		my $tok = $peek->();
		if ( !defined($tok) ) {
			die( $where . ' ends unexpectedly' );
		}
		if ( $tok eq '(' ) {
			$next->();
			my $node  = $parse_or->();
			my $close = $next->();
			if ( !defined($close) || $close ne ')' ) {
				die( $where . ' has an unbalanced paren' );
			}
			return $node;
		}
		# a quantifier... (all|N) of (them | <prefix>_*)
		if (   ( lc($tok) eq 'all' || $tok =~ /^[0-9]+$/ )
			&& defined( $tokens[ $pos + 1 ] )
			&& lc( $tokens[ $pos + 1 ] ) eq 'of' )
		{
			my $qty = $next->();
			$next->();    # of
			my $target = $next->();
			if ( !defined($target) ) {
				die( $where . ' has an "of" with no target' );
			}
			my @names = $self->_cond_resolve( $target, $selections, $where );
			# a *-pattern matching nothing would make "all of" vacuously
			# true, turning a typo into match-everything
			if ( !@names ) {
				die( $where . ' has an "of" target "' . $target . '" that covers no selections' );
			}
			my $threshold = ( lc($qty) eq 'all' ) ? scalar(@names) : $qty + 0;
			if ( $threshold < 1 ) {
				die( $where . ' asks for 0 of, which is vacuously true' );
			}
			if ( $threshold > scalar(@names) ) {
				die(      $where
						. ' asks for '
						. $threshold . ' of '
						. scalar(@names)
						. ' selections, which can never be met' );
			}
			return [ 'count', $threshold, \@names ];
		} ## end if ( ( lc($tok) eq 'all' || $tok =~ /^[0-9]+$/...))
		my $name = $next->();
		if ( $name =~ /^(?:and|or|not|of|them|all)$/i || $name eq ')' ) {
			die( $where . ' has a misplaced "' . $name . '"' );
		}
		if ( !exists( $selections->{$name} ) ) {
			die( $where . ' references the unknown selection "' . $name . '"' );
		}
		return [ 'sel', $name ];
	}; ## end $parse_primary = sub

	$parse_not = sub {
		my $tok = $peek->();
		if ( defined($tok) && lc($tok) eq 'not' ) {
			$next->();
			return [ 'not', $parse_not->() ];
		}
		return $parse_primary->();
	};

	$parse_and = sub {
		my $node = $parse_not->();
		while ( defined( $peek->() ) && lc( $peek->() ) eq 'and' ) {
			$next->();
			$node = [ 'and', $node, $parse_not->() ];
		}
		return $node;
	};

	$parse_or = sub {
		my $node = $parse_and->();
		while ( defined( $peek->() ) && lc( $peek->() ) eq 'or' ) {
			$next->();
			$node = [ 'or', $node, $parse_and->() ];
		}
		return $node;
	};

	my $ast = $parse_or->();
	if ( $pos != scalar(@tokens) ) {
		die( $where . ' has trailing tokens after "' . $tokens[$pos] . '"' );
	}

	return $ast;
} ## end sub _compile_condition

# resolves a quantifier target to the list of selection names it covers...
# "them" is all, a trailing * is a name prefix, else a single named selection
sub _cond_resolve {
	my ( $self, $target, $selections, $where ) = @_;

	if ( lc($target) eq 'them' ) {
		my @names = sort( keys( %{$selections} ) );
		return @names;
	}
	if ( $target =~ /^(.*)\*$/ ) {
		my $prefix = $1;
		my @names  = grep { index( $_, $prefix ) == 0 } sort( keys( %{$selections} ) );
		return @names;
	}
	if ( !exists( $selections->{$target} ) ) {
		die( $where . ' has an "of" target "' . $target . '" that is not a selection or a *-pattern' );
	}
	return ($target);
} ## end sub _cond_resolve

# folds a condition AST, asking $eval_sel for each selection's boolean as
# needed... the and/or arms short-circuit and the count fold bails as soon
# as the threshold is met or unreachable
sub _eval_condition {
	my ( $self, $ast, $eval_sel ) = @_;

	my $op = $ast->[0];
	if ( $op eq 'sel' ) {
		return $eval_sel->( $ast->[1] ) ? 1 : 0;
	}
	if ( $op eq 'not' ) {
		return $self->_eval_condition( $ast->[1], $eval_sel ) ? 0 : 1;
	}
	if ( $op eq 'and' ) {
		return ( $self->_eval_condition( $ast->[1], $eval_sel ) && $self->_eval_condition( $ast->[2], $eval_sel ) )
			? 1
			: 0;
	}
	if ( $op eq 'or' ) {
		return ( $self->_eval_condition( $ast->[1], $eval_sel ) || $self->_eval_condition( $ast->[2], $eval_sel ) )
			? 1
			: 0;
	}
	# count... at least threshold of the named selections are true
	my ( $threshold, $names ) = ( $ast->[1], $ast->[2] );
	my $hits      = 0;
	my $remaining = scalar( @{$names} );
	foreach my $name ( @{$names} ) {
		$remaining--;
		if ( $eval_sel->($name) ) {
			$hits++;
			if ( $hits >= $threshold ) {
				return 1;
			}
		} elsif ( ( $hits + $remaining ) < $threshold ) {
			return 0;
		}
	}
	return 0;
} ## end sub _eval_condition

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991, or (at your
  option) any later version, matching fail2ban, which parts of this
  project, most notably the shipped rules, are derived from.

=cut

1;
