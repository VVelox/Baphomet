# The log analysis engine

Baphomet has two faces. One is the accuser... it counts an IP's offenses and
banishes the repeat ones to Kur, fail2ban's job (see [fail2ban](fail2ban.md)).
The other is the one this page is about: the same galla that bans is also a
log analysis engine, in the family of Sagan, Wazuh, and the Sigma
detection model... it parses a stream, reads each line against signatures,
enriches and correlates, and raises an alert. A rule need not end in a ban.

Nothing here is a separate mode or a second daemon. The detection half and
the banning half are the same rules, the same parsers, the same gates... only
the verdict at the end differs.

## The two verdicts

A rule names its offender with one of two keys, and that choice is the whole
of it:

- **`ban_var`** :: For banishing. The named value is counted toward a ban and,
  at the threshold, banished to Kur.
- **`detection_var`** :: Detection only. The named value is counted the same
  way, through the same window and threshold, but crossing it banishes
  nobody... it writes a `sighted` to EVE and touches no firewall.

`detection_var` is what makes a rule detection-only, and it lifts the subject
off the leash of being an address. It counts by anything the line carries...
a username, a hostname, a URI, a service, a config key... so a rule can alert
on a thing with no address to banish at all, a policy tripwire, a service
crash, a configuration change. This is the Sagan/Wazuh(LAE/Log Analysis Engine) reach a
pure banisher can not follow. See [rules](rules.md#detection_var).

## What makes it a detection engine

Between a line arriving and a verdict, the galla runs the whole signature
vocabulary a log analysis engine is judged by. All of it is documented in
[rules](rules.md); gathered here is what it amounts to as detection...

- **Structured matching, not just a regexp per line.** Lines are parsed once
  into fields... syslog, access logs, error logs, JSON... and rules match the
  fields. The `json` type carries the full Sigma detection model:
  `selections` of predicates composed by a `condition` with `and`/`or`/`not`,
  `all of them`, `1 of them`, `N of <prefix>_*`, over operators
  (`contains`/`startswith`/`re`/`cidr`/...) and decode chains
  (base64, utf16, windash). See [sigma](sigma.md).
- **Correlation across lines.** Offense and address, or offense and context,
  logged apart and tied by a key... `capture_regexp`/`key`/`defer` on the
  text and json types.
- **Staged sequences.** Ordered stages with count, time, and line bounds...
  the brute-force-that-worked shape, failures then a success, in one rule.
- **Marks, cross-rule state.** Sagan's xbits/flexbits... one rule brands a
  key, a later rule fires only on the branded, which is how distributed
  brute force is caught.
- **Weighted scoring.** A signature carries a `weight` and the threshold is a
  score, not a hit count, so a dangerous signature weighs heavy and alarms on
  one hit while a noisy one weighs light. sshguard's dangerousness, per rule.
- **Enriching gates.** Geography (`country`), blocklists (`namtar_list`),
  time of day (`active_time`), and reverse DNS refine a match on outside
  knowledge before it counts.

## The alert, and its metadata

A detection is only as useful as what it says. Every rule carries the
Suricata/Sagan alert-metadata set, flattened onto each event it raises so a
stream of matches is a stream of triageable detections... `msg` (the
`[TAG] description` signature line), `severity`, `category` (the rule's
classtype in words, as Suricata writes it), `references`, `attack` (MITRE
ATT&CK ids), and `rev`, plus a `sid` and `gid` the loader derives. This is the vocabulary a SOC reads a detection by. See
[triage metadata](rules.md#triage-metadata).

## The output... the EVE stream

Where the accuser's output is a ban request to Ereshkigal, the detection
engine's output is the **EVE event log**, a Suricata-shaped NDJSON stream of
what the gallas see. A detection rule writes a `sighting` per match and a
`sighted` when a subject crosses its threshold; a would-be ban held in
observe mode surfaces as an `alert`; a real ban rides as a `found`. One
stream, machine-shaped, is what drives a SIEM, a dashboard, or a notifier...
the alerting Ereshkigal's half never sees. See [eve](eve.md).

## Observe mode... detection before trust

Any rule, watcher, kur, or the whole deployment can be set `eve_only`... it
matches and writes to EVE but never bans, a would-be banishment surfacing as
an `alert`. Stand a new signature up, watch what it would have done against
live traffic, and only then trust it to act. It is CrowdSec's simulation, and
it is also, on its own, the way to run Baphomet as a pure detector that never
touches a firewall. See [rules](rules.md#eve_only).
