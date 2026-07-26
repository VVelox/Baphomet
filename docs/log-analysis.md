# The log analysis engine

Baphomet has two faces. One is the accuser... it counts an IP's offenses and
banishes the repeat ones to Kur, fail2ban's job (see [fail2ban](fail2ban.md)).
The other is the one this page is about: the same galla that bans is also a
log analysis engine, in the family of Sagan, Wazuh/OSSEC, and the Sigma
detection model... it parses a stream, reads each line against signatures,
enriches and correlates, and raises an alert. A rule need not end in a ban.
When it detects with out banishing, carries triage metadata, and writes to
the EVE stream, the galla is doing exactly what a log analysis engine does.

Nothing here is a separate mode or a second daemon. The detection half and
the banning half are the same rules, the same parsers, the same gates... only
the verdict at the end differs.

## The two verdicts

A rule names its offender with one of two keys, and that choice is the whole
of it:

- **`ban_var`** — the accuser. The named value is counted toward a ban and,
  at the threshold, banished to Kur.
- **`detection_var`** — the detection. The named value is counted the same
  way, through the same window and threshold, but crossing it banishes
  nobody... it writes a `sighted` to EVE and touches no firewall.

`detection_var` is what makes a rule detection-only, and it lifts the subject
off the leash of being an address. It counts by anything the line carries...
a username, a hostname, a URI, a service, a config key... so a rule can alert
on a thing with no address to banish at all, a policy tripwire, a service
crash, a configuration change. This is the Sagan/Wazuh reach a pure banisher
can not follow. See [rules](rules.md#detection_var).

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
`[TAG] description` signature line), `severity`, `classtype`, `references`,
`attack` (MITRE ATT&CK ids), and `rev`, plus a `sid` and `gid` the loader
derives. This is the vocabulary a SOC reads a detection by, and it is the
same set Suricata and Sagan emit. See
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

## Where it stops

Honesty section... Baphomet is a log analysis engine, not a SIEM, and the
charter is drawn on purpose.

- **No storage, no backscan.** The galla matches a live stream and forgets,
  holding only its counting window. There is no data lake, no query over
  stored history, no aggregation beyond the window. That is a SIEM's job, not
  a log analysis engine's... Sagan streams and forgets the same way, which is
  why both feed their alerts to something that does keep them.
- **One output.** There is the EVE stream and nothing else... no unified2, no
  syslog-out, no output-plugin fan. A consumer reads EVE or reads nothing.
- **Log sources are the ceiling.** Detection reaches only as far as the
  parsers... syslog services, access and error logs, and JSON. The Windows
  corpus that fills the public Sigma set (Sysmon, the Security event log) has
  nowhere to land, and more coverage means more parsers, not more rule
  language. See [sigma](sigma.md).
- **It detects; Ereshkigal acts.** Beyond a ban, the galla raises an alert
  and stops. There is no active response, no FIM, no SOAR... the things a
  Wazuh does past detection are out of charter. Acting on a detection is
  yours to wire off the EVE stream.

## The family

Baphomet did not invent this half, it folded it in. Three docs map the
lineage rule for rule...

- [sagan](sagan.md) — the log analysis engine Baphomet most resembles here;
  its gates (xbits, country_code, blacklist, alert_time) rebuilt in the galla.
- [wazuh](wazuh.md) — the OSSEC-fork platform whose log-analysis stage this
  matches; Baphomet plus Ereshkigal is its detect-and-respond, with out the
  agent fleet, the file-integrity monitor, or the indexer.
- [sigma](sigma.md) — the generic detection format the `json` rule type
  speaks, modifier for modifier.
- [fail2ban](fail2ban.md) — the other face, the accuser, for when the verdict
  is a ban.

Start with [rules](rules.md) to write a detection, and [eve](eve.md) for the
shape of what it emits.
