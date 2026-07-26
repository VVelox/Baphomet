# The EVE event log

Baphomet can keep a record of its own judgments, an NDJSON log in the
shape Suricata's eve.json uses, so the same tooling... jq, Filebeat, a
SIEM... can consume what the gallas do.

The path is set by default but nothing is written unless it is turned on...

```toml
eve_log    = "/var/log/baphomet/eve.json"   # the default
eve_enable = true
```

One file, shared by every galla, appended to under a lock, so all the kurs
land in one stream filterable by `.kur`.

## The events

One JSON object per line. Six kinds, in `.event_type`... a real pair, an
observe-mode pair, and a detection pair. Within a pair the terminal event
subsumes the routine one: a line whose hit crosses the threshold emits
only the `banish` (or `alert`, or `sighted`), never a `found` (or `noted`,
or `sighting`) beside it, since the terminal event already carries the
whole match. So one line is one event... a burst of failures reads as
several `found`s and then a single `banish` on the one that tipped it, not
a `found` and a `banish` for that last line both.

- **found** ... a rule matched a line and the offender stayed under the
  threshold. The record of a sighting that did not (yet) act... the
  crossing hit is the `banish`, not a `found`.
- **banish** ... an IP crossed its threshold and was condemned to Kur.
  Written when the decision is made, synchronously and with the full
  context, not when Ereshkigal accepts it... so the audit never waits on
  delivery, and a Kur that is down or slow costs the send a retry, never a
  lost or context-stripped record. Carries the triggering line whole, the
  same `raw`/`parsed`/`found`/`marks_set` a `found` would have, so it
  stands for that line by itself.
- **noted** ... the observe-mode twin of `found`, a match under an
  `eve_only` rule or watcher, which is recorded but never counted toward a
  real ban. See [rules](rules).
- **alert** ... the observe-mode twin of `banish`, an offender whose score
  reached the threshold under observe mode. It reads just like the banish it
  stands in for, minus the fact of the ban... nothing was sent to Kur.
- **sighting** ... the detection twin of `found`, a sub-threshold match
  under a detection-only rule (one carrying a `detection_var`). The rule
  banishes nobody, only counts its subject... the crossing match is the
  `sighted`. See [rules](rules).
- **sighted** ... the detection twin of `banish`, a subject whose count
  crossed the threshold under a detection rule. It carries the match
  envelope but names a `.subject`, not an `.ip`... the subject need not be a
  address, and nothing is sent to Kur.

Every record carries these fields...

| field | what |
| --- | --- |
| `eve_type` | `baphomet`, always... marks the producer for downstream tooling. |
| `event_type` | `found`, `banish`, `noted`, `alert`, `sighting`, or `sighted`. |
| `timestamp` | ISO 8601 with zone. |
| `hostname` | the system hostname. |
| `kur` | the kur. |
| `path` | the source... the log file, or `journal:<matches>` for a journal watcher. |
| `score` | the offender's accumulated weighted score after this hit... equal to the raw hit count when no weights are in play. |
| `msg` | the rule's human-readable signature, Sagan/Suricata `[TAG] description` style... its `msg`, or the rule name when it sets none. Suricata's `alert.signature`, promoted to the top level. |
| `gid` | the rule's group id, Suricata's `alert.gid`... `0` when the rule is one of the shipped ones, `1` when it came from the site override dir (`rules_dir`). Always present. |
| `sid` | the rule's signature id, Suricata's `alert.signature_id`... a stable positive integer hashed from the rule name, so `syslog/sshd` always carries the same `sid`, shipped or overridden. Always present. |
| `rev` | the rule's revision, Suricata's `alert.rev`... the rule's `rev`, or `0` when it sets none (an unversioned rule). Always present as an integer. |
| `severity` | the rule's severity (`info`/`low`/`medium`/`high`/`critical`), or the config `default_severity`... omitted when neither is set. |
| `classtype` | the rule's category, Snort/Sagan/Suricata classtype... present only when the rule sets one. |
| `references` | the rule's references (URLs, CVE ids)... an array, present only when set. |
| `attack` | the rule's MITRE ATT&CK technique ids... an array, present only when set. |
| `src_ip` | the flow's source IP, lifted from the found var the rule's `src_ip_var` names (default `src_ip`)... always present, `null` when that var is absent. |
| `dest_ip` | the flow's destination IP, lifted from the found var the rule's `dest_ip_var` names (default `dest_ip`)... always present, `null` when that var is absent. |
| `raw` | the line as received, or, when that line is itself a JSON object or array, the decoded structure rather than a escaped string. |
| `parsed` | the parser's output, or the parsed JSON itself for a JSON log. |
| `found` | all the found hash keys, what the rule captured. |
| `stages` | a staged rule's whole story... an array of every stage hit (`stage` index, `time` epoch, `line`), `raw` above being only the final line. Present only on staged-rule events. |
| `rule` | the rule's name and def, with its tests stripped to save space. |

A **banish** event adds `.ip` and `.ban_time`, and `.recidive` is true
when it is a seventh-gate escalation to the recidive kur. A banish
triggered by a specific line crossing the threshold carries that line's
`raw`/`parsed`/`found`/`rule`, always... the record is written at the
crossing, so a Kur outage that pends the send for later retry never
strips it. A recidive escalation, which is triggered by the ledger count
rather than a line, is the bare banishment. With a `geoip_db` loaded, the
banished IP's `.country` rides along too.

A **subnet banish** is a banish whose `.ip` is a CIDR (`65.49.1.0/24`)
rather than a single address... raised when a network bucket crosses
`subnet_max_score` (see [configuration](configuration)). Its `.raw` (and
`.parsed`/`.found`) are the last line that tipped the bucket over, and it
adds a `.bucket` table describing the network: `family` (`v4`/`v6`),
`cidr`, `prefix`, `members` (the distinct offender IPs that fed it, in
first-seen order), `hits`, `score`, and the `first`/`last` epochs the
window spanned. It carries no `.country`, a CIDR has no single one. In
observe mode the same crossing surfaces as an `alert` with the same
`.ip` and `.bucket`. An **alert** carries the same
`.ip`, `.ban_time`, `.score`, and envelope a banish would, being its
observe-mode stand-in. A **found** or **noted** event carries `.marks_set`
and `.unmarked` when the rule branded or lifted marks, and `.ip`, the
offender the match would pass for banning (the first `ban_var` candidate to
survive the per-IP gates)... absent when the rule branded only, banished
nobody, or every candidate was internal. The terminal events carry the
same `.marks_set` and `.unmarked`, so a line that both brands and banishes
records the brand on its `banish`, the `found` it stands in for having been
suppressed.

A **sighted** event adds `.subject`, the value of the `detection_var` that
crossed the threshold... a username, a hostname, a URI, or a IP when that is
what the rule counts. It carries the same `.score` and match envelope a
banish would, but no `.ip`, `.ban_time`, `.country`, or `.recidive`... a
detection rule never banishes, so none of those apply. A **sighting** carries
the match envelope like a `found`, plus `.marks_set` / `.unmarked` when the
rule brands.

## Reading it

```shell
# every banishment, as ip and kur
jq -r 'select(.event_type=="banish") | "\(.kur) \(.ip)"' /var/log/baphomet/eve.json

# the busiest offenders, by how often they tripped a rule... both found
# (the sub-threshold hits) and banish (the crossing ones), since a
# banishing line emits only the banish
jq -r 'select(.event_type=="found" or .event_type=="banish") | .found.SRC // .found.HOST' \
    /var/log/baphomet/eve.json | sort | uniq -c | sort -rn | head

# what a given IP did, in full
jq 'select(.found.SRC=="1.2.3.4" or .ip=="1.2.3.4")' /var/log/baphomet/eve.json

# what observe mode WOULD have banished
jq -r 'select(.event_type=="alert") | "\(.kur) \(.ip)"' /var/log/baphomet/eve.json

# every detection that crossed its threshold, as subject and kur
jq -r 'select(.event_type=="sighted") | "\(.kur) \(.subject)"' /var/log/baphomet/eve.json
```

## Notes

- `found` fires on every match, not every line read, so the volume tracks
  how much abuse is landing, not how chatty the logs are... still, a site
  under heavy attack writes a lot, so mind the disk. `noted` and `alert`
  are the same, for rules running in observe mode, as are `sighting` and
  `sighted` for detection rules.
- A detection rule (one with a `detection_var`) writes only to EVE, so its
  output would vanish with the log off... loading one forces `eve_enable` on,
  logged at start, so a detection deployment is never a silent no-op.
- The file is reopened per event, so a logrotate that moves it aside is
  picked up on the next write with no signal needed.
- It is telemetry, never load bearing... a write failure is logged and
  shrugged off, it never keeps an IP from being banished.
