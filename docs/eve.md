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
observe-mode pair, and a detection pair:

- **found** ... a rule matched a line. Written on every match, whether or
  not it tips the offender over the threshold, so it is the full audit of
  what tripped what.
- **banish** ... an IP was successfully sent below to Kur.
- **noted** ... the observe-mode twin of `found`, a match under an
  `eve_only` rule or watcher, which is recorded but never counted toward a
  real ban. See [rules](rules).
- **alert** ... the observe-mode twin of `banish`, an offender whose score
  reached the threshold under observe mode. It reads just like the banish it
  stands in for, minus the fact of the ban... nothing was sent to Kur.
- **sighting** ... the detection twin of `found`, a match under a
  detection-only rule (one carrying a `detection_var`). The rule banishes
  nobody, only counts its subject, so every match is a sighting. See
  [rules](rules).
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
| `severity` | the rule's severity (`info`/`low`/`medium`/`high`/`critical`), or the config `default_severity`... omitted when neither is set. |
| `classtype` | the rule's category, Snort/Sagan/Suricata classtype... present only when the rule sets one. |
| `references` | the rule's references (URLs, CVE ids)... an array, present only when set. |
| `attack` | the rule's MITRE ATT&CK technique ids... an array, present only when set. |
| `raw` | the line as received. |
| `parsed` | the parser's output, or the parsed JSON itself for a JSON log. |
| `found` | all the found hash keys, what the rule captured. |
| `rule` | the rule's name and def, with its tests stripped to save space. |

A **banish** event adds `.ip` and `.ban_time`, and `.recidive` is true
when it is a seventh-gate escalation to the recidive kur. A banish
triggered by a specific line crossing the threshold carries that line's
`raw`/`parsed`/`found`/`rule`; one from a pending retry or a recidive
escalation is the bare banishment. With a `geoip_db` loaded, the
banished IP's `.country` rides along too. An **alert** carries the same
`.ip`, `.ban_time`, `.score`, and envelope a banish would, being its
observe-mode stand-in. A **found** or **noted** event carries `.marks_set`
and `.unmarked` when the rule branded or lifted marks.

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

# the busiest offenders, by how often they were found
jq -r 'select(.event_type=="found") | .found.SRC // .found.HOST' /var/log/baphomet/eve.json \
    | sort | uniq -c | sort -rn | head

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
