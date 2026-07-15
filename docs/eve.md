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

One JSON object per line. Two kinds, in `.event_type`...

- **found** ... a rule matched a line. Written on every match, whether or
  not it tips the offender over the threshold, so it is the full audit of
  what tripped what.
- **banish** ... an IP was successfully sent below to Kur.

Every record carries these fields...

| field | what |
| --- | --- |
| `eve_type` | `baphomet`, always... marks the producer for downstream tooling. |
| `event_type` | `found` or `banish`. |
| `timestamp` | ISO 8601 with zone. |
| `hostname` | the system hostname. |
| `kur` | the kur. |
| `path` | the source... the log file, or `journal:<matches>` for a journal watcher. |
| `count` | how many times the offender has been seen... its live counter after this hit. |
| `raw` | the line as received. |
| `parsed` | the parser's output, or the parsed JSON itself for a JSON log. |
| `found` | all the found hash keys, what the rule captured. |
| `rule` | the rule's name and def, with its tests stripped to save space. |

A **banish** event adds `.ip` and `.ban_time`, and `.recidive` is true
when it is a seventh-gate escalation to the recidive kur. A banish
triggered by a specific line crossing the threshold carries that line's
`raw`/`parsed`/`found`/`rule`; one from a pending retry or a recidive
escalation is the bare banishment. With a `geoip_db` loaded, the
banished IP's `.country` rides along too. A **found** event carries
`.marks_set` and `.unmarked` when the rule branded or lifted marks.

## Reading it

```shell
# every banishment, as ip and kur
jq -r 'select(.event_type=="banish") | "\(.kur) \(.ip)"' /var/log/baphomet/eve.json

# the busiest offenders, by how often they were found
jq -r 'select(.event_type=="found") | .found.SRC // .found.HOST' /var/log/baphomet/eve.json \
    | sort | uniq -c | sort -rn | head

# what a given IP did, in full
jq 'select(.found.SRC=="1.2.3.4" or .ip=="1.2.3.4")' /var/log/baphomet/eve.json
```

## Notes

- `found` fires on every match, not every line read, so the volume tracks
  how much abuse is landing, not how chatty the logs are... still, a site
  under heavy attack writes a lot, so mind the disk.
- The file is reopened per event, so a logrotate that moves it aside is
  picked up on the next write with no signal needed.
- It is telemetry, never load bearing... a write failure is logged and
  shrugged off, it never keeps an IP from being banished.
