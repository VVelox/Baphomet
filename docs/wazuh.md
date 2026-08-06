# Coming from Wazuh

Wazuh is a whole security platform... an agent on every host, a manager that
decodes and rules on their logs, an indexer that stores the alerts, and a
dashboard over the lot, with file-integrity monitoring, configuration
assessment, vulnerability detection, and active response bolted alongside.
Baphomet is not that. But cut Wazuh down to the one thing it does with a log
line... decode it, match it against rules, and raise an alert with a
severity... and that stage, Wazuh's `analysisd`, is what Baphomet's log
analysis engine is (see [log-analysis](log-analysis.md)). Run in eve mode it
reads a stream against signatures and emits alerts exactly as analysisd does.

Wazuh (the modern fork of OSSEC) differs from Sagan in one way that matters
here... it does not only alert, it also **acts**, firing an active-response
script to drop an attacker at the firewall. That is the ban. So the honest
mapping is not Baphomet alone but the pair: **Baphomet plus
[Ereshkigal](https://github.com/LilithSec/Ereshkigal) is Wazuh's log analysis
and active response**, with out the fleet, the file-integrity monitor, or the
indexer. Baphomet decodes and rules and counts; Ereshkigal is the
active-response half that touches the firewall.

## The concept map

Only Wazuh's log-analysis stage maps... the decoders, the rules, and the
alert. The rest of the platform has no counterpart here, by charter.

| Wazuh | here |
| --- | --- |
| a decoder (`decoders/*.xml`), fields pulled from a line | the parser (syslog/http/http_error/json)... fields broken out before rules |
| a rule (`rules/*.xml`) | a rule (`rules/<type>/<name>.yaml`) |
| `<decoded_as>` / `<program_name>` | the rule type and its `daemons` gate |
| `<match>` / `<regex>` / `<pcre2>` | `message_regexp` (syslog/raw/http_error) or `match` (http/json) |
| `<field name="...">` over decoded fields | the json type's `gate`/`match` over flattened dotted paths |
| the extracted `srcip` | the `%%%%SRC%%%%` token, named in `ban_var` |
| `level` (0–16) | `severity` (info/low/medium/high/critical) |
| `<group>` classification | `classtype` |
| `<mitre><id>` | `attack` |
| a rule's numeric `id` | `sid`, derived from the rule name; `gid` marks shipped vs override |
| `<if_sid>` / `<if_group>`, composite rules | marks... one rule gates on another having fired (`mark`/`marked`) |
| `<if_matched_sid>` + `<frequency>` + `<timeframe>` | per-rule `max_score` / `find_time`, under `allow_per_rule_thresholds` |
| `<same_source_ip>`, `<different_url>`, ... | a staged rule's `per` key, or a mark's `var` / `value_var` |
| a CDB `<list>` lookup | the `namtar_list` gate (boolean membership) |
| `alerts.json` | the EVE stream ([eve](eve.md)) |
| active response (`firewall-drop`) | Ereshkigal's kur backends... the ban itself |
| the agent / manager / indexer / dashboard | no counterpart... Baphomet follows log files, it is not a fleet |

## What needs no borrowing

Wazuh's log-analysis vocabulary is already spoken. Its decoders are the parser
layer; its `match`/`regex`/`pcre2` are Perl regexps; its decoded-field rules
are the json type's dotted paths; its `level`, `group`, and `mitre` metadata
carry across as `severity`, `classtype`, and `attack`; its CDB lists are the
`namtar_list` gate; its `if_matched_sid` frequency thresholds are per-rule
`max_score`/`find_time`; and its active response is Ereshkigal's half. A Wazuh
log rule ports about as mechanically as a Sagan one.

## What Wazuh does that this does not

Honesty section... the log-analysis engines are the same class, but Wazuh is a
platform and Baphomet is one program in a pair.

- **Everything that is not log analysis.** File-integrity monitoring,
  security-configuration assessment, rootcheck, vulnerability detection,
  system inventory... Wazuh's agent does all of it, and none of it is here.
  The charter is log processing plus detection; FIM, SCA, and the rest stay
  out on purpose.
- **The agent fleet.** Wazuh ships an agent to every endpoint that collects
  locally and runs the response there. Baphomet follows log files on the host
  it runs on... several Baphomet hosts can accuse to one Ereshkigal, but there
  is no agent protocol, no endpoint inventory, no central push of rules.
- **Storage, indexing, dashboards.** Wazuh keeps its alerts in an OpenSearch
  indexer under a dashboard. Baphomet streams EVE and forgets, holding only
  its counting window... the same no-data-lake as Sagan. Point EVE at your own
  indexer if you want history.
- **Hierarchical decoders.** Wazuh's parent/child decoder tree pulls fields
  from almost any format. Baphomet has fixed parser modules plus the
  `%%%%TOKEN%%%%` engine, so a novel format needs a `raw` rule or a new
  parser... a grok-like named-pattern layer is a roadmap item, not a thing
  today.
- **A composite rule graph.** Wazuh's `if_sid` / `if_matched_sid` chain rules
  into a dependency tree by id. Baphomet's marks, staged sequences, and
  weighted scoring cover much of the same ground, but there is no rule-id
  dependency language wiring one rule to another by number.

## Porting a rule

A Wazuh rule is XML in a `<group>` block, and a log rule ports by hand about as
mechanically as a [sagan](sagan.md) or [fail2ban](fail2ban.md) one. Rules keyed on
FIM, SCA, rootcheck, or a Windows/Sysmon decoder have no parser here and do not
port... the reachable slice is the syslog, web-log, and JSON rules, the same
ceiling as [sigma](sigma.md).

| Wazuh option | becomes |
| --- | --- |
| `<decoded_as>` / `<program_name>` | the rule type + `daemons` |
| `<match>` / `<regex>` / `<pcre2>` | `message_regexp` or `match` |
| the decoded `srcip` | a `%%%%SRC%%%%` token |
| `level` | `severity` |
| `<group>` | `classtype` |
| `<mitre><id>` | `attack` |
| `<if_matched_sid>` + `<frequency>` + `<timeframe>` | `max_score` / `find_time` |
| `<if_sid>` / `<if_group>` | marks (`mark` / `marked`) |
| `<list>` (CDB) | the `namtar_list` gate |
| `id`, and the `<description>` wording | `sid` is derived; `<description>` becomes `msg` |

Two things the table does not settle, the same two every port asks.

**Ban or detect.** Wazuh alerts, and separately its active response acts. To
keep just the alert... surface the signature, banish nobody... port it as a
detection rule with `detection_var: [ SRC ]`, writing `sighting`/`sighted` to
EVE. To fold Wazuh's active response in as well, name `ban_var: [ SRC ]` and
let the kur's thresholds decide, and Ereshkigal does the firewall-drop.

**Tests.** Lift sample lines from the rule's comments or your own logs into a
`tests:` block, then `baphomet test_line` pokes single lines at a draft and
`baphomet check_rules` runs the embedded tests, refusing to load a rule that
fails its own... the same guard `baphomet start` uses.

See [rules](rules.md) to write one, [log-analysis](log-analysis.md) for the engine
in full, and [rules-catalog](rules-catalog.md) for what already ships.
