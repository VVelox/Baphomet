# Coming from Wazuh

## The concept map

Only Wazuh's log-analysis stage maps... the decoders, the rules, and the
alert. The rest of the platform has no counterpart.

| Wazuh                                                   | here                                                                           |
|---------------------------------------------------------|--------------------------------------------------------------------------------|
| a decoder (`decoders/*.xml`), fields pulled from a line | the parser (syslog/http/http_error/json)... fields broken out before rules     |
| a rule (`rules/*.xml`)                                  | a rule (`rules/<type>/<name>.yaml`)                                            |
| `<decoded_as>` / `<program_name>`                       | the rule type and its `daemons` gate                                           |
| `<match>` / `<regex>` / `<pcre2>`                       | `message_regexp` (syslog/raw/http_error) or `match` (http/json)                |
| `<field name="...">` over decoded fields                | the json type's `gate`/`match` over flattened dotted paths                     |
| the extracted `srcip`                                   | the `%%%%SRC%%%%` token, named in `ban_var`                                    |
| `level` (0–16)                                          | `severity` (info/low/medium/high/critical)                                     |
| `<group>` classification                                | `classtype`                                                                    |
| `<mitre><id>`                                           | `attack`                                                                       |
| a rule's numeric `id`                                   | `sid`, derived from the rule name; `gid` marks shipped vs override             |
| `<if_sid>` / `<if_group>`, composite rules              | marks... one rule gates on another having fired (`mark`/`marked`)              |
| `<if_matched_sid>` + `<frequency>` + `<timeframe>`      | per-rule `max_score` / `find_time`, under `allow_per_rule_thresholds`          |
| `<same_source_ip>`, `<different_url>`, ...              | a staged rule's `per`, a mark's `var` / `value_var`, or `distinct`             |
| a CDB `<list>` lookup                                   | the `namtar_list` gate (boolean membership)                                    |
| `alerts.json`                                           | the EVE stream ([eve](eve.md))                                                 |
| active response (`firewall-drop`)                       | Ereshkigal's kur backends... the ban itself                                    |
| the agent / manager / indexer / dashboard               | none... no agent, indexer, or dashboard; Baphomet follows logs and the journal |

The one fleet-shaped piece is the redis [tablet](tablets.md) backend, which
shares marks across hosts as a sync bus.

## What needs no borrowing

Wazuh's log-analysis vocabulary is already spoken. Its decoders are the parser
layer; its `match`/`regex`/`pcre2` are Perl regexps; its decoded-field rules
are the json type's dotted paths; its `level`, `group`, and `mitre` metadata
carry across as `severity`, `classtype`, and `attack`; its CDB lists are the
`namtar_list` gate; its `if_matched_sid` frequency thresholds are per-rule
`max_score`/`find_time`; and its active response is Ereshkigal's half. A Wazuh
log rule ports about as mechanically as a Sagan one.

## What Wazuh does that this does not

The log-analysis engines are the same class, but Wazuh is a platform and
Baphomet is one program in a pair.

- **Hierarchical decoders.** Wazuh's parent/child decoder tree pulls fields
  from almost any format. Baphomet has fixed parser modules plus the
  `%%%%TOKEN%%%%` engine, with [mungers](rules.md#enriching-a-match-mungers)
  borrowing Log::Munger's decoders to read a line into fields. A format none
  of those know needs a `raw` rule or a new parser... a grok-like
  named-pattern layer is a roadmap item, not a thing today.
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

| Wazuh option                                       | becomes                                         |
|----------------------------------------------------|-------------------------------------------------|
| `<decoded_as>` / `<program_name>`                  | the rule type + `daemons`                       |
| `<match>` / `<regex>` / `<pcre2>`                  | `message_regexp` or `match`                     |
| the decoded `srcip`                                | a `%%%%SRC%%%%` token                           |
| `level`                                            | `severity`                                      |
| `<group>`                                          | `classtype`                                     |
| `<mitre><id>`                                      | `attack`                                        |
| `<if_matched_sid>` + `<frequency>` + `<timeframe>` | `max_score` / `find_time`                       |
| `<if_sid>` / `<if_group>`                          | marks (`mark` / `marked`)                       |
| `<list>` (CDB)                                     | the `namtar_list` gate                          |
| `id`, and the `<description>` wording              | `sid` is derived; `<description>` becomes `msg` |

Two things the table does not settle, the same two every port asks.

**Ban or detect.** Keep just the alert with a `detection_var: [ SRC ]` gate, or
fold in Wazuh's active response with `ban_var: [ SRC ]` and let Ereshkigal do
the firewall-drop... see [the two verdicts](log-analysis.md#the-two-verdicts).

**Tests.** Lift sample lines into a `tests:` block and run them with
`baphomet check_rules`... see [tests](rules.md#tests).

See [rules](rules.md) to write one, [log-analysis](log-analysis.md) for the engine
in full, and [rules-catalog](rules-catalog.md) for what already ships.
