# Coming from Sagan

Run in eve mode, Baphomet is similar to Sagan.
[Sagan](https://github.com/quadrantsec/sagan)... the same real-time engine
that parses a stream, matches each line against signatures, correlates, and
emits a eve alert (see [log-analysis](log-analysis.md)). Neither
keeps the events; both stream and forget, feeding their alerts onward.

## The concept map

| Sagan                                  | here                                                                                                                               |
|----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| a rule's `count` / `seconds`           | per-rule `max_score` / `find_time` / `ban_time`, under `allow_per_rule_thresholds`                                                 |
| `xbits` / `flexbits` (set/isset/unset) | marks... `mark`/`unmark`/`marked`/`not_marked`/`mark_only`, read by `baphomet marked`                                              |
| `country_code` (is/isnot)              | the `country` gate, resolved via `IP::Geolocation::MMDB` and a `geoip_db`                                                          |
| `blacklist`                            | the `namtar_list` gate, the inverse of `ignore_ips`                                                                                |
| `alert_time`                           | the `active_time` gate, named `{days, hours}` windows                                                                              |
| `content` / `pcre` match chains        | Perl regexps in `message_regexp` (syslog/raw/http_error) or `match` (http/json)                                                    |
| `json_content`                         | the json rule type's dotted paths (`attr.remote`, `request.client_ip`)                                                             |
| `program` / `facility` / `level` gates | `daemons` and the parser's own gates                                                                                               |
| `msg`                                  | the rule's `msg`... the `[TAG] description` convention                                                                             |
| `classtype`                            | the rule's `classtype`, the same category strings                                                                                  |
| a rule that alerts without banning     | a detection-only rule, a `detection_var` in place of `ban_var`... counts any subject, writes `sighting`/`sighted`, banishes nobody |
| rule actions                           | Ereshkigal's domain... Baphomet accuses and does not act                                                                           |

## Porting a rule

A Sagan rule can in generally be ported.

The options translate like so:

| Sagan option                                                                  | becomes                                                                                             |
|-------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `program: sshd`                                                               | `daemons: [ sshd ]`                                                                                 |
| `content:"..."`, `pcre:"/.../"`                                               | `message_regexp` entries (Perl regexps)                                                             |
| the tracked source (`parse_src_ip`, `by_src`)                                 | a `%%%%SRC%%%%` token in the regexp                                                                 |
| `msg:"..."`                                                                   | `msg`                                                                                               |
| `classtype:`                                                                  | `classtype`                                                                                         |
| `reference: url,...`                                                          | `references`                                                                                        |
| `threshold:` / `after: count N, seconds M`                                    | `max_score` / `find_time`                                                                           |
| `xbits` / `flexbits` (set/isset)                                              | `mark` / `marked` (see [rules](rules.md))                                                           |
| the bit's `track` (`ip_src`/`by_src`, `by_username`, `ip_username`/`ip_both`) | the mark's keying... var-less for the offender IP, `var` for one capture, `vars` for a compound key |
| a `\|`-joined isset (`isset, a\|b`)                                           | a `marked` entry with `names`                                                                       |
| a `&`-joined set (`set, a&b`)                                                 | two entries under `mark`                                                                            |
| `country_code:`                                                               | the `country` gate                                                                                  |
| `blacklist:`                                                                  | the `namtar_list` gate                                                                              |
| `alert_time:`                                                                 | the `active_time` gate                                                                              |
| `sid`, `rev`, `metadata`                                                      | dropped                                                                                             |

**Keep the bit names.** The shipped rules brand Sagan's standard vocabulary name for
name... `brute_force`, `recon`, `exploit_attempt`, `honeypot`, at the corpus's own
TTLs... so port a rule's xbits without renaming them and it interlocks with the shipped
setters and the `-condemned`/`-escalation` readers instead of a private namespace. See the
standard brands in [rules](rules.md).

**Ban or detect.** A Sagan rule alerts, it does not firewall. To keep that...
surface the signature without banning... port it as a detection rule with
`detection_var: [ SRC ]`, so it writes `sighting`/`sighted` to [EVE](eve.md)
and touches
no firewall. To turn the signature into a ban instead, name `ban_var: [ SRC ]`
and let the kur's thresholds decide. This is the one real choice the port asks
of you. See [rules](rules.md) for more info.

**Tests.** Lift sample lines from the rule's comments or your own logs into a
`tests:` block, then `baphomet test_line` pokes single lines at a draft and
`baphomet check_rules` runs the embedded tests, refusing to load a rule that
fails its own... the same guard `baphomet start` uses.

See [rules](rules.md) to write one, and [rules-catalog](rules-catalog.md) for what
already ships.
