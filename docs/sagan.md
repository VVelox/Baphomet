# Coming from Sagan

Baphomet is not Sagan... Sagan is a full log-analysis engine, a Snort for
text logs that matches, correlates, and alerts across dozens of products.
Baphomet is narrower by design, an accuser that counts an IP's offenses and
banishes the repeat ones to Kur, leaving the firewalling to
[Ereshkigal](https://github.com/LilithSec/Ereshkigal). But fail2ban, the
tool Baphomet most resembles ([fail2ban](fail2ban)), counts one regexp per
jail and stops there, and Sagan's rule language reaches much further. The
gates Sagan has that fail2ban lacks were read end to end and folded into
the galla... they run between a rule matching and the offense being
counted, so rules stay pure matchers.

## The concept map

| Sagan | here |
| --- | --- |
| a rule's `count` / `seconds` | per-rule `max_score` / `find_time` / `ban_time`, under `allow_per_rule_thresholds` |
| `xbits` / `flexbits` (set/isset/unset) | marks... `mark`/`unmark`/`marked`/`not_marked`/`mark_only`, read by `baphomet marked` |
| `country_code` (is/isnot) | the `country` gate, resolved via `IP::Geolocation::MMDB` and a `geoip_db` |
| `blacklist` | the `namtar_list` gate, the inverse of `ignore_ips` |
| `alert_time` | the `active_time` gate, named `{days, hours}` windows |
| `content` / `pcre` match chains | Perl regexps in `message_regexp` (syslog/raw/http_error) or `match` (http/json) |
| `json_content` | the json rule type's dotted paths (`attr.remote`, `request.client_ip`) |
| `program` / `facility` / `level` gates | `daemons` and the parser's own gates |
| `msg` | the rule's `msg`... the `[TAG] description` convention |
| `classtype` | the rule's `classtype`, the same category strings |
| a rule that alerts without banning | a detection-only rule, a `detection_var` in place of `ban_var`... counts any subject, writes `sighting`/`sighted`, banishes nobody |
| rule actions | Ereshkigal's domain... Baphomet accuses and does not act |

## The gates folded in

Sagan's gates, the tests it runs around a signature match, were rebuilt in
the galla. None of these has a fail2ban equivalent.

- **Per-rule thresholds (`count` / `seconds`).** A rule may carry its own
  `max_score` / `find_time` / `ban_time`, so one noisy signature can demand
  more hits, or fewer, than its neighbours in the same kur... where fail2ban
  could only threshold a whole jail at once. Inert unless the config opts in
  with `allow_per_rule_thresholds`.
- **Marks, cross-rule state (`xbits` / `flexbits`).** A galla-wide store of
  expiring named marks, keyed by the offender IP or by any capture or field
  (`var`), optionally harvesting and gating on a value (`value_var`,
  `value_is`/`value_not`). Rule keys `mark`/`unmark`/`marked`/`not_marked`/
  `mark_only` let one rule brand a line and a later rule fire only on the
  branded. This is how distributed brute force is caught...
  `syslog/sshd-mark-users` brands each account with the source that hit it,
  `syslog/sshd-spray` fires when a second source hits the same account.
  `baphomet marked` reads the store.
- **A country gate (`country_code`).** A rule key
  `country: {is|isnot: [...], vars?: [...]}` counts a match only when the
  offender (or a harvested var) geolocates inside, or outside, a named set of
  country codes. Lists come from the config `country_codes` and a
  `%%%country_codes{name}%%%` token; resolution is via the optional
  `IP::Geolocation::MMDB` and a `geoip_db`. Fails closed on a unlocatable IP.
- **A blocklist gate (`blacklist`), the namtar_list.** The inverse of
  `ignore_ips`... a rule key `namtar_list: [{list|lists, var?}, ...]` counts
  an offense only when a value is already on a named list, drawn from the
  config `namtar_lists` and reloaded on file mtime. A list is a CIDR list
  matched by address, or a string list matched by exact (optionally
  case-folded) name, so the gate reaches beyond the offender IP to any
  captured field via `var`... a honeypot username, a known-bad URI or
  user-agent. For acting only on the already-known-bad.
- **A time-of-day gate (`alert_time`), active_time.** A rule key
  `active_time: {is|isnot: [window names], vars?: [...]}` counts a match only
  inside, or outside, named `{days, hours}` windows (hours may wrap midnight),
  so the same log line can be ignored at midday and banished at 03:00.

## What needs no borrowing

Sagan's remaining vocabulary maps onto machinery already here... its
content/pcre match chains are subsumed by Perl regexps, its json_content by
the json rule type's dotted paths, its program/facility/level gates by
`daemons`, and its `msg` and `classtype` metadata carry across under the same
names. Its actions are Ereshkigal's domain, since Baphomet accuses and does
not act.

## What Sagan does that this does not

Honesty section... Sagan is a full log-analysis engine and Baphomet is not.

- **A correlation language.** Sagan's xbits and flexbits compose into
  multi-stage, cross-signature state machines. Marks cover the offender- and
  capture-keyed cases (the spray example above), but they brand and gate...
  there is no rule graph, no `after`, no threshold-across-signatures engine.
- **The full signature library.** Sagan ships thousands of rules across dozens
  of products and protocols. Baphomet ports the shapes that end in a ban, an
  offender IP counted toward a judgment, not the broader alerting corpus.
- **Output beyond EVE.** Sagan feeds unified2, syslog, and assorted output
  plugins onward. Here there is one stream, the Suricata-shaped EVE log
  ([eve](eve)), and acting on the alert is Ereshkigal's half.

Detection with no offender, once the sharpest gap, is closed... a
detection-only rule (a `detection_var` in place of `ban_var`) alerts on a
thing with no address to banish, a config change or a service crash, counting
by any subject and writing `sighting`/`sighted` to EVE. It does not act, since
acting is Ereshkigal's half, but it detects. See [rules](rules) and
[eve](eve).

## Porting a rule

A Sagan rule ports to a Baphomet rule about as mechanically as a fail2ban
filter does ([fail2ban](fail2ban)). A Sagan `.rules` line is one
`alert ... ( ... )` with semicolon-separated options, and the ones that matter
map straight across. They live at
[github.com/quadrantsec/sagan-rules](https://github.com/quadrantsec/sagan-rules),
grouped by product... most are syslog-shaped and become `syslog` rules, while a
rule leaning on `json_content` becomes a `json` rule.

The options translate like so:

| Sagan option | becomes |
| --- | --- |
| `program: sshd` | `daemons: [ sshd ]` |
| `content:"..."`, `pcre:"/.../"` | `message_regexp` entries (Perl regexps) |
| the tracked source (`parse_src_ip`, `by_src`) | a `%%%%SRC%%%%` token in the regexp |
| `msg:"..."` | `msg` |
| `classtype:` | `classtype` |
| `reference: url,...` | `references` |
| `threshold:` / `after: count N, seconds M` | `max_score` / `find_time` |
| `xbits` / `flexbits` (set/isset) | `mark` / `marked` (see [rules](rules)) |
| `country_code:` | the `country` gate |
| `blacklist:` | the `namtar_list` gate |
| `alert_time:` | the `active_time` gate |
| `sid`, `rev`, `metadata` | dropped |

Two things the table does not settle.

**Ban or detect.** A Sagan rule alerts, it does not firewall. To keep that...
surface the signature without banning... port it as a detection rule with
`detection_var: [ SRC ]`, so it writes `sighting`/`sighted` to EVE and touches
no firewall. To turn the signature into a ban instead, name `ban_var: [ SRC ]`
and let the kur's thresholds decide. This is the one real choice the port asks
of you, since Baphomet acts where Sagan only alerts.

**Tests.** Lift sample lines from the rule's comments or your own logs into a
`tests:` block, then `baphomet test_line` pokes single lines at a draft and
`baphomet check_rules` runs the embedded tests, refusing to load a rule that
fails its own... the same guard `baphomet start` uses.

See [rules](rules) to write one, and [rules-catalog](rules-catalog) for what
already ships.
