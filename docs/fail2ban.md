# Coming from fail2ban

Baphomet and Ereshkigal together do fail2ban's job, split in two...
fail2ban is one daemon that reads logs, decides, and bans; here the
accuser and the punisher are separate. Baphomet reads the logs and counts
offenses, Ereshkigal rules Kur and touches the firewall. They meet at the
kur names... a `[kur.sshd]` in Baphomet's config sends its banishments to
the kur named `sshd` on the Ereshkigal side. That kur may be a real one or
a gate... a `fan_out` kur relaying each banishment to its members, which
is how a jail with several actions maps over (see below).

## The concept map

| fail2ban | here |
| --- | --- |
| jail | a kur... the counting side in Baphomet's `[kur.<name>]`, the banning side in Ereshkigal's |
| filter (`filter.d/*.conf`) | a rule (`rules/<type>/<name>.yaml`)... most shipped rules cite the fail2ban filter they were translated from |
| `failregex` | `message_regexp` (syslog/raw/http_error types) or `match` entries (http/json types) |
| `ignoreregex` | `ignore_regexp` / `ignore` |
| `<HOST>` | the `%%%%SRC%%%%` and friends tokens... or nothing at all for the http/http_error/json types, where the parser already extracted the client |
| `maxretry` | `max_score` |
| `findtime` | `find_time` |
| `bantime` | `ban_time`... 0 means eternal, and unset defers to the Ereshkigal side default |
| `logpath` | the watcher `log`, which may also be a array and may glob, re-expanded live |
| `backend = auto/polling` | POE::Wheel::FollowTail, always |
| `backend = systemd` / `journalmatch` | a watcher's `journal` key, matches and all... native, via journalctl |
| action (`action.d/*.conf`) | Ereshkigal's kur backends... some thirty underworlds, from pf, ipfw, iptables, and nftables through network gear and cloud edges to abuseipdb, shell, and dummy... see its kurs docs |
| a jail's several actions (`banaction` + mail + report) | a fan_out gate on the Ereshkigal side... the Baphomet kur targets the gate, whose members each do their own thing, say a pf kur plus an abuseipdb kur reporting upstream |
| `ignoreip` | `ignore_ips`, global or per kur |
| `fail2ban-client status/set` | `baphomet status`, `ereshkigal status/ban/unban/banned` |
| `fail2ban-client status <jail>`, currently failed | `baphomet accused`... and with the per-IP detail fail2ban never shows |
| `fail2ban-client status <jail>`, banned IP list | `baphomet banished`, asking Ereshkigal and marking bans still pending delivery |
| `fail2ban-client banned <ip>` | `baphomet banished --ip <ip>` |
| `fail2ban-client get <jail> banip --with-time` | `baphomet ledger`, filterable by kur, IP, and time |
| `fail2ban-regex` | `baphomet check_rules` and `baphomet test_line` |
| `recidive` jail | the `[recidive]` table, escalating across all kurs |
| `bantime.increment` | not directly... recidive escalates to a longer-held kur instead of growing a IP's own ban |
| sqlite persistence | the state tablets under `tablet_base_dir`, the ban history in the shared banishment ledger |

## What is better over here

- **Rules carry their own tests.** Every rule embeds positive and negative
  log lines, ran at every load... a broken rule refuses to load at
  `baphomet start` instead of silently matching nothing. fail2ban-regex
  sessions become part of the rule file itself.
- **A parser layer with a daemon gate.** Lines are parsed once (syslog,
  access log, error log, JSON) and rules match structured fields, with
  cheap gates (daemon, status, level, arbitrary JSON fields) running
  before any expensive regexp. fail2ban's prefregex machinery is the
  rough equivalent, spelled per filter.
- **First class JSON.** mongod structured logs, Caddy, Suricata eve.json,
  and anything else NDJSON-shaped get real field addressing
  (`attr.remote`, `request.client_ip`) rather than regexps over JSON
  text. fail2ban has no equivalent.
- **Live globs.** `log = "/jails/*/var/log/auth.log"` picks up a jail
  created while running with in ten seconds.
- **Correlation without the buffer.** Offense-and-address-on-different-
  lines cases (mongodb pre-4.4, sendmail's No such user) correlate by
  key with TTLs, instead of fail2ban's maxlines buffer rematching.
- **The split itself.** The thing reading hostile input holds no firewall
  privileges, and several Baphomet hosts can accuse to one Ereshkigal.

## Beyond fail2ban, adapted from Sagan

fail2ban counts a regexp per jail and bans. Sagan's rule language reaches
further, and the gates it has that fail2ban lacks were read end to end and
folded in... they run in the galla between a rule matching and the offense
being counted, so rules stay pure matchers. None of these has a fail2ban
equivalent.

- **Per-rule thresholds (Sagan's own count/seconds).** A rule may carry its
  own `max_score` / `find_time` / `ban_time`, so one noisy signature can
  demand more hits, or fewer, than its neighbours in the same kur. fail2ban's
  thresholds are per-jail only, one number for every failregex at once.
  Inert unless the config opts in with `allow_per_rule_thresholds`.
- **Marks... cross-rule state (Sagan xbits/flexbits).** A galla-wide store of
  expiring named marks, keyed by the offender IP or by any capture or field
  (`var`), optionally harvesting and gating on a value (`value_var`,
  `value_is`/`value_not`). Rule keys `mark`/`unmark`/`marked`/`not_marked`/
  `mark_only` let one rule brand a line and a later rule fire only on the
  branded. This is how distributed brute force is caught... `syslog/sshd-mark-users`
  brands each account with the source that hit it, `syslog/sshd-spray` fires
  when a second source hits the same account. `baphomet marked` reads the
  store. fail2ban has no shared state between filters.
- **A country gate (Sagan country_code).** A rule key
  `country: {is|isnot: [...], vars?: [...]}` counts a match only when the
  offender (or a harvested var) geolocates inside, or outside, a named set of
  country codes. Lists come from the config `country_codes` and a
  `%%%country_codes{name}%%%` token; resolution is via the optional
  `IP::Geolocation::MMDB` and a `geoip_db`. Fails closed on a unlocatable IP.
- **A blocklist gate (Sagan blacklist), the namtar_list.** The inverse of
  `ignore_ips`... a rule key `namtar_list: [{list|lists, var?}, ...]` counts
  an offense only when a value is already on a named list, drawn from the
  config `namtar_lists` and reloaded on file mtime. A list is a CIDR list
  matched by address, or a string list matched by exact (optionally
  case-folded) name, so the gate reaches beyond the offender IP to any
  captured field via `var`... a honeypot username, a known-bad URI or
  user-agent. For acting only on the already-known-bad.
- **A time-of-day gate (Sagan alert_time), active_time.** A rule key
  `active_time: {is|isnot: [window names], vars?: [...]}` counts a match only
  inside, or outside, named `{days, hours}` windows (hours may wrap midnight),
  so the same log line can be ignored at midday and banished at 03:00.

Sagan's remaining vocabulary needs no borrowing... its content/pcre match
chains are subsumed by Perl regexps, its json_content by the json rule type's
dotted paths, its program/facility/level gates by `daemons`, and its
actions are Ereshkigal's domain, since Baphomet accuses and does not act.

## Beyond fail2ban, from sshguard and CrowdSec

Two more turns fail2ban has no equivalent for, from the wider field...

- **Weighted scoring (sshguard, CrowdSec).** fail2ban counts every match as
  one and bans at `maxretry`. Here a rule carries a `weight`, and `max_score`
  is a score to reach, not a retry count... so a dangerous signature can weigh
  10 and banish on one hit, and several different rules against one IP accrue
  together toward the one judgment instead of racing separate counters.
  sshguard scores attacks by dangerousness; this is that, per rule. Honored
  under the same `allow_per_rule_thresholds` consent, and with every weight 1
  it is exactly the old count. See [rules](rules).
- **Observe mode (CrowdSec simulation).** A rule, watcher, kur, or the whole
  deployment can be set `eve_only`... it matches and writes to EVE but never
  banishes, a would-be ban surfacing as an `alert` and each match as `noted`.
  Stand a new rule up, watch what it would have done, then trust it to act by
  setting `eve_only: false`. `observe_ignored` widens it to also score what
  `ignore_ips` would drop. fail2ban has no dry run. See [rules](rules) and
  [eve](eve).

## What fail2ban still does that this does not

Honesty section, roughly in order of how much it matters...

- **Rich action context.** A fan_out gate covers the several-actions-
  per-jail shape (see the concept map), but a member kur only hears the
  IP... fail2ban interpolates the matched log lines into a action via
  `<matches>`, where here a shell member gets `%%%BAN%%%` and nothing
  else, and Ereshkigal's abuseipdb kur reports with a fixed comment.
  The EVE event log ([eve](eve)) is the stream carrying the raw line,
  the rule, and the count for driving a SIEM or notifications with
  full context.
- **Keyless multiline.** Correlation needs a shared key. fail2ban's
  F-MLFID session tracking, mostly feeding its aggressive/ddos filter
  modes, has no equivalent... shipped rules port the normal modes.
- **`usedns`.** Hostname offenders (pam-generic, mysqld) are handed to
  Ereshkigal verbatim, neither resolved nor refused.
- **Per-IP escalating bans (`bantime.increment`).** A repeat offender is
  escalated by banishing it to a longer-held recidive kur, not by growing
  its own individual ban time.
- **apache-fakegooglebot.** The one filter deliberately not ported... its
  trick is a reverse DNS check (the `usedns` point above), not a regexp.

The filter library is otherwise essentially complete... every fail2ban
filter that is a regexp over a log line is ported, across the syslog, raw,
http, http_error, and multiline families, plus the JSON and Suricata
rules. See [rules-catalog](rules-catalog) for the full list.

## Migrating a jail

A fail2ban jail.local like...

```ini
[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/auth.log
maxretry = 5
findtime = 10m
bantime  = 1h
```

...becomes, on the Ereshkigal side (`/usr/local/etc/ereshkigal.toml`)...

```toml
[kur.sshd]
backend   = "pf"
ports     = [ "22" ]
protocols = [ "tcp" ]
```

A jail carrying several actions, `action = %(action_mwl)s` style, the
ban plus a mailer or a AbuseIPDB reporter, becomes a gate instead... keep
the name the Baphomet side targets on the gate, and give each action its
own member kur...

```toml
[kur.sshd]
fan_out = [ "sshd-pf", "reporter" ]

[kur.sshd-pf]
backend   = "pf"
ports     = [ "22" ]
protocols = [ "tcp" ]

[kur.reporter]
backend = "abuseipdb"

[kur.reporter.options]
key        = "your-abuseipdb-api-key"
categories = [ "18", "22" ]
comment    = "ssh brute force"
```

...and on the Baphomet side (`/usr/local/etc/baphomet/config.toml`)...

```toml
[kur.sshd]
max_score = 5
find_time  = 600
ban_time   = 3600

[kur.sshd.authlog]
log  = "/var/log/auth.log"
rule = "syslog/sshd"
```

Then...

```shell
baphomet check_rules
ereshkigal start
baphomet start
baphomet status --all
ereshkigal banned
```

A filter with no shipped rule ports by hand... [rules](rules) walks
the format, `test_line` pokes single lines at a draft, and the fail2ban
test log corpus (`fail2ban/tests/files/logs/` in its source) is a fine
vein of test lines, as every shipped rule here demonstrates.
