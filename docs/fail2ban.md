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
| the fail2ban SNMP extend for LibreNMS | `baphomet lnms-f2b-extend`, emitting the same jail-tally JSON so a Baphomet host drops into the LibreNMS fail2ban application with no fail2ban present |
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
- **Gates fail2ban never had.** Per-rule thresholds, cross-rule marks, and
  country / blocklist / time-of-day gates, folded in from Sagan whose rule
  language reaches past a regexp per jail... see [sagan](sagan).

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
- **Cross-line backreferences.** fail2ban's buffer-join rematching
  (maxlines with SKIPLINES between arbitrary failregex fragments) has no
  general equivalent. Its two real uses are covered by sharper tools...
  F-MLFID session tracking by envelope-keyed correlation
  (`key: [ syslog.host, syslog.daemon, syslog.pid ]`, see [rules](rules)),
  and physically multi-line records by a watcher's `join` table (see
  [configuration](configuration)). The sshd ddos/extra/aggressive modes
  that ride F-MLFID ship as the opt-in `syslog/sshd-ddos`,
  `syslog/sshd-extra`, and `syslog/sshd-aggressive` rules.
- **`usedns` differs on purpose.** Hostname offenders (pam-generic,
  mysqld) are covered by `usedns` = `no` / `resolve_seen` / `resolve_ban`
  behind an `enable_dns` consent (see [configuration](configuration)),
  but fail2ban's `raw` mode does not exist... Ereshkigal takes addresses,
  not names... and the default is `no`, so a hostname banishes nothing
  until an operator opts into resolution knowingly.
- **Per-IP escalating bans (`bantime.increment`).** A repeat offender is
  escalated by banishing it to a longer-held recidive kur, not by growing
  its own individual ban time.

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

## Porting a filter

A filter with no shipped rule ports by hand, and the translation is mostly
mechanical...

1. **Find the filter and its log samples.** fail2ban ships them in
   `config/filter.d/<name>.conf`, a `[Definition]` of `failregex`,
   `ignoreregex`, and sometimes a `prefregex` common prefix. Its test lines
   live in `fail2ban/tests/files/logs/<name>` in the source... a ready vein of
   positive cases, and the successful-login lines make the best negatives.
2. **Pick the rule type by the log's shape**, not the daemon. A `daemon[pid]:`
   syslog line is a `syslog` rule; a free-form app log with its own timestamp
   is `raw`; an access log is `http`; an apache/nginx error log is
   `http_error`; JSON is `json`. See [rules](rules).
3. **Translate the regexps.** Each `failregex` line becomes a `message_regexp`
   entry, each `ignoreregex` an `ignore_regexp`. Drop fail2ban's tags for
   Baphomet's address tokens... `<HOST>` (host or address) becomes
   `%%%%HOST%%%%`, `<ADDR>` (address only) `%%%%ADDR%%%%`, and name the one you
   count on in `ban_var`, usually captured as `%%%%SRC%%%%`. Spell out
   `%(...)s` includes, drop `<F-...>` capture markers for plain named groups,
   and anchor with `^`... a syslog rule matches the message after the
   `daemon[pid]:`, so a `prefregex` folds into the `daemons` gate and the
   anchor rather than the regexp.
4. **Add the metadata and tests.** Give it a `msg`, `severity`, and
   `classtype`, then paste the corpus lines under `tests: positive:` with the
   `SRC` each should capture, and the must-not-match lines under `negative:`.
   The `fail2ban-regex` session becomes part of the rule file.
5. **Verify.** `baphomet test_line` pokes a single line at a draft with its
   tests skipped, and `baphomet check_rules` runs the embedded tests, refusing
   to load a rule that fails its own... the same guard `baphomet start` uses.

What does not port one-to-one: `journalmatch` is a watcher's `journal` key,
not a rule key; `datepattern` is the parser's job, chosen by the rule type;
and fail2ban's `maxlines` buffer splits into two sharper tools... keyed
correlation, envelope keys included, for lines sharing a session or id, and
a watcher's `join` for records that are physically one event (see
[rules](rules) and [configuration](configuration)). The
[rules-catalog](rules-catalog) lists what already ships, and the handful
deliberately not ported and why.
