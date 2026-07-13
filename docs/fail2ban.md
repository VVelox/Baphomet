# Coming from fail2ban

Baphomet and Ereshkigal together do fail2ban's job, split in two...
fail2ban is one daemon that reads logs, decides, and bans; here the
accuser and the punisher are separate. Baphomet reads the logs and counts
offenses, Ereshkigal rules Kur and touches the firewall. They meet at the
kur names... a `[kur.sshd]` in Baphomet's config sends its consignments to
the kur named `sshd` on the Ereshkigal side. That kur may be a real one or
a gate... a `fan_out` kur relaying each consignment to its members, which
is how a jail with several actions maps over (see below).

## The concept map

| fail2ban | here |
| --- | --- |
| jail | a kur... the counting side in Baphomet's `[kur.<name>]`, the banning side in Ereshkigal's |
| filter (`filter.d/*.conf`) | a rule (`rules/<type>/<name>.yaml`)... most shipped rules cite the fail2ban filter they were translated from |
| `failregex` | `message_regexp` (syslog/raw/http_error types) or `match` entries (http/json types) |
| `ignoreregex` | `ignore_regexp` / `ignore` |
| `<HOST>` | the `%%%%SRC%%%%` and friends tokens... or nothing at all for the http/http_error/json types, where the parser already extracted the client |
| `maxretry` | `max_retrys` |
| `findtime` | `find_time` |
| `bantime` | `ban_time`... 0 means eternal, and unset defers to the Ereshkigal side default |
| `logpath` | the watcher `log`, which may also be a array and may glob, re-expanded live |
| `backend = auto/polling` | POE::Wheel::FollowTail, always |
| `backend = systemd` / `journalmatch` | a watcher's `journal` key, matches and all... native, via journalctl |
| action (`action.d/*.conf`) | Ereshkigal's kur backends... pf, ipfw, iptables, shell, dummy |
| a jail's several actions (`banaction` + mail + report) | a fan_out gate on the Ereshkigal side... the Baphomet kur targets the gate, whose members each do their own thing, say a pf kur plus a shell kur running a reporter |
| `ignoreip` | `ignore_ips`, global or per kur |
| `fail2ban-client status/set` | `baphomet status`, `ereshkigal status/ban/unban/banned` |
| `fail2ban-client status <jail>`, currently failed | `baphomet accused`... and with the per-IP detail fail2ban never shows |
| `fail2ban-client status <jail>`, banned IP list | `baphomet consigned`, asking Ereshkigal and marking bans still pending delivery |
| `fail2ban-client banned <ip>` | `baphomet consigned --ip <ip>` |
| `fail2ban-client get <jail> banip --with-time` | `baphomet ledger`, filterable by kur, IP, and time |
| `fail2ban-regex` | `baphomet check_rules` and `baphomet test_line` |
| `recidive` jail | the `[recidive]` table, escalating across all kurs |
| `bantime.increment` | not directly... recidive escalates to a longer-held kur instead of growing a IP's own ban |
| sqlite persistence | the state tablets under `tablet_base_dir`, the ban history in the shared consignment ledger |

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

## What fail2ban still does that this does not

Honesty section, roughly in order of how much it matters...

- **Rich action context.** A fan_out gate covers the several-actions-
  per-jail shape (see the concept map), but a member kur only hears the
  IP... fail2ban interpolates the matched log lines into a action via
  `<matches>`, where here a shell member gets `%%%BAN%%%` and nothing
  else. The EVE event log ([eve.md](eve.md)) is the stream carrying the
  raw line, the rule, and the count for driving AbuseIPDB reports, a
  SIEM, or notifications with full context.
- **Keyless multiline.** Correlation needs a shared key. fail2ban's
  F-MLFID session tracking, mostly feeding its aggressive/ddos filter
  modes, has no equivalent... shipped rules port the normal modes.
- **`usedns`.** Hostname offenders (pam-generic, mysqld) are handed to
  Ereshkigal verbatim, neither resolved nor refused.
- **Per-IP escalating bans (`bantime.increment`).** A repeat offender is
  escalated by consigning it to a longer-held recidive kur, not by growing
  its own individual ban time.
- **apache-fakegooglebot.** The one filter deliberately not ported... its
  trick is a reverse DNS check (the `usedns` point above), not a regexp.

The filter library is otherwise essentially complete... every fail2ban
filter that is a regexp over a log line is ported, across the syslog, raw,
http, http_error, and multiline families, plus the JSON and Suricata
rules. See [rules-catalog.md](rules-catalog.md) for the full list.

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
backend = "shell"
# see the shell backend POD for the ban/unban command options
```

...and on the Baphomet side (`/usr/local/etc/baphomet/config.toml`)...

```toml
[kur.sshd]
max_retrys = 5
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

A filter with no shipped rule ports by hand... [rules.md](rules.md) walks
the format, `test_line` pokes single lines at a draft, and the fail2ban
test log corpus (`fail2ban/tests/files/logs/` in its source) is a fine
vein of test lines, as every shipped rule here demonstrates.
