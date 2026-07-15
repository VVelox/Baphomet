# Configuration

The config file is TOML, by default
`/usr/local/etc/baphomet/config.toml`, overridable via `--config` on
`baphomet start`. Both the manager and the gallas read the same file.

## Top level settings

| setting | default | what |
| --- | --- | --- |
| `run_base_dir` | `/var/run/baphomet` | Base dir for the sockets and PID files. |
| `tablet_base_dir` | `/var/db/baphomet` | Base dir for the state tablets, the CSVs and JSONL a galla writes so its counters, pending bans, correlation context, and log positions survive a restart. |
| `checkpoint` | `60` | Seconds between periodic rewrites of the tablets (rounded up to the ten second sweeper cadence). 0 disables the periodic rewrite; a checkpoint on stop still happens. |
| `ledger_keep` | `2592000` | How long rows are kept in the shared banishment ledger, 30 days by default. 0 means forever. Rows still inside the recidive `find_time` are always kept. |
| `rules_dir` | `/usr/local/etc/baphomet/rules` | The dir holding the rules. |
| `ereshkigal_socket` | `/var/run/ereshkigal/socket` | The Ereshkigal manager socket bans are sent to. |
| `galla_bin` | `galla` | The galla bin to spawn workers with. |
| `timeout` | `30` | Timeout in seconds for socket calls, both to gallas and to Ereshkigal. |
| `max_score` | `5` | The accumulated score with in `find_time` at which a IP is banned. Each match adds its rule's `weight` (default 1), so with unweighted rules this is just an offense count. |
| `find_time` | `600` | The window in seconds offenses are counted across. |
| `ban_time` | unset | Ban time in seconds forwarded with ban requests, 0 meaning eternal. Unset means it is left out and the Ereshkigal side default applies. |
| `allow_per_rule_thresholds` | `false` | Whether rules carrying their own `max_score`/`find_time`/`ban_time`/`weight` are honored. Off, a rule's numbers are inert and the watcher's apply. Global, per kur, and per watcher. See [rules](rules). |
| `eve_only` | `false` | Observe mode... the rules under this scope match and write to EVE but never banish, a would-be ban surfacing as an `alert` and each match as `noted`. A rule's own `eve_only` layers over this. Global, per kur, and per watcher. See [rules](rules) and [eve](eve). |
| `observe_ignored` | `false` | When observing, also process IPs `ignore_ips` would otherwise drop, so they too are scored and can `alert`. Only meaningful with `eve_only`. Global, per kur, and per watcher. |
| `ignore_ips` | `[]` | IPv4/IPv6 addresses and CIDRs never banished, no matter what the rules say. A kur's own `ignore_ips` extends this list for that kur. Hostnames are not accepted. |
| `socket_group` | root's default group | Group ownership of the manager socket. |
| `socket_mode` | `"0660"` | Perms for the manager socket, an octal string, processed via oct. Galla sockets are always 0600. |
| `enable_auth` | `false` | Opens the Neti gate... the unix ownership auth challenge on the manager socket. See below. |
| `authed_users` | `[]` | Users allowed past the Neti gate. |
| `authed_groups` | `[]` | Groups whose members are allowed past the Neti gate. |
| `auth_temp_dir` | unset | Dir for the auth challenge cookie files. |
| `[recidive]` | off | A table turning on repeat offender escalation. See below. |
| `internal` | same as `ignore_ips` | Addresses and CIDRs that are your own hosts. Rules with `ban_not_internal` banish the end of a flow that is not internal. Global and per kur. |
| `eve_log` | `/var/log/baphomet/eve.json` | Path of the EVE event log. |
| `eve_enable` | `false` | Whether to write the EVE log. The path is set by default but stays silent until this is on. See [eve](eve). |
| `geoip_db` | unset | Path to a MaxMind GeoIP2/GeoLite2 country database, for rules with a `country` gate. Read via the optional `IP::Geolocation::MMDB` module. Unset, or unloadable, and every country gate fails closed (banishes nobody), with a loud warning at galla start. |
| `country_codes` | `{}` | Named lists of ISO 3166 country codes a `country` gate can import. A hash of arrays. Global, per kur, and per watcher, merged per name. See below. |
| `namtar_lists` | `{}` | Named lists of CIDR files a `namtar_list` gate checks against, each a path or array of paths. A hash. Global, per kur, and per watcher, merged per name. Reloaded on mtime change. See below. |
| `active_time` | `{}` | Named time windows a `active_time` gate references, each a `{days, hours}` spec or array of them. A hash. Global, per kur, and per watcher, merged per name. See below. |

## Country code lists

`country_codes` names reusable lists of country codes so a rule can import
one rather than hardcoding countries, keeping the rule library
geography-neutral. It is a hash of named arrays, layered watcher over kur
over global and merged per name... a deeper level replaces a same-named
list, names it does not mention stay inherited. Codes are ISO 3166 alpha-2
and case-insensitive.

```toml
[country_codes]
allowed   = [ "US", "CA", "GB" ]
high_risk = [ "CN", "RU", "KP" ]

[kur.web.country_codes]        # narrow high_risk for this kur
high_risk = [ "CN", "RU" ]

[kur.web.login.country_codes]  # ...or tighten allowed for one watcher
allowed = [ "US" ]
```

A rule imports a list with the `%%%country_codes{name}%%%` token in its
`country` gate. See [rules](rules).

## Namtar lists

`namtar_lists` names lists a `namtar_list` gate checks a value against...
the inverse of `ignore_ips`, so a rule can banish only what appears on a
feed. Named so a rule stays policy-neutral and imports a feed the operator
supplies. Layered watcher over kur over global, merged per name, and every
file is reloaded when its mtime changes, so a feed that updates on disk
takes effect with in a sweep... no restart.

A list comes in two flavors. The bare form, a file path or an array of
paths, is a **CIDR list** of one CIDR or IP per line, matched by address
containment... for gating on the offender IP or a captured address. The
typed table form may instead be a **string list**, one literal string per
line, matched by exact equality... for gating on a captured username, URI,
user-agent, or any other field a rule harvests through the gate's `var`.
Both skip `#` comments and blank lines.

```toml
[namtar_lists]
threatfeed = "/var/db/baphomet/threatfeed.cidr"   # a CIDR list (the default)
torexits   = [ "/var/db/baphomet/tor.cidr", "/var/db/baphomet/tor6.cidr" ]

[namtar_lists.bait_users]      # a string list of honeypot account names
type  = "string"
files = "/var/db/baphomet/bait-accounts.list"

[namtar_lists.bad_agents]      # a string list matched case-insensitively
type   = "string"
files  = [ "/var/db/baphomet/bad-agents.list" ]
nocase = true

[kur.web.namtar_lists]         # override or add for this kur
threatfeed = "/var/db/baphomet/web-threats.cidr"
```

`type` defaults to `cidr`, so every existing bare-path list stays a CIDR
list unchanged. `nocase` folds case at load and lookup and is meaningful
only for a string list. A file that is unreadable or empty matches nobody,
so its gate banishes nobody from it, and the galla says so loudly at start.
A rule names a list with the `namtar_list` gate. See [rules](rules).

## Active time windows

`active_time` names time-of-day/day-of-week windows a `active_time` gate
references, so a rule can count only in, or only out of, certain hours...
an admin login that is routine at midday and an alarm at 03:00. Named so a
rule stays policy-neutral. Each name is a spec, or an array of specs (in
the window if in any). Layered watcher over kur over global, merged per
name. Times are the system's local time.

```toml
[active_time.business]
days  = [ 1, 2, 3, 4, 5 ]     # 0=Sun .. 6=Sat, optional (default every day)
hours = "0900-1700"           # optional (default all day), start > end wraps midnight

[active_time.overnight]
hours = "2200-0600"

[[active_time.mixed]]         # array-of-tables bundles several ranges under one name
days  = [ 1, 2, 3, 4, 5 ]
hours = "0900-1700"
[[active_time.mixed]]
days  = [ 6 ]
hours = "0900-1200"
```

A spec sets `days` (an array of 0–6), `hours` (a `"HHMM-HHMM"` range or an
array of them), or both, and must set at least one. Membership is inclusive
of both ends. A rule references a window with the `active_time` gate. See
[rules](rules).

## Kurs and watchers

Hashes under `kur` define kurs, one galla each. The name is the hash name
and is also what ban requests are targeted at on the Ereshkigal side, so it
should match a kur over there. The kur over there may be a real one or a
gate (a `fan_out` kur)... a gate has no firewall of its own and relays
each banishment to its members, so one Baphomet kur can feed a whole set
of Ereshkigal kurs through a single name. With Ereshkigal's `enable_auth`
on, the baphomet user need only be granted the gate, not any member.

Scalar keys inside a kur hash are settings for that kur
(`max_score`/`find_time`/`ban_time`, plus a `ignore_ips` array extending
the global one). Hash keys inside it are watchers, each binding one log
file to a parser and a rule. The key name of a watcher is just a freeform
name used in logs and status output.

```toml
# the base kur config for sshd
[kur.sshd]
max_score=5
ban_time=300
# read authlog
# the key for the hash under sshd is just a freeform name
[kur.sshd.authlog]
log=/var/log/auth.log
parser=bsd_syslog
rule=syslog/sshd
```

Watcher keys...

| key | what |
| --- | --- |
| `log` | The log file, or an array of them, to follow. Entries containing glob metacharacters are expanded, and re-expanded every ten seconds while running... new matches get followed, vanished matches get dropped, and literal entries are kept even if the file does not exist yet. Required unless `journal` is given. |
| `journal` | The systemd journal instead of a file. A array of journalctl matches, `FIELD=VALUE` like fail2ban's journalmatch, ANDed across fields and ORed with in one, or `true` for the whole journal. A galla runs `journalctl -f -o json` for it, resuming from the last cursor across restarts. Mutually exclusive with `log`. |
| `parser` | The parser for lines of that log. Defaults to `syslog`. |
| `rule` | The rule, or an array of rules, to match parsed lines against, relative to `rules_dir`, in the form `type/name`, so `syslog/sshd` is `syslog/sshd.yaml` under the rules dir. With an array, rules are checked in order and the first to match a line wins... suits logs carrying several daemons, like a maillog. Required. |
| `parser` (journal) | A journal watcher's parser defaults to `journal`. |
| `max_score` / `find_time` / `ban_time` | Optional overrides for this watcher. |
| `allow_per_rule_thresholds` | Whether this watcher honors thresholds and weights a rule carries. |
| `eve_only` | Put this watcher in observe mode... match and write to EVE but never banish. |
| `observe_ignored` | When observing, also process what `ignore_ips` would drop. |
| `country_codes` | Named country-code lists overriding the kur's and global's for this watcher's rules. A hash of arrays. |
| `namtar_lists` | Named blocklists (CIDR or string) overriding the kur's and global's for this watcher's rules. A hash. |
| `active_time` | Named time windows overriding the kur's and global's for this watcher's rules. A hash. |

`max_score`, `find_time`, `ban_time`, `allow_per_rule_thresholds`,
`eve_only`, and `observe_ignored` layer watcher over kur over global over
default.

With `allow_per_rule_thresholds` on, a rule carrying its own `max_score`,
`find_time`, or `ban_time` speaks over the watcher... the layering becomes
rule over watcher over kur over global. The flag is the consent, and it is
off by default, so the aggressive numbers some shipped rules carry (one
shellshock probe is enough) do nothing until you turn it on. A rule
overriding how counting works gets its own counter bucket, so a
strict rule crossing its threshold does not eat the shared count other
rules are building against the same IP... `baphomet accused` breaks such
buckets out per rule.

## The Neti gate

Neti is the gatekeeper of Kur, and the manager socket has one too. By
default the socket's group ownership and perms (`socket_group`,
`socket_mode`) are all that gate who may ask the manager its status or
stop it. Setting `enable_auth` opens the Neti gate proper... the
[POE::Component::Server::JSONUnix](https://metacpan.org/pod/POE::Component::Server::JSONUnix)
unix ownership challenge, where a caller proves who they are by owning a
cookie file, and only UID 0 or a user in `authed_users` or a
`authed_groups` is let through.

```toml
enable_auth   = true
authed_users  = [ "kitsune" ]
authed_groups = [ "wheel" ]
```

The `baphomet` CLI completes the challenge transparently, so nothing
changes in how you drive it beyond being one of the permitted. Group and
user membership is resolved per request, so changes apply without a
restart. This gates the manager socket only... the galla sockets are 0600
and spoken to only by the manager.

## Recidivists

Every banishment any galla makes is chiseled into a shared ledger under
the tablet dir, readable via `baphomet ledger`. The `[recidive]` table
turns on repeat offender escalation against that ledger... a IP banished
`max_score` times across all kurs with in `find_time` is dragged through
a further gate... banished to the `recidive` kur, which should hold them
long.

```toml
[recidive]
kur        = "recidive"   # the deeper kur, over on the Ereshkigal side
max_score = 5            # banishments before a IP is a recidivist
find_time  = 604800       # counted over a week
ban_time   = 0            # eternal
```

| key | default | what |
| --- | --- | --- |
| `kur` | required | The kur recidivists are banished to. There must be a matching kur on the Ereshkigal side, covering everything worth protecting... a fan_out gate over every real kur suits it well. |
| `max_score` | `5` | Banishments before a IP is a recidivist. |
| `find_time` | `604800` | The window, a week by default, the banishments are counted over. |
| `ban_time` | `0` | How long a recidivist is held, 0 being eternal. |

The recidive kur wants ports covering all the kurs it backstops... from
the deeper gate there is meant to be no easy returning.

## Parsers

| parser | what |
| --- | --- |
| `syslog` | Any of the three below, sniffed per line. The default, and the right pick when a log's format is unknown or mixed. |
| `bsd_syslog` | RFC 3164 syslog... `Jul 12 08:15:50 host daemon[pid]: message`. Also handles a leading `<PRI>` and the FreeBSD verbose `<facility.level>` form. |
| `ietf_syslog` | RFC 5424 syslog... `<PRI>1 timestamp host app procid msgid sd message`. |
| `json_syslog` | The JSON output of syslog-ng, one object per line, `$(format-json --scope rfc3164 --scope rfc5424)` style. The `syslog/*` rules apply to it unchanged. |
| `journal` | The systemd journal, via `journalctl -o json`, mapped onto the syslog shape. The parser a journal watcher uses by default. The `syslog/*` rules apply to it unchanged. |
| `http_access` | HTTP access logs, both the common and combined formats. For `http/*` rules, not `syslog/*` ones. |
| `apache_error` | Apache error logs, both the 2.2 and 2.4 shapes. For `http_error/*` rules. |
| `nginx_error` | nginx error logs. For `http_error/*` rules. |
| `json` | Generic JSON application logs, whatever the schema... one object per line, flattened into dotted field paths for `json/*` rules to address. mongod, Caddy, Suricata eve.json, journalctl -o json output, and the like. |
| `raw` | The no-op escape hatch for logs nothing else fits... the whole line is the message. For `raw/*` rules, and never format-sniffed... it must be configured explicitly. |

The specific syslog parsers are the stricter choice when the format is
known... they refuse lines that should not be in that log to begin with.
Rule types and parsers pair up... `syslog/*` rules take the syslog
parsers, `http/*` rules take `http_access`, `http_error/*` rules take
`apache_error` and `nginx_error`, `json/*` rules take `json`, `raw/*` rules take `raw`, and a mismatched
pairing is a start error rather than a watcher that silently matches
nothing.

## A fuller example

```toml
ereshkigal_socket = "/var/run/ereshkigal/socket"
socket_group = "wheel"
max_score = 5
find_time = 600
ban_time = 3600

[kur.sshd]
ban_time = 300

[kur.sshd.authlog]
log = "/var/log/auth.log"
parser = "bsd_syslog"
rule = "syslog/sshd"

[kur.sshd.jail]
log = "/jails/shell/var/log/auth.log"
parser = "bsd_syslog"
rule = "syslog/sshd"
# the jail is more sensitive
max_score = 3
```

Two watchers of the same kur share one offense counter, so an IP failing in
the host authlog and the jail authlog accumulates towards one ban.
