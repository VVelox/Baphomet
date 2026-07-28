# Configuration

The config file is TOML, by default
`/usr/local/etc/baphomet/config.toml`, overridable via `--config` on
`baphomet start`. Both the manager and the gallas read the same file.

## Top level settings

Grouped by concern. Many of these layer... a "Global, per kur, and per
watcher" note means the same key may appear at any of those levels, the
most specific winning (see [the layering rules](#kurs-and-watchers)).

### Paths and process

| setting | default | what |
| --- | --- | --- |
| `run_base_dir` | `/var/run/baphomet` | Base dir for the sockets and PID files... the manager socket is `socket` under it, the galla sockets under its `galla/` subdir. |
| `tablet_base_dir` | `/var/db/baphomet` | Base dir for the state tablets, the CSVs and JSONL a galla writes so its counters, pending bans, correlation context, and log positions survive a restart. Also the file backend's base dir and the home of the shared banishment ledger. |
| `[ClayTablet]` | file backend | Table choosing where the per-galla state lives. `backend` names it (`file` default; `redis` shares marks across a fleet as a sync bus while keeping local state on disk); `options` is the free-form table that backend interprets. Absent, the file backend is used, the current on-disk system. See [tablets](tablets). |
| `checkpoint` | `60` | Seconds between periodic rewrites of the tablets (rounded up to the ten second sweeper cadence). 0 disables the periodic rewrite; a checkpoint on stop still happens. |
| `ledger_keep` | `2592000` | How long rows are kept in the shared banishment ledger, 30 days by default. 0 means forever. Rows still inside the recidive `find_time` are always kept. |
| `rules_dir` | `/usr/local/etc/baphomet/rules` | Site override dir for rules, searched ahead of the rules shipped with the dist. A rule here shadows the shipped one of the same name. It need not exist... names absent here fall through to the shipped rules, so this is only for a site's own rules or overrides. See [rules.md](rules.md#where-rules-live). |
| `groups_dir` | `/usr/local/etc/baphomet/groups` | Site override dir for rule groups, searched ahead of the groups shipped with the dist, exactly as `rules_dir` is for rules. It need not exist. See [rules.md](rules.md#rule-groups). |
| `ereshkigal_socket` | `/var/run/ereshkigal/socket` | The Ereshkigal manager socket bans are sent to. |
| `galla_bin` | `galla` | The galla bin the manager spawns workers with. The bare default finds it on the manager's PATH; set a full path when the manager runs under a stripped environment, as under some service supervisors. |
| `journalctl_bin` | `journalctl` | The journalctl bin a galla reads journal watchers with. Same PATH note as `galla_bin`. |
| `timeout` | `30` | Timeout in seconds for socket calls, both to gallas and to Ereshkigal. |

### Counting and banning

| setting | default | what |
| --- | --- | --- |
| `max_score` | `5` | The accumulated score with in `find_time` at which a IP is banished. Each match adds its rule's `weight` (default 1), so with unweighted rules this is just an offense count. |
| `find_time` | `600` | The window in seconds offenses are counted across. |
| `ban_time` | unset | Ban time in seconds forwarded with ban requests, 0 meaning eternal. Unset means it is left out and the Ereshkigal side default applies. |
| `ban_subnet_v4` | unset | IPv4 prefix length (1..32). Set, an offender also feeds a second bucket keyed by its `/prefix` network, alongside the per-IP count, and crossing `subnet_max_score` banishes the whole CIDR via Ereshkigal's `cidr_ban`. Unset, IPv4 offenders are not subnet-bucketed. Global, per kur, and per watcher. See [subnet banning](#subnet-banning). |
| `ban_subnet_v6` | unset | IPv6 prefix length (1..128). The IPv6 twin of `ban_subnet_v4`, kept in a wholly separate bucket family. Naming one family and not the other buckets only that family. Global, per kur, and per watcher. |
| `subnet_max_score` | unset | The accumulated score with in `subnet_find_time` at which a subnet bucket banishes its CIDR. Unset, the per-IP `max_score` applies. Only meaningful with a `ban_subnet_v4`/`ban_subnet_v6` set. Global, per kur, and per watcher. |
| `subnet_find_time` | unset | The window in seconds a subnet bucket counts across. Unset, the per-IP `find_time` applies. Global, per kur, and per watcher. |
| `allow_per_rule_thresholds` | `false` | Whether rules carrying their own `max_score`/`find_time`/`ban_time`/`weight` are honored. Off, a rule's numbers are inert and the watcher's apply. Global, per kur, and per watcher. See [rules](rules). |
| `overlap` | `"first"` | How a record matching more than one rule of a watcher's list is judged. `first` is first-match-wins... the first rule to fire consumes the record and the later rules never see it. `shadow` keeps the real judgment on the first rule to fire and demotes every later one that also fires to observe mode for that hit... the demoted rule still runs its gates and still brands its marks, but its counting rides the same shadow buckets observe mode fills, where it can neither cause nor delay a real ban, its match surfacing as `noted` and a crossing as an `alert`. `observe_ignored` widens demoted counting just as it widens observe mode. `all` judges every firing rule for real, the Suricata way, each depositing toward the one judgment. Global, per kur, and per watcher. See [eve](eve). |
| `ignore_ips` | `[]` | IPv4/IPv6 addresses and CIDRs never banished, no matter what the rules say. A kur's own `ignore_ips` extends this list for that kur. Hostnames are not accepted. |
| `internal` | same as `ignore_ips` | Addresses and CIDRs that are your own hosts. Rules with `ban_not_internal` banish the end of a flow that is not internal. Global and per kur. |
| `[recidive]` | off | A table turning on repeat offender escalation. See [recidivists](#recidivists). |

### Observe mode and EVE

| setting | default | what |
| --- | --- | --- |
| `eve_only` | `false` | Observe mode... the rules under this scope match and write to EVE but never banish, a would-be ban surfacing as an `alert` and each match as `noted`. A rule's own `eve_only` layers over this. Global, per kur, and per watcher. See [rules](rules) and [eve](eve). |
| `observe_ignored` | `false` | When observing, also process IPs `ignore_ips` would otherwise drop, so they too are scored and can `alert`. Only meaningful with `eve_only` (or a `shadow` `overlap`, whose demoted counting it widens the same way). Global, per kur, and per watcher. |
| `default_severity` | unset | The severity (`info`/`low`/`medium`/`high`/`critical`) written to EVE for a rule that carries no `severity` of its own. Unset means such rules simply omit the field. Global, per kur, and per watcher. See [rules](rules) and [eve](eve). |
| `eve_log` | `/var/log/baphomet/eve.json` | Path of the EVE event log. |
| `eve_enable` | `false` | Whether to write the EVE log. The path is set by default but stays silent until this is on. See [eve](eve). |

### Lookups... DNS and GeoIP

| setting | default | what |
| --- | --- | --- |
| `enable_dns` | `false` | The consent for DNS resolution. With out it, any `usedns` is treated as `no`, loudly. Resolution rides the optional `Net::DNS` module... set but unloadable, and `usedns` behaves as `no`, also loudly. See [usedns](usedns). |
| `usedns` | `no` | How a hostname offender... a `ban_var` value that is not an IP... is handled: `no`, `resolve_seen`, or `resolve_ban`. Global, per kur, and per watcher. See [usedns](usedns). |
| `usedns_timeout` | `2` | Seconds a DNS query may take before being given up on. Resolution is blocking, so this bounds how long a hostile name can stall the galla. |
| `usedns_max_addrs` | `4` | The most addresses a hostname may resolve to and still be acted on... more and the whole resolution is refused rather than trimmed, failing closed. |
| `enable_rdns` | `true` | Whether the `reverse_dns` rule gate may look things up. A separate consent from `enable_dns` on purpose... the gate only refines matches and never redirects a ban, so it is safe by default. Off, reverse_dns gates fail closed and count nothing, loudly. Rides the optional `Net::DNS` module, loaded only when some rule carries the gate. |
| `rdns_timeout` | `2` | Seconds a `reverse_dns` gate query may take before being given up on. A failed lookup vetoes the count regardless of the gate's `negate`, so a slow resolver slows detection, never misaims it. |
| `geoip_db` | unset | Path to a MaxMind GeoIP2/GeoLite2 country database, for rules with a `country` gate. Read via the optional `IP::Geolocation::MMDB` module. Unset, or unloadable, and every country gate fails closed (banishes nobody), with a loud warning at galla start. |

### The manager socket and its gate

| setting | default | what |
| --- | --- | --- |
| `socket_group` | root's default group | Group ownership of the manager socket. |
| `socket_mode` | `"0660"` | Perms for the manager socket, an octal string, processed via oct. Galla sockets are always 0600. |
| `enable_auth` | `false` | Opens the Neti gate... the unix ownership auth challenge on the manager socket. See [neti-gate](neti-gate). |
| `authed_users` | `[]` | Users allowed past the Neti gate. |
| `authed_groups` | `[]` | Groups whose members are allowed past the Neti gate. |
| `auth_temp_dir` | unset | Dir for the auth challenge cookie files, handed to the server module. Unset, that module chooses its own temp dir. |
| `[command_perms]` | off | Per command authorization layered over `authed_users`/`authed_groups`. See [neti-gate](neti-gate). |

### Named lists for the rule gates

| setting | default | what |
| --- | --- | --- |
| `country_codes` | `{}` | Named lists of ISO 3166 country codes a `country` gate can import. A hash of arrays. Global, per kur, and per watcher, merged per name. See [below](#country-code-lists). |
| `namtar_lists` | `{}` | Named lists of CIDR files a `namtar_list` gate checks against, each a path or array of paths. A hash. Global, per kur, and per watcher, merged per name. Reloaded on mtime change. See [below](#namtar-lists). |
| `active_time` | `{}` | Named time windows a `active_time` gate references, each a `{days, hours}` spec or array of them. A hash. Global, per kur, and per watcher, merged per name. See [below](#active-time-windows). |

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
feed. A blocklist, in short, named for Namtar, the underworld's messenger
of fate and disease. The naming keeps a rule policy-neutral: it imports a
feed the operator supplies rather than baking one in. Layered watcher over kur over global, merged per name, and every
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

A **kur** is a named group of watchers that share thresholds and one ban
destination... Baphomet's equivalent of a fail2ban jail. (It is named for
Kur, the realm bans are sent to; see the [glossary](glossary) if the
vocabulary is new.) Each `[kur.NAME]` table defines one, run by one galla.
The name is also what ban requests are targeted at on the Ereshkigal side,
so it should match a kur over there. The kur over there may be a real one or a
gate (a `fan_out` kur)... a gate has no firewall of its own and relays
each banishment to its members, so one Baphomet kur can feed a whole set
of Ereshkigal kurs through a single name. With Ereshkigal's `enable_auth`
on, the baphomet user need only be granted the gate, not any member.

Scalar keys inside a kur hash are settings for that kur... any of the
layered counting and presentation settings (`max_score`, `find_time`,
`ban_time`, the four subnet knobs, `allow_per_rule_thresholds`,
`eve_only`, `observe_ignored`, `overlap`, `default_severity`, `usedns`),
the named-list hashes (`country_codes`, `namtar_lists`, `active_time`,
`rule_config`), plus `ignore_ips` and `internal` arrays extending the
global ones. Those last two are global and kur level only... a watcher may
not carry its own, since who is beyond banishment is a policy of the kur,
not of one log. Hash keys inside a kur are watchers, each binding one log
file (or the journal) to a parser and a rule list. The key name of a
watcher is just a freeform name used in logs and status output.

```toml
# the base kur config for sshd
[kur.sshd]
max_score=5
ban_time=300
# read authlog
# the key for the hash under sshd is just a freeform name
[kur.sshd.authlog]
log="/var/log/auth.log"
parser="bsd_syslog"
rule="syslog/sshd"
```

Watcher keys...

| key | what |
| --- | --- |
| `log` | The log file, or an array of them, to follow. Entries containing glob metacharacters are expanded, and re-expanded every ten seconds while running... new matches get followed, vanished matches get dropped, and literal entries are kept even if the file does not exist yet. Required unless `journal` is given. |
| `journal` | The systemd journal instead of a file. A array of journalctl matches, `FIELD=VALUE` like fail2ban's journalmatch, ANDed across fields and ORed with in one, or `true` for the whole journal. A galla runs `journalctl -f -o json` for it, resuming from the last cursor across restarts. Mutually exclusive with `log`. |
| `parser` | The parser for lines of that log. Defaults to `syslog`. |
| `rule` | The rule, or an array of rules, to match parsed lines against, relative to `rules_dir`, in the form `type/name`, so `syslog/sshd` is `syslog/sshd.yaml` under the rules dir. An entry wrapped in percent signs, `%json/suricata-all%`, is a [rule group](rules.md#rule-groups) that expands to its member rules in place. With an array, rules (post-expansion) are checked in order and, under the default `overlap` of `first`, the first to match a line wins... suits logs carrying several daemons, like a maillog. Required. |
| `parser` (journal) | A journal watcher's parser defaults to `journal`. |
| `max_score` / `find_time` / `ban_time` | Optional overrides for this watcher. |
| `ban_subnet_v4` / `ban_subnet_v6` / `subnet_max_score` / `subnet_find_time` | Optional subnet-ban overrides for this watcher. |
| `allow_per_rule_thresholds` | Whether this watcher honors thresholds and weights a rule carries. |
| `eve_only` | Put this watcher in observe mode... match and write to EVE but never banish. |
| `observe_ignored` | When observing, also process what `ignore_ips` would drop. |
| `overlap` | How a record matching more than one rule of this watcher's list is judged... `first`, `shadow`, or `all`. |
| `usedns` | How this watcher handles a hostname offender... `no`, `resolve_seen`, or `resolve_ban`. See [usedns](usedns). |
| `default_severity` | The EVE severity for this watcher's rules that carry none of their own. |
| `country_codes` | Named country-code lists overriding the kur's and global's for this watcher's rules. A hash of arrays. |
| `namtar_lists` | Named blocklists (CIDR or string) overriding the kur's and global's for this watcher's rules. A hash. |
| `active_time` | Named time windows overriding the kur's and global's for this watcher's rules. A hash. |
| `rule_config` | Per-rule overrides keyed by rule name (`type/name`), each a table of `max_score`/`find_time`/`ban_time`/`weight`/`eve_only`/`severity`. Layered watcher over kur. See [below](#per-rule-config-overrides). A hash. |
| `join` | A joiner gluing physical continuation lines onto their head line ahead of the parser, for one-event-many-lines logs like stack traces. A hash, see [below](#joining-multi-line-records). Not on journal watchers, whose messages arrive whole. |

`max_score`, `find_time`, `ban_time`, `ban_subnet_v4`, `ban_subnet_v6`,
`subnet_max_score`, `subnet_find_time`, `allow_per_rule_thresholds`,
`eve_only`, `observe_ignored`, `overlap`, `usedns`, and
`default_severity` layer watcher over kur over global over default... the
most specific level that says anything wins.

With `allow_per_rule_thresholds` on, a rule carrying its own `max_score`,
`find_time`, or `ban_time` speaks over the watcher... the layering becomes
rule over watcher over kur over global. The flag is the consent, and it is
off by default, so the aggressive numbers some shipped rules carry (one
shellshock probe is enough) do nothing until you turn it on. A rule
overriding how counting works gets its own counter bucket, so a
strict rule crossing its threshold does not eat the shared count other
rules are building against the same IP... `baphomet accused` breaks such
buckets out per rule.

## Per-rule config overrides

`allow_per_rule_thresholds` honors the numbers a rule *file* carries, the same
everywhere that rule is used. `rule_config` is the other axis... it tunes a
named rule from the config, differently per kur or per watcher, with no rule
file touched. It is a table keyed by rule name, or by group (see
[tuning a whole family](#tuning-a-whole-family-at-once)), each entry any of
`max_score`, `find_time`, `ban_time`, `weight`, `eve_only`, and `severity`.

```toml
[kur.ids.eve]
log = "/var/log/suricata/eve.json"
parser = "json"
rule = [ "json/suricata-attempted-admin", "json/suricata-denial-of-service" ]

# an admin-panel hit is enough on its own, and worth an eternal ban
[kur.ids.eve.rule_config."json/suricata-attempted-admin"]
max_score = 1
ban_time  = 86400
severity  = "high"

# the DoS classtype is noisy... raise the bar for it here only
[kur.ids.eve.rule_config."json/suricata-denial-of-service"]
max_score = 20
find_time = 60
```

### Tuning a whole family at once

A key wrapped in percent signs is a **group**, the same spelling the `rule`
list uses, and its table applies to every rule the group names. This is how a
family is stood up in observe mode without thirteen stanzas:

```toml
[kur.mail.maillog]
log = "/var/log/maillog"
parser = "syslog"
rule = [ "%syslog/foreign-auth%", "%syslog/mail%" ]

# the whole foreign-auth family watched, not acting, until you trust it
[kur.mail.maillog.rule_config."%syslog/foreign-auth%"]
eve_only = true

# ...except this one, which you have seen enough of to let act
[kur.mail.maillog.rule_config."syslog/dovecot-foreign-auth"]
eve_only = false
```

Within one level the groups are laid down first and the plain rule names over
them, so a rule named outright beats the group it belongs to, whichever order
they appear in the file. Keys a group set and the exception did not touch are
still inherited by that rule. A group naming no rule that the watcher actually
loads is harmless... the override simply lands on nothing.

A `rule_config` table lays over the kur's then the watcher's, merged per rule
name and then per key, so a watcher may tweak one knob of a rule the kur
already tuned while the rest stays inherited. It **beats the rule file's own
numbers** and, unlike them, is honored **regardless of
`allow_per_rule_thresholds`**... that flag guards against a shipped rule quietly
reshaping the tuning, not against your own hand in the config. Full precedence:
`rule_config` (watcher over kur) → the rule file (when the flag is on) → watcher
→ kur → global. `eve_only` and `severity` layer the same way, over the rule's
own and then the watcher-resolved default.

A `max_score` or `find_time` override forms a private counter bucket for the
rule, keyed by rule name across the galla. Because a galla is one kur, two
watchers of that kur that both list a rule share its bucket... so tune such a
rule at the kur level, or alike across those watchers. The other knobs
(`ban_time`, `weight`, `eve_only`, `severity`) carry no such caveat.

## Joining multi-line records

Some logs print one event across several physical lines... a stack trace, a
wrapped panic, a report whose detail lines only mean anything under their
head. No amount of per-line matching reaches those, so a watcher may carry a
`join` table, a joiner gluing continuation lines onto their head line ahead
of the parser. What the parser, and so the rules, see is one record, the
physical lines joined with newlines... a regexp spans them with `(?s)` or
explicit `\n`.

```toml
[kur.app.errorlog]
log = "/var/log/app/error.log"
parser = "raw"
rule = "raw/app-trace"

[kur.app.errorlog.join]
continuation = '^\s+(?:at |Caused by)'
max_lines = 50
flush_after = 2
```

| key | what |
| --- | --- |
| `continuation` | A regexp... a line matching it is glued to the record being built rather than starting one of its own. Required. |
| `max_lines` | The most physical lines one record may gather before being flushed regardless. Default 50. |
| `flush_after` | How many seconds a record waits for another continuation line before being flushed... also the longest a quiet log holds detection back, so keep it short. Default 2. |

A record is flushed whole when the next head line arrives, when it reaches
`max_lines`, when `flush_after` seconds pass with no further line, and on a
clean stop. The buffering is per followed file, so several files feeding one
watcher never interleave into one record, and only watchers carrying a
`join` pay any of this. The buffer is memory only... a crash mid-record can
lose that one partial record, the same class of loss as pending correlation.
A continuation line with no head to glue to, like starting mid-record,
heads its own record. The `joined` stat counts the multi-line records a
watcher flushed.

For offense-and-address-on-different-lines cases with a shared key, keyed
[correlation](rules) is the sharper tool... the joiner is for records that
are physically one event, where the continuation lines are not
independently parseable at all.

## Hostname offenders... usedns

Some daemons log a hostname where an offense wants an address... PAM's
rhost above all, and mysqld when it resolves clients itself. What becomes
of one is the `usedns` setting (`no`, the default, drops it; the resolve
modes ban what it resolves to) with `enable_dns` as the consent and
`usedns_timeout`/`usedns_max_addrs` as the bounds. A resolve mode hands a
say over what your firewall bans to whoever controls a name, so the modes,
the fences around them, and why the default is `no` have
[their own page](usedns)... read it before turning a resolve mode on.

## Subnet banning

Alongside the per-IP count, a watcher can bucket offenders by network, so a
spread of hosts probing from one `/24` is caught even when no single one
crosses `max_score`. Naming a prefix for a family turns it on:

    [kur.ids]
    max_score        = 5     # a single IP: 5 offenses in find_time
    ban_subnet_v4    = 24    # also bucket IPv4 offenders by /24
    ban_subnet_v6    = 64    # and IPv6 offenders by /64
    subnet_max_score = 20    # a /24 or /64: 20 offenses across its members
    subnet_find_time = 3600  # counted across this window

Every offender that would feed the per-IP count also feeds its network's
bucket, keyed by the masked CIDR (`65.49.1.118` under a `/24` becomes
`65.49.1.0/24`). When a network's bucket crosses `subnet_max_score` with in
`subnet_find_time`, the whole CIDR is banished through Ereshkigal's `cidr_ban`,
which the target kur must have `enable_cidr` on to honor.

The per-IP ban is untouched... a member can still cross `max_score` and be
banished on its own. IPv4 and IPv6 keep wholly separate buckets, and only a
family given a prefix buckets at all... setting only `ban_subnet_v4` leaves
IPv6 offenders counted per-IP alone. Your own space (`internal`) is never
subnet-bucketed. `subnet_max_score`/`subnet_find_time` fall back to the per-IP
`max_score`/`find_time` when unset, but a `/24` aggregates many hosts, so a
higher subnet bar is usually wanted. The banish event lists the CIDR as its
`ip`, the last triggering line as its `raw`, and a `bucket` field naming the
members that fed it (see [eve](eve)).

A subnet ban is chiseled into the shared banishment ledger under its own CIDR
key, so a network banished `[recidive]`'s `max_score` times drags through to
the recidive kur just as a repeat-offender IP would, re-banished there as a
`cidr_ban`. That recidive kur must also have `enable_cidr` on.

## The Neti gate

Neti is the gatekeeper of Kur, and the manager socket has one too. By
default the socket's group ownership and perms (`socket_group`,
`socket_mode`) are all that gate who may drive the manager. `enable_auth`
opens the Neti gate proper... a unix ownership challenge admitting only
UID 0, `authed_users`, and `authed_groups`... and `command_perms` lays per
command rules over that baseline, so the snmpd user can be granted one
read-only command and nothing else. The gate, the challenge, and a worked
`command_perms` example have [their own page](neti-gate).

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

## Tablet storage

Each galla keeps its memory in state tablets... the counters, pending
bans, log positions, journal cursors, running stats, correlation context,
and the marks that survive a restart. Where those tablets live is
pluggable, chosen by the global `[ClayTablet]` table. Left out, a galla
writes them to files under `tablet_base_dir`, the way it always has; the
`redis` backend instead shares marks across a fleet as a sync bus while
keeping local state on disk. The backends and every redis option have
[their own page](tablets).

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
ignore_ips = [ "127.0.0.0/8", "192.0.2.0/24" ]

# keep the audit trail of what the gallas do
eve_enable = true

# an IP banished 5 times in a week goes to the deeper kur, eternally
[recidive]
kur      = "recidive"
ban_time = 0

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

# a maillog carrying several daemons... a rule list, first match wins
[kur.mail.maillog]
log = "/var/log/maillog"
parser = "syslog"
rule = [ "syslog/postfix-sasl", "syslog/postfix", "syslog/dovecot" ]
```

Two watchers of the same kur share one offense counter, so an IP failing in
the host authlog and the jail authlog accumulates towards one ban. The
`recidive` and `mail` kurs want same-named kurs on the Ereshkigal side, as
`sshd` does.
