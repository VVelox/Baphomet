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
| `ledger_keep` | `2592000` | How long rows are kept in the shared consignment ledger, 30 days by default. 0 means forever. Rows still inside the recidive `find_time` are always kept. |
| `rules_dir` | `/usr/local/etc/baphomet/rules` | The dir holding the rules. |
| `ereshkigal_socket` | `/var/run/ereshkigal/socket` | The Ereshkigal manager socket bans are sent to. |
| `galla_bin` | `galla` | The galla bin to spawn workers with. |
| `timeout` | `30` | Timeout in seconds for socket calls, both to gallas and to Ereshkigal. |
| `max_retrys` | `5` | Offenses with in `find_time` before a IP is banned. |
| `find_time` | `600` | The window in seconds offenses are counted across. |
| `ban_time` | unset | Ban time in seconds forwarded with ban requests, 0 meaning eternal. Unset means it is left out and the Ereshkigal side default applies. |
| `ignore_ips` | `[]` | IPv4/IPv6 addresses and CIDRs never consigned, no matter what the rules say. A kur's own `ignore_ips` extends this list for that kur. Hostnames are not accepted. |
| `socket_group` | root's default group | Group ownership of the manager socket. |
| `socket_mode` | `"0660"` | Perms for the manager socket, an octal string, processed via oct. Galla sockets are always 0600. |
| `enable_auth` | `false` | Opens the Neti gate... the unix ownership auth challenge on the manager socket. See below. |
| `authed_users` | `[]` | Users allowed past the Neti gate. |
| `authed_groups` | `[]` | Groups whose members are allowed past the Neti gate. |
| `auth_temp_dir` | unset | Dir for the auth challenge cookie files. |
| `[recidive]` | off | A table turning on repeat offender escalation. See below. |
| `internal` | same as `ignore_ips` | Addresses and CIDRs that are your own hosts. Rules with `ban_not_internal` consign the end of a flow that is not internal. Global and per kur. |
| `eve_log` | `/var/log/baphomet/eve.json` | Path of the EVE event log. |
| `eve_enable` | `false` | Whether to write the EVE log. The path is set by default but stays silent until this is on. See [eve.md](eve.md). |

## Kurs and watchers

Hashes under `kur` define kurs, one galla each. The name is the hash name
and is also what ban requests are targeted at on the Ereshkigal side, so it
should match a kur over there. The kur over there may be a real one or a
gate (a `fan_out` kur)... a gate has no firewall of its own and relays
each consignment to its members, so one Baphomet kur can feed a whole set
of Ereshkigal kurs through a single name. With Ereshkigal's `enable_auth`
on, the baphomet user need only be granted the gate, not any member.

Scalar keys inside a kur hash are settings for that kur
(`max_retrys`/`find_time`/`ban_time`, plus a `ignore_ips` array extending
the global one). Hash keys inside it are watchers, each binding one log
file to a parser and a rule. The key name of a watcher is just a freeform
name used in logs and status output.

```toml
# the base kur config for sshd
[kur.sshd]
max_retrys=5
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
| `max_retrys` / `find_time` / `ban_time` | Optional overrides for this watcher. |

`max_retrys`, `find_time`, and `ban_time` layer watcher over kur over
global over default.

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

Every consignment any galla makes is chiseled into a shared ledger under
the tablet dir, readable via `baphomet ledger`. The `[recidive]` table
turns on repeat offender escalation against that ledger... a IP consigned
`max_retrys` times across all kurs with in `find_time` is dragged through
a further gate... consigned to the `recidive` kur, which should hold them
long.

```toml
[recidive]
kur        = "recidive"   # the deeper kur, over on the Ereshkigal side
max_retrys = 5            # consignments before a IP is a recidivist
find_time  = 604800       # counted over a week
ban_time   = 0            # eternal
```

| key | default | what |
| --- | --- | --- |
| `kur` | required | The kur recidivists are consigned to. There must be a matching kur on the Ereshkigal side, covering everything worth protecting... a fan_out gate over every real kur suits it well. |
| `max_retrys` | `5` | Consignments before a IP is a recidivist. |
| `find_time` | `604800` | The window, a week by default, the consignments are counted over. |
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
max_retrys = 5
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
max_retrys = 3
```

Two watchers of the same kur share one offense counter, so an IP failing in
the host authlog and the jail authlog accumulates towards one ban.
