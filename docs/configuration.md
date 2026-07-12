# Configuration

The config file is TOML, by default
`/usr/local/etc/baphomet/config.toml`, overridable via `--config` on
`baphomet start`. Both the manager and the gallas read the same file.

## Top level settings

| setting | default | what |
| --- | --- | --- |
| `run_base_dir` | `/var/run/baphomet` | Base dir for the sockets and PID files. |
| `rules_dir` | `/usr/local/etc/baphomet/rules` | The dir holding the rules. |
| `ereshkigal_socket` | `/var/run/ereshkigal/socket` | The Ereshkigal manager socket bans are sent to. |
| `galla_bin` | `galla` | The galla bin to spawn workers with. |
| `timeout` | `30` | Timeout in seconds for socket calls, both to gallas and to Ereshkigal. |
| `max_retrys` | `5` | Offenses with in `find_time` before a IP is banned. |
| `find_time` | `600` | The window in seconds offenses are counted across. |
| `ban_time` | unset | Ban time in seconds forwarded with ban requests, 0 meaning eternal. Unset means it is left out and the Ereshkigal side default applies. |
| `socket_group` | root's default group | Group ownership of the manager socket. |
| `socket_mode` | `"0660"` | Perms for the manager socket, as a string, processed via oct. Galla sockets are always 0600. |

## Kurs and watchers

Hashes under `kur` define kurs, one galla each. The name is the hash name
and is also what ban requests are targeted at on the Ereshkigal side, so it
should match a kur over there.

Scalar keys inside a kur hash are settings for that kur. Hash keys inside
it are watchers, each binding one log file to a parser and a rule. The key
name of a watcher is just a freeform name used in logs and status output.

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
| `log` | The log file to follow. Required. |
| `parser` | The parser for lines of that log. Defaults to `syslog`. |
| `rule` | The rule, or an array of rules, to match parsed lines against, relative to `rules_dir`, in the form `type/name`, so `syslog/sshd` is `syslog/sshd.yaml` under the rules dir. With an array, rules are checked in order and the first to match a line wins... suits logs carrying several daemons, like a maillog. Required. |
| `max_retrys` / `find_time` / `ban_time` | Optional overrides for this watcher. |

`max_retrys`, `find_time`, and `ban_time` layer watcher over kur over
global over default.

## Parsers

| parser | what |
| --- | --- |
| `syslog` | Either of the two below, sniffed per line. The default, and the right pick when a log's format is unknown or mixed. |
| `bsd_syslog` | RFC 3164 syslog... `Jul 12 08:15:50 host daemon[pid]: message`. Also handles a leading `<PRI>` and the FreeBSD verbose `<facility.level>` form. |
| `ietf_syslog` | RFC 5424 syslog... `<PRI>1 timestamp host app procid msgid sd message`. |
| `http_access` | HTTP access logs, both the common and combined formats. For `http/*` rules, not `syslog/*` ones. |

The specific syslog parsers are the stricter choice when the format is
known... they refuse lines that should not be in that log to begin with.
Rule types and parsers pair up... `syslog/*` rules take the syslog
parsers, `http/*` rules take `http_access`, and a mismatched pairing is a
start error rather than a watcher that silently matches nothing. `json`
and `raw` are planned but not yet implemented.

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
