# Examples

All of these assume a running Ereshkigal with kurs matching the names used
here... see its docs for setting those up.

## sshd, the classic

Ereshkigal side, `/usr/local/etc/ereshkigal.toml`...

```toml
[kur.sshd]
backend   = "pf"
ports     = [ "22" ]
protocols = [ "tcp" ]
```

Baphomet side, `/usr/local/etc/baphomet/config.toml`...

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

```shell
baphomet check_rules
baphomet start
baphomet status --all
```

Five failures from one IP inside ten minutes and it is banished to the
sshd kur for 300 seconds.

## Several logs, one kur

Multiple watchers under one kur share a counter, so offenses accumulate
across the logs...

```toml
[kur.sshd]
max_score = 5

[kur.sshd.host]
log = "/var/log/auth.log"
parser = "bsd_syslog"
rule = "syslog/sshd"

[kur.sshd.shelljail]
log = "/jails/shell/var/log/auth.log"
parser = "bsd_syslog"
rule = "syslog/sshd"
```

Or with a glob, one watcher covers every jail, including ones created
while running... globs are re-expanded every ten seconds...

```toml
[kur.sshd.jails]
log = "/jails/*/var/log/auth.log"
rule = "syslog/sshd"
```

## A stricter watcher

Per watcher overrides layer over the kur and global settings...

```toml
[kur.sshd]
max_score = 5
ban_time = 300

[kur.sshd.authlog]
log = "/var/log/auth.log"
parser = "bsd_syslog"
rule = "syslog/sshd"

[kur.sshd.honeypot]
log = "/var/log/honeypot-auth.log"
parser = "bsd_syslog"
rule = "syslog/sshd"
# anything poking the honeypot goes below on the first offense, eternally
max_score = 1
ban_time = 0
```

## One maillog, several daemons

A maillog carries postfix, dovecot, and more, all interleaved. A watcher
may take an array of rules... they are checked in order and the first to
match a line wins, with each rule's own daemon gate keeping things cheap.

```toml
[kur.mail]
max_score = 5
ban_time = 3600

[kur.mail.maillog]
log = "/var/log/maillog"
parser = "bsd_syslog"
rule = [ "syslog/postfix", "syslog/postfix-sasl", "syslog/dovecot" ]
```

This needs a kur named `mail` on the Ereshkigal side covering the mail
ports.

## A web server's access log

Access logs use the `http_access` parser and `http/*` rules... the parser
must be named, as the `syslog` default is for syslog rules only and the
mismatch is a start error.

```toml
[kur.www]
max_score = 3
ban_time = 3600

[kur.www.accesslog]
log = "/var/log/nginx/access.log"
parser = "http_access"
rule = [ "http/badbots", "http/botsearch" ]
```

This needs a kur named `www` on the Ereshkigal side covering ports 80/443.
The `www` over there may also be a gate... a `fan_out` kur relaying to
several real kurs, say separate nginx and apache ones, so one galla feeds
them all through the one name.

The error log rides along in the same kur, sharing its offense counter,
with the parser matching the server...

```toml
[kur.www.errorlog]
log = "/var/log/nginx/error.log"
parser = "nginx_error"
rule = "http_error/nginx-http-auth"
```

...or for Apache...

```toml
[kur.www.errorlog]
log = "/var/log/httpd-error.log"
parser = "apache_error"
rule = [ "http_error/apache-auth", "http_error/apache-botsearch", "http_error/apache-overflows" ]
```

## The systemd journal

On a host where sshd only logs to the journal, a watcher takes a `journal`
of journalctl matches instead of a `log`... the galla runs
`journalctl -f -o json` for it, and the shipped `syslog/*` rules apply
unchanged, since the journal parser maps onto the syslog shape.

```toml
[kur.sshd.journal]
journal = [ "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session" ]
rule = "syslog/sshd"
```

Matches of the same field are ORed and different fields ANDed, as with
fail2ban's journalmatch. Give `journal = true` to follow the whole
journal. The last cursor is saved to the tablets, so a restart resumes
just after the last line seen rather than replaying or skipping. This
needs journalctl on the host... its path is the `journalctl_bin` setting.

## Escalating repeat offenders

An IP that keeps coming back, kur after kur, week after week, has earned a
deeper gate. Turn on recidive and give the Ereshkigal side a kur to hold
them...

Ereshkigal side...

```toml
[kur.recidive]
backend   = "pf"
# no ports/protocols... block them outright
```

Baphomet side...

```toml
[recidive]
kur        = "recidive"
max_score = 5
find_time  = 604800
ban_time   = 0
```

Now any IP banished five times across sshd, the mail kurs, the web kurs,
whatever, inside a week is banished to the recidive kur eternally. The
shared ledger under `/var/db/baphomet/banishments.csv` is what the
gallas count against, so it works across every kur at once.

## A custom rule for a custom daemon

`/usr/local/etc/baphomet/rules/syslog/toaster.yaml`...

```yaml
---
daemons:
  - toasterd
message_regexp:
  - '^bad bread inserted by %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 09:00:00 kitchen toasterd[9]: bad bread inserted by 192.0.2.1"
      found: 1
      data:
        SRC: "192.0.2.1"
  negative:
    - message: "Jul 12 09:00:01 kitchen toasterd[9]: acceptable bread inserted by 192.0.2.2"
      found: 0
      undefed: ["SRC"]
```

```toml
[kur.toaster]
max_score = 3

[kur.toaster.log]
log = "/var/log/toaster.log"
parser = "bsd_syslog"
rule = "syslog/toaster"
```

```shell
baphomet check_rules syslog/toaster
baphomet test_line --rule syslog/toaster \
    'Jul 12 09:00:00 kitchen toasterd[9]: bad bread inserted by 192.0.2.1'
```

## RFC 5424 logs

For a syslogd writing RFC 5424, just swap the parser... the same rules
work, as they match on the extracted daemon and message rather than the
raw line.

```toml
[kur.sshd.authlog]
log = "/var/log/auth.log"
parser = "ietf_syslog"
rule = "syslog/sshd"
```
