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
max_retrys=5
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

Five failures from one IP inside ten minutes and it is consigned to the
sshd kur for 300 seconds.

## Several logs, one kur

Multiple watchers under one kur share a counter, so offenses accumulate
across the logs...

```toml
[kur.sshd]
max_retrys = 5

[kur.sshd.host]
log = "/var/log/auth.log"
parser = "bsd_syslog"
rule = "syslog/sshd"

[kur.sshd.shelljail]
log = "/jails/shell/var/log/auth.log"
parser = "bsd_syslog"
rule = "syslog/sshd"
```

## A stricter watcher

Per watcher overrides layer over the kur and global settings...

```toml
[kur.sshd]
max_retrys = 5
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
max_retrys = 1
ban_time = 0
```

## One maillog, several daemons

A maillog carries postfix, dovecot, and more, all interleaved. A watcher
may take an array of rules... they are checked in order and the first to
match a line wins, with each rule's own daemon gate keeping things cheap.

```toml
[kur.mail]
max_retrys = 5
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
max_retrys = 3
ban_time = 3600

[kur.www.accesslog]
log = "/var/log/nginx/access.log"
parser = "http_access"
rule = [ "http/badbots", "http/botsearch" ]
```

This needs a kur named `www` on the Ereshkigal side covering ports 80/443.

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
max_retrys = 3

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
