# Rules catalog

The rules shipped under `rules/syslog/`, each translated from the matching
fail2ban filter (`config/filter.d/<name>.conf` in the fail2ban source) with
tests mined from fail2ban's test log corpus. Every rule carries its own
positive and negative tests, ran at load time and by
`baphomet check_rules`.

Unless said otherwise, the default/normal mode of the fail2ban filter is
what got ported... the aggressive/ddos mode machinery is dropped.

| rule | watches for | daemon gate |
| --- | --- | --- |
| `syslog/asterisk` | Asterisk auth/registration failures | `asterisk` |
| `syslog/courier-auth` | Courier IMAP/POP3 login failures | `imapd`, `pop3d`, and ssl/login variants |
| `syslog/courier-smtp` | Courier SMTP rejects | `courieresmtpd` |
| `syslog/cyrus-imap` | Cyrus IMAP/POP3 login failures | `imapd`/`pop3d`, optionally `cyrus/` prefixed |
| `syslog/dovecot` | Dovecot auth failures | `dovecot`, `dovecot-auth`, auth workers |
| `syslog/dropbear` | Dropbear auth failures | `dropbear` |
| `syslog/freeswitch` | FreeSWITCH auth failures | `freeswitch` |
| `syslog/monit` | Monit httpd access failures | `monit` (carries a live `ignore_regexp` for the empty first-connect user) |
| `syslog/murmur` | Murmur/Mumble rejected connections | `murmurd`, `mumble-server` |
| `syslog/named-refused` | BIND denied queries/transfers | `named` (know your named config first... refusals can be innocent) |
| `syslog/pam-generic` | PAM auth failures from any daemon | any (uses the `HOST` token... rhost is not always a IP) |
| `syslog/perdition` | Perdition auth failures | `perdition.*` |
| `syslog/postfix` | Postfix smtpd rejects and abuse | `postfix/smtpd` and variants |
| `syslog/postfix-sasl` | Postfix SASL auth failures | `postfix/smtpd` and variants |
| `syslog/proftpd` | ProFTPD login failures | `proftpd` |
| `syslog/pure-ftpd` | Pure-FTPd auth failures | `pure-ftpd` (ASCII locales only) |
| `syslog/qmail` | qmail/rblsmtpd rejects | `qmail`, `rblsmtpd` |
| `syslog/sendmail-auth` | Sendmail AUTH failures | `sendmail`, `sm-mta` |
| `syslog/sendmail-reject` | Sendmail spam/relay rejects | `sendmail`, `sm-mta` |
| `syslog/sieve` | Sieve (timsieved) login failures | `sieved`/`timsieved` |
| `syslog/solid-pop3d` | Solid POP3 auth failures | `solid-pop3d` |
| `syslog/sshd` | OpenSSH auth failures | `sshd`, `sshd-session` |
| `syslog/vsftpd` | vsftpd login failures | `vsftpd` |
| `syslog/webmin-auth` | Webmin login failures | `webmin` |
| `syslog/xinetd-fail` | xinetd connection failures | `xinetd` |

## Not ported, and why

- **The web server family** (apache-*, nginx-*, lighttpd, haproxy, and
  friends)... these match access/error logs in the web servers' own
  formats, not syslog. They wait on the planned `raw` parser type.
- **mysqld-auth, exim, exim-spam, mongodb-auth, and other own-format
  logs**... same story, their logs do not go through syslog in a shape the
  syslog parsers handle.
- **recidive**... fail2ban watching its own log. The Baphomet equivalent
  would be a rule watching Ereshkigal's own syslog output for repeat
  consignments and re-banning long. A future idea.
- **Multiline filters** (parts of sendmail-reject, sshd's multi-line
  correlation)... Baphomet matches line by line and has no multiline
  buffer, so those specific regexps are dropped where the rest of the
  filter was ported.

## Caveats worth knowing

- Baphomet does not strip `::ffff:` IPv4-mapped prefixes the way fail2ban
  does. Rules whose daemons log that form match it outside the capture
  (`(?:::ffff:)?`) so the bare IPv4 is what goes to Ereshkigal.
- `pam-generic` bans whatever PAM logged as rhost, which may be a
  hostname rather than a IP.
