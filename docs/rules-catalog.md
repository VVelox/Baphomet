# Rules catalog

The rules shipped under `rules/syslog/`, each translated from the matching
fail2ban filter (`config/filter.d/<name>.conf` in the fail2ban source) with
tests mined from fail2ban's test log corpus. Every rule carries its own
positive and negative tests, ran at load time and by
`baphomet check_rules`.

Unless said otherwise, the default/normal mode of the fail2ban filter is
what got ported... the aggressive/ddos mode machinery is dropped.

Rules whose fail2ban jail.conf sets a non-default `maxretry` carry that
number as their own `max_score` (shellshock, badbots, nagios, and
portsentry at 1, the overflow/botsearch family at 2, asterisk and
freeswitch at 10), as do the priority 1 Suricata classes and
`json/suricata-blocked` (one alert is enough). These numbers are inert
unless the `allow_per_rule_thresholds` config setting says otherwise...
see [configuration](configuration) and [rules](rules).

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
| `syslog/sshd-mark-users` | brands each sshd failure's account with the source that hit it (mark_only, sets no ban) | `sshd`, `sshd-session` |
| `syslog/sshd-spray` | one sshd account hit from a second source... distributed brute force (gates on sshd-mark-users, `max_score 1`) | `sshd`, `sshd-session` |
| `syslog/sudo-policy` | sudo authorization failures... detection-only, counts by the offending username (`detection_var`), banishes nobody | `sudo` |
| `syslog/vsftpd` | vsftpd login failures | `vsftpd` |
| `syslog/webmin-auth` | Webmin login failures | `webmin` |
| `syslog/xinetd-fail` | xinetd connection failures | `xinetd` |
| `syslog/gssftpd`, `syslog/wuftpd` | GSS and wu-ftpd login failures | `ftpd`, `wu-ftpd` |
| `syslog/haproxy-http-auth` | haproxy 401s | `haproxy` |
| `syslog/nagios` | NRPE bad command / access denied | `nrpe` |
| `syslog/scanlogd` | port scans detected | `scanlogd` |
| `syslog/screensharingd` | macOS screen sharing auth failures | `screensharingd` |
| `syslog/uwimap-auth` | UW IMAP/POP login failures | `ipop3d`, `imapd` |
| `syslog/suhosin` | suhosin script attack alerts | `lighttpd`, `suhosin` |
| `syslog/froxlor-auth` | Froxlor login failures | `Froxlor` |
| `syslog/phpmyadmin-syslog` | phpMyAdmin login failures | `phpMyAdmin` |
| `syslog/drupal-auth` | Drupal login failures (syslog format) | any (site-named) |
| `syslog/slapd` | OpenLDAP bind failures, correlated by conn id | `slapd` |
| `syslog/openvpn` | OpenVPN auth/TLS handshake failures | `openvpn` (needs `--syslog`) |
| `syslog/postgresql` | PostgreSQL password auth failures | `postgres` (needs `log_line_prefix` with `%h`) |
| `syslog/samba` | Samba connection denials | `smbd` (needs `logging = syslog`) |
| `syslog/rsyncd` | rsync daemon module auth failures | `rsyncd`, `rsync` |

## http rules

For access logs via the `http_access` parser... these ban the client
field, and the daemon gate column does not apply.

| rule | watches for |
| --- | --- |
| `http/badbots` | requests from known bad bots by user agent... from fail2ban apache-badbots, list trimmed to the still recognizable plus modern scanners, meant to be extended locally |
| `http/botsearch` | probes for admin panels and login pages that 40x... adapted from fail2ban's botsearch-common path vocabulary into access log form |
| `http/apache-pass` | from fail2ban apache-pass... note fail2ban uses it to allowlist a knocker, so point its path at a honeypot to repurpose it as an offense |
| `http/openhab` | 401s against the openHAB UI and REST API |
| `http/php-url-fopen` | requests handing a `http://` URL to a script param |

## http_error rules

For apache/nginx error logs via the `apache_error` and `nginx_error`
parsers... these ban the parsed client field.

| rule | watches for |
| --- | --- |
| `http_error/apache-auth` | Apache auth failures... both 2.2 and 2.4 spellings |
| `http_error/apache-botsearch` | requests for admin panels that are not there, per the error log |
| `http_error/apache-modsecurity` | mod_security Access denied lines |
| `http_error/apache-nohome` | probing for user home dirs |
| `http_error/apache-noscript` | requests for scripts that are not there |
| `http_error/apache-overflows` | overlong or malformed request lines |
| `http_error/apache-shellshock` | shellshock attempts |
| `http_error/nginx-http-auth` | nginx basic auth failures |
| `http_error/nginx-limit-req` | ngx_http_limit_req rejections |
| `http_error/nginx-botsearch` | missing-path probes, per the error log |
| `http_error/zoneminder` | ZoneMinder login-denied messages in the apache error log |

## json rules

For JSON application logs via the `json` parser. No fail2ban corpus exists
for these formats, so their tests are hand built from the documented
output shapes.

| rule | watches for |
| --- | --- |
| `json/mongodb-auth` | MongoDB auth failures, per the structured JSON log of mongod 4.4 and later |
| `json/caddy-botsearch` | probes for admin panels that 40x, per Caddy's JSON access log |
| `json/suricata` | sources of Suricata eve.json alerts at severities 1 and 2... mind the false positive warning in the rule header |
| `json/suricata-blocked` | sources Suricata itself decided to block, per `alert.action == "blocked"`... reject rules in any mode, drop rules when inline. The strongest of the Suricata rules, deferring to Suricata's own disposition. In pure IDS mode it catches only rejects, as drop-intent then logs as allowed... run Suricata inline or use the class/severity rules for passive setups. |

### The per-class Suricata rules

Beside the severity-gated `json/suricata`, there is a rule per Suricata
classification class, `json/suricata-<classtype>`, each gating on that
class's `alert.category` and banishing `src_ip`. Pick the classes you
actually want to act on rather than banning on everything Suricata
alerts... a watcher's rule array is how you choose.

```toml
[kur.ids.eve]
log = "/var/log/suricata/eve.json"
parser = "json"
rule = [
  "json/suricata-trojan-activity",
  "json/suricata-exploit-kit",
  "json/suricata-command-and-control",
  "json/suricata-attempted-admin",
  "json/suricata-web-application-attack",
]
```

The full set, from Suricata's own classification.config, one rule each...
`not-suspicious`, `unknown`, `bad-unknown`, `attempted-recon`,
`successful-recon-limited`, `successful-recon-largescale`,
`attempted-dos`, `successful-dos`, `attempted-user`, `unsuccessful-user`,
`successful-user`, `attempted-admin`, `successful-admin`,
`rpc-portmap-decode`, `shellcode-detect`, `string-detect`,
`suspicious-filename-detect`, `suspicious-login`, `system-call-detect`,
`tcp-connection`, `trojan-activity`, `unusual-client-port-connection`,
`network-scan`, `denial-of-service`, `non-standard-protocol`,
`protocol-command-decode`, `web-application-activity`,
`web-application-attack`, `misc-activity`, `misc-attack`, `icmp-event`,
`inappropriate-content`, `policy-violation`, `default-login-attempt`,
`targeted-activity`, `exploit-kit`, `external-ip-check`, `domain-c2`,
`pup-activity`, `credential-theft`, `social-engineering`, `coin-mining`,
`command-and-control`.

The benign and informational classes (`not-suspicious`, `unknown`,
`tcp-connection`, `icmp-event`, `misc-activity`) are shipped for
completeness but are rarely ones you want to banish on.

Every Suricata rule lists both `src_ip` and `dest_ip` as ban_vars and sets
`ban_not_internal`, so the offender is picked as whichever end of the flow
is not one of your own hosts... an inbound attack bans the external src, a
C2 callout from an inside host bans the external dest. Set the `internal`
config field to your networks; it defaults to the ignore IPs. See the
"Banning the external end of a flow" section of [rules](rules).

## raw rules

For logs in their own formats via the `raw` parser... regexp-extracted
offenders, like syslog rules but with no daemon gate.

| rule | watches for |
| --- | --- |
| `raw/mongodb-auth-legacy` | MongoDB auth failures in the pre-4.4 text log, correlated by conn id... 4.4 and later use `json/mongodb-auth` |
| `raw/mysqld-auth` | MySQL/MariaDB auth failures in the server error log (HOST token... may be a hostname) |
| `raw/exim` / `raw/exim-spam` | exim mainlog auth failures, rejects, SMTP protocol abuse, and spam/virus rejects |
| `raw/3proxy`, `raw/squid` | proxy denied connections |
| `raw/gitlab`, `raw/grafana`, `raw/directadmin`, `raw/centreon`, `raw/tine20`, `raw/groupoffice`, `raw/oracleims` | web app / panel login failures in their own log formats |
| `raw/roundcube-auth`, `raw/sogo-auth`, `raw/squirrelmail`, `raw/openwebmail`, `raw/horde` | webmail login failures (HOST token where the offender can be a hostname) |
| `raw/mssql-auth`, `raw/lighttpd-auth`, `raw/stunnel`, `raw/kerio`, `raw/domino-smtp`, `raw/assp` | assorted server auth/reject logs |
| `raw/softethervpn`, `raw/portsentry`, `raw/counter-strike`, `raw/znc-adminlog`, `raw/monitorix`, `raw/bitwarden`, `raw/selinux-ssh` | VPN, scan detectors, game/IRC/monitor servers, SELinux audit |
| `raw/ejabberd-auth`, `raw/guacamole` | XMPP and Guacamole auth failures (single line despite fail2ban buffering a banner) |
| `raw/traefik-auth`, `raw/nginx-bad-request` | web access logs whose own extra fields the http_access parser rejects |

## Coverage

The shipped set covers essentially every fail2ban filter that is a
regexp over a log line... the syslog, raw, http, http_error, and multiline
families above, plus the JSON and Suricata rules. `baphomet check_rules`
lists them all with their test results.

Four syslog rules go beyond fail2ban's set, drawn from Sagan's rules for
daemons fail2ban leaves uncovered... `syslog/openvpn`, `syslog/postgresql`,
`syslog/samba`, and `syslog/rsyncd`. Each needs the daemon to log through
syslog, and postgresql additionally needs `%h` in its `log_line_prefix` for
the client address to reach the failure line (see its header comment).

## Not ported, and why

- **apache-fakegooglebot**... its trick is a reverse DNS check, not a
  regexp, and Baphomet does not resolve at match time.
- **recidive**... fail2ban watching its own log to escalate repeat
  offenders. Baphomet does this natively instead, via the `[recidive]`
  config table, across all kurs at once.
- **The common include files** (common.conf, apache-common.conf,
  botsearch-common.conf, selinux-common.conf, exim-common.conf)... shared
  fragments, not standalone jails. Their content is folded into the rules
  that used them.
- **fail2ban's buffer-join multiline model** (maxlines, SKIPLINES,
  cross-line backreferences) as a general mechanism... Baphomet correlates
  by key instead, via capture_regexp, which covered every case that
  actually needed it (slapd, mongodb-auth-legacy, sendmail-reject).

## Caveats worth knowing

- Baphomet does not strip `::ffff:` IPv4-mapped prefixes the way fail2ban
  does. Rules whose daemons log that form match it outside the capture
  (`(?:::ffff:)?`) so the bare IPv4 is what goes to Ereshkigal.
- `pam-generic` bans whatever PAM logged as rhost, which may be a
  hostname rather than a IP.
