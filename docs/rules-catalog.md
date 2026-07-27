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
portsentry at 1, apache-overflows and apache-botsearch at 2, asterisk and
freeswitch at 10), as do the priority 1 Suricata classes and
`json/suricata-blocked` (one alert is enough). These numbers are inert
unless the `allow_per_rule_thresholds` config setting says otherwise...
see [configuration](configuration) and [rules](rules).

Rules of the brute-force, recon, and exploit classtypes also brand the
matching standard mark as they count... `brute_force`, `recon`,
`exploit_attempt`, and portsentry `honeypot` besides... read by the
`-condemned` and `-escalation` reader rules below. Branding is additive
and changes no rule's own behavior. See the standard brands in
[rules](rules).

| rule | watches for | daemon gate |
| --- | --- | --- |
| `syslog/asterisk` | Asterisk auth/registration failures | `asterisk` |
| `syslog/auditd-auth-failed` | auditd remote authentication failures forwarded via audisp-syslog (USER_LOGIN/USER_AUTH/USER_ERR/CRED_ACQ, `res=failed` with a network `addr`)... bans the source | `audisp-syslog`, `audispd`, `audit` |
| `syslog/auditd-anom-login-failures` | auditd `ANOM_LOGIN_FAILURES`... the audit subsystem's own verdict that an account crossed its failure threshold; bans the source when the record names one | `audisp-syslog`, `audispd`, `audit` |
| `syslog/auditd-user-mgmt` | auditd account/group lifecycle (ADD_USER/DEL_USER/USER_MGMT/...)... detection-only audit trail, counts by the responsible login uid | `audisp-syslog`, `audispd`, `audit` |
| `syslog/auditd-avc-denied` | auditd SELinux AVC `denied` records... detection-only, counts by the denied process (`comm`) | `audisp-syslog`, `audispd`, `audit` |
| `syslog/courier-auth` | Courier IMAP/POP3 login failures | `imapd`, `pop3d`, and ssl/login variants |
| `syslog/courier-smtp` | Courier SMTP rejects | `courieresmtpd` |
| `syslog/cyrus-imap` | Cyrus IMAP/POP3 login failures | `imapd`/`pop3d`, optionally `cyrus/` prefixed |
| `syslog/dovecot` | Dovecot auth failures | `dovecot`, `dovecot-auth`, auth workers |
| `syslog/dovecot-foreign-login` | a successful Dovecot login from outside `country_codes{home}`... detection-only, opt-in, needs geoip_db | `dovecot` |
| `syslog/dropbear` | Dropbear auth failures | `dropbear` |
| `syslog/freeswitch` | FreeSWITCH auth failures | `freeswitch` |
| `syslog/monit` | Monit httpd access failures | `monit` (carries a live `ignore_regexp` for the empty first-connect user) |
| `syslog/murmur` | Murmur/Mumble rejected connections | `murmurd`, `mumble-server` |
| `syslog/named-refused` | BIND denied queries/transfers | `named` (know your named config first... refusals can be innocent) |
| `syslog/pam-generic` | PAM auth failures from any daemon | any (uses the `HOST` token... rhost is not always a IP) |
| `syslog/perdition` | Perdition auth failures | `perdition.*` |
| `syslog/postfix` | Postfix smtpd rejects and abuse | `postfix/smtpd` and variants |
| `syslog/postfix-sasl` | Postfix SASL auth failures | `postfix/smtpd` and variants |
| `syslog/postfix-sasl-foreign` | authenticated Postfix relay use from outside `country_codes{home}`... detection-only, opt-in, needs geoip_db | `postfix/smtpd` and variants |
| `syslog/proftpd` | ProFTPD login failures | `proftpd` |
| `syslog/pure-ftpd` | Pure-FTPd auth failures | `pure-ftpd` (ASCII locales only) |
| `syslog/qmail` | qmail/rblsmtpd rejects | `qmail`, `rblsmtpd` |
| `syslog/sendmail-auth` | Sendmail AUTH failures | `sendmail`, `sm-mta` |
| `syslog/sendmail-reject` | Sendmail spam/relay rejects | `sendmail`, `sm-mta` |
| `syslog/sieve` | Sieve (timsieved) login failures | `sieved`/`timsieved` |
| `syslog/solid-pop3d` | Solid POP3 auth failures | `solid-pop3d` |
| `syslog/sshd` | OpenSSH auth failures | `sshd`, `sshd-session` |
| `syslog/sshd-ddos` | pre-auth abuse... preauth disconnects and hostless kex banner failures resolved by session (fail2ban's ddos mode, opt-in beside `syslog/sshd`) | `sshd`, `sshd-session` |
| `syslog/sshd-extra` | algorithm negotiation probes, hostless shapes resolved by session (fail2ban's extra mode, opt-in) | `sshd`, `sshd-session` |
| `syslog/sshd-aggressive` | the union of sshd-ddos and sshd-extra as one rule (fail2ban's aggressive mode)... enable instead of those two | `sshd`, `sshd-session` |
| `syslog/sshd-mark-users` | brands each sshd failure's account with the source that hit it (mark_only, sets no ban) | `sshd`, `sshd-session` |
| `syslog/sshd-spray` | one sshd account hit from a second source... distributed brute force (gates on sshd-mark-users, `max_score 1`) | `sshd`, `sshd-session` |
| `syslog/sshd-condemned` | a sshd auth failure from a source already branded the standard `brute_force`, wherever it earned the brand... list ahead of `syslog/sshd` (`weight 10`, `max_score 10`) | `sshd`, `sshd-session` |
| `syslog/sshd-breach` | a successful ssh login from a source holding any standard brand... likely credential compromise (detection-only, from sagan-rules openssh-correlated) | `sshd`, `sshd-session` |
| `syslog/vsftpd-breach` | a successful vsftpd login from a source holding any standard brand (detection-only, from sagan-rules vsftpd-correlated) | `vsftpd` |
| `syslog/vsftpd-breach-upload` | a vsftpd upload by a source holding any standard brand (detection-only, from sagan-rules vsftpd-correlated) | `vsftpd` |
| `syslog/courier-breach` | a successful Courier IMAP/POP3 login from a source holding any standard brand (detection-only, from sagan-rules imapd-correlated) | courier imapd/pop3d variants |
| `syslog/sshd-worked` | a brute force that landed... counted password failures then an Accepted from the same source (staged, detection-only, excludes agent publickey walks) | `sshd`, `sshd-session` |
| `syslog/sshd-foreign-login` | a successful ssh login from outside `country_codes{home}`... detection-only, opt-in, needs geoip_db and your home list (see [rules](rules), the country gate) | `sshd`, `sshd-session` |
| `syslog/systemd-flap` | a service crash loop... three scheduled restarts of one unit inside two minutes (staged, detection-only, counts by unit per host) | `systemd` |
| `syslog/sudo-policy` | sudo authorization failures... detection-only, counts by the offending username (`detection_var`), banishes nobody | `sudo` |
| `syslog/su` | failed su attempts (verbose, terse, PAM, and shadow forms)... detection-only, counts by the invoking username, the local-escalation twin of `sudo-policy` | `su` |
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
| `http/fakegooglebot` | a user agent claiming Googlebot whose client does not reverse into Google's domains, forward-confirmed... needs `enable_rdns` and Net::DNS, the gate failing closed with out them (from fail2ban apache-fakegooglebot) |
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
| `json/suricata-condemned` | any alert from a src already branded the standard `brute_force`, whatever the alert's own class... list ahead of the per-class rules (`weight 10`, `max_score 10`) |
| `json/suricata-escalation` | any alert from a src holding the standard `recon` then `exploit_attempt` brands in that order... scanned, then exploited... list ahead of the per-class rules (`weight 10`, `max_score 10`) |

### The per-class Suricata rules

Beside the severity-gated `json/suricata`, there is a rule per Suricata
classification class, `json/suricata-<classtype>`, each gating on that
class's `alert.category` and banishing whichever of `src_ip`/`dest_ip` is
external (`ban_not_internal`, as below). Pick the classes you
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

### Network gear

Seven firewall/router families ported from sagan-rules, all natively
syslog-speaking... their lines land on a collector and match as raw rules
anchored on each vendor's own message tokens, never the line start. The
Sagan signatures were consolidated by offense rather than ported one to
one, so a family is a handful of themed rules... the attack-shaped ones
ban `SRC` and brand the [standard marks](rules), the config-change and
system-distress ones are detection-only, counting by user, device, or
event since they accuse no address. The `-breach`/`-condemned` rules are
the correlated readers, a success or repeat offense from a source holding
any standard brand, folded per product into one any-of `marked` gate.
Sagan's geoip/aetas/blacklist sibling rulesets were deliberately not
ported... those are the `country`, `active_time`, and `namtar_list` gates,
composed in config over these rules instead.

Formats were rebuilt from vendor references rather than a live corpus, so
each file's header names the shakiest regexps... worth confirming against
your own collector before trusting the bans.

| family | rules |
| --- | --- |
| Cisco ASA/PIX (`%ASA-` syslog) | `cisco-asa-auth-bruteforce`, `-auth-failed`, `-vpn-auth`, `-exploit`, `-scan`, `-spoof` (banning); `-auth-user`, `-rapid-grants`, `-system` (detection-only); `-breach` (reader) |
| Citrix NetScaler/ADC | `citrix-appfw-web`, `-appfw-xml`, `-appfw-xml-dos`, `-auth-bruteforce`, `-cli-shell-bypass` (banning); `-appfw-config`, `-vpn-denied`, `-cert-expiry` (detection-only); `-vpn-mark-logins` + `-vpn-traveler` (an impossible-traveler mark pair), `-breach`, `-condemned` (readers) |
| Fortinet FortiGate (key=value) | `fortinet-admin-auth`, `-vpn-auth`, `-attack` (banning); `-malware`, `-virus`, `-policy`, `-config-change`, `-system`, `-integrity`, `-cve-2022-40684`, `-admin-external` (detection-only); `-breach` (reader) |
| Juniper JunOS/SRX/ScreenOS | `juniper-auth-bruteforce`, `-screen`, `-vpn-auth`, `-vpn-probe`, `-idp`, `-screenos-backdoor` (CVE-2015-7755) (banning); `-auth-anomaly`, `-appddos`, `-idp-system`, `-system` (detection-only) |
| Huawei VRP | `huawei-auth-bruteforce`, `-dos`, `-attack`, `-scan` (banning); `-config-change`, `-system`, `-net-health` (detection-only) |
| Palo Alto PAN-OS (CSV) | `palo-alto-auth-bruteforce`, `-vpn-bruteforce`, `-threat-exploit`, `-threat-virus` (banning, the THREAT rules via `ban_not_internal` over both flow ends); `-threat-infected`, `-system` (detection-only) |
| SonicWall SonicOS (key=value) | `sonicwall-scan`, `-auth-bruteforce`, `-attack`, `-flood` (banning); `-security-services`, `-policy`, `-vpn-cert`, `-wlan`, `-config`, `-system` (detection-only) |

## Coverage

The shipped set covers essentially every fail2ban filter that is a
regexp over a log line... the syslog, raw, http, http_error, and multiline
families above, plus the JSON and Suricata rules. `baphomet check_rules`
lists them all with their test results.

The network gear families above go beyond fail2ban entirely, drawn from
sagan-rules... roughly 450 Sagan signatures across Cisco ASA, Citrix,
Fortinet, Juniper, Huawei, Palo Alto, and SonicWall, consolidated by
offense into the themed raw rules listed in their own section.

Four syslog rules go beyond fail2ban's set, drawn from Sagan's rules for
daemons fail2ban leaves uncovered... `syslog/openvpn`, `syslog/postgresql`,
`syslog/samba`, and `syslog/rsyncd`. Each needs the daemon to log through
syslog, and postgresql additionally needs `%h` in its `log_line_prefix` for
the client address to reach the failure line (see its header comment).

Two more go beyond any ported corpus, built on staged sequences (see
[rules](rules)): `syslog/sshd-worked`, the brute force that landed, and
`syslog/systemd-flap`, the service crash loop. Both are detection-only...
they surface as `sighting`/`sighted` in EVE and banish nobody, so loading
either turns EVE on.

## Not ported, and why

- **apache-fakegooglebot**... ported at last as `http/fakegooglebot`,
  once the `reverse_dns` gate existed... its trick was always a
  forward-confirmed reverse lookup, not a regexp. It needs `enable_rdns`
  (on by default) and the optional `Net::DNS` module.
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
  Envelope keys (`syslog.daemon`/`syslog.pid`) cover the F-MLFID session
  shape, and a watcher's `join` glues physically multi-line records, so
  what remains unported is only the arbitrary cross-line backreference.

## Caveats worth knowing

- Baphomet does not strip `::ffff:` IPv4-mapped prefixes the way fail2ban
  does. Rules whose daemons log that form match it outside the capture
  (`(?:::ffff:)?`) so the bare IPv4 is what goes to Ereshkigal.
- `pam-generic`'s offender is whatever PAM logged as rhost, which may be
  a hostname rather than a IP. Under the default `usedns = "no"` a
  hostname offender counts and banishes nothing (the match still writes
  to EVE); a resolve mode banishes its addresses instead... see the
  hostname offenders section of [configuration](configuration) before
  turning one on.
