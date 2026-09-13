# Rules catalog

- `syslog/asterisk` :: Asterisk auth/registration failures
  - daemon gate :: `asterisk`
- `syslog/asterisk-foreign-auth` :: any Asterisk authentication event,
  failed or successful, from outside `country_codes{home}`... a
  registration that WORKED from abroad is toll fraud. Opt-in, needs
  geoip_db. The success pattern is a mechanical extension of the proven
  security-event format, not a mined line... confirm against your own PBX
  - daemon gate :: `asterisk`
- `syslog/linux-auditd-auth-failed` :: auditd remote authentication
  failures forwarded via audisp-syslog
  (USER_LOGIN/USER_AUTH/USER_ERR/CRED_ACQ, `res=failed` with a network
  `addr`)... bans the source
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-anom-login-failures` :: auditd
  `ANOM_LOGIN_FAILURES`... the audit subsystem's own verdict that an
  account crossed its failure threshold; bans the source when the record
  names one
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-user-mgmt` :: auditd account/group lifecycle
  (ADD_USER/DEL_USER/USER_MGMT/...)... detection-only audit trail, counts
  by the responsible login uid
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-avc-denied` :: auditd SELinux AVC `denied`
  records... detection-only, counts by the denied process (`comm`)
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-apparmor-denied` :: auditd AppArmor
  `apparmor="DENIED"` records, top-level and dbus-nested alike (any
  record type... the `apparmor=` token is the discriminator, not the
  type)... detection-only, counts by the denied profile
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-apparmor-denied` :: the same AppArmor denials read off
  the kernel ring buffer (`audit: type=1400 ... apparmor="DENIED"`) on a
  host running no auditd, the stock Debian/Ubuntu case... detection-only,
  counts by the denied profile
  - daemon gate :: `kernel`
- `syslog/linux-auditd-promiscuous` :: auditd `ANOM_PROMISCUOUS`... a NIC
  entering promiscuous mode (a sniffer coming up); detection-only, counts
  by the device
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-mac-tamper` :: auditd
  `MAC_STATUS`/`MAC_CONFIG_CHANGE` with `enforcing=0` (SELinux dropped
  out of enforcing), or an AppArmor `operation="profile_remove"` (a
  profile unloaded)... detection-only, counts by the responsible login
  uid or, for AppArmor, by the profile removed
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-audit-tamper` :: auditd recording its own
  subversion (`CONFIG_CHANGE op=remove_rule`, `audit_enabled=0`,
  `DAEMON_ABORT`)... detection-only, counts by the responsible login uid
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-abend` :: auditd `ANOM_ABEND` on a
  memory-corruption fault signal (SIGILL/ABRT/BUS/FPE/SEGV)...
  detection-only, counts by the crashing program (`comm`)
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-anom-exec` :: auditd `ANOM_EXEC`... an execution
  the kernel flagged as forbidden; detection-only, counts by the
  executable (`exe`)
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-kmod-load` :: auditd kernel module load/unload
  (x86_64 init/finit/delete_module syscalls, or a module watch key)...
  detection-only, counts by the loading program (`comm`)
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-preload-tamper` :: auditd a write to the
  dynamic-linker preload config (`/etc/ld.so.preload`, `ld.so.conf*`, or
  an `ldpreload` watch key)... detection-only, counts by the target
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-exec-from-writable` :: auditd an exec out of
  `/tmp`, `/var/tmp`, `/dev/shm`, or a `susp_exec` watch key...
  detection-only, counts by the executable (`exe`)
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/linux-auditd-odd-path` :: auditd a path named to hide (`...`
  dir, dotfile in a system bin/lib dir or `/dev/shm`, or a bare
  hex-encoded name)... detection-only, counts by the path
  - daemon gate :: `audisp-syslog`, `audispd`, `audit`
- `syslog/courier-auth` :: Courier IMAP/POP3 login failures
  - daemon gate :: `imapd`, `pop3d`, and ssl/login variants
- `syslog/courier-smtp` :: Courier SMTP rejects
  - daemon gate :: `courieresmtpd`
- `syslog/cyrus-imap` :: Cyrus IMAP/POP3 login failures
  - daemon gate :: `imapd`/`pop3d`, optionally `cyrus/` prefixed
- `syslog/dovecot` :: Dovecot auth failures
  - daemon gate :: `dovecot`, `dovecot-auth`, auth workers
- `syslog/dovecot-foreign-login` :: a successful Dovecot login from
  outside `country_codes{home}`... detection-only, opt-in, needs geoip_db
  - daemon gate :: `dovecot`
- `syslog/dovecot-stuffing` :: one source failing against many different
  mailboxes... credential stuffing on IMAP/POP3, counting
  [distinct](rules.md#distinct-counting-how-many-not-how-often) mailboxes
  rather than hits. In no group, wants `overlap = "all"` beside
  `syslog/dovecot`
  - daemon gate :: `dovecot`, `dovecot-auth`, auth workers
- `syslog/dropbear` :: Dropbear auth failures
  - daemon gate :: `dropbear`
- `syslog/freeswitch` :: FreeSWITCH auth failures
  - daemon gate :: `freeswitch`
- `syslog/freeradius-auth` :: RADIUS authentication failures...
  detection-only by ACCOUNT, since the line names the relaying NAS and a
  MAC but no supplicant address. Munger read, no regexp of its own
  - daemon gate :: `radiusd`, `freeradius`
- `syslog/freeradius-unknown-client` :: a host speaking RADIUS from no
  entry in clients.conf... the bannable half, this shape being the only
  one that names a source
  - daemon gate :: `radiusd`, `freeradius`
- `syslog/monit` :: Monit httpd access failures
  - daemon gate :: `monit` (carries a live `ignore_regexp` for the empty
    first-connect user)
- `syslog/murmur` :: Murmur/Mumble rejected connections
  - daemon gate :: `murmurd`, `mumble-server`
- `syslog/named-refused` :: BIND denied queries/transfers
  - daemon gate :: `named` (know your named config first... refusals can
    be innocent)
- `syslog/unbound-refused` :: unbound answering REFUSED to a client
  outside access-control... open-resolver probing. Munger read. Needs
  `log-queries`/`log-replies` on, or the refusals are never logged
  - daemon gate :: `unbound`
- `syslog/pam-generic` :: PAM auth failures from any daemon
  - daemon gate :: any (uses the `HOST` token... rhost is not always a IP)
- `syslog/perdition` :: Perdition auth failures
  - daemon gate :: `perdition.*`
- `syslog/postfix` :: Postfix smtpd rejects and abuse
  - daemon gate :: `postfix/smtpd` and variants
- `syslog/postfix-harvest` :: one client rejected against many different
  unknown recipients... directory harvest, counting
  [distinct](rules.md#distinct-counting-how-many-not-how-often)
  recipients off the postfix munger's fields with no regexp of its own.
  In no group, wants `overlap = "all"` beside `syslog/postfix`
  - daemon gate :: `postfix/smtpd` and variants
- `syslog/postfix-sasl` :: Postfix SASL auth failures
  - daemon gate :: `postfix/smtpd` and variants
- `syslog/postfix-sasl-foreign` :: authenticated Postfix relay use from
  outside `country_codes{home}`... detection-only, opt-in, needs geoip_db
  - daemon gate :: `postfix/smtpd` and variants
- `syslog/proftpd` :: ProFTPD login failures
  - daemon gate :: `proftpd`
- `syslog/pure-ftpd` :: Pure-FTPd auth failures
  - daemon gate :: `pure-ftpd` (ASCII locales only)
- `syslog/qmail` :: qmail/rblsmtpd rejects
  - daemon gate :: `qmail`, `rblsmtpd`
- `syslog/sendmail-auth` :: Sendmail AUTH failures
  - daemon gate :: `sendmail`, `sm-mta`
- `syslog/sendmail-reject` :: Sendmail spam/relay rejects
  - daemon gate :: `sendmail`, `sm-mta`
- `syslog/sieve` :: Sieve (timsieved) login failures
  - daemon gate :: `sieved`/`timsieved`
- `syslog/solid-pop3d` :: Solid POP3 auth failures
  - daemon gate :: `solid-pop3d`
- `syslog/sshd` :: OpenSSH auth failures
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/sshd-ddos` :: pre-auth abuse... preauth disconnects and
  hostless kex banner failures resolved by session (opt-in beside
  `syslog/sshd`)
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/sshd-extra` :: algorithm negotiation probes, hostless shapes
  resolved by session (opt-in)
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/sshd-aggressive` :: the union of sshd-ddos and sshd-extra as
  one rule... enable instead of those two
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/sshd-mark-users` :: brands each sshd failure's account with the
  source that hit it (mark_only, sets no ban)
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/sshd-spray` :: one sshd account hit from a second source...
  distributed brute force (gates on sshd-mark-users, `max_score 1`)
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/sshd-stuffing` :: one source failing against many different
  accounts... credential stuffing, the other diagonal from sshd-spray.
  Counts [distinct](rules.md#distinct-counting-how-many-not-how-often)
  accounts rather than hits, so five is five accounts and not five
  guesses. In no group, and wants `overlap = "all"` beside `syslog/sshd`
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/sshd-condemned` :: a sshd auth failure from a source already
  branded the standard `brute_force`, wherever it earned the brand...
  list ahead of `syslog/sshd` (`weight 10`, `max_score 10`)
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/sshd-breach` :: a successful ssh login from a source holding
  any standard brand... likely credential compromise (detection-only)
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/vsftpd-breach` :: a successful vsftpd login from a source
  holding any standard brand (detection-only)
  - daemon gate :: `vsftpd`
- `syslog/vsftpd-breach-upload` :: a vsftpd upload by a source holding
  any standard brand (detection-only)
  - daemon gate :: `vsftpd`
- `syslog/courier-breach` :: a successful Courier IMAP/POP3 login from a
  source holding any standard brand (detection-only)
  - daemon gate :: courier imapd/pop3d variants
- `syslog/sshd-worked` :: a brute force that landed... counted password
  failures then an Accepted from the same source (staged, detection-only,
  excludes agent publickey walks)
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/sshd-foreign-login` :: a successful ssh login from outside
  `country_codes{home}`... detection-only, opt-in, needs geoip_db and
  your home list (see [rules](rules.md), the country gate)
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/systemd-flap` :: a service crash loop... three scheduled
  restarts of one unit inside two minutes (staged, detection-only, counts
  by unit per host)
  - daemon gate :: `systemd`
- `syslog/sudo-policy` :: sudo authorization failures... detection-only,
  counts by the offending username (`detection_var`), banishes nobody
  - daemon gate :: `sudo`
- `syslog/su` :: failed su attempts (verbose, terse, PAM, and shadow
  forms)... detection-only, counts by the invoking username, the
  local-escalation twin of `sudo-policy`
  - daemon gate :: `su`
- `syslog/vsftpd` :: vsftpd login failures
  - daemon gate :: `vsftpd`
- `syslog/webmin-auth` :: Webmin login failures
  - daemon gate :: `webmin`
- `syslog/xinetd-fail` :: xinetd connection failures
  - daemon gate :: `xinetd`
- `syslog/gssftpd`, `syslog/wuftpd` :: GSS and wu-ftpd login failures
  - daemon gate :: `ftpd`, `wu-ftpd`
- `syslog/haproxy-http-auth` :: haproxy 401s
  - daemon gate :: `haproxy`
- `syslog/nagios` :: NRPE bad command / access denied
  - daemon gate :: `nrpe`
- `syslog/scanlogd` :: port scans detected
  - daemon gate :: `scanlogd`
- `syslog/screensharingd` :: macOS screen sharing auth failures
  - daemon gate :: `screensharingd`
- `syslog/uwimap-auth` :: UW IMAP/POP login failures
  - daemon gate :: `ipop3d`, `imapd`
- `syslog/suhosin` :: suhosin script attack alerts
  - daemon gate :: `lighttpd`, `suhosin`
- `syslog/froxlor-auth` :: Froxlor login failures
  - daemon gate :: `Froxlor`
- `syslog/phpmyadmin-syslog` :: phpMyAdmin login failures
  - daemon gate :: `phpMyAdmin`
- `syslog/drupal-auth` :: Drupal login failures (syslog format)
  - daemon gate :: any (site-named)
- `syslog/slapd` :: OpenLDAP bind failures, correlated by conn id
  - daemon gate :: `slapd`
- `syslog/strongswan` :: an IKE peer with no matching configuration... a
  udp/500 sweep, or a branch office whose entry is missing. Munger read.
  Does NOT cover charon's EAP failures, which name no address on their
  own line and want thread correlation
  - daemon gate :: `charon`, `ipsec`, `strongswan`, `charon-systemd`
- `syslog/openvpn` :: OpenVPN auth/TLS handshake failures
  - daemon gate :: `openvpn` (needs `--syslog`)
- `syslog/postgresql` :: PostgreSQL password auth failures
  - daemon gate :: `postgres` (needs `log_line_prefix` with `%h`)
- `syslog/samba` :: Samba connection denials
  - daemon gate :: `smbd` (needs `logging = syslog`)
- `syslog/rsyncd` :: rsync daemon module auth failures
  - daemon gate :: `rsyncd`, `rsync`

### The foreign-auth family

Thirteen rules, the group `%syslog/foreign-auth%`, one per login service.
Each carries its service's entire offense vocabulary from the rule above
**plus that service's successful login**, gated on `country_codes{home}` with
`max_score: 1`, so any authentication event from outside your home countries
banishes on the first one. This is the drive-by policy: the prober who tries
four passwords and leaves never reaches a per-service threshold, and from a
country you do no business with the first touch is the whole verdict.

They ban, including on a login that **succeeded**... which is the point, and
also the risk. Read the group file before listing it: the ordering rule (put
these ahead of the per-service rules, so a domestic event falls through
un-consumed and counts normally), the config it needs, and the traveler
problem. The three `*-foreign-login` rules above are the gentler policy over
the same ground, sighting a foreign success and banishing nobody... run one
family or the other per service.

Where no captured log line existed for a service's success, the success
pattern was written from the daemon's own output and is flagged in the rule
file for live-log confirmation; every failure half is corpus-proven. `sshd`, `dovecot`,
`postfix-sasl`, `courier` and `vsftpd` have both halves proven in-tree.

- `syslog/sshd-foreign-auth` :: any ssh authentication event from
  outside `country_codes{home}`, failed or successful
  - daemon gate :: `sshd`, `sshd-session`
- `syslog/dovecot-foreign-auth` :: " for Dovecot IMAP/POP3/submission
  - daemon gate :: `dovecot` and variants
- `syslog/postfix-sasl-foreign-auth` :: " for Postfix SASL
  - daemon gate :: `postfix/smtpd` and variants
- `syslog/courier-foreign-auth` :: " for Courier IMAP/POP3
  - daemon gate :: `imapd`, `pop3d` and variants
- `syslog/vsftpd-foreign-auth` :: " for vsftpd
  - daemon gate :: `vsftpd`
- `syslog/cyrus-imap-foreign-auth` :: " for Cyrus IMAP/POP3
  - daemon gate :: `imap`, `pop3` and variants
- `syslog/dropbear-foreign-auth` :: " for Dropbear ssh
  - daemon gate :: `dropbear`
- `syslog/proftpd-foreign-auth` :: " for ProFTPD
  - daemon gate :: `proftpd`
- `syslog/pure-ftpd-foreign-auth` :: " for Pure-FTPd
  - daemon gate :: `pure-ftpd`
- `syslog/wuftpd-foreign-auth` :: " for wu-ftpd
  - daemon gate :: `wu-ftpd`
- `syslog/uwimap-foreign-auth` :: " for UW IMAP/POP3
  - daemon gate :: `imapd`, `ipop3d`
- `syslog/perdition-foreign-auth` :: " for perdition (verdict is the
  `status=` field)
  - daemon gate :: `perdition.*`
- `syslog/openvpn-foreign-auth` :: " for OpenVPN... read the traveler
  warning twice, a VPN is usually meant to be reached from abroad
  - daemon gate :: `openvpn`

## http rules

For access logs via the `http_access` parser... these ban the client
field, and no daemon gate applies.

- `http/badbots` :: requests from known bad bots by user agent... the
  list holds the still recognizable classics plus modern scanners, meant
  to be extended locally
- `http/fakegooglebot` :: a user agent claiming Googlebot whose client
  does not reverse into Google's domains, forward-confirmed... needs
  `enable_rdns` and Net::DNS, the gate failing closed with out them
- `http/path-scan` :: a client fetching many different paths that do not
  exist... scanning by breadth rather than by signature, counting
  [distinct](rules.md#distinct-counting-how-many-not-how-often) 404
  paths. Needs no ignore list, since a browser's handful of missing
  assets is a handful of paths. In no group, wants `overlap = "all"`
  beside the other scanners
- `http/botsearch` :: probes for admin panels and login pages that 40x
- `http/apache-pass` :: a successful GET of a port-knocking path...
  point the path at a honeypot to make the knocker the offender
- `http/openhab` :: 401s against the openHAB UI and REST API
- `http/php-url-fopen` :: requests handing a `http://` URL to a script
  param

## http_error rules

For apache/nginx error logs via the `apache_error` and `nginx_error`
parsers... these ban the parsed client field.

- `http_error/apache-auth` :: Apache auth failures... both 2.2 and 2.4
  spellings
- `http_error/apache-botsearch` :: requests for admin panels that are
  not there, per the error log
- `http_error/apache-modsecurity` :: mod_security Access denied lines
- `http_error/apache-nohome` :: probing for user home dirs
- `http_error/apache-noscript` :: requests for scripts that are not there
- `http_error/apache-overflows` :: overlong or malformed request lines
- `http_error/apache-shellshock` :: shellshock attempts
- `http_error/nginx-http-auth` :: nginx basic auth failures
- `http_error/nginx-limit-req` :: ngx_http_limit_req rejections
- `http_error/nginx-botsearch` :: missing-path probes, per the error log
- `http_error/zoneminder` :: ZoneMinder login-denied messages in the
  apache error log

## json rules

For JSON application logs via the `json` parser. Their tests are hand
built from the documented output shapes.

- `json/mongodb-auth` :: MongoDB auth failures, per the structured JSON
  log of mongod 4.4 and later
- `json/caddy-botsearch` :: probes for admin panels that 40x, per
  Caddy's JSON access log
- `json/suricata` :: sources of Suricata eve.json alerts at severities 1
  and 2... mind the false positive warning in the rule header
- `json/suricata-blocked` :: sources Suricata itself decided to block,
  per `alert.action == "blocked"`... reject rules in any mode, drop
  rules when inline. The strongest of the Suricata rules, deferring to
  Suricata's own disposition. In pure IDS mode it catches only rejects,
  as drop-intent then logs as allowed... run Suricata inline or use the
  class/severity rules for passive setups.
- `json/suricata-condemned` :: any alert from a src already branded the
  standard `brute_force`, whatever the alert's own class... list ahead
  of the per-class rules (`weight 10`, `max_score 10`)
- `json/suricata-escalation` :: any alert from a src holding the
  standard `recon` then `exploit_attempt` brands in that order...
  scanned, then exploited... list ahead of the per-class rules
  (`weight 10`, `max_score 10`)
- `json/suricata-breadth` :: a src that has tripped many DIFFERENT
  signatures rather than one many times... counts
  [distinct](rules.md#distinct-counting-how-many-not-how-often)
  `alert.signature_id`, so a chatty rule cannot trigger it. In no group,
  wants `overlap = "all"` beside the per-class rules

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
config field to your networks; it defaults to the ignore IPs. See
[`ban_not_internal`](rules.md#ban_not_internal).

## raw rules

For logs in their own formats via the `raw` parser... like syslog rules but
with no daemon gate. Most extract their offender with a regexp; the appliance
families under [network gear](#network-gear) mostly read it out of a decomposed
field instead, the type being the same either way.

- `raw/mongodb-auth-legacy` :: MongoDB auth failures in the pre-4.4 text
  log, correlated by conn id... 4.4 and later use `json/mongodb-auth`
- `raw/mysqld-auth` :: MySQL/MariaDB auth failures in the server error
  log (HOST token... may be a hostname)
- `raw/exim` / `raw/exim-spam` :: exim mainlog auth failures, rejects,
  SMTP protocol abuse, and spam/virus rejects
- `raw/3proxy`, `raw/squid` :: proxy denied connections
- `raw/gitlab`, `raw/grafana`, `raw/directadmin`, `raw/centreon`,
  `raw/tine20`, `raw/groupoffice`, `raw/oracleims` :: web app / panel
  login failures in their own log formats
- `raw/roundcube-auth`, `raw/sogo-auth`, `raw/squirrelmail`,
  `raw/openwebmail`, `raw/horde` :: webmail login failures (HOST token
  where the offender can be a hostname)
- `raw/mssql-auth`, `raw/lighttpd-auth`, `raw/stunnel`, `raw/kerio`,
  `raw/domino-smtp`, `raw/assp` :: assorted server auth/reject logs
- `raw/nsd` :: NSD refusing a zone transfer to an address in no acl, and
  its RRL blocking a flood of ANY queries... a raw rule because NSD's
  own log file writes its own bracketed prefix rather than a syslog
  header, and the one pattern steps over that, the older epoch form, and
  a syslog header alike
- `raw/softethervpn`, `raw/portsentry`, `raw/counter-strike`,
  `raw/znc-adminlog`, `raw/monitorix`, `raw/bitwarden`,
  `raw/selinux-ssh` :: VPN, scan detectors, game/IRC/monitor servers,
  SELinux audit
- `raw/ejabberd-auth`, `raw/guacamole` :: XMPP and Guacamole auth
  failures
- `raw/traefik-auth`, `raw/nginx-bad-request` :: web access logs whose
  own extra fields the http_access parser rejects

### Network gear

Currently ported as raw rules and really need cleaned up/checked and made proper syslog
rules.

- Cisco ASA/PIX (`%ASA-` syslog) :: `cisco-asa-auth-bruteforce`,
  `-auth-failed`, `-vpn-auth`, `-exploit`, `-scan`, `-spoof` (banning);
  `-auth-user`, `-rapid-grants`, `-system` (detection-only); `-breach`
  (reader)
- Citrix NetScaler/ADC :: `citrix-appfw-web`, `-appfw-xml`,
  `-appfw-xml-dos`, `-auth-bruteforce`, `-cli-shell-bypass` (banning);
  `-appfw-config`, `-vpn-denied`, `-cert-expiry` (detection-only);
  `-vpn-mark-logins` + `-vpn-traveler` (an impossible-traveler mark
  pair), `-breach`, `-condemned` (readers)
- Fortinet FortiGate (`key=value`, munger read) ::
  `fortinet-admin-auth`, `-vpn-auth`, `-attack` (banning); `-malware`,
  `-virus`, `-policy`, `-admin-external`, `-breach` (detection-only,
  munger read); `-config-change`, `-system`, `-integrity`,
  `-cve-2022-40684` (detection-only, regexp over the message, counting
  by user or device)
- Juniper JunOS/SRX/ScreenOS :: `juniper-auth-bruteforce`, `-screen`,
  `-vpn-auth`, `-vpn-probe`, `-idp`, `-screenos-backdoor`
  (CVE-2015-7755) (banning); `-auth-anomaly`, `-appddos`, `-idp-system`,
  `-system` (detection-only)
- Huawei VRP (`Key=Value` pairs, munger read) ::
  `huawei-auth-bruteforce`, `-dos`, `-attack`, `-scan` (banning);
  `-net-health` (detection-only, munger read); `-config-change`,
  `-system` (detection-only, regexp over the message)
- Palo Alto PAN-OS (CSV) :: `palo-alto-auth-bruteforce`,
  `-vpn-bruteforce`, `-threat-exploit`, `-threat-virus` (banning, the
  THREAT rules via `ban_not_internal` over both flow ends);
  `-threat-infected`, `-system` (detection-only)
- SonicWall SonicOS (`key=value`, munger read) :: `sonicwall-scan`,
  `-auth-bruteforce`, `-attack`, `-flood` (banning);
  `-security-services`, `-policy` (detection-only, munger read);
  `-vpn-cert`, `-wlan`, `-config`, `-system` (detection-only, regexp
  over the message)

## Coverage

`baphomet check_rules` lists every shipped rule with its test results.

Of the syslog set, `syslog/openvpn`, `syslog/postgresql`, `syslog/samba`,
and `syslog/rsyncd` each need the daemon to log through syslog, and
postgresql additionally needs `%h` in its `log_line_prefix` for the
client address to reach the failure line (see its header comment).

Two rules are built on staged sequences (see [rules](rules.md)):
`syslog/sshd-worked`, the brute force that landed, and
`syslog/systemd-flap`, the service crash loop. Both are detection-only...
they surface as `sighting`/`sighted` in EVE and banish nobody, so loading
either turns EVE on.

Repeat-offender escalation is no rule's job... the `[recidive]` config
table does it natively, across all kurs at once.

## Caveats worth knowing

- Baphomet does not strip `::ffff:` IPv4-mapped prefixes for you. Rules
  whose daemons log that form match it outside the capture
  (`(?:::ffff:)?`) so the bare IPv4 is what goes to Ereshkigal.
- `pam-generic`'s offender is whatever PAM logged as rhost, which may be
  a hostname rather than a IP. Under the default `usedns = "no"` a
  hostname offender counts and banishes nothing (the match still writes
  to EVE); a resolve mode banishes its addresses instead... see
  [usedns](usedns.md) before turning one on.
