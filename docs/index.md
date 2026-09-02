# Baphomet

Baphomet has two faces. It is a log watcher in the same family as fail2ban,
the accuser half of a pair whose punisher half is
[Ereshkigal](https://github.com/LilithSec/Ereshkigal). It reads logs,
matches lines against rules, counts the offenses of each IP, and banishes
repeat offenders to Kur... a ban request sent to the Ereshkigal manager,
which does the actual firewalling.

It is also a LAE, log analysis engine, in the family of Sagan, Wazuh, and the
Sigma detection model... the same galla that bans can instead detect,
counting any subject and raising a triageable alert to the EVE stream with
out banishing anyone. Ban or detect is one key's difference. See
[log-analysis](log-analysis.md) for that half.

A kur is a named group of watchers that share thresholds and one ban
destination... Baphomet's equivalent of a fail2ban jail, defined by a
`[kur.NAME]` table in the config. Its bans go to the kur of the same name
for [Ereshkigal](https://github.com/LilithSec/Ereshkigal) rules.

## The docs

- [glossary](glossary.md) :: A glossary of various terms etc.
- [architecture](architecture.md) :: How it all works.
- [install](install.md) :: Install related stuff.
- [configuration](configuration.md) :: Config info.
- [usedns](usedns.md) :: Information on usedns related stuff.
- [neti-gate](neti-gate.md) :: Who may drive the manager socket... the
  ownership challenge and per command authorization.
- [tablets](tablets.md) :: Where a galla's state lives... the file backend
  and the redis mark bus for fleets.
- [rules](rules.md) :: How the various rule files work.
- [rules-catalog](rules-catalog.md) :: Currently shipped rules.
- [log-analysis](log-analysis.md) :: the detection half... rules that alert
  with out banishing, the alert metadata, the EVE stream, and how the galla
  is a log analysis engine in the Sagan/Wazuh/Sigma family.
- [eve](eve.md) :: Information on the EVE format.
- [linux-auditd](linux-auditd.md) :: Forwarding the Linux auditd stream to
  syslog and configuring the kernel's audit rules to feed the
  `%syslog/linux-audit%` group, plus the shorter road for AppArmor denials
  on a host running no auditd at all.
- [usage](usage.md) :: The `baphomet` CLI.
- [examples](examples.md) :: Various examples.
- [fail2ban](fail2ban.md) :: A short comparison for those coming from fail2ban.
- [sagan](sagan.md) :: A short comparison for those coming from sagan.
- [wazuh](wazuh.md) :: A short comparison for those coming from wazuh.
- [sigma](sigma.md) :: A short comparison between SIGMA rules and porting them.

## Module POD

The reference docs live in the modules themselves...

- [`App::Baphomet`](https://metacpan.org/pod/App::Baphomet) ... the manager and the config overview.
- [`App::Baphomet::Galla`](https://metacpan.org/pod/App::Baphomet::Galla) ... the worker.
- [`App::Baphomet::Config`](https://metacpan.org/pod/App::Baphomet::Config) ... every config setting.
- [`App::Baphomet::Rules`](https://metacpan.org/pod/App::Baphomet::Rules) ... rule loading.
- [`App::Baphomet::Rules::Syslog`](https://metacpan.org/pod/App::Baphomet::Rules::Syslog) ... the syslog rule format.
- [`App::Baphomet::Parser`](https://metacpan.org/pod/App::Baphomet::Parser) ... the parsers and what they extract.
