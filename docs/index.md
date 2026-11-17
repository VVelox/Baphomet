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
out banishing anyone. Ban or detect is one gate's difference. See
[log-analysis](log-analysis.md) for that half.

A kur is a named group of watchers that share thresholds and one ban
destination... Baphomet's equivalent of a fail2ban jail, defined by a
`[kur.NAME]` table in the config. Its bans go to the same-named kur on the
[Ereshkigal](https://github.com/LilithSec/Ereshkigal) side.

## The docs

- [glossary](glossary.md) :: What kur, Kur, galla, Neti, Namtar, and the rest of the
  vocabulary stand for.
- [architecture](architecture.md) :: How it all works.
- [install](install.md) :: Dependencies with their FreeBSD and Debian package names,
  building from source, and running at boot.
- [configuration](configuration.md) :: Every config setting, kurs and watchers, the named lists,
  per-rule overrides, subnet bans, recidivists, and the parsers.
- [usedns](usedns.md) :: What becomes of a hostname offender, the resolve modes, and
  why the default is to resolve nothing.
- [neti-gate](neti-gate.md) :: Who may drive the manager socket... the
  ownership challenge and per command authorization.
- [tablets](tablets.md) :: Where a galla's state lives... the file backend
  and the redis mark bus for fleets.
- [rules](rules.md) :: How the various rule files work.
- [rule gates](rules.md#every-gate) :: One page per gate a rule matches with,
  each with what it is told, where it goes, and what it refuses.
- [rules-catalog](rules-catalog.md) :: Currently shipped rules.
- [log-analysis](log-analysis.md) :: The detection half... rules that alert
  with out banishing, the alert metadata, the EVE stream, and how the galla
  is a log analysis engine in the Sagan/Wazuh/Sigma family.
- [eve](eve.md) :: The NDJSON event log... each event type, its fields, and jq
  recipes for reading it.
- [linux-auditd](linux-auditd.md) :: Forwarding the Linux auditd stream to
  syslog and configuring the kernel's audit rules to feed the
  `%syslog/linux-audit%` group, plus the shorter road for AppArmor denials
  on a host running no auditd at all.
- [usage](usage.md) :: The `baphomet` CLI.
- [examples](examples.md) :: Worked configs... sshd, several logs in one kur, a maillog,
  web logs, the journal, recidive, and a custom rule.
- [fail2ban](fail2ban.md) :: A short comparison for those coming from fail2ban.
- [sagan](sagan.md) :: A short comparison for those coming from Sagan.
- [wazuh](wazuh.md) :: A short comparison for those coming from Wazuh.
- [sigma](sigma.md) :: How Sigma rules compare, and porting them.

## Module POD

The reference docs live in the modules themselves...

- [`App::Baphomet`](https://metacpan.org/pod/App::Baphomet) ... the manager and the config overview.
- [`App::Baphomet::Galla`](https://metacpan.org/pod/App::Baphomet::Galla) ... the worker.
- [`App::Baphomet::Config`](https://metacpan.org/pod/App::Baphomet::Config) ... every config setting.
- [`App::Baphomet::Rules`](https://metacpan.org/pod/App::Baphomet::Rules) ... rule loading.
- [`App::Baphomet::Rule`](https://metacpan.org/pod/App::Baphomet::Rule) ... the rule format.
- [`App::Baphomet::Gate`](https://metacpan.org/pod/App::Baphomet::Gate) ... the gates, each type a class of its own under it.
- [`App::Baphomet::Parser`](https://metacpan.org/pod/App::Baphomet::Parser) ... the parsers and what they extract.
