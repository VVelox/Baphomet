# Baphomet

Baphomet has two faces. It is a log watcher in the same family as fail2ban,
the **accuser** half of a pair whose punisher half is
[Ereshkigal](https://github.com/LilithSec/Ereshkigal). It reads logs,
matches lines against rules, counts the offenses of each IP, and banishes
repeat offenders to Kur... a ban request sent to the Ereshkigal manager,
which does the actual firewalling.

It is also a **log analysis engine** in the family of Sagan, Wazuh, and the
Sigma detection model... the same galla that bans can instead detect,
counting any subject and raising a triageable alert to the EVE stream with
out banishing anyone. Ban or detect is one key's difference. See
[log-analysis](log-analysis.md) for that half.

A **kur** is a named group of watchers that share thresholds and one ban
destination... Baphomet's equivalent of a fail2ban jail, defined by a
`[kur.NAME]` table in the config. Its bans go to **Kur**, the underworld
realm [Ereshkigal](https://github.com/LilithSec/Ereshkigal) rules... so mind
the case: lowercase `kur` is the jail, capital `Kur` is where the banished
go. Each kur is run by one **galla**, a worker process; the `baphomet`
manager looses and oversees them.

## The docs

- [glossary](glossary.md) ... every borrowed term (kur, Kur, galla, Namtar,
  Neti, ...) in plain language, in one place. Start here if a name is
  unfamiliar.
- [architecture](architecture.md) ... the processes, the sockets, how a
  line becomes a ban, and how Baphomet relates to Ereshkigal.
- [install](install.md) ... dependencies and installing.
- [configuration](configuration.md) ... the config file,
  `/usr/local/etc/baphomet/config.toml`.
- [usedns](usedns.md) ... hostname offenders... the resolve modes, the
  fences around them, and why the default is to drop names.
- [neti-gate](neti-gate.md) ... who may drive the manager socket... the
  ownership challenge and per command authorization.
- [tablets](tablets.md) ... where a galla's state lives... the file backend
  and the redis mark bus for fleets.
- [rules](rules.md) ... the rule files, their tokens, and their embedded
  tests. Read this to write your own.
- [rules-catalog](rules-catalog.md) ... the shipped rules, what each
  watches for, and what was deliberately not ported from fail2ban.
- [log-analysis](log-analysis.md) ... the detection half... rules that alert
  with out banishing, the alert metadata, the EVE stream, and how the galla
  is a log analysis engine in the Sagan/Wazuh/Sigma family.
- [eve](eve.md) ... the EVE event log, a Suricata-shaped NDJSON record
  of what the gallas do.
- [linux-auditd](linux-auditd.md) ... forwarding the Linux auditd stream to
  syslog and configuring the kernel's audit rules to feed the
  `%syslog/linux-audit%` group, plus the shorter road for AppArmor denials
  on a host running no auditd at all.
- [usage](usage.md) ... the `baphomet` CLI.
- [examples](examples.md) ... copy-paste scenarios.
- [fail2ban](fail2ban.md) ... the concept map, what is better, what is
  still missing, and how to migrate a jail.
- [sagan](sagan.md) ... the gates folded in from Sagan's rule language,
  and what a full log-analysis engine still does that this does not.
- [wazuh](wazuh.md) ... the log-analysis slice of Wazuh mapped rule for
  rule, why the pair with Ereshkigal is its detect-and-respond, and the
  platform around it (agents, FIM, storage) that stays out of charter.
- [sigma](sigma.md) ... how the json rule type speaks Sigma's detection
  model, the modifier mapping, and porting a Sigma rule by hand.

## Module POD

The reference docs live in the modules themselves...

- [`App::Baphomet`](https://metacpan.org/pod/App::Baphomet) ... the manager and the config overview.
- [`App::Baphomet::Galla`](https://metacpan.org/pod/App::Baphomet::Galla) ... the worker.
- [`App::Baphomet::Config`](https://metacpan.org/pod/App::Baphomet::Config) ... every config setting.
- [`App::Baphomet::Rules`](https://metacpan.org/pod/App::Baphomet::Rules) ... rule loading.
- [`App::Baphomet::Rules::Syslog`](https://metacpan.org/pod/App::Baphomet::Rules::Syslog) ... the syslog rule format.
- [`App::Baphomet::Parser`](https://metacpan.org/pod/App::Baphomet::Parser) ... the parsers and what they extract.
