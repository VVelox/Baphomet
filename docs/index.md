# Baphomet

Baphomet is a log watcher in the same family as fail2ban, and the accuser
half of a pair whose punisher half is
[Ereshkigal](https://github.com/LilithSec/Ereshkigal). It reads logs,
matches lines against rules, counts the offenses of each IP, and banishes
repeat offenders to Kur... a ban request sent to the Ereshkigal manager,
which does the actual firewalling.

The mythology carries the architecture. The galla are the demons of Kur who
seize the condemned and drag them below, and here each `galla` is a worker
process doing exactly that, one per kur configured. The `baphomet` manager
looses and oversees them.

## The docs

- [architecture](architecture) ... the processes, the sockets, how a
  line becomes a ban, and how Baphomet relates to Ereshkigal.
- [install](install) ... dependencies and installing.
- [configuration](configuration) ... the config file,
  `/usr/local/etc/baphomet/config.toml`.
- [rules](rules) ... the rule files, their tokens, and their embedded
  tests. Read this to write your own.
- [rules-catalog](rules-catalog) ... the shipped rules, what each
  watches for, and what was deliberately not ported from fail2ban.
- [eve](eve) ... the EVE event log, a Suricata-shaped NDJSON record
  of what the gallas do.
- [usage](usage) ... the `baphomet` CLI.
- [examples](examples) ... copy-paste scenarios.
- [fail2ban](fail2ban) ... the concept map, what is better, what is
  still missing, and how to migrate a jail.

## Module POD

The reference docs live in the modules themselves...

- [`App::Baphomet`](https://metacpan.org/pod/App::Baphomet) ... the manager and the config overview.
- [`App::Baphomet::Galla`](https://metacpan.org/pod/App::Baphomet::Galla) ... the worker.
- [`App::Baphomet::Config`](https://metacpan.org/pod/App::Baphomet::Config) ... every config setting.
- [`App::Baphomet::Rules`](https://metacpan.org/pod/App::Baphomet::Rules) ... rule loading.
- [`App::Baphomet::Rules::Syslog`](https://metacpan.org/pod/App::Baphomet::Rules::Syslog) ... the syslog rule format.
- [`App::Baphomet::Parser`](https://metacpan.org/pod/App::Baphomet::Parser) ... the parsers and what they extract.
