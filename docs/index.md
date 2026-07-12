# Baphomet

Baphomet is a log watcher in the same family as fail2ban, and the accuser
half of a pair whose punisher half is
[Ereshkigal](https://github.com/LilithSec/Ereshkigal). It reads logs,
matches lines against rules, counts the offenses of each IP, and consigns
repeat offenders to Kur... a ban request sent to the Ereshkigal manager,
which does the actual firewalling.

The mythology carries the architecture. The galla are the demons of Kur who
seize the condemned and drag them below, and here each `galla` is a worker
process doing exactly that, one per kur configured. The `baphomet` manager
looses and oversees them.

## The docs

- [architecture.md](architecture.md) ... the processes, the sockets, how a
  line becomes a ban, and how Baphomet relates to Ereshkigal.
- [install.md](install.md) ... dependencies and installing.
- [configuration.md](configuration.md) ... the config file,
  `/usr/local/etc/baphomet/config.toml`.
- [rules.md](rules.md) ... the rule files, their tokens, and their embedded
  tests. Read this to write your own.
- [rules-catalog.md](rules-catalog.md) ... the shipped rules, what each
  watches for, and what was deliberately not ported from fail2ban.
- [usage.md](usage.md) ... the `baphomet` CLI.
- [examples.md](examples.md) ... copy-paste scenarios.

## Module POD

The reference docs live in the modules themselves...

- `perldoc App::Baphomet` ... the manager and the config overview.
- `perldoc App::Baphomet::Galla` ... the worker.
- `perldoc App::Baphomet::Config` ... every config setting.
- `perldoc App::Baphomet::Rules` ... rule loading.
- `perldoc App::Baphomet::Rules::Syslog` ... the syslog rule format.
- `perldoc App::Baphomet::Parser` ... the parsers and what they extract.
