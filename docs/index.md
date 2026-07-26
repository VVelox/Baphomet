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
[log-analysis](log-analysis) for that half.

The galla are the demons of Kur who seize the condemned and drag them below,
and here each `galla` is a worker process, one per kur configured. The
`baphomet` manager looses and oversees them.

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
- [log-analysis](log-analysis) ... the detection half... rules that alert
  with out banishing, the alert metadata, the EVE stream, and how the galla
  is a log analysis engine in the Sagan/Wazuh/Sigma family.
- [eve](eve) ... the EVE event log, a Suricata-shaped NDJSON record
  of what the gallas do.
- [usage](usage) ... the `baphomet` CLI.
- [examples](examples) ... copy-paste scenarios.
- [fail2ban](fail2ban) ... the concept map, what is better, what is
  still missing, and how to migrate a jail.
- [sagan](sagan) ... the gates folded in from Sagan's rule language,
  and what a full log-analysis engine still does that this does not.
- [wazuh](wazuh) ... the log-analysis slice of Wazuh mapped rule for
  rule, why the pair with Ereshkigal is its detect-and-respond, and the
  platform around it (agents, FIM, storage) that stays out of charter.
- [sigma](sigma) ... how the json rule type speaks Sigma's detection
  model, the modifier mapping, and porting a Sigma rule by hand.

## Module POD

The reference docs live in the modules themselves...

- [`App::Baphomet`](https://metacpan.org/pod/App::Baphomet) ... the manager and the config overview.
- [`App::Baphomet::Galla`](https://metacpan.org/pod/App::Baphomet::Galla) ... the worker.
- [`App::Baphomet::Config`](https://metacpan.org/pod/App::Baphomet::Config) ... every config setting.
- [`App::Baphomet::Rules`](https://metacpan.org/pod/App::Baphomet::Rules) ... rule loading.
- [`App::Baphomet::Rules::Syslog`](https://metacpan.org/pod/App::Baphomet::Rules::Syslog) ... the syslog rule format.
- [`App::Baphomet::Parser`](https://metacpan.org/pod/App::Baphomet::Parser) ... the parsers and what they extract.
