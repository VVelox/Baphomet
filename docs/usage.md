# Usage

The `baphomet` CLI is a App::Cmd app... `baphomet help` lists the commands
and `baphomet help <command>` details one. The commands that talk to the
running manager do so over its unix socket, by default
`/var/run/baphomet/socket`, overridable via `-s`/`--socket`.

## Loosing and quieting the galla

```shell
# read the config, daemonize, and spawn a galla per kur
baphomet start

# with a different config
baphomet start --config /some/other/config.toml

# stay in the foreground... handy under a supervisor or when debugging
baphomet start --foreground

# stop the gallas and the manager
baphomet stop
```

`start` fails fast... every kur def is checked and every referenced rule is
loaded and has its embedded tests ran before anything is spawned, so a typo
in the config or a broken rule is a start error rather than a runtime
mystery.

## Watching the watchers

```shell
# manager status and the up/down state of each galla
baphomet status

# the above plus each galla's full status block
baphomet status --all

# one galla in full
baphomet status sshd
```

A galla's status block includes its watchers with their effective settings,
its stats (lines seen, lines that did not parse, matches, bans, ban
errors... galla-wide totals plus `per_watcher` and `per_rule` breakdowns),
how many IPs it is currently counting, and any bans pending retry because
Ereshkigal could not be reached. The stats survive a restart via the stats
tablet, so the totals mean since first loosing.

Everything also logs to syslog under the daemon facility... the manager as
`baphomet`, each worker as `galla-<kur>`.

## The accused, the consigned, and the ledger

```shell
# the IPs being counted but not yet consigned... per IP the live hit
# count and the first and last hit epochs
baphomet accused

# just one galla's, or one IP wherever it is being counted
baphomet accused sshd
baphomet accused --ip 1.2.3.4

# who Kur holds right now, per kur this Baphomet feeds... asks
# Ereshkigal, expands fan_out gates to their members, and marks bans
# still pending delivery
baphomet consigned
baphomet consigned sshd

# which kurs hold a IP
baphomet consigned --ip 1.2.3.4

# the consignment history... every consignment any galla made, when,
# which kur, which IP, by which rule and watcher
baphomet ledger
baphomet ledger sshd --since 7d
baphomet ledger --ip 1.2.3.4 --tail 20
```

`accused` and `consigned` want the manager and Ereshkigal up
respectively... `ledger` reads the shared ledger file straight from the
tablet dir, so it works with everything down. How far back the ledger
reaches is bounded by the `ledger_keep` setting, 30 days by default.

## Working on rules

```shell
# run the embedded tests of every rule under the rules dir
baphomet check_rules

# just one, from a rules dir being worked on
baphomet check_rules --rules-dir ./rules syslog/sshd

# feed one line through a parser and a rule and see what comes of it
baphomet test_line --rule syslog/sshd \
    'Jul 12 08:15:50 vixen42 sshd[1]: Invalid user foo from 1.2.3.4'
```

See [rules.md](rules.md) for the rule format.

## Talking to the socket directly

The manager socket speaks newline delimited JSON, so with nothing but nc...

```shell
printf '%s\n' '{"command":"status"}' | nc -U /var/run/baphomet/socket
```

Or from Perl via the same client the CLI uses...

```perl
use Ereshkigal::Client;
my $client = Ereshkigal::Client->new( socket => '/var/run/baphomet/socket' );
my $status = $client->call_ok('status_all');
```
