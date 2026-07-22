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

# stop the gallas and the manager, waiting for the process to actually exit
baphomet stop

# do not wait for the exit, or cap the wait
baphomet stop --no-wait
baphomet stop --timeout 10
```

`start` fails fast... every kur def is checked and every referenced rule is
loaded and has its embedded tests ran before anything is spawned, so a typo
in the config or a broken rule is a start error rather than a runtime
mystery.

`stop` is asynchronous on the manager side... it acknowledges, then shuts
the gallas down and exits a beat later. So the command waits for the
manager process to actually die before returning, up to the config
`timeout` (30s when no config is read), which is what makes `service
baphomet restart` safe... otherwise the following `start` would race the
still-present PID file and abort. `--no-wait` skips the wait, `--timeout`
caps it.

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

## The accused, the banished, the marked, and the ledger

```shell
# the IPs being counted but not yet banished... per IP the live hit
# count and the first and last hit epochs
baphomet accused

# just one galla's, or one IP wherever it is being counted
baphomet accused sshd
baphomet accused --ip 1.2.3.4

# the marks the gallas hold... per mark name the branded keys with their
# expiries and any stored value. just one galla's, or one mark name
baphomet marked
baphomet marked sshd
baphomet marked --name sshd-account-src

# who Kur holds right now, per kur this Baphomet feeds... the manager
# asks Ereshkigal, expands fan_out gates to their members, and marks
# bans still pending delivery
baphomet banished
baphomet banished sshd

# which kurs hold a IP
baphomet banished --ip 1.2.3.4

# the banishment history... every banishment any galla made, when,
# which kur, which IP, by which rule and watcher
baphomet ledger
baphomet ledger sshd --since 7d
baphomet ledger --ip 1.2.3.4 --tail 20
```

Every one of these rides the one manager socket... the CLI never reaches
around the manager to Ereshkigal, the manager does that itself. So
`accused`, `marked`, and `banished` all want the manager up; the manager
in turn asks Ereshkigal for the `banished` lists. The lone exception is
`ledger`, which reads the shared ledger file straight from the tablet dir,
so it works with everything down. How far back the ledger reaches is
bounded by the `ledger_keep` setting, 30 days by default.

## Feeding LibreNMS

```shell
# the same JSON the fail2ban SNMP extend emits, each kur a jail
baphomet lnms-f2b-extend
baphomet lnms-f2b-extend --pretty

# GZip+Base64 compressed, for a fleet of jails
baphomet lnms-f2b-extend -b
```

`lnms-f2b-extend` speaks the exact JSON the fail2ban SNMP extend for
LibreNMS emits, each kur this Baphomet feeds standing in for a jail and its
banned tally coming from the manager's `banished` command, so a Baphomet
host drops straight into the LibreNMS fail2ban application with no fail2ban
present. Point an snmpd extend at it...

```
extend fail2ban /usr/local/bin/baphomet lnms-f2b-extend
```

With `-b` the reply is GZip compressed then Base64 encoded onto one line,
the LibreNMS extend compression convention it decodes on its own by the
GZip magic... worth it once a fleet has enough jails to strain the SNMP
reply...

```
extend fail2ban /usr/local/bin/baphomet lnms-f2b-extend -b
```

It wants the manager up for the tallies, which is what reaches Ereshkigal;
with the manager unreachable it still emits valid JSON with `error` set and
`errorString` naming the fault, as the extend does. Since the snmpd user
drives it over the manager socket, the Neti gate governs it... see the
`command_perms` example in the [configuration](configuration) doc for
letting `snmpd` run just this one command.

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

See [rules](rules) for the rule format.

## Talking to the socket directly

The manager socket speaks newline delimited JSON, so with nothing but nc...

```shell
printf '%s\n' '{"command":"status"}' | nc -U /var/run/baphomet/socket
```

Or from Perl via
[`POE::Component::Server::JSONUnix::BlockingClient`](https://metacpan.org/pod/POE::Component::Server::JSONUnix::BlockingClient),
the same client the CLI drives the manager with... it handles the framing,
the timeouts, and the Neti gate challenge...

```perl
use POE::Component::Server::JSONUnix::BlockingClient;
my $client = POE::Component::Server::JSONUnix::BlockingClient->new(
    socket_path => '/var/run/baphomet/socket',
);
# the ownership challenge... answers ok whether or not the gate is up
$client->authenticate;
my $response = $client->call( command => 'status_all' );
die $response->{error} if $response->{status} ne 'ok';
my $status = $response->{result};
```

Note that with `enable_auth` on, a raw `nc` integration must complete
the auth challenge itself (see the Neti gate section of
[configuration](configuration))... the blocking client's `authenticate`
is much less bother.
