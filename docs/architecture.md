# Architecture

## The pair

Baphomet and [Ereshkigal](https://github.com/LilithSec/Ereshkigal) split
the fail2ban job in two...

- **Ereshkigal** rules Kur. It owns the firewalls, holds the state of who
  is banished where, times sentences, and releases the served. Its manager
  listens on `/var/run/ereshkigal/socket` speaking newline delimited JSON.
- **Baphomet** is the accuser. It reads logs, decides which IPs have
  offended enough, and delivers them to that socket. It never touches a
  firewall itself.

The two meet at the kur names. A `[kur.sshd]` in Baphomet's config sends
its bans targeted at the kur named `sshd` on the Ereshkigal side, so the
names should line up across the two configs. The target over there may be
a real kur or a gate... a `fan_out` kur with no firewall of its own that
relays each banishment to its members, letting one galla feed a whole
set of kurs through a single name.

## The processes

```
baphomet (manager)
├── galla sshd     one worker per [kur.*] in the config
├── galla nginx
└── ...
```

The manager watches no logs itself. At start it reads the config, checks
every kur def, and loads every rule referenced by a watcher, running the
tests embedded in each... a broken config or rule is fatal here, before
anything is spawned, rather than something the workers trip over one by
one. It then spawns one `galla` process per kur via POE::Wheel::Run and
supervises them, restarting any that die with a backoff that doubles from
a second up to a minute, resetting once a galla holds for one.

Each galla re-reads the config, takes its own kur from it, and follows
each watcher of that kur... a file watcher with POE::Wheel::FollowTail,
picking up where the file left off through rotations, a journal watcher
by running `journalctl --follow` as a supervised child of its own,
resuming from the saved cursor.

## From a line to a ban

Inside a galla, each new line of a watcher's log runs the gauntlet...

![the gauntlet, from a line to a ban](from-a-line-to-a-ban.svg)

The gates a rule opens with were ground down when the rule was read... the
plain shapes compiled to bare code refs (see compiled gates below). The ban
itself is
`{"command":"ban","args":{"ips":["..."],"kur":"<name>","ban_time":...}}` on
the Ereshkigal manager socket. Observe mode and detection rules walk the
same road but count into the shadow buckets and never banish. The full
clause set and its exact order of judgment live in [rules](rules.md).

Counts are per galla, so an IP hitting two watchers of the same kur
accumulates in one counter, while kurs count independently.

### The rule index

A watcher does not offer each line to every rule it has. It keeps an
index of which of its rules a line could possibly match, keyed on one field
of the record, and walks only those... in config order, so the `overlap`
semantics are untouched.

Which field depends on what the rules have to offer. For a `syslog` watcher
it is the daemon: every syslog rule carries a `daemons` list, and the gate is
the first thing the rule does, before it looks at or remembers anything. For
the types with no daemon it is whichever field the rules pin most
*selectively* through a plain equality in their `gate`. On a
`%json/suricata-all%` watcher that is `alert.category`, not `event_type`:
nearly every rule pins both, but `event_type` takes the one value `alert`
across the whole set where `alert.category` takes one per rule, so keying
on it hands a line one or two rules instead of forty-four... two, because
a rule pinning nothing on the chosen field constrains it not at all and
rides along with every value.

A rule is only indexed on a gate it can not fire around, and only a plain
string equality can be indexed at all. A json rule carrying a `capture`, an
`ignore`, or a `key` offers nothing and is always tried... a capture entry
judges on its own gates and can complete a deferred offense on a line the
rule's own gate refused, and a key defers the offense itself. A
`selections`/`condition` boolean offers nothing either, an arm of it
possibly sitting under an `or`. A `keywords` entry, a `//regexp//` value,
or a typed predicate merely contributes nothing for its field... the rule
is still indexed on whatever plain equalities its `gate` holds, and only
one holding none is always tried. A watcher whose rules pin nothing
indexes on nothing and walks them all, exactly as before.

A `track` is the same clause for a different reason, and the one place the
index deliberately gives work back. A tracked record's harvest runs whether
or not the line was an offense, so a rule party to a record has to be handed
every line of its watcher... index it on a gate and the harvest would only
ever see lines the rule already matched, which is exactly the conflation
tracking exists to undo. That is a real per-line cost and it is only paid by
the non-syslog types: a syslog rule is routed by daemon, and a postfix line
already reaches every postfix rule.

The index fills lazily, one entry per distinct value seen, and is bounded...
the value comes off the log line, so a broken or hostile producer chiselling
a fresh one per line can not grow it without limit.

### Compiled gates

The rules the index does hand a line to then run their gates. Answering a
gate is two questions... what shape it is, a keyword fan, a typed predicate,
or a plain field equality, and whether the line satisfies it. The first was
settled when the rule was read, yet the one runner that handles every shape
re-asks it per gate, per line.

So each gate of the plain shape... one field, string equality... is compiled
at load into a code ref that does only what that gate needs, a single hash
lookup with no branching around it, and a rule whose boolean is nothing but
such gates is run by walking those code refs and nothing else.

The rest stay with the shape-asking runner: a keyword fan, a typed
predicate, a gate on the reserved `MESSAGE` field, and any rule whose
boolean is more than a gate list... one carrying `keywords` to AND in, or
`selections` with a `condition` to fold. Those are the rare shapes, so
compiling them would restate more paths to buy nothing. Nothing about what
a gate means changes; only when the question of which kind it is gets
asked.

## The sockets

```
/var/run/baphomet/
├── socket             manager socket... status and stop
├── pid                manager PID
└── galla/
    ├── <kur>.sock     per galla socket (0600, only the manager talks to it)
    └── <kur>.pid      per galla PID
```

Both speak the newline delimited JSON protocol of
[POE::Component::Server::JSONUnix](https://metacpan.org/pod/POE::Component::Server::JSONUnix),
same as Ereshkigal. The manager socket answers `status`, `status_all`,
`status_galla`, `accused`, `marked`, `tracked`, `watching`, `banished`,
and `stop`, with the status, accused, marked, tracked, and watching
fan-out proxied to the galla sockets and `banished` asking Ereshkigal who
Kur holds for the fed kurs, gates expanded to their members and each
galla's still-pending bans folded in. Every CLI query of the live daemons
rides this one socket rather than reaching around the manager, so the
manager is the single door to the control plane... only `baphomet ledger`
reads its tablet straight off disk. The manager socket's group and mode
are configurable via `socket_group` and `socket_mode`, with the
[Neti gate](neti-gate.md) available over that... it only exposes
read-only views and stop, but stop is still stop.

Everything logs to syslog under the daemon facility, the manager as
`baphomet` and each worker as `galla-<kur>`.

## The tablets

Each galla writes its state to clay tablets under `tablet_base_dir`, so a
restart or a crash does not forget what it was in the middle of...

```
/var/db/baphomet/
├── galla.<kur>.counters.csv      still-live hits, per IP and per rule bucket
├── galla.<kur>.subnet.csv        the per-subnet tallies
├── galla.<kur>.distinct.jsonl    distinct-counting sets
├── galla.<kur>.pending.csv       bans Ereshkigal could not be reached for
├── galla.<kur>.pending_cidr.csv  the subnet twin of pending
├── galla.<kur>.positions.csv     file, inode, and byte offset per followed log
├── galla.<kur>.cursors.csv       journal cursors, one per journal watcher
├── galla.<kur>.stats.jsonl       running stats, so totals survive a respawn
├── galla.<kur>.context.jsonl     correlation context and deferred offenses
├── galla.<kur>.marks.csv         branded marks
├── galla.<kur>.tracked.csv       tracked records
├── galla.<kur>.mark_stream.csv   fleet mark-stream cursor, under mark_sync
└── banishments.csv               the shared ledger... every banishment, by all
```

Checkpointed on the `checkpoint` cadence from the sweeper and again on
stop, atomically via temp file and rename. On start the tablets are read
back... stale counters dropped, pending bans taken up for retry, stats
totals taken up, correlation context restored into the rules, and each log
resumed at its saved offset if it is still the same file and no shorter
(so lines written while the galla was down are still read), from the top
if it was rotated or truncated, or from the end if it was never followed
before. The tablets are the counting-side echo of
Ereshkigal's own ban tablets... the bans themselves live over there.

The ledger is the one tablet shared by every galla rather than per kur...
each banishment is chiseled in as `epoch,kur,ip,rule,watcher` under an
exclusive lock, pruned to `ledger_keep` but never below the recidive
window, read by the recidive gate for its counting and by
`baphomet ledger` for history.

Where the per-galla tablets live is pluggable... the file layout above is
the default backend, and a `[ClayTablet]` config table can put them
elsewhere, the redis backend sharing marks across a fleet. The ledger is
the exception, staying on local disk whatever the backend. See
[tablets](tablets.md).
