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
supervises them, restarting any that die with a backoff that doubles up to
a minute.

Each galla re-reads the config, takes its own kur from it, and follows the
log of each watcher of that kur with POE::Wheel::FollowTail, picking up
where the file left off through rotations.

## From a line to a ban

Inside a galla, each new line of a watcher's log runs the gauntlet...

1. **Parse.** The watcher's parser (e.g. `bsd_syslog`, one of several) breaks
   the line into time, hostname, daemon, level, pid, facility, severity,
   and message. Lines that do not parse are counted and skipped.
2. **The daemon gate.** The rule's `daemons` list is checked against the
   daemon of the line. No match, no further work.
3. **The message regexps.** The rule's `message_regexp` entries are tried
   in order against the message. The first to match wins.
4. **Extraction.** The named captures the rule's tokens compiled to are
   pulled out, and each capture named in `ban_var` yields an IP.
5. **Counting.** Each IP gets a hit recorded. Hits older than `find_time`
   seconds no longer count. When an IP reaches `max_score` hits, it is
   seized.
6. **Banishment.** The galla sends
   `{"command":"ban","args":{"ips":["..."],"kur":"<name>","ban_time":...}}`
   to the Ereshkigal manager socket. If Ereshkigal can not be reached, the
   ban is queued and retried every ten seconds rather than dropped.

Counts are per galla, so an IP hitting two watchers of the same kur
accumulates in one counter, while kurs count independently.

### The rule index

A watcher does not offer each line to every rule it carries. It keeps an
index of which of its rules a line could possibly match, keyed on one field
of the record, and walks only those... in config order, so the `overlap`
semantics are untouched.

Which field depends on what the rules have to offer. For a `syslog` watcher
it is the daemon: every syslog rule carries a `daemons` list, and the gate is
the first thing the rule does, before it looks at or remembers anything. For
the types with no daemon it is whichever field the rules pin most
*selectively* through a plain equality in their `gate`. On a
`%json/suricata-all%` watcher that is `alert.category`, not `event_type`:
both are pinned by every rule, but `event_type` takes two or three values
across the whole set where `alert.category` takes one per rule, so keying on
it hands a line one rule instead of forty-four.

A rule is only indexed on a gate it can not fire around. One carrying a
`capture`, an `ignore`, or a `key` offers nothing and is always tried, since
a capture entry judges on its own gates and can complete a deferred offense
on a line the rule's own gate refused. So can a `selections` arm, which may
sit under an `or`, and a `keywords` entry, which fans over many fields rather
than pinning one. A watcher whose rules pin nothing indexes on nothing and
walks them all, exactly as before.

The index fills lazily, one entry per distinct value seen, and is bounded...
the value comes off the log line, so a broken or hostile producer chiselling
a fresh one per line can not grow it without limit.

### Compiled gates

The rules the index does hand a line to then run their gates, and a gate's
shape... whether it is a keyword fan, a typed predicate, or a plain field
equality... was settled when the rule was read. Each gate whose shape is the
plain one is compiled at load into a code ref that does only what that gate
needs, so the shape is not re-asked per line, and a rule that is nothing but
such gates is run by walking those code refs and nothing else.

A keyword fan, a typed predicate, and a gate on the reserved `MESSAGE` field
keep their branching and take the general path, as does any rule whose
boolean is more than a gate list... one carrying `keywords` to AND in, or
`selections` with a `condition` to fold. Nothing about what a gate means
changes; only when the question of which kind it is gets asked.

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
same as Ereshkigal, and every client... the CLI included... drives them
with that dist's own blocking and async clients. The manager socket
answers `status`, `status_all`, `status_galla`, `accused`, `marked`,
`watching`, `banished`, and `stop`, with the status, accused, marked, and
watching fan-out proxied to the galla sockets and `banished` proxied on to
Ereshkigal for who Kur holds. Every CLI query rides this one socket rather
than reaching around the manager, so the manager is the single door to the
control plane. The manager socket's group and mode are configurable via
`socket_group` and `socket_mode`... it only exposes read-only views and
stop, but stop is still stop.

Everything logs to syslog under the daemon facility, the manager as
`baphomet` and each worker as `galla-<kur>`.

## The tablets

Each galla writes its state to clay tablets under `tablet_base_dir`, so a
restart or a crash does not forget what it was in the middle of...

```
/var/db/baphomet/
├── galla.<kur>.counters.csv    per-IP offense counts, still-live hits
├── galla.<kur>.pending.csv     bans Ereshkigal could not be reached for
├── galla.<kur>.positions.csv   file, inode, and byte offset per followed log
├── galla.<kur>.cursors.csv     journal cursors, one per journal watcher
├── galla.<kur>.stats.jsonl     running stats, so totals survive a respawn
├── galla.<kur>.context.jsonl   correlation context and deferred offenses
└── banishments.csv             the shared ledger... every banishment, by all
```

Checkpointed on the `checkpoint` cadence from the sweeper and again on
stop, atomically via temp file and rename. On start the tablets are read
back... counters and pending bans pruned to what is still relevant, stats
totals taken up, correlation context restored into the rules, and each log
resumed at its saved offset if it is the same file grown longer (so lines
written while the galla was down are still read), or from the top if it
was rotated or truncated. The tablets are the counting-side echo of
Ereshkigal's own ban tablets... the bans themselves live over there.

The ledger is the one tablet shared by every galla rather than per kur...
each banishment is chiseled in as `epoch,kur,ip,rule,watcher` under a
exclusive lock, pruned to `ledger_keep`, read by the recidive gate for
its counting and by `baphomet ledger` for history.

Where the per-galla tablets live is pluggable... the file layout above is
the default backend, and a `[ClayTablet]` config table can put them
elsewhere, the redis backend sharing marks across a fleet. See
[tablets](tablets.md).
