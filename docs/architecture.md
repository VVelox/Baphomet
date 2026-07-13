# Architecture

## The pair

Baphomet and [Ereshkigal](https://github.com/LilithSec/Ereshkigal) split
the fail2ban job in two...

- **Ereshkigal** rules Kur. It owns the firewalls, holds the state of who
  is banned where, times sentences, and releases the served. Its manager
  listens on `/var/run/ereshkigal/socket` speaking newline delimited JSON.
- **Baphomet** is the accuser. It reads logs, decides which IPs have
  offended enough, and delivers them to that socket. It never touches a
  firewall itself.

The two meet at the kur names. A `[kur.sshd]` in Baphomet's config sends
its bans targeted at the kur named `sshd` on the Ereshkigal side, so the
names should line up across the two configs.

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

1. **Parse.** The watcher's parser (`bsd_syslog` or `ietf_syslog`) breaks
   the line into time, hostname, daemon, level, pid, facility, severity,
   and message. Lines that do not parse are counted and skipped.
2. **The daemon gate.** The rule's `daemons` list is checked against the
   daemon of the line. No match, no further work.
3. **The message regexps.** The rule's `message_regexp` entries are tried
   in order against the message. The first to match wins.
4. **Extraction.** The named captures the rule's tokens compiled to are
   pulled out, and each capture named in `ban_var` yields an IP.
5. **Counting.** Each IP gets a hit recorded. Hits older than `find_time`
   seconds no longer count. When an IP reaches `max_retrys` hits, it is
   seized.
6. **Consignment.** The galla sends
   `{"command":"ban","args":{"ips":["..."],"kur":"<name>","ban_time":...}}`
   to the Ereshkigal manager socket. If Ereshkigal can not be reached, the
   ban is queued and retried every ten seconds rather than dropped.

Counts are per galla, so an IP hitting two watchers of the same kur
accumulates in one counter, while kurs count independently.

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
POE::Component::Server::JSONUnix, same as Ereshkigal. The manager socket
answers `status`, `status_all`, `status_galla`, and `stop`, with the status
fan-out proxied to the galla sockets. The manager socket's group and mode
are configurable via `socket_group` and `socket_mode`... it only exposes
status and stop, but stop is still stop.

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
└── galla.<kur>.context.jsonl   correlation context and deferred offenses
```

Checkpointed on the `checkpoint` cadence from the sweeper and again on
stop, atomically via temp file and rename. On start the tablets are read
back... counters and pending bans pruned to what is still relevant,
correlation context restored into the rules, and each log resumed at its
saved offset if it is the same file grown longer (so lines written while
the galla was down are still read), or from the top if it was rotated or
truncated. The tablets are the counting-side echo of Ereshkigal's own ban
tablets... the bans themselves live over there.
