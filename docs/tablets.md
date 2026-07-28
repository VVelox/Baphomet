# State tablets

Each galla keeps its memory in state tablets... the counters, pending
bans, log positions, journal cursors, running stats, correlation context,
and the marks that survive a restart. What the tablets are and when they
are written is covered in [architecture](architecture); this page is about
choosing where they live, which is pluggable, chosen by the global
`[ClayTablet]` table in the config. Left out, a galla writes them to files
under `tablet_base_dir`, the way it always has.

```toml
# the default, and what you get with no [ClayTablet] table at all
[ClayTablet]
backend = "file"
[ClayTablet.options]
base_dir = "/var/db/baphomet"   # optional, else tablet_base_dir

# or share marks across a fleet over redis, keeping local state on disk
[ClayTablet]
backend = "redis"
[ClayTablet.options]
server = "127.0.0.1:6379"
scope  = "sshd"                 # mark sharing unit, default the kur name
# sock = "/var/run/redis/redis.sock"   # a unix socket instead of server
[ClayTablet.options.local]
base_dir = "/var/db/baphomet"   # host-local tablets on disk; redis is bus-only
```

| backend | what |
| --- | --- |
| `file` | The default, the current on-disk system. Each tablet is a file `galla.<name>.<kind>.<csv\|jsonl>` under the base dir, swapped in whole via a temp file and rename. Options: `base_dir` (else `tablet_base_dir`). |
| `redis` | Shares marks across a fleet, a sync bus rather than a store. A galla keeps and gates its marks in memory as always, but publishes each brand and lift to a per-scope Redis Stream and drains the fleet's on its sweep, so machines running the same kur converge. The reads never touch Redis, so an outage is invisible to the gates... the galla degrades to standalone marks and buffers un-published brands until the bus returns. Built on the optional `Redis::Fast`. |

## The redis backend options

| option | default | what |
| --- | --- | --- |
| `server` / `sock` | `127.0.0.1:6379` | The Redis, by host:port or a unix socket. |
| `password` | unset | The AUTH password, when the Redis wants one. |
| `prefix` | `baphomet` | The key namespace. |
| `db` | unset | The numbered database to `SELECT` into. |
| `scope` | the kur name | The mark sharing unit. Machines sharing a scope share marks, so same-named kurs across the fleet share while different kurs stay apart. |
| `mark_max_ttl` | `604800` | The stream trim horizon and the cold-replay bound, in seconds. Must exceed the longest mark `ttl`. A cold or long-down galla reconstructs its marks by replaying the retained stream. |
| `host` | the hostname | This machine's identity, stamped on published deltas so a galla skips its own on drain. Pin it to keep identity stable across a hostname change. |
| `local` | unset | Enables local disk persistence of the host-local tablets (a table with an optional `base_dir`, or a plain `true`). With it, Redis carries only the mark stream and a galla that loses the bus and is restarted while it is still gone resumes its whole state from disk. Without it, the host-local tablets live in Redis too. |
| `cnx_timeout` | `1` | Seconds a connect attempt waits, so a dead or firewalled server fails fast rather than hanging the galla. |
| `reconnect` | `5` | Seconds between reconnect attempts while the bus is down. The link is opened fast-fail, so this throttles retries, it does not block. |
| `outbox_max` | `10000` | Un-published deltas buffered while the bus is down before the oldest are dropped. |

A third party backend is a module `App::Baphomet::ClayTablet::<Ucfirst>`
selected by its lower-cased name.

The shared banishment ledger is not a per-galla tablet and is unaffected...
it stays a flock'd file under `tablet_base_dir` whatever the backend.

The fleet-wide marks the redis backend exists for are covered from the
rules side in [rules](rules)... a mark branded on one machine gating a
count on another.
