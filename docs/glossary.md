# Glossary

Baphomet's vocabulary borrows from the Sumerian underworld, since its
companion is [Ereshkigal](https://github.com/LilithSec/Ereshkigal), queen
of the dead. The names are evocative, but each maps to a plain idea. This
is the one place to look any of them up.

The pair of names that trips people first: **kur** (lowercase, a config
unit) and **Kur** (the realm). A `kur` is a jail; `Kur` is where its bans
go. The rest follows from those.

- **Baphomet** — this tool, the *accuser*. It reads logs, counts each
  IP's offenses, and requests bans. It never touches a firewall itself.
- **Ereshkigal** — the companion tool, the *punisher*. Queen of Kur, she
  owns the firewalls, holds who is banished where, times sentences, and
  releases the served. Baphomet accuses; Ereshkigal acts. See
  [architecture](architecture).
- **Kur** (capital) — the Sumerian underworld, and here the realm
  Ereshkigal rules: the firewalls and ban state. To *banish to Kur* is to
  ban.
- **kur** (lowercase, a config unit) — a named group of watchers that
  share thresholds and one ban destination. It is Baphomet's equivalent
  of a fail2ban **jail**, and it is named for Kur because that is where
  its bans are sent. Defined by a `[kur.NAME]` table in the config; one
  galla runs per kur. See [configuration](configuration).
- **galla** — a worker process, one per kur. In myth the galla are the
  demons of Kur that seize the condemned and drag them below; here each
  `galla` tails its kur's logs and does the matching. The `baphomet`
  manager looses and oversees them.
- **watcher** — inside a kur, one log source bound to a parser and a set
  of rules. A kur has one or more; a `[kur.sshd.authlog]` table is the
  `authlog` watcher of the `sshd` kur.
- **offender** — the thing a match counts toward a ban, almost always an
  IP. Named by a rule's `ban_var`.
- **subject** — what a *detection* rule counts instead of an offender: a
  username, a hostname, a unit... anything, and it never bans. Named by a
  rule's `detection_var`.
- **banish / banishment** — a ban: a request Baphomet sends to Ereshkigal
  to firewall an offender for a `ban_time`.
- **gate** — an optional test layered over a matched line that can still
  drop it before it counts: `country`, `namtar_list`, `active_time`,
  `reverse_dns`, and the mark gates. A match that clears the pattern but
  fails a gate is not an offense. See [rules](rules).
- **mark** — a named, expiring brand a rule leaves on a key (an IP, a
  username) that a later rule can gate on... Baphomet's take on Sagan's
  xbits and flexbits. See [rules](rules).
- **Namtar** — the underworld's messenger of fate and disease. A
  `namtar_list` is a **blocklist**, the inverse of `ignore_ips`: a rule
  gated by one acts only on a value a feed you supply has already
  condemned. See [configuration](configuration).
- **Neti** — the gatekeeper of Kur. The **Neti gate** is the manager
  socket's authorization... who may ask a galla its status or stop it.
  See [configuration](configuration).
- **clay tablet / tablet** — the on-disk state store under the tablet
  dir: the hit counters, the marks, the pending bans, and the shared
  banishment ledger, written so state survives a restart. See
  [configuration](configuration).
- **recidive / recidivist** — the repeat-offender escalation. An IP
  banished too many times across all kurs is dragged through a further
  gate to the `recidive` kur, which should hold it longer. See
  [configuration](configuration).
- **EVE** — the event log: a Suricata-shaped NDJSON record of what the
  gallas do (`found`, `banish`, `noted`, `alert`, `sighting`, `sighted`).
  See [eve](eve).
