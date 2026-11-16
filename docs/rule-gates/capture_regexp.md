# capture_regexp... the address, from a line that is not the offense

A `capture_regexp` gate harvests context rather than making offenses. A
line one of its entries matches has its captures kept under that entry's
key, where a keyed [`message_regexp`](message_regexp.md) entry of the same
rule finds them for an offense of the same key. And an offense that
`message_regexp` left waiting on the key completes here, the moment the
capture line arrives. It is for the daemon that logs the offense and the
offender's address on different lines, tied by a connection or queue id...
pre-4.4 mongod logs `[conn7] Failed to authenticate` with no address and
later `[conn7] end connection 192.0.2.35:53276`.

```yaml
rule_gates:
  - capture_regexp:
      - regexp: '^\S+\s+\[conn(?<KEY>\d+)\] end connection %%%%SRC%%%%:\d+'
        key: KEY
        ttl: 600
  - message_regexp:
      - regexp: '^\S+\s+\[conn(?<KEY>\d+)\] Failed to authenticate '
        key: KEY
        defer: 600
  - ban_var:
      - SRC
```

## At a glance

- phase :: line
- rule types :: syslog, raw
- keys on :: the line
- vetoes :: no, it only stores
- needs :: nothing, or Log::Munger for a primitive fragment
- repeatable :: yes, each entry is a gate of its own

## Told

A non-empty list of entries, every one tried against the message, each a
hash of...

- `regexp` :: The regexp the message has to match.
- `key` :: The capture the context is kept under, or a list of them joined into one key.
- `ttl` :: Seconds the context is kept.
  - default :: 60

The regexp is tokened as `message_regexp`'s is, offender tokens and
primitive fragments both. On syslog a `key` component may name the
reserved envelope fields `syslog.daemon`, `syslog.host`, and `syslog.pid`
in place of a capture, so a daemon whose lines share nothing but the
logging process correlates by its session. `syslog.pid` alone scopes to
one process life... include `syslog.host` when several hosts share the
log. Raw has no envelope.

Every key component has to resolve, or the entry keeps nothing... a daemon
logging with out a pid gives a `syslog.pid` key no value. Every entry the
message matches keeps its captures, not only the first. A later capture
line of the same key replaces what an earlier one kept, and kept context is
not used up... it resolves every offense of its key until its `ttl` runs
out.

## Where it goes

**Above the `message_regexp` it feeds.** A capture line is usually one
`message_regexp` does not match, and a line none of its entries matches
ends the rule's walk, so a `capture_regexp` written below it is never asked
of the lines it is there for.

**Below the gates that are to stop it.** An `ignore_regexp` written below
it lets the context be stored on a line the rule was told to ignore, and a
deferred offense that line completes stands.

An offense it completes stands among the line's results and is judged by
every gate below it, line and offense phase both, like any other.

## When it does not hold

It turns no line away and judges no offense. A line none of its entries
matches is passed on as it was.

An offense left waiting whose capture line never comes, or comes after the
`defer` ran out, is dropped with out ever having counted. Kept context
whose offense never comes expires at its `ttl`.

## What it leaves behind

Context in the rule's correlation store, per watcher, the matched entry's
captures under its key until the `ttl` runs out. At most 10000 keys are
kept per watcher, the expired pruned and then the soonest to expire
evicted past that. Only the captures are kept... what `mungers` or
`message_json` laid down on the capture line is not, so an offense the
context resolves later has none of it.

An offense it completes is built the way one that found its context
waiting is... the offense's own captures over this line's captures, over
the fields `mungers` and `message_json` made of the offense's own line,
which were parked with it. This line's own fields go under all of that,
only filling what the rest left unset.

The store is written to the context tablet at each checkpoint and read
back at start, anything expired by then dropped, so both the context and
the offenses waiting on it can survive a restart.

## Refused at load

- not a non-empty list of hashes :: "is not a non-empty array", "entry N is not a hash"
- an entry with out `regexp` or `key`, an unknown key, or a `ttl` that is not a positive int of seconds :: "lacks a ...", "has the unknown key ...", "has a ttl that is not ..."
- a key that is neither a string nor a list, an empty list, or a component that is not a non-empty string :: "has a key that is not a string or a array", "has a empty key array", "has a key component that is not a non-empty string"
- a `syslog.*` key component on a raw rule, or one the envelope does not have :: "keys on ..., which is not a envelope field this rule type carries"
- a regexp naming an unknown token, or one that will not compile :: "uses the unknown token ...", "does not compile"
- one beside a `stages` gate :: "is beside capture_regexp... stages are the whole matcher"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

The `messages:` test form, the lines fed in order... the capture line then
the offense, and the offense then the capture where the daemon allows both,
with negatives for a capture line alone and an offense whose capture line
never comes. See [tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - messages:
        - "Jul  8 02:10:03 ldap-server slapd[1183]: conn=2048 fd=30 ACCEPT from IP=203.0.113.7:52001 (IP=0.0.0.0:636)"
        - "Jul  8 02:10:04 ldap-server slapd[1183]: conn=2048 op=1 RESULT tag=97 err=49 text="
      found: 1
      data:
        SRC: "203.0.113.7"
  negative:
    # an ACCEPT alone is context, not a offense
    - message: "Jul  8 03:20:00 ldap-server slapd[1183]: conn=4000 fd=50 ACCEPT from IP=192.0.2.20:41000 (IP=0.0.0.0:636)"
      found: 0
      undefed: ["SRC"]
```

## Shipped rules using it

- `syslog/slapd` :: The `ACCEPT` line's address, kept under the `conn=` id for the `err=49` result.
- `syslog/sendmail-reject` :: The relay's address under the queue id, for the No such user line logged after.
- `raw/mongodb-auth-legacy` :: The `end connection` address under the `[connN]` id, the offense logged first.
- `syslog/sshd-ddos`, `syslog/sshd-extra`, `syslog/sshd-aggressive` :: The `Connection from` address under the session's host, daemon, and pid, for the failures that log none.

## See also

- [`message_regexp`](message_regexp.md) :: The keyed entries that resolve through it and park to wait on it.
- [`capture`](capture.md) :: The same harvest on json, keyed on fields.
- [`stages`](stages.md) :: Order and counts across lines, which correlation knows nothing of.
- [`mungers`](mungers.md) :: Whose fields a completed offense takes from the capture line.
- [correlation](../rules.md#correlation-offense-and-address-on-different-lines) :: Both arrival orders and the envelope keys, in the type overview.
