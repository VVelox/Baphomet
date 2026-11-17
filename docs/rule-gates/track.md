# track... harvesting a line into a record

A `track` gate files what a line found under a joining id, building up a
[tracked record](../rules.md#tracked-records-state-that-accumulates-across-lines)
one line at a time, newest value winning. It vetoes nothing. A daemon that
logs one transaction over several lines, postfix and its queue id say, says
who to ban on one line and what was done on another, and the record is what
lets a later line be judged by the earlier ones.

```yaml
track_only: true
rule_gates:
  - daemons: [ postfix/smtpd ]
  - message_regexp:
      - '^(?<postfix_queueid>[0-9A-F]+): client=\S+\[(?<postfix_client_ip>[^\]]+)\]'
  - track:
      name: mail-queue
      key: postfix_queueid
      fields: [ postfix_client_ip, postfix_sasl_username ]
      ttl: 3600
  - ban_var: [ postfix_client_ip ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: a found value
- vetoes :: no, it only stores
- needs :: the galla's tracked-record store
- repeatable :: yes, each entry is a gate of its own, one per record

## Told

- `name` :: The record's name.
- `key` :: The found var the record is kept under, or a list of them joined into one compound key.
- `fields` :: The found vars to contribute.
  - default :: everything found
- `ttl` :: Seconds the record lives with out a line naming its key.
  - default :: 3600
- `count` :: A field of the record to keep a tally in, one more per line harvested.

A bare string `key` is taken as a list of one. A line with out a value for
every part of the key, or with a empty one, is no part of any record and
harvests nothing. `fields: []` contributes nothing and is how a rule that
only reads a record still declares it, the read needing a `track` to be a
read of. A `count` field some line gave as other than a whole number starts
the tally over at one.

`track_only: true` on the rule is `mark_only`'s sibling... the rule
harvests, never counts toward a ban, and does not consume the line.

## Where it goes

**Below the `tracked` and `not_tracked` that read its record.** Written
above them, the read follows the write, so a `not_tracked` can never hold
and a `where` judges what this very line just filed rather than the
history.

**Below the matcher whose captures it files.** What is harvested is the
data of each offense the line made, as it stood before any gate below the
matcher judged it away, or the line's own fields when it made none. Above
the matcher there are no captures yet, so only the parsed fields go in.

## When it does not hold

It always holds, and it is asked whether or not the matcher hit and whether
or not a gate that judges held, a record being of the transaction and not
of offenses. A line the matcher missed is filed from its own fields, which
on a syslog line are none unless `message_json` or `mungers` laid some
down. Only a line gate above it that turns the line away outright stops
it, `daemons` and `ignore` being the usual two... the one because a
postfix record has no business reading sshd lines, the other because
`ignore` is the operator saying the line is not evidence. A `tracked` or
`not_tracked` that refuses the offense does not stop it.

## What it leaves behind

A record in the galla's tracked store, a hash of fields under the name and
key. Each line lays its fields over what the key holds, a field a line is
silent on keeping what a earlier line gave. Every line naming the key
refreshes the `ttl`, even one contributing nothing, as postfix retries
deferred mail for days. A record that has aged out is not revived... a
expired id seen again is a new transaction reusing it, and starts empty.

A record holds at most 64 fields. Past that a new field name is dropped
while the ones held still update, and a `count` field the record does not
yet hold is kept out the same way. Each record name keeps at most 10000
keys, the soonest to expire going first.

Records are per galla, crossing watchers and rules but not kurs. They
survive a restart on the tracked tablet and are listed with
`baphomet tracked`. They are not fleet synced.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `name` or no `key` :: "lacks a name", "lacks a key"
- a `name` that is not a name :: "has a name that is not a name matching /^[a-zA-Z0-9_\-]+$/"
- a `key` that is not a string or a list of them :: "has a key that is not a non-empty string or a non-empty array of them"
- a `fields` that is not a list of strings :: "has a fields that is not a array of non-empty strings"
- a `ttl` that is not a positive whole number :: "has a ttl that is not a positive int of seconds"
- a `count` that is not a string :: "has a count that is not a non-empty string"
- the same record declared by a `track` above it :: "declares "..." twice, which leaves its key ambiguous"
- a `track_only` rule with no `track` :: "is track_only but has no track gate"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

`tracked_expected` asserts the record a run left, either live with the
named fields or, under `absent`, not there at all. `tracked_after` does the
same between lines of a `messages:` test. Where the rule file holds both
the harvest and the read, a multiline `messages:` test walking both lines
through one scope proves the record the rule really built. See
[Proving brands and gates](../rules.md#proving-brands-and-gates) and
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: "Jan  2 03:00:00 mx1 postfix/smtpd[111]: 1C36D185729: client=unknown[203.0.113.9]"
      tracked_expected:
        - name: mail-queue
          key: 1C36D185729
          fields: { postfix_client_ip: "203.0.113.9" }
```

## See also

- [`tracked`](tracked.md) :: Reads the record back, judging a line by it or lifting fields out of it.
- [`not_tracked`](not_tracked.md) :: Holds only when the key has no live record.
- [`mark`](mark.md) :: The one-scalar brand, where a record is a hash.
- [tracked records](../rules.md#tracked-records-state-that-accumulates-across-lines) :: The postfix story the three gates tell together.
