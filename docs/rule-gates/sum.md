# sum... how much, not how often

A `sum` gate is [`after`](after.md) for a number... it adds a found var to
a running total for a key and holds while what the key has added up to with
in `seconds` is above a mark. The bytes sent to one client in an hour, say,
off an access log.

```yaml
rule_gates:
  - status: [ 200, 206 ]
  - sum: { by: host, of: bytes, above: 1000000000, seconds: 3600 }
  - detection_var: [ host ]
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: a found value, the `by` vars joined
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `by` :: The found var, or a list of them, whose values joined are the key.
- `of` :: The found var holding the number to add.
- `above` :: What the total has to be more than.
- `seconds` :: How far back it is added up over.

A bare `by` is a list of one. The number may have a fraction, and adds as
written. A total of exactly `above` does not hold.

The total is kept in sixty spans of the `seconds`, each a whole second or
more, so what falls out of it does so a span at a time. A span counts while
any of it is within `seconds`, so the total may run up to one span long
and never short. Once above the mark it holds on every offense of the key
while the total stands, whatever that offense added.

## Where it goes

It reads no offender, so it may sit above the `ban_var`.

Every offense that reaches it adds to the total, whether or not it held. A
gate above it that vetoes keeps the number out of the total, and one below
it does not.

## When it does not hold

A vetoed offense is vetoed as by any gate... it is not counted, and the
line goes on to the rules after this one.

It fails closed. An offense lacking one of the `by` vars, or whose `of` is
not a number of zero or more, adds nothing and is vetoed. An access log's
`-` for no bytes sent is no number.

## What it leaves behind

The totals, kept per watcher, so the same key on two watchers adds up
twice over. They are bounded as the mark store is, at ten thousand keys, a
key pushed out by a flood of others starting over. They are not shared with
a fleet, and are forgotten at a restart.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `by`, `of`, `above`, or `seconds` :: "lacks a ..."
- a `by` that is not a string or a list of them :: "has a by that is not a non-empty string or a non-empty array of them"
- an `of` that is not a string :: "has a of that is not a non-empty string"
- an `above` that is not a number over nothing :: "has a above that is not a positive number"
- a `seconds` that is not a whole number of one or more :: "has a seconds that is not a positive int of seconds"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture, the totals being its own, and every test entry starts
with none. A `messages` test adds the total up, with an `advance` to let a
span fall out. See [Proving order and time](../rules.md#proving-order-and-time),
and [tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - status: [ 200 ]
  - sum: { by: host, of: bytes, above: 1000000, seconds: 3600 }
  - detection_var: [ host ]
tests:
  positive:
    # six hundred thousand is not above the mark, and twice it is
    - messages:
        - '203.0.113.11 - - [12/Jul/2026:08:15:50 -0500] "GET /backup.tar HTTP/1.1" 200 600000 "-" "curl/8.0"'
        - message: '203.0.113.11 - - [12/Jul/2026:08:16:50 -0500] "GET /backup.tar HTTP/1.1" 200 600000 "-" "curl/8.0"'
          advance: 60
          found_after: 1
      found: 1
```

## See also

- [`after`](after.md) :: Counts offenses for a key, where this adds up a number.
- [`limit`](limit.md) :: Holds a key to so many offenses.
