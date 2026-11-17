# concurrent... too many at once

A `concurrent` gate holds when a key has been seen with more than
`more_than` different values within the last `seconds`, this offense's
among them. One account logged in from three addresses in the one ten
minutes is an account shared, or one that is not its owner's any more.

```yaml
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - concurrent: { by: USER, of: SRC, more_than: 2, seconds: 600 }
  - detection_var: [ SRC ]
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
- `of` :: The found var whose different values are counted.
- `more_than` :: How many values a key may have at once and the gate not hold.
- `seconds` :: How long a value counts after it was last seen.

A bare `by` is a list of one. `more_than` is one or more, so a key with one
value never holds.

A value seen again stays one value, its `seconds` starting over. It says
what [`distinct`](../rules.md#distinct-counting-how-many-not-how-often)
says, but `distinct` is how the rule itself counts, and a rule counts only
one way. This is a gate, so it sits beside whatever counting the rule does.

## Where it goes

It reads no offender, so it may sit above the `ban_var`.

Every offense that reaches it has its value noted, whether or not it held.
A gate above it that vetoes keeps the value out, and one below it does not.

## When it does not hold

A vetoed offense is vetoed as by any gate... it counts toward no rule's
score, and the line goes on to the rules after this one.

It fails closed. An offense lacking one of the `by` vars or the `of`, or
holding the `of` empty, is vetoed and noted nowhere.

## What it leaves behind

The values of each key and when each was last seen, kept per watcher, so
the same key on two watchers is two sets. A key holds a thousand values at
most, the longest unseen let go first, and the keys are bounded as the mark
store is, at ten thousand. They are not shared with a fleet, and are
forgotten at a restart.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `by`, `of`, `more_than`, or `seconds` :: "lacks a ..."
- a `by` that is not a string or a list of them :: "has a by that is not a non-empty string or a non-empty array of them"
- an `of` that is not a string :: "has a of that is not a non-empty string"
- a `more_than` that is not a whole number of one or more :: "has a more_than that is not a positive int"
- a `seconds` that is not a whole number of one or more :: "has a seconds that is not a positive int of seconds"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture, what it has seen being its own, and every test entry
starts with nothing seen. A `messages` test feeds a key its values, with an
`advance` to let one stop counting. See
[Proving order and time](../rules.md#proving-order-and-time), and
[tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - concurrent: { by: USER, of: SRC, more_than: 1, seconds: 600 }
  - detection_var: [ SRC ]
tests:
  positive:
    # the same address twice is one, and a second address is two
    - messages:
        - "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for neti from 192.0.2.7 port 4711 ssh2"
        - "Jul 12 08:26:49 mail01 sshd[2279]: Accepted password for neti from 192.0.2.7 port 4712 ssh2"
        - message: "Jul 12 08:27:49 mail01 sshd[2280]: Accepted password for neti from 203.0.113.9 port 4713 ssh2"
          found_after: 1
      found: 1
```

## See also

- [`novel`](novel.md) :: Holds on one value new to a key, where this holds on too many at once.
- [`after`](after.md) :: Counts how often a key is seen, where this counts its different values.
- [`travel`](travel.md) :: Two addresses too far apart for the time between them.
