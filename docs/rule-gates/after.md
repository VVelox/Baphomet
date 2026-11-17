# after... only once a key has been seen enough

An `after` gate is [`limit`](limit.md) the other way about... it vetoes the
first offenses of a key and holds from the `count`th within `seconds` on.
A rule's own count is kept by its offender. This one is kept by anything,
which is how a rule says twenty failures against one account, whoever they
came from.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for (?<USER>\S+) from %%%%SRC%%%%'
  - after: { by: USER, count: 20, seconds: 600 }
  - ban_var: [ SRC ]
max_score: 1
```

That banishes every source that goes on trying the account once it is
under a spread-out attack, each on its first try, where
[`distinct`](../rules.md#distinct-counting-how-many-not-how-often) would
count how many sources there were.

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: a found value, the `by` vars joined
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `by` :: The found var, or a list of them, whose values joined are the key.
- `count` :: How many offenses of a key it takes, two or more.
- `seconds` :: How long they have to land within.

A bare `by` is a list of one. A key differing in any one part is another
key, counted on its own.

The window slides. An offense holds when it and the `count` less one before
it all landed within `seconds`, wherever a window might be said to start.
Exactly `seconds` from the oldest of them is not within. Once a key is
there, every offense of it holds while the last `count` stay that close.

## Where it goes

It reads no offender, so it may sit above the `ban_var`.

Listed ahead of the service's ordinary rule, the line of a vetoed offense
falls through to be counted as before, so the first nineteen failures are
still counted by the ordinary rule and the twentieth on banishes outright.

Every offense that reaches it is noted under its key, whether or not it
held. A gate above it that vetoes keeps the offense out of the count, and
one below it does not.

## When it does not hold

A vetoed offense is vetoed as by any gate... it counts toward no rule's
score, and the line goes on to the rules after this one.

It fails closed. An offense lacking one of the `by` vars has nothing to be
counted under and is vetoed.

## What it leaves behind

The times of the last `count` offenses of each key, kept per watcher, so
the same key on two watchers is counted apart on each. They are bounded as
the mark store is, at ten thousand keys, a key pushed out by a flood of
others starting over. They are not shared with a fleet, and are forgotten
at a restart.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `by`, `count`, or `seconds` :: "lacks a ..."
- a `by` that is not a string or a list of them :: "has a by that is not a non-empty string or a non-empty array of them"
- a `count` under two, or not a whole number :: "has a count that is not a int of two or more"
- a `seconds` that is not a whole number of one or more :: "has a seconds that is not a positive int of seconds"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture, what it has seen being its own, and every test entry
starts with nothing seen. A `messages` test walks the count up, with an
`advance` to let the oldest slide out. See
[Proving order and time](../rules.md#proving-order-and-time), and
[tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for (?<USER>\S+) from %%%%SRC%%%%'
  - after: { by: USER, count: 3, seconds: 600 }
  - ban_var: [ SRC ]
max_score: 1
tests:
  positive:
    # three sources at one account, and the third is the one that holds
    - messages:
        - "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for neti from 192.0.2.10 port 4711 ssh2"
        - "Jul 12 08:25:50 mail01 sshd[2279]: Failed password for neti from 198.51.100.20 port 4712 ssh2"
        - message: "Jul 12 08:25:51 mail01 sshd[2280]: Failed password for neti from 203.0.113.30 port 4713 ssh2"
          found_after: 1
      found: 1
```

## See also

- [`limit`](limit.md) :: Lets the first offenses of a key by, where this vetoes them.
- [`concurrent`](concurrent.md) :: Counts how many different values a key has, where this counts how often it is seen.
- [`sum`](sum.md) :: Adds up a number for a key, where this adds up offenses.
