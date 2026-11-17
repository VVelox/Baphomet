# beacon... like clockwork

A `beacon` gate holds when the last `count` gaps between a key's offenses
are all much the same length. A host calling home every five minutes, or a
slow brute force on a timer, stays under every count, and is far too even
to be a person.

```yaml
rule_gates:
  - beacon: { by: [ SRC, dest ], count: 10, jitter: 0.1 }
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
- `count` :: How many gaps it takes, two or more.
- `jitter` :: How uneven the gaps may be, as a share of their average.
  - default :: 0.1
- `min_interval` :: The shortest average gap that can be a beacon, in seconds.
  - default :: 10
- `max_interval` :: The longest gap that does not start the key over, in seconds.
  - default :: 86400

A bare `by` is a list of one. `min_interval` has to be under `max_interval`.

How even is the gaps' standard deviation over their average, which has to
be at most `jitter`. Gaps of 300, 302, and 298 seconds are well under one
percent. An average shorter than `min_interval` is a burst and never holds,
however even. A gap longer than `max_interval` starts the key over, a
beacon that stopped and started again being two.

It takes `count` gaps, so `count` and one offenses, before the first can
hold. Once regular, every even offense after holds too, until an uneven one
breaks it, and it holds again only once that gap is out of the last
`count`.

## Where it goes

It reads no offender, so it may sit above the `ban_var`.

Every offense that reaches it is a gap measured, whether or not it held. A
gate above it that vetoes keeps the offense out of the rhythm, and one
below it does not.

## When it does not hold

A vetoed offense is vetoed as by any gate... it counts toward no rule's
score, and the line goes on to the rules after this one.

It fails closed. An offense lacking one of the `by` vars is vetoed. So is a
key's first offense, and the first after a gap past `max_interval`. An
offense that came in ahead of the key's last, as lines of two logs may, is
no gap... it is vetoed and not counted.

## What it leaves behind

The time of each key's last offense and the gaps before it, kept per
watcher, so the same key on two watchers is two rhythms. A key is forgotten
`max_interval` after it was last seen. They are bounded as the mark store
is, at ten thousand keys, a key pushed out by a flood of others starting
over. They are not shared with a fleet, and are forgotten at a restart.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `by` or no `count` :: "lacks a ..."
- a `by` that is not a string or a list of them :: "has a by that is not a non-empty string or a non-empty array of them"
- a `count` under two, or not a whole number :: "has a count that is not a int of two or more"
- a `jitter` that is not a number over zero :: "has a jitter that is not a positive number"
- a `min_interval` or `max_interval` that is not a whole number of one or more :: "has a ... that is not a positive int of seconds"
- a `min_interval` not under the `max_interval` :: "has a min_interval that is not under its max_interval"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture, what it has seen being its own, and every test entry
starts with nothing seen. A `messages` test with an `advance` on each line
walks a rhythm. See [Proving order and time](../rules.md#proving-order-and-time),
and [tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - beacon: { by: SRC, count: 3 }
  - detection_var: [ SRC ]
tests:
  positive:
    # three gaps of about five minutes, and the fourth line holds
    - messages:
        - "Jul 12 08:00:00 mail01 sshd[2278]: Failed password for neti from 203.0.113.9 port 4711 ssh2"
        - message: "Jul 12 08:05:00 mail01 sshd[2279]: Failed password for neti from 203.0.113.9 port 4712 ssh2"
          advance: 300
        - message: "Jul 12 08:10:02 mail01 sshd[2280]: Failed password for neti from 203.0.113.9 port 4713 ssh2"
          advance: 302
        - message: "Jul 12 08:15:00 mail01 sshd[2281]: Failed password for neti from 203.0.113.9 port 4714 ssh2"
          advance: 298
          found_after: 1
      found: 1
```

## See also

- [`after`](after.md) :: Holds on how often a key is seen, where this holds on how evenly.
- [`limit`](limit.md) :: Thins what this sights, every even offense after the first holding too.
