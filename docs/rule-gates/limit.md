# limit... only so many of a key

A `limit` gate lets the first few offenses of a key by and vetoes the rest
until its window runs out. It is for a detection or `eve_only` rule that
sights more than it needs to say, one noisy source filling the EVE log with
the same event.

```yaml
rule_gates:
  - detection_var: [ SRC ]
  - limit: { by: [ SRC, USER ], count: 3, seconds: 300 }
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
- `seconds` :: The length of a window, measured from the first offense it let by.
- `count` :: How many offenses of a key a window lets by.
  - default :: 1

A bare `by` is a list of one. A key differing in any one part is another
key, with a window of its own.

The window is fixed, not sliding. It opens on the first offense of a key,
lets `count` by, and vetoes the rest until `seconds` after that first one.
The next offense then opens a new window, measured from itself.

## Where it goes

It reads no offender, so it may sit above the `ban_var`, and a detection
rule may have one.

Gates above it have had their turn by the time it is asked. A `mark` above
it brands every offense, and one below it only what was let by. Only an
offense that reaches it is counted into a window, so a gate above it that
vetoes leaves the window as it was.

## When it does not hold

A vetoed offense is vetoed as by any gate... it is not counted, and the
line goes on to the rules after this one. On a banning rule it slows the
count as well, what it vetoes never reaching the threshold.

It fails open. An offense lacking one of the `by` vars has nothing to be
held to and is let by, however many of them there are.

## What it leaves behind

The windows, kept per watcher, so the same key on two watchers is two
windows. They are bounded as the mark store is, at ten thousand keys, a
key pushed out by a flood of others starting over. They are not shared
with a fleet, and are forgotten at a restart.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `by` or no `seconds` :: "lacks a ..."
- a `by` that is not a string or a list of them :: "has a by that is not a non-empty string or a non-empty array of them"
- a `seconds` that is not a whole number of one or more :: "has a seconds that is not a positive int of seconds"
- a `count` that is not a whole number of one or more :: "has a count that is not a positive int"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture, its windows being its own, and every test entry
starts with none open. A `messages` test with an `advance` walks a window
open and shut. See [Proving order and time](../rules.md#proving-order-and-time),
and [tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - limit: { by: SRC, seconds: 300 }
  - detection_var: [ SRC ]
tests:
  positive:
    # the second is vetoed, and the window run out lets the third by
    - messages:
        - "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for neti from 203.0.113.9 port 4711 ssh2"
        - message: "Jul 12 08:25:50 mail01 sshd[2279]: Failed password for neti from 203.0.113.9 port 4712 ssh2"
          found_after: 1
        - message: "Jul 12 08:30:51 mail01 sshd[2280]: Failed password for neti from 203.0.113.9 port 4713 ssh2"
          advance: 301
          found_after: 2
      found: 2
```

## See also

- [`after`](after.md) :: The other way about, vetoing the first offenses of a key and holding from the `count`th on.
- [`sample`](sample.md) :: Thins a whole rule whatever the key, where this holds each key to so many.
