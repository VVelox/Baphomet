# sample... one in so many

A `sample` gate lets the first offense by, then one in every `every` after
it, whatever its key, and vetoes the rest. It thins a whole detection rule
that sights more than anyone will read. A [`limit`](limit.md) holds each
key to so many, so a flood from many keys gets through it, and what
`sample` lets by is a fair cut of all of it.

```yaml
rule_gates:
  - detection_var: [ SRC ]
  - sample: { every: 100 }
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: nothing, every offense being counted together
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `every` :: One offense in how many is let by, two or more.

## Where it goes

It reads no offender, so it may sit above the `ban_var`.

Only an offense that reaches it is counted, so a gate above it that vetoes
leaves the count as it was. A `mark` above it brands every offense, and one
below it only what was let by.

## When it does not hold

A vetoed offense is vetoed as by any gate... it is not counted, and the
line goes on to the rules after this one. On a banning rule it slows the
count by `every`.

## What it leaves behind

A count of the offenses asked of it, kept per watcher. It is not shared
with a fleet, and starts over at a restart, the first offense after one
being let by.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `every` :: "lacks a every"
- an `every` under two, or no whole number :: "has a every that is not a int of two or more"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture, the count being its own, and every test entry starts
from nothing. A `messages` test of more lines than `every` shows the cut.
See [tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - sample: { every: 3 }
  - detection_var: [ SRC ]
tests:
  positive:
    # the first is let by, the next two are not, and the fourth is
    - messages:
        - "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for neti from 192.0.2.10 port 4711 ssh2"
        - "Jul 12 08:25:50 mail01 sshd[2279]: Failed password for neti from 198.51.100.20 port 4712 ssh2"
        - "Jul 12 08:25:51 mail01 sshd[2280]: Failed password for neti from 203.0.113.30 port 4713 ssh2"
        - message: "Jul 12 08:25:52 mail01 sshd[2281]: Failed password for neti from 203.0.113.31 port 4714 ssh2"
          found_after: 2
      found: 2
```

## See also

- [`limit`](limit.md) :: Holds each key to so many, where this cuts across every key.
