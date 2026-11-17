# fresh... old news

A `fresh` gate turns a line away when the time it says it was written is
too long before it was read. A hit is counted when the line is read, so an
hour of backlog handed over at once, by a relay catching up or a log picked
up after an outage, reads as a burst happening now and can banish on events
long over. With this ahead of a rule's matcher, old news is not counted at
all.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - epoch: { into: WHEN }
  - fresh: { var: WHEN, within: 300 }
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: a found value, against the clock
- vetoes :: yes, it turns the line away
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `var` :: The field holding the time, in seconds since the epoch.
- `within` :: How many seconds old a line may be.
- `on_unparsed` :: What a line with no time to read does, `pass` or `fail`.
  - default :: `fail`

The seconds are what an [`epoch`](epoch.md) gate above it makes of a
timestamp. A line whose time is still to come, the clock that wrote it
running ahead, is fresh.

## Where it goes

Below the `epoch` that fills its `var`, and above the matcher, so a stale
line is turned away before anything is made of it. It reads the line's
fields, never a capture, wherever it is written.

On a syslog rule write the two below the `daemons` gate, as above. The rule
index only reads the `daemons` gates leading the list, and with an `epoch`
ahead of them the rule is offered every line of the log and not just its
own daemon's.

A syslog timestamp names no zone, so a log shipped in from a host in
another needs the `epoch` above it told the `zone`, or every line of it is
hours old or hours ahead.

## When it does not hold

The line is turned away outright, so nothing below it is asked and nothing
is harvested. A line with no time in the `var`, or one that is not a number,
can not be shown to be fresh and is turned away too, failing closed, unless
`on_unparsed` is `pass`.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not know :: "has the unknown key ..."
- no `var` or no `within` :: "lacks a ..."
- a `var` that is not a string :: "has a var that is not a non-empty string"
- a `within` that is not a positive whole number :: "has a within that is not a positive int of seconds"
- an `on_unparsed` that is neither `pass` nor `fail` :: "has a on_unparsed that is not one of pass or fail"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture. The line is read at the test's virtual clock, base
`1000000000`, which is 2001-09-09T01:46:40Z, so a timestamp a minute before
that is fresh and one an hour before is not. See [tests](../rules.md#tests)
for the shape.

```yaml
rule_gates:
  - gate:
      - { field: event, value: fail }
  - epoch: { var: when, into: WHEN }
  - fresh: { var: WHEN, within: 300 }
  - ban_var: [ ip ]
tests:
  positive:
    - message: '{"event":"fail","ip":"203.0.113.9","when":"2001-09-09T01:45:40Z"}'
  negative:
    # an hour old
    - message: '{"event":"fail","ip":"203.0.113.9","when":"2001-09-09T00:46:40Z"}'
    # no time to read
    - message: '{"event":"fail","ip":"203.0.113.9","when":"a while ago"}'
```

## See also

- [`epoch`](epoch.md) :: Makes the seconds it reads.
- [`startup`](startup.md) :: Keeps the backlog out by how long the galla has been up, for the logs whose lines have no time to read.
