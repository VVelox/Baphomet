# startup... only just started

A `startup` gate turns every line away while the galla has been up for less
than `grace` seconds. A galla that starts reads what was written to its
logs while it was down and counts all of it as happening now, so a minute
of failures from an hour ago reads as a burst. A rule this gate leads lets
that by uncounted.

```yaml
rule_gates:
  - startup: { grace: 120 }
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: the clock, how long the galla has been up
- vetoes :: yes, it turns the line away
- needs :: the galla's uptime
- repeatable :: yes, each entry is a gate of its own

## Told

- `grace` :: How many seconds after the galla starts lines are turned away.

[`fresh`](fresh.md) does the same by the time a line says it was written,
which is the better wherever the lines carry a time that can be read... it
keeps the backlog out and counts the lines that are new, where this keeps
everything out for the grace. This is for the logs whose lines carry no
such time.

## Where it goes

First. It reads nothing of the line, so leading the list it turns a line
away before anything else is made of it. It is one of the gates that read
only the parsed line, so a `daemons` gate right below it still leads for
the rule index, and the rule is still offered only its own daemon's lines.

## When it does not hold

The line is turned away outright, so nothing below it is asked and nothing
is harvested, for every line of the grace. A galla not started as a server,
as one a test drives, has nothing to wait out and lets every line by.

## Refused at load

- no `grace`, or a key it does not know :: lacks a grace / has the unknown
      key
- a `grace` that is not a positive whole number :: is not a positive int
      of seconds

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A test gives how long the galla has been up as an `uptime` fixture. With
none the gate is skipped and the line let by. See
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: "Jul 12 08:15:50 bastion sshd[4012]: Failed password for morgan from 198.51.100.23 port 51122 ssh2"
      uptime: 120
  negative:
    - message: "Jul 12 08:15:50 bastion sshd[4012]: Failed password for morgan from 198.51.100.23 port 51122 ssh2"
      uptime: 30
```

## See also

- [`fresh`](fresh.md) :: The better choice wherever a line has a time to
      read.
- [`pressure`](pressure.md) :: The other gate that reads nothing of the
      line.
