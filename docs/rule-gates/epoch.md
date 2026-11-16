# epoch... a timestamp as seconds

An `epoch` gate reads a timestamp and makes the seconds since the epoch of
it, for a gate below to read as a number. It judges nothing and turns no
line away. A `fresh` gate needs it to tell old news, and with the hour or
the day lifted a `novel` gate can tell a login at an hour the account never
used.

```yaml
rule_gates:
  - epoch: { into: WHEN }                                    # the line's own
  - epoch: { var: started, format: '%Y-%m-%d %H:%M:%S' }     # a field, where it is
  - epoch: { var: time, into: WHEN, zone: utc }              # a field, into another
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: a found value, or the line's own timestamp
- vetoes :: no, it only lifts
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `var` :: The field holding the timestamp.
    - default :: the line's own timestamp, as the parser found it
- `into` :: The field the seconds go into.
    - default :: the `var`, converted where it is
- `format` :: How the timestamp is written, a `strptime` format or one of
      the names below.
    - default :: `auto`
- `zone` :: The zone of a timestamp that names none... `local`, `utc`, or
      an offset as `+02:00`.
    - default :: `local`
- `hour_into` :: The field the hour, 0 to 23, is lifted into.
- `weekday_into` :: The field the day of the week, 0 for Sunday to 6 for
      Saturday as `active_time` counts them, is lifted into.

The line's own timestamp is no field, so reading it needs an `into`, or an
`hour_into` or `weekday_into`, for the seconds to go somewhere. The hour
and the day are told in the `zone`, as is a timestamp that names no zone of
its own. An offset may be written `+0200` as well.

The formats that are names...

- `auto` :: Whichever of the others reads it, then the ways the parsers
      write one.
- `epoch` / `epoch_ms` / `epoch_us` :: Seconds, milliseconds, or
      microseconds since the epoch already.
- `iso8601` :: `2026-07-12T08:15:50`, a fraction of a second and a zone
      after it or not.

`auto` tells the units of a bare number apart by how many digits it has,
then tries `iso8601`, then a syslog `Jul 12 08:15:50`, an access log
`12/Jul/2026:08:15:50 -0500`, and the two error logs. A fraction of a
second is dropped under every format.

A timestamp with no year, as syslog's has none, is taken as this year's, or
as last year's when that would put it more than a day ahead of the line.

## Where it goes

It reads the line's fields, so it sees what is there when it is asked... a
json record's, an access log line's, what `mungers` and `message_json` laid
down above it. A capture of a `message_regexp` is never its `var`, wherever
the two are written. It writes to the line's fields too, never into an
offense already made, so an offense gate reading what it lifts needs it
above the matcher, as the `novel` below has it.

On a syslog rule write it below the `daemons` gate. The rule index only
reads the `daemons` gates leading the list, and with an `epoch` ahead of
them the rule is offered every line of the log and not just its own
daemon's.

With the hour lifted, [`novel`](novel.md) says a login at an hour the
account never used, where `active_time` can only say "outside office hours"
for everyone at once:

```yaml
rule_gates:
  - daemons: [ sshd ]
  - epoch: { hour_into: HOUR, zone: '-05:00' }
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - novel: { name: login-hour, by: USER, of: HOUR, after_seen: 20 }
  - detection_var: [ SRC ]
```

## When it does not hold

It always lets the line by. A timestamp that can not be read leaves the
field as it was, unset when it is an `into`, and what reads it judges that
for itself... a [`fresh`](fresh.md) below turns the line away, by default.

## What it leaves behind

The seconds in the `into`, and the hour and the day in theirs, as fields of
the line, read by every gate below it and by the offense made below it.
Nothing outlives the line.

## Refused at load

- neither a `var`, an `into`, an `hour_into`, nor a `weekday_into` :: has
      neither a var nor a into, and the line's own timestamp is no field to
      convert where it is
- a `zone` that is not `local`, `utc`, or an offset :: is not local, utc,
      or a offset as +02:00
- a key it does not know :: has the unknown key

A `format` is not vetted, so one that never reads a line's timestamp loads
and leaves every `into` unset.

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture. A positive test's `data` names the field it wrote, and
a timestamp with no year is placed by the test's virtual clock, base
`1000000000`, which is 2001-09-09T01:46:40Z. See
[tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - gate:
      - { field: event, value: fail }
  - epoch: { var: when, into: WHEN }
  - ban_var: [ ip ]
tests:
  positive:
    - message: '{"event":"fail","ip":"203.0.113.9","when":"2001-09-09T01:45:40Z"}'
      data:
        WHEN: 999999940
```

## See also

- [`fresh`](fresh.md) :: Turns away a line whose seconds are too old.
- [`novel`](novel.md) :: A value never seen before, the lifted hour say.
- [`active_time`](active_time.md) :: Named windows of the clock, the same
      for every key.
