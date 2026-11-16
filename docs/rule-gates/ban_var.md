# ban_var... who the offense is counted against

A `ban_var` gate names the offenders of an offense... the captures or
fields whose value is the thing a hit is registered against and, at the
threshold, banished to Kur. For each var it is told that the offense has a
value for, that value is counted. Usually it is just `SRC`. Every rule has
to have a `ban_var` or a [`detection_var`](detection_var.md), never both.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: a found value, each var it is told
- vetoes :: no, it only names
- needs :: nothing
- repeatable :: no, a rule names who it counts against once

## Told

A list of one or more vars. A bare string is not taken as a list of one,
so `ban_var: SRC` is refused.

How a var resolves depends on the type... a regexp capture on syslog and
raw, a flattened field or a capture on json, so dotted paths work there,
and a parsed field on http and http_error, whose rules name `host` and
`client` (see [how the types differ](../rules.md#how-the-types-differ)).

Naming several is ordinary... both ends of a flow, say. Each is counted in
a bucket of its own and judged by the offender-keyed gates on its own. Two
vars naming the one address are one piece of evidence, and it counts once.

## Where it goes

It is where the offenders come to be. A gate keyed by the offender goes
below it. A gate above it in the offense phase can only read found values,
which is where the gates that lift the offender's address go...
[`forwarded`](forwarded.md) above a `ban_var` naming the client it lifts,
say.

[`ban_not_internal`](ban_not_internal.md) goes below it too. Above it
there is nobody named yet for it to spare, and it quietly does nothing.

## When it does not hold

It always holds. A var the offense has no value for names nobody, and an
offense it names nobody for still stands... it consumes the line, writes
its `found` event, and counts against no one. An offender-keyed gate below
it has nobody to ask and lets it by.

A value that is a hostname and not an address is handled as the watcher's
`usedns` has it, the first time a gate asks who the offenders are. By
default it banishes nobody. See [usedns](../usedns.md).

## What it leaves behind

The offenders, for every gate below it and for the counting. Every event
the match raises names each var and what each is worth, under
`subject_vars` and `subject_vars_scores`, and a terminal event adds
`subjects_crossed`, which of them tipped over. See [eve](../eve.md).

## Refused at load

- told other than a list of names :: "is not a non-empty array of non-empty strings"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A test's `data` asserts who the offense named, and an
[injection test](../rules.md#injection-tests-who-picks-the-offender) proves
a forged copy of the field can not change it. See
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for root from 203.0.113.9 port 4711 ssh2"
      found: 1
      data:
        SRC: "203.0.113.9"
```

## Shipped rules using it

- `syslog/sshd` :: The usual case, the one `SRC` capture.
- `%json/suricata-all%` :: Both ends of a flow, `src_ip` and `dest_ip`, with `ban_not_internal` below.
- `http/fakegooglebot` :: The parsed `host` of an access log line.

## See also

- [`detection_var`](detection_var.md) :: The same naming for a rule that only sights and banishes nobody.
- [`ban_not_internal`](ban_not_internal.md) :: Drops the offenders that are your own hosts.
- [`forwarded`](forwarded.md) :: Lifts the client behind a proxy for it to name.
- [usedns](../usedns.md) :: What becomes of an offender that is a hostname.
- [src_ip_var and the rest](../rules.md#src_ip_var--dest_ip_var--src_port_var--dest_port_var--user_var) :: Shape the EVE event and not who is banished.
