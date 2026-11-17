# banished... what an address has already been banished for

A `banished` gate holds on an address by what the galla has banished it
for... that it is banished now, or that it has been so many times of late.
A line from a banished address means the ban is not holding, and an address
banished three times this month has earned a shorter rope than one that has
not been.

```yaml
# a ban that is not holding... a line from an address a minute into its ban
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - banished: { var: SRC, now: true, for: 60 }
  - detection_var: [ SRC ]
```

```yaml
# a shorter rope for one banished three times this month
max_score: 1
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - banished: { times: 3, within: 2592000 }
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `var`
- vetoes :: yes
- needs :: the galla's own brands, `banished` and `banishments`
- repeatable :: yes, each entry is a gate of its own

## Told

- `var` :: The found var holding the address, in place of the offender.
- `now` :: `true` to hold on an address that is banished, `false` on one that is not.
- `for` :: Beside a true `now`, seconds it has to have been banished for.
- `times` / `within` :: How many times it has to have been banished, and within how many seconds back.

It has to be told a `now` or a `times`, and may be told both, everything
asked having to be so. `now: false` with a `times` holds on an address
banished often of late but not now.

`times` and `within` go only together, `within` 90 days at the most, as
that is as far back as the galla remembers. It remembers the last
[`banished_history`](../configuration.md#counting-and-banning) bans of an
address, 20 unless set, and a `times` over that does not load, as it could
never hold.

`for` is there because a line or two just after a ban are ones already on
their way.

## Where it goes

With out a `var` it keys on the offender, so it goes below the `ban_var`
that names one, and is asked of each. With a `var` it is asked once for the
offense, and is the only way a detection rule can have a `banished` gate.

The first example catches a ban that is not holding, which no count can
see... the ban put in the wrong table, an IPv6 path round it, or a proxy
in front of the daemon. List that rule ahead of the one that banishes, as
it only sights. The second, listed ahead of the service's ordinary rule,
banishes a repeat offender on the first hit.

## When it does not hold

An offender it does not hold for is dropped, and an offense left with none
is vetoed, its line going on to the rules after this one.

It fails closed. A `var` the offense lacks holds nobody, and a ban that does
not say when it was made fails a `for`.

What it reads are brands the galla sets on each address it banishes,
`banished` for as long as the ban lasts and `banishments` with when each
one was. So it knows what any brand knows... it survives a restart, and
over a Redis tablet it is shared with the fleet, a ban made by one host
seen by the rest.

It is the galla's own account of it. A ban lifted by hand in the kur is not
known of here, and one whose length is the kur's to choose is taken as a
day long.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- a `var` that is not a string :: "has a var that is not a non-empty string"
- a `for` that is not a whole number of one or more :: "has a for that is not a positive int of seconds"
- a `times` that is not a whole number of one or more :: "has a times that is not a positive int"
- a `within` over 7776000, or not a whole number of one or more :: "has a within that is not a positive int of seconds, 7776000 at the most"
- neither `now` nor `times` :: "has neither now nor times"
- a `times` or a `within` with out the other :: "has a times with out a within, or a within with out a times"
- a `for` with out a true `now` :: "has a for with out a now that is true"
- a `times` over `banished_history`, when a galla binds the rule :: "has a
  banished gate asking for ... bans, and the galla remembers only the last
  ..."

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It reads brands, so the test's own mark store stands in. Seed the two with
`marks_before`... `banished` under the address, its `set` when the ban was
made and its `ttl` how long it lasts, and `banishments` under the address,
valued with the epoch of each ban, a space between them. The test clock
starts at `1000000000`. See
[Proving brands and gates](../rules.md#proving-brands-and-gates), and
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    # banished three times within the month
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for neti from 203.0.113.9 port 4711 ssh2"
      marks_before:
        - name: banishments
          key: "203.0.113.9"
          value: "999000000 999500000 999900000"
          ttl: 7776000
      found: 1
  negative:
    # the first of them a month and more back
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for neti from 203.0.113.9 port 4711 ssh2"
      marks_before:
        - name: banishments
          key: "203.0.113.9"
          value: "997000000 999500000 999900000"
          ttl: 7776000
      found: 0
```

## See also

- [the galla's own brands](../rules.md#the-gallas-own-brands) :: The two brands this reads, and what sets them.
- [`marked`](marked.md) :: Reads the same brands, with no count or age asked.
- [`breadth`](breadth.md) :: Reads the hits not yet banished on, where this reads the bans.
