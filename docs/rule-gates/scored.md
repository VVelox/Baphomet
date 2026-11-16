# scored... counted for enough

A `scored` gate holds when the hits the galla is counting against an
address add up to more than `above`, over every rule.
[`breadth`](breadth.md) says how many rules have counted an address, and
this how much they have counted it for. A source sitting just under the
thresholds of several rules at once is nearer a ban than any one of them
shows.

```yaml
max_score: 1
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - scored: { above: 8 }
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `var`
- vetoes :: yes
- needs :: the hits the galla is counting
- repeatable :: yes, each entry is a gate of its own

## Told

- `above` :: What the hits have to add up to more than.
- `seconds` :: How far back a hit is read.
  - default :: every live hit
- `var` :: The found var holding the address, in place of the offender.

A score of exactly `above` does not hold.

It reads the weight of each live hit, the shared bucket and each rule's
own, observe mode's and detection rules' included, with whatever a
[`weigh`](weigh.md) made of it. A hit a ban already cleared, or one older
than its rule's `find_time`, is not there to read. The hit this line is
about to be is not counted, as its weight is not known until it is.

## Where it goes

With out a `var` it keys on the offender, so it goes below the `ban_var`
that names one, and is asked of each. With a `var` it is asked once for the
offense, and is the only way a detection rule can have one.

Listed ahead of the service's ordinary rules, with a `max_score: 1`, it
banishes the address the moment it has been counted for enough anywhere,
and lets every other line fall through to be counted as before.

## When it does not hold

An offender it does not hold for is dropped, and an offense left with none
is vetoed, its line going on to the rules after this one.

It fails closed. A `var` the offense lacks holds nobody, and an address
never counted adds up to nothing.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `above` :: "lacks a above"
- an `above` that is not a number over nothing :: "has a above that is not a positive number"
- a `seconds` that is not a whole number of one or more :: "has a seconds that is not a positive int of seconds"
- a `var` that is not a string :: "has a var that is not a non-empty string"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A `scores` fixture stands in for the galla's counts, a map of address to
what its live hits add up to. It answers the same however far back the
gate reads, so `seconds` is proved galla-side only. With out the fixture
the gate is skipped. See [tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for neti from 203.0.113.9 port 4711 ssh2"
      scores:
        "203.0.113.9": 9
      found: 1
  negative:
    # the mark exactly is not more than it
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for neti from 203.0.113.10 port 4711 ssh2"
      scores:
        "203.0.113.10": 8
      found: 0
```

## See also

- [`breadth`](breadth.md) :: How many rules have counted an address, where this is how much.
- [`weigh`](weigh.md) :: Makes the hits this reads count for more or less.
- [weight](../rules.md#max_score--find_time--ban_time--weight) :: What a hit is counted with to begin with.
