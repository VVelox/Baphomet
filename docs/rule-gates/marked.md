# marked... only what already has a brand

A `marked` gate holds when the key it checks, the offender by default, has
a live brand of the name, or of any of a list of names. It is the reading
half of a [`mark`](mark.md)... a sshd failure counted heavier from a source
already branded `brute_force` wherever it earned the brand, or a login that
worked from a source holding any of the standard brands.

```yaml
rule_gates:
  - marked: { name: sshd-account-src, var: USER, value_not: SRC }
  - ban_var: [ SRC ]
  - marked: { names: [ brute_force, recon ], newer_than: 3600 }
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender | a found value
- vetoes :: yes
- needs :: the galla's mark store
- repeatable :: yes, each entry is a gate of its own

## Told

- `name` :: The brand to look for.
- `names` :: A list of brands, any one of which will do.
- `var` :: The found var whose value is the key.
  - default :: each offender
- `vars` :: The found vars whose values joined are one compound key.
- `value_is` :: The found var the brand's stored value has to equal.
- `value_not` :: The found var the brand's stored value has to differ from.
- `older_than` :: Seconds the brand has to have been set for, at least.
- `newer_than` :: Seconds the brand has to have been set for less than.
- `hosts` :: How many hosts of the fleet have to have set the brand.

Exactly one of `name` and `names`. `var` and `vars` exclude each other, as
do `value_is` and `value_not`. A var-keyed entry is checked against the
line's captures once for the offense. A var-less one is checked against
each offender, dropping the ones with out the brand. With `names`, each
listed brand is judged with every compare on its own, so an any-of never
holds on a brand whose value or age did not prove out.

A brand is as old as when it was first set, however often it has been set
since, so `older_than` is "still at it a day after being branded" and
`newer_than` "with in five minutes of the login". Both together are a span
of ages. `hosts` counts this host when it set the brand, and every other
the brand says did.

## Where it goes

**Below the `ban_var` that names the offender**, when it names no var.

**In a rule listed ahead of the one that brands.** Listed after it, the
gate sees the brand the same line just set... `syslog/sshd-spray` reading
`value_not: SRC` would find its own source and never fire. A vetoed reader
does not consume the line, so the brander after it still gets it.

## When it does not hold

It fails closed. A line with out the var, or vars, it keys on vetoes, and
so does a brand that has expired. A value compare with the stored value or
the found var missing can not be proven, and does not hold. Neither does
an age asked of a brand with no saying when it was set. With out a
[Redis tablet](../tablets.md) sharing brands there is only ever this host,
so `hosts: 2` never holds.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- both `name` and `names` :: "has both name and names"
- neither `name` nor `names` :: "has neither name nor names"
- a `name` that is not a name :: "has a name that is not a name matching /^[a-zA-Z0-9_\-]+$/"
- a `names` that is not a list of names :: "has a names that is not a non-empty array, each a name matching ..."
- a `var`, `value_is`, or `value_not` that is not a string :: "has a var that is not a non-empty string"
- a `vars` that is not a list of strings :: "has a vars that is not a non-empty array of non-empty strings"
- both `var` and `vars` :: "has both var and vars"
- both `value_is` and `value_not` :: "has both value_is and value_not"
- an `older_than` or `newer_than` that is not a positive whole number :: "has a older_than that is not a positive int of seconds"
- a `hosts` that is not a positive whole number :: "has a hosts that is not a positive int"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

The brands come from other rules, so `marks_before` seeds them, each entry
a `name`, a `key`, and optionally its `value`, its `set` time, its `ttl`,
and a `hosts` count. Prove it both ways... the seeded line fires, and the
same line unseeded is a negative. With out that negative a misspelled
brand name passes every test and never fires in the field. A value compare
is proved by seeding the stored value, once matching and once not. See
[Proving brands and gates](../rules.md#proving-brands-and-gates) and
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for root from 192.0.2.7 port 4711 ssh2"
      marks_before:
        - name: honeypot
          key: "192.0.2.7"
      found: 1
  negative:
    # the same line, no seed... the gate must veto
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for root from 192.0.2.7 port 4711 ssh2"
      found: 0
```

A vetoed line is no match at all, so the negative says `found: 0` with out
`undefed`. A brand outliving its `ttl` is proved with `advance:` on a
`messages:` entry, see
[Proving order and time](../rules.md#proving-order-and-time).

## Shipped rules using it

- `syslog/sshd-spray` :: A second source on an account `syslog/sshd-mark-users` branded, by `value_not: SRC`.
- `raw/citrix-vpn-traveler` :: The same, a VPN account seen from a second source.
- `syslog/sshd-condemned`, `json/suricata-condemned` :: A failure or alert from a source branded `brute_force`, weighted heavy.
- `syslog/sshd-breach`, `syslog/vsftpd-breach`, `syslog/courier-breach`, `raw/fortinet-breach` :: A login that worked from a source holding any standard brand, by `names`.
- `raw/citrix-condemned` :: A NetScaler AAA failure from a source branded `recon`, `exploit_attempt`, or `honeypot`.

## See also

- [`mark`](mark.md) :: Sets the brands this reads.
- [`not_marked`](not_marked.md) :: The inverse, holding when the brand is not set.
- [`sequence`](sequence.md) :: Asks that several brands were set in order, not only that they are set.
- [`banished`](banished.md) :: Reads the galla's own `banished` and `banishments` brands.
- [marks](../rules.md#marks-cross-rule-state-keyed-by-anything) :: How rules tie together over brands.
- [how old a brand is](../rules.md#how-old-a-brand-is-and-who-set-it) :: Age and fleet hosts, and how tests seed them.
- [the standard brands](../rules.md#the-standard-brands) :: The vocabulary the shipped readers gate on.
