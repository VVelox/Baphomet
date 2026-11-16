# network... the network as a found var

A `network` gate lifts the network an address is in into a found var, and
does nothing else. It judges nothing and vetoes nothing. An attack that
comes from one address after another out of the one provider stays under
every count kept by address, and is one key once it is counted by network.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - network: { var: SRC, into: NET }
  - after: { by: NET, count: 30, seconds: 600 }
  - ban_var: [ SRC ]
max_score: 1
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: a found value, the address in `var`
- vetoes :: no, it only lifts
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `var` :: The found var holding the address.
- `into` :: The found var the network is lifted into, as a CIDR.
- `v4` :: The prefix length an IPv4 address is cut to, 1 to 32.
  - default :: 24
- `v6` :: The prefix length an IPv6 address is cut to, 1 to 128.
  - default :: 64

## Where it goes

Above the gates that read what it lifts. It is of the offense phase, so
only those of the offense phase can read it, and of those only the ones
written below it.

## When it does not hold

It always holds. A value that is not an address, or a var the offense
lacks, lifts nothing, and what reads the var then fails closed on its own.

## What it leaves behind

The network in `into`, written `198.51.100.0/24` or `2001:db8:1:2::/64`.
An IPv4 address written in the `::ffff:` form is cut and written as the
IPv4 address it is. It never lifts over a value the offense already has.
What can read it is what can read
[`country`'s `into`](country.md#what-it-leaves-behind)...
[`after`](after.md), [`limit`](limit.md), [`sum`](sum.md),
[`distinct`](../rules.md#distinct-counting-how-many-not-how-often), and
the mark gates.

This only names the network. Banishing one is the config's
[subnet banning](../configuration.md#subnet-banning).

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `var` or no `into` :: "lacks a ..."
- a `var` or `into` that is not a string :: "has a ... that is not a non-empty string"
- a `v4` out of 1 to 32 :: "has a v4 that is not a prefix length of 1 to 32"
- a `v6` out of 1 to 128 :: "has a v6 that is not a prefix length of 1 to 128"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs nothing, so a rule's tests judge it as the galla does, and the
`data` of a test whose rule fires shows what it lifted. A rule counting
by network with `after` proves itself with a `messages` test walking
enough addresses out of the one network. See [tests](../rules.md#tests)
for the shape.

## Shipped rules using it

None.

## See also

- [`after`](after.md) :: Counts the network once it is a key.
- [`asn`](asn.md) :: The network an address is routed by, from a database, where this cuts by prefix.
- [subnet banning](../configuration.md#subnet-banning) :: Banishing the network as a whole CIDR.
