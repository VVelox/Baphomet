# address... what kind of address it is

An `address` gate holds when an address is of one of the kinds the address
space sets aside, for `is`, or of none of them, for `isnot`. No list of
yours has to name them. A source from behind a carrier's NAT is shared by
every customer behind it, and banning it bans them all. A bogon source in
a firewall log is spoofed traffic, not an attacker to banish.

```yaml
rule_gates:
  - ban_var: [ SRC ]
  - address: { isnot: [ private, cgnat, loopback ] }
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `var`
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `is` / `isnot` :: Exactly one. A kind, or a list of them.
- `var` :: The found var holding the address, in place of the offender.

The kinds...

- `private` :: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `fc00::/7`.
- `loopback` :: `127.0.0.0/8` and `::1`.
- `link_local` :: `169.254.0.0/16` and `fe80::/10`.
- `cgnat` :: `100.64.0.0/10`, a carrier's shared space.
- `documentation` :: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`.
- `multicast` :: `224.0.0.0/4` and `ff00::/8`.
- `bogon` :: Any address no one on the internet can have... all of the above, and `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4`, and `::`.

A bare kind is taken as a list of one. A list is read as any of its kinds,
so `is` holds on an address of one or more of them and `isnot` on one of
none.

## Where it goes

With no `var` it keys on the offender, so it goes below the `ban_var`.
With a `var` it is asked once of the whole offense. It asks nothing of
anyone and costs next to nothing, so it can go first among the gates that
judge.

## When it does not hold

A veto drops the offense, or with no `var` drops the offender it does not
hold for, the offense vetoed only when none are left. A vetoed offense
does not consume the line.

A value that is not an address, or a var the offense lacks, fails closed
whichever way the gate asks.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- an `is` or `isnot` that is not kinds :: "has a is that is not one of bogon, cgnat, documentation, link_local, loopback, multicast, private, or a non-empty array of them"
- a `var` that is not a string :: "has a var that is not a non-empty string"
- both `is` and `isnot` :: "has both is and isnot"
- neither `is` nor `isnot` :: "has neither is nor isnot"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs nothing, so a rule's tests judge it as the galla does, no fixture
asked for. Mind the documentation kind in a test... the addresses the
examples use are of it. See [tests](../rules.md#tests) for the shape.

```yaml
tests:
  negative:
    # a carrier's shared space, spared
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for root from 100.64.12.9 port 4711 ssh2"
      found: 0
```

## See also

- [`ban_not_internal`](ban_not_internal.md) :: Spares the hosts you listed as your own, where this knows the ones no list needs to name.
- [`network`](network.md) :: Lifts the network an address is in.
- [`namtar_list`](namtar_list.md) :: Addresses of a kind you name in a file of your own.
