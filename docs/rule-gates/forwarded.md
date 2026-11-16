# forwarded... the client behind a proxy

A `forwarded` gate names the real client of a request that came through
proxies, lifting its address into a found var for the `ban_var` below it.
Behind a load balancer every line has the balancer's address, and banning
that bans everyone. Taking the header at its word instead lets whoever sent
the request write in any address they like to have banished. So the header
is believed only as far as the proxies are trusted.

```yaml
rule_gates:
  - gate:
      - field: event
        values: [ fail ]
  - forwarded: { var: xff, peer: host, trusted: [ 10.0.0.0/8 ], into: CLIENT }
  - ban_var: [ CLIENT ]
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: a found value, the header in `var` and the address in `peer`
- vetoes :: no, it only lifts
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `var` :: The found var holding the forwarding header.
- `peer` :: The found var holding the address the request came from.
- `trusted` :: A CIDR, or a list of them, of the proxies whose word is taken.
- `into` :: The found var the client's address is lifted into.
- `max_hops` :: The most hops read before it gives up.
  - default :: 10

A request whose `peer` is not a trusted proxy is the peer's, and its
header is ignored. One whose peer is a trusted proxy is read from the
right, each address a hop nearer the client, and the first that is not a
trusted proxy is the client. Everything to the left of it was written by
that client or before it, and is never read... so a forged address put
ahead of the real one is never the one banished.

It reads an `X-Forwarded-For` list, addresses a comma apart, or a
`Forwarded` one, the `for=` of each hop. An address may have a port after
it, or be an IPv6 one in brackets.

## Where it goes

Above the `ban_var` naming its `into`. Both are of the offense phase, so
the order written is the order run, and written below the `ban_var` the
lift comes too late to be named.

## When it does not hold

It always holds. It lifts nothing when it can not say... a peer that is no
address, a trusted peer with no header, a hop that is not an address, more
hops than `max_hops`, or a chain of nothing but trusted proxies... and the
`ban_var` below it then names nobody.

The header has to be in the log to be read. An access log's common and
combined formats have none, so the server's log format has to be told to
write it, as a json log or a format of its own.

## What it leaves behind

The client's address in `into`, for the `ban_var` and every gate below it
to read. It never lifts over a value the offense already has.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `var`, `peer`, `trusted`, or `into` :: "lacks a ..."
- a `var`, `peer`, or `into` that is not a string :: "has a ... that is not a non-empty string"
- a `trusted` that is not a string or a list of them :: "has a trusted that is not a non-empty string or a non-empty array of them"
- a `trusted` entry that is not an address or a CIDR :: "trusted entry "..." is not a IPv4 or IPv6 address or CIDR"
- a `trusted` CIDR with a prefix the family has no bits for :: "trusted entry "..." has a invalid prefix length"
- a `max_hops` that is not a whole number of one or more :: "has a max_hops that is not a positive int"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs nothing, so a rule's tests judge it as the galla does. Prove the
forged hop is passed over, and an untrusted peer named in its own right.
See [tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    # the forged 192.0.2.66 is to the left of the real client, never read
    - message: '{"event":"fail","host":"10.0.0.5","xff":"192.0.2.66, 198.51.100.7, 10.0.0.9"}'
      found: 1
      data:
        CLIENT: "198.51.100.7"
    # a peer that is no proxy of yours is the client, whatever it claims
    - message: '{"event":"fail","host":"203.0.113.9","xff":"198.51.100.8"}'
      found: 1
      data:
        CLIENT: "203.0.113.9"
```

## Shipped rules using it

None. Which proxies are yours is yours to say.

## See also

- [`ban_var`](ban_var.md) :: Names the client it lifts.
- [`network`](network.md) :: The other gate that only lifts an address-derived var.
- [`address`](address.md) :: Asks what kind of address the client turned out to be.
