# dnsbl... what a blocklist says of an address

A `dnsbl` gate asks one or more DNS blocklists about an address and holds
when any of them lists it... what a mail server does with
`reject_rbl_client`, for any rule.

```yaml
rule_gates:
  - ban_var: [ SRC ]
  - dnsbl:
      zones: [ bl.example.org, dnsbl.example.net ]
      codes: [ 127.0.0.2, 127.0.0.4 ]    # only these answers count
max_score: 1
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `var`
- vetoes :: yes
- needs :: `enable_dnsbl`, off by default, and the optional `Net::DNS` and `POE::Component::Client::DNS` modules
- repeatable :: yes, each entry is a gate of its own

## Told

- `zones` :: The zone to ask, or a list of them.
- `var` :: The found var holding the address to check, in place of the offender.
- `codes` :: The answer, or a list of them, that counts as a listing.
  - default :: any answer a zone lists with
- `negate` :: True to hold when no zone lists the address.
- `on_servfail` :: What a failed lookup does when no zone lists the address, `pass` or `fail`.
  - default :: `fail`
- `zone_into` :: The found var the zone that listed the address is lifted into.
- `code_into` :: The found var the answer it listed it with is lifted into.

A zone lists an address by answering the lookup of it with an address of
its own out of `127.0.0.0/8`, which one saying why. `codes` narrows the
listing to the answers you care about.

## Where it goes

With no `var` it keys on the offender, so it goes below the `ban_var`.
With a `var` it is asked once of the whole offense.

Keep it the last of a rule's gates that judge, so a cheaper gate's veto
spares the lookup. The lookups ride the machinery of
[`reverse_dns`](reverse_dns.md)... the same optional modules,
`rdns_timeout`, a one minute cache, and under a running galla the
background engine, so a cold address fails its first line and is answered
for the next.

## When it does not hold

A veto drops the offense, or with no `var` drops the offender it does not
hold for, the offense vetoed only when none are left. A vetoed offense
does not consume the line.

**It tells a third party who you were talking to.** Every lookup hands the
address to whoever runs the zone, so the gate sits behind a consent of its
own, `enable_dnsbl`, off by default. With out it, or with out the modules,
the gate fails closed, and the galla says so loudly at start. An address
on your `internal` list is never asked about and is taken as on no list,
so a negated gate holds for it. Most public blocklists also meter or
refuse queries that come by way of a large shared resolver, so read a
zone's terms before naming it.

**A zone that could not be asked clears nobody.** A listing in any zone
stands, whatever became of the others. With no listing, a timeout or
SERVFAIL settles the gate by `on_servfail`, `negate` or not. Two answers
are read as a failed lookup and never as a listing... one out of
`127.255.255.0/24`, which is how a zone says it refused the query, and one
that is not out of `127.0.0.0/8` at all, which is what a parked or
hijacked zone gives. A value that is not an address fails closed.

## What it leaves behind

With a `zone_into` or `code_into`, the first zone to list the address and
the first counted answer it gave, so the EVE event says why. Either needs
a `var`, under the rules [`country`'s `into`](country.md#told) has. A gate
holding on no listing, as under `negate`, lifts nothing.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `zones` :: "lacks a zones"
- a `zones` that is not zone names :: "has a zones that is not a zone name or a non-empty array of them"
- a `codes` that is not out of 127.0.0.0/8 :: "has a codes that is not a address out of 127.0.0.0/8 or a non-empty array of them"
- an `on_servfail` other than `pass` or `fail` :: "has a on_servfail that is not one of pass or fail"
- a `var`, `zone_into`, or `code_into` that is not a string :: "has a ... that is not a non-empty string"
- a `zone_into` or `code_into` with no `var` :: "has a zone_into or code_into, which needs a var to lift the listing of"

A zone name has to have at least two labels.

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

The `dns` fixture's `dnsbl` map stands in for the blocklists, a zone to a
map of address to what the zone answers, each a list, `nxdomain`, or
`servfail`. Anything unfixtured answers servfail, so an address a zone
does not list is written `nxdomain`, not left out. With out the map the
gate is skipped. Your `internal` list is config a rule file has none of,
so in a test every address is asked. See
[proving lookups](../rules.md#proving-lookups), and
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    # on a blocklist
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for oracle from 203.0.113.9 port 4711 ssh2"
      dns:
        dnsbl:
          bl.example.org:
            "203.0.113.9": [ "127.0.0.2" ]
      found: 1
```

## See also

- [`reverse_dns`](reverse_dns.md) :: The lookup machinery it rides, asking what an address calls itself.
- [`namtar_list`](namtar_list.md) :: A blocklist you keep yourself, asked of a file and told to nobody.
- [configuration](../configuration.md#lookups-dns-and-geoip) :: `enable_dnsbl` and `rdns_timeout`.
