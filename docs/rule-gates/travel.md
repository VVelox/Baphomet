# travel... further than it could have gone

A `travel` gate holds when a key is seen at an address too far from the one
it was last seen at for the time between the two. An account that logs in
from one continent and an hour later from another did not fly there.

```yaml
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - travel: { name: last-login, by: USER, var: SRC, faster_than_kmh: 900 }
  - detection_var: [ SRC ]
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: a found value, the `by` vars joined, placed by the address in `var`
- vetoes :: yes
- needs :: MaxMind's City database, the `geoip_city_db` setting, read through the optional `IP::Geolocation::MMDB` module
- repeatable :: yes, each entry is a gate of its own

## Told

- `name` :: The brand the sightings are kept in.
- `by` :: The found var, or a list of them, whose values joined are the key.
- `var` :: The found var holding the address.
- `faster_than_kmh` :: The speed, in kilometres an hour, it has to have taken more than.
- `min_km` :: The least distance worth asking the speed of.
  - default :: 100
- `ttl` :: Seconds a sighting is kept.
  - default :: 2592000
- `km_into` / `kmh_into` :: The found vars the distance and the speed are lifted into.

A bare `by` is a list of one. It holds when the distance is `min_km` or
more and was covered faster than `faster_than_kmh`, so two addresses in one
city never trip it.

The distance is the great circle one less the accuracy radius the database
gives each place, and never under nothing, so an address placed only
roughly is not held to a point. Two sightings in the one second are taken
as a second apart, and one that came in ahead of the last, as lines of two
logs may, is as far off in time as it is.

`km_into` and `kmh_into` lift whole numbers, so the EVE event says how far
and how fast. They are lifted once there is a last sighting to measure
against, whether or not the gate held, and never over a value the offense
already has.

## Where it goes

It keys on a found value, so it is asked once for the offense and may sit
above the `ban_var`.

**Feed it only what the owner of the key can do.** A failed login from
anywhere would move where the account was last seen, so the gate belongs
on a rule matching logins that worked, and below any gate that could veto
one, so a login the rule turned down is not kept as a sighting. Put an
[`asn`](asn.md) gate above it to spare the carriers you know.

A gate that reads what `km_into` or `kmh_into` lifts goes below it.

## When it does not hold

A veto drops the offense, and the line goes on to the rules after this one.

It fails closed. It does not hold on a key's first sighting, on a last
sighting past its `ttl`, on an address the database can not place, or on an
offense lacking the address or part of the key. Of these, the unplaceable
address and the offense lacking a part are not kept as sightings either. If
some other rule set a brand of the same `name` with a value that is not a
sighting, the gate does not measure against it, and this sighting takes its
place.

With no city database loaded, unset or unloadable, it never holds, and the
galla says so at its start... "travel-gated rules are configured but no
city database is loaded". Places are cached for a minute. Mobile and VPN
addresses place badly, so keep it on a `detection_var`.

## What it leaves behind

Every offense that reaches the gate and can be placed is a sighting, and
takes the place of the key's last one whether or not the gate held. So an
intruder's login fires once, and the owner's next one from home fires
again... both true.

The sightings are [brands](../rules.md#marks-cross-rule-state-keyed-by-anything)
of the gate's `name`, keyed by the joined `by` values, each valued
`latitude longitude radius time` and kept `ttl` seconds. They are kept as
any brand is... across the watchers of a galla, across a restart, and
across a fleet on a Redis tablet, so a login on one host and then another
is measured. `baphomet marked` shows them.

The lifted `km_into` and `kmh_into` are found vars the gates below it and
the EVE event read.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `name`, `by`, `var`, or `faster_than_kmh` :: "lacks a ..."
- a `name` that is not a name :: "has a name that is not a name matching /^[a-zA-Z0-9_\-]+$/"
- a `by` that is not a string or a list of them :: "has a by that is not a non-empty string or a non-empty array of them"
- a `var`, `km_into`, or `kmh_into` that is not a string :: "has a ... that is not a non-empty string"
- a `faster_than_kmh` or `min_km` that is not a number over nothing :: "has a ... that is not a positive number"
- a `ttl` that is not a whole number of one or more :: "has a ttl that is not a positive int of seconds"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

The `locations` of a `geo` fixture place each address, a
`[ latitude, longitude ]` pair, a `{lat, lon, radius}` hash, or `unknown`.
With out them the gate is skipped. Its sightings are brands, so the test's
own mark store holds them, and `marks_before` stands in for a sighting
some earlier line left. A `messages` test with an `advance` walks an
account from one place to another. See
[Proving lookups](../rules.md#proving-lookups), and
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    # New York an hour after London
    - messages:
        - "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for neti from 198.51.100.5 port 4711 ssh2"
        - message: "Jul 12 09:25:49 mail01 sshd[2279]: Accepted password for neti from 203.0.113.9 port 4711 ssh2"
          advance: 3600
      geo:
        locations:
          "198.51.100.5": [ 51.5072, -0.1276 ]
          "203.0.113.9": { lat: 40.7128, lon: -74.0060, radius: 20 }
      found: 1
```

## See also

- [`novel`](novel.md) :: A value a key has not had before, kept as brands the same way.
- [`concurrent`](concurrent.md) :: Too many addresses for a key at once, where this is two too far apart.
- [`asn`](asn.md) :: Spares the networks that place badly, written above this.
- [Lookups... DNS and GeoIP](../configuration.md#lookups-dns-and-geoip) :: Where `geoip_city_db` is set.
