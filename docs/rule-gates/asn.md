# asn... narrowing an offense by network

An `asn` gate only lets a match count when the offender, or some captured
address, is on (or off) a set of networks... the autonomous systems the
internet is routed by, each a number and the name of who runs it. It is
[`country`](country.md) asking a different question of the same address,
and is written the same way. A login that is fine from the office network
and worth a ban from a hosting provider is one rule.

```yaml
rule_gates:
  - ban_var: [ SRC ]
  - asn:
      isnot:                           # count only if NOT on these
        - "%%%asn_lists{office}%%%"    # import a named list from the config
        - AS64496                      # literal numbers compose too
max_score: 1
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `vars`
- vetoes :: yes
- needs :: `geoip_asn_db` and the optional `IP::Geolocation::MMDB` module, and `asn_lists` for what it imports
- repeatable :: yes, each entry is a gate of its own

## Told

- `is` / `isnot` :: By number. An AS number, bare or written `AS64496`, a `%%%asn_lists{name}%%%` token, or a list of them.
- `org_is` / `org_isnot` :: By name. A regexp, or a list of them, matched against the name the database gives the network.
- `vars` :: The found var, or a list of them, holding the addresses to check, in place of the offender.
- `into` :: The found var the AS number is lifted into.
- `org_into` :: The found var the network's name is lifted into.

At most one of the four that judge may be written, and a gate that lifts
needs none of them. The token splices in a named list from the config,
layered per watcher (see [ASN lists](../configuration.md#asn-lists)).
`064496`, `AS64496`, and `64496` are the one number.

A number is the stable thing to list. The names are the database's own and
drift, so they are for the broad sweep, `org_is: '(?i)hosting|cloud|vps'`.
They are case-sensitive, so lead one with `(?i)` to fold it.

`into` and `org_into` follow the rules of
[`country`'s `into`](country.md#told)... exactly one entry in `vars`,
never lifting over a value the offense already has, and a gate that only
lifts judges nothing and vetoes nothing.

## Where it goes

As [`country`](country.md#where-it-goes) goes. With no `vars` it keys on
the offender and goes below the `ban_var`. With `vars` it is asked once of
the whole offense.

## When it does not hold

A veto drops the offense, or with no `vars` drops the offender it does not
hold for, the offense vetoed only when none are left. A vetoed offense does
not consume the line.

It **fails closed** like `country`... an address the database does not
place, a var the offense lacks, or a missing database blocks the count,
and a network with no name can not be cleared by `org_isnot` or held by
`org_is`. A galla with asn-gated rules and no loadable database says so
loudly at start. Lookups are cached for a minute.

## What it leaves behind

With an `into`, the AS number, bare, in that var. With an `org_into`, the
name, when the database has one. What can read them is what can read
[`country`'s](country.md#what-it-leaves-behind).

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- an `is` or `isnot` that is not numbers or imports :: "has a is that is not a AS number or a %%%asn_lists{name}%%% import, or a non-empty array of them"
- an `org_is`, `org_isnot`, or `vars` that is not a string or a list of them :: "has a ... that is not a non-empty string or a non-empty array of them"
- two of the four that judge :: "has both ... and ..."
- nothing to judge and nothing to lift :: "has none of is, isnot, org_is, org_isnot, into, or org_into"
- an `org_is` or `org_isnot` regexp that does not compile :: "has a ... that does not compile..."
- an `into` or `org_into` with other than one var :: "has a into or org_into, which needs exactly one var to lift the network of"
- an import of a list the watcher does not define, when bound :: "imports asn_lists{...}, which is not a defined list for it"

The last is found when the galla binds the rule to a watcher, and the
galla will not start on it.

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

The `geo` fixture's `asns` map stands in for the database, an address to
an AS number, a `{number, org}` hash, or `unknown`, and its `asn_lists`
for the config's lists. A lone number is a network with no name. With out
`asns` or `asn_lists` the gate is skipped, so a fixture of only
`countries` leaves it skipped. See
[proving lookups](../rules.md#proving-lookups), and
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    # on a hosting network
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for oracle from 203.0.113.9 port 4711 ssh2"
      geo:
        asns:
          "203.0.113.9": { number: 64496, org: "Example Hosting" }
        asn_lists:
          hosting: [ 64496 ]
      found: 1
```

## Shipped rules using it

None. Which networks are the office and which are hosting is yours to
say.

## See also

- [`country`](country.md) :: The same address asked which country it is in.
- [`network`](network.md) :: Lifts the network an address is in by prefix, with no database.
- [`namtar_list`](namtar_list.md) :: Networks named by CIDR in a file of your own, in place of the database's.
