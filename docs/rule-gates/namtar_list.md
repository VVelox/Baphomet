# namtar_list... only the already-condemned

A `namtar_list` gate only lets a match count when a value appears on a
named list, the inverse of `ignore_ips`. The lists are named in the
config's `namtar_lists`, layered per watcher and reloaded when a file's
mtime changes, so a rule can count only what a feed you supply condemns.
A list is either a **CIDR list**, matched by address containment, or a
**string list**, matched by exact equality, optionally case-folded... so
the gate reaches beyond IPs to any field a rule captures, a username, a
URI, a user-agent.

```yaml
rule_gates:
  - namtar_list:
      lists: [ threatfeed, torexits ]   # SRC on ANY of these (union)
      var: SRC
  - namtar_list:
      list: bait_users                  # a string list of honeypot accounts
      var: USER                         # check the user, still ban the offender
  - ban_var: [ SRC ]
max_score: 1
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `var`
- vetoes :: yes
- needs :: the `namtar_lists` it names, and their files
- repeatable :: yes, each entry is a gate of its own

## Told

- `list` / `lists` :: Exactly one. The name of a list, or a list of them, out of the watcher's `namtar_lists`.
- `var` :: The found var holding the value to check, in place of the offender.

A value on **any** of an entry's lists satisfies it, even across flavors,
each list matched its own way. Of a rule's entries **every** one must hold.

The flavor, the files, and the case folding are set on the list in the
config, not here, so a rule stays a pure matcher. See
[namtar lists](../configuration.md#namtar-lists).

## Where it goes

With no `var` it keys on the offender, so it goes below the `ban_var` and
filters which offenders count. With a `var` it is asked once of the whole
offense and needs no `ban_var` above it.

It reads a value [`country`](country.md#what-it-leaves-behind) or another
gate lifted, so it goes below the gate that lifts it. A name a
[`digest`](digest.md) hashes is a hash by the time this gate sees it, so a
rule wanting the name gives the `digest` an `into`.

## When it does not hold

A veto drops the offense, or with no `var` drops the offender it does not
hold for, the offense vetoed only when none are left. A vetoed offense does
not consume the line.

The gate **fails closed**. A value on no list, a var the offense lacks, or
a list whose file is unreadable or empty blocks the count... an absent feed
banishes nobody, never everybody, and the galla says so loudly at start.
`ignore_ips` still wins absolutely.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- a `list` or `lists` that is not a name or a list of them :: "has a list that is not a name matching /^[a-zA-Z0-9_\-]+$/ or a non-empty array of them"
- a `var` that is not a string :: "has a var that is not a non-empty string"
- both `list` and `lists` :: "has both list and lists"
- neither `list` nor `lists` :: "has neither list nor lists"
- a list the watcher does not define, when bound :: "references namtar_lists{...}, which is not a defined list for it"

The last is found when the galla binds the rule to a watcher, and the
galla will not start on it.

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A rule's tests can not prove it. Its lists are config, and a rule file has
none of it, so in a test the gate is unjudged and the rule counts as if
it were not written. It is proven galla-side only.

## Shipped rules using it

None. Which addresses are condemned is your policy.

## See also

- [`dnsbl`](dnsbl.md) :: A blocklist someone else keeps, asked over DNS.
- [`asn`](asn.md) :: Networks named by the database rather than by a file of yours.
- [`digest`](digest.md) :: Hashes a name ahead of it.
