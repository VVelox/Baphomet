# mark... branding what an offense names

A `mark` gate sets a named, expiring brand on a key, the offender by
default, for a later rule to gate on with `marked`, `not_marked`, or
`sequence`. It vetoes nothing. It is how one rule remembers something for
another, in the same watcher or any other of the galla... "this address
brute forced sshd", or "this account was hit from this source".

```yaml
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Failed \S+ for (?:invalid user )?(?<USER>\S+) from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - mark: { name: brute_force, ttl: 21600 }
  - mark: { name: sshd-account-src, ttl: 3600, var: USER, value_var: SRC }
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `var` or `vars`
- vetoes :: no, it only stores
- needs :: the galla's mark store
- repeatable :: yes, each entry is a gate of its own

## Told

- `name` :: The brand to set.
- `ttl` :: Its life in seconds.
- `var` :: The found var whose value is the key.
  - default :: each offender
- `vars` :: The found vars whose values joined are one compound key.
- `value_var` :: The found var whose value is stored on the brand.

`var` and `vars` exclude each other. With neither, each offender is
branded, less any in `ignore_ips`. With `vars`, the values are joined on
the unit separator, `\u001f` in JSON, which is how the key shows in
`baphomet marked` and on tablets... `vars: [ SRC, USER ]` brands the pair,
not either alone. A line missing any of the vars, or the one `var`, brands
nothing.

`mark_only: true` on the rule makes it only brand and gate, never counting
toward a ban, and leaves the line unconsumed so the rules after it still
get it.

## Where it goes

**Below the `ban_var` that names the offender**, when it names no var. A
`detection_var` above it lets it load too, but a detection rule has no
offender, so a var-less `mark` there brands nobody.

**Below every gate that is to be able to stop it.** Only an offense that
stood when it is asked gets branded, and a brand set is not taken back by a
gate below vetoing. A `mark` above a `country` gate brands the offender the
`country` gate then spares.

**A reader of the same brand goes in a rule listed ahead of this one.**
Otherwise the reading gate sees the brand this line just set, not the one
a earlier line left.

## When it does not hold

It always holds. A offense with no offender, or a line with out the var it
keys on, brands nothing and goes on.

## What it leaves behind

A brand in the galla's mark store, under its name and key, with the
`value_var`'s value when there was one. Setting it again refreshes the
expiry and the value, and keeps the time it was first set, which is what
`marked`'s `older_than` / `newer_than` and `sequence` read. A line with no
value for the `value_var` sets the brand with out one, dropping whatever
value it held.

Brands are galla state... they cross watchers and rules but not kurs,
survive a restart on the marks tablet, and over a
[Redis tablet](../tablets.md) ride to every host of the fleet. Each mark
name keeps at most 10000 keys, a new one evicting the expired and then the
soonest to expire. `baphomet marked` lists them.

The names `banished` and `banishments` are the galla's own, see
[the galla's own brands](../rules.md#the-gallas-own-brands). A rule should
not set either.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `name` or no `ttl` :: "lacks a name", "lacks a ttl"
- a `name` that is not a name :: "has a name that is not a name matching /^[a-zA-Z0-9_\-]+$/"
- a `ttl` that is not a positive whole number :: "has a ttl that is not a positive int of seconds"
- a `var` or `value_var` that is not a string :: "has a var that is not a non-empty string"
- a `vars` that is not a list of strings :: "has a vars that is not a non-empty array of non-empty strings"
- both `var` and `vars` :: "has both var and vars"
- no var, and no `ban_var` or `detection_var` above it :: "keys on the offender, and no ban_var above it names one"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

`marks_expected` asserts the brand, the key it landed on, and any stored
value, which catches a regexp edit that shifts which capture feeds it.
`marks_after` does the same between lines of a `messages:` test. See
[Proving brands and gates](../rules.md#proving-brands-and-gates) and
[tests](../rules.md#tests) for the shape.

```yaml
# syslog/sshd-mark-users... brand the account with the source that hit it
tests:
  positive:
    - message: "Jul 12 08:15:50 mail01 sshd[66891]: Invalid user moth3r from 216.137.179.214 port 34640"
      found: 1
      marks_expected:
        - name: sshd-account-src
          key: moth3r
          value: "216.137.179.214"
```

A `mark_only` rule still counts its firings toward `found`. What it never
does is count toward a ban.

## Shipped rules using it

- `%syslog/ssh%`, `%syslog/ftp%`, the auth rules of `%syslog/mail%` :: Brand `brute_force`, as every shipped rule of classtype `brute-force` does.
- `syslog/scanlogd`, `syslog/named-refused` :: Brand `recon`, as the scanning classtypes do.
- `syslog/suhosin` :: Brands `exploit_attempt`, as the exploit classtypes do.
- `raw/portsentry`, `json/cowrie` :: Brand `honeypot`.
- `syslog/sshd-mark-users` :: Brands the account with the source that hit it, for `syslog/sshd-spray`.
- `raw/citrix-vpn-mark-logins` :: Brands the VPN account with its source, for `raw/citrix-vpn-traveler`.
- `syslog/sshd-condemned` :: Re-brands `brute_force` as it reads it, so reading never lets the brand lapse.

## See also

- [`marked`](marked.md) :: Holds when a brand is set.
- [`not_marked`](not_marked.md) :: Holds when it is not.
- [`sequence`](sequence.md) :: Holds when several were set in order.
- [`unmark`](unmark.md) :: Lifts a brand.
- [`banished`](banished.md) :: Reads the galla's own brands.
- [marks](../rules.md#marks-cross-rule-state-keyed-by-anything) :: How rules tie together over brands.
- [the standard brands](../rules.md#the-standard-brands) :: The shared vocabulary the shipped rules brand and read.
