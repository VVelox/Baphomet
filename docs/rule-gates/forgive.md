# forgive... a login that worked clears the failures

A `forgive` gate takes back the hits other rules have counted against an
address, the offender by default. It vetoes nothing. With out one, someone
who mistypes their password four times and then gets in is one typo from a
ban for the rest of the `find_time`.

```yaml
mark_only: true
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - forgive: { rules: [ syslog/sshd ], same: USER }
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `var`
- vetoes :: no, it only takes back counts
- needs :: the galla's running counts
- repeatable :: yes, each entry is a gate of its own

## Told

- `rules` :: The rule whose hits are taken back, or a list of them, named as a watcher names them.
- `var` :: The found var holding the address to forgive.
  - default :: each offender
- `same` :: The found var holding the account the hits have to have been about.

A bare string `rules` is taken as a list of one.

**Name a `same`.** With out it one login that worked washes every guess
the address made at every other account, which is what a stuffing run with
one good password looks like. With it only the failures for that account
go. What a hit was about is the value of the
[`user_var`](../rules.md#src_ip_var--dest_ip_var--src_port_var--dest_port_var--user_var)
of the rule that counted it, so the rule being forgiven has to name one...
a hit of a rule with none is about nobody, and a `same` leaves it.

## Where it goes

**Below the `ban_var` that names the offender**, when it names no `var`. A
detection rule has no offender, and needs the `var`.

**Below every gate that is to be able to stop it.** Only an offense that
stood when it is asked forgives anything.

## When it does not hold

It always holds. With a `same`, a line with out the account, or with it
empty, forgives nothing, a account that can not be named not being the
same one. A `var` with no value forgives nothing either.

## What it leaves behind

Fewer hits. Only the running counts are touched... the shared bucket, the
named rules' own, and the shadow buckets of observe mode alike, so what a
rule would have done stays in step with what it did. A ban already made
stands, as do the subnet counts and what a `distinct` rule has seen. What
is taken back is counted in the `forgiven` stat.

A rule named that no watcher of the galla lists is said loudly at start,
as an error, since a name spelled wrong would otherwise forgive nothing and
say nothing.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `rules` :: "lacks a rules"
- a `rules` that is not a rule name or a list of them :: "has a rules that is not a rule name or a non-empty array of them"
- a `var` or `same` that is not a string :: "has a ... that is not a non-empty string"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It can not be proved from the rule file. The counts are the galla's, there
is no fixture to stand in for them, and a rule's embedded tests skip the
gate, leaving it unjudged. See [tests](../rules.md#tests).

## See also

- [`unmark`](unmark.md) :: Takes back a brand, where this takes back hits.
- [`weigh`](weigh.md) :: Changes what a hit is worth as it is counted, where this takes it back after.
