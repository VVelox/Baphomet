# unmark... lifting a brand

An `unmark` gate lifts a named brand from a key, the offender by default.
It vetoes nothing, and a key with no such brand lifts nothing. It is the
undoing of a `mark`... a login that worked lifting the suspicion its
failures earned, say.

```yaml
mark_only: true
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - unmark: { name: suspect }
  - unmark: { name: sshd-account-src, var: USER }
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender | a found value
- vetoes :: no, it only lifts
- needs :: the galla's mark store
- repeatable :: yes, each entry is a gate of its own

## Told

- `name` :: The brand to lift.
- `var` :: The found var whose value is the key.
  - default :: each offender
- `vars` :: The found vars whose values joined are one compound key.

`var` and `vars` exclude each other, and key as they do on a
[`mark`](mark.md), so an `unmark` lifts what a `mark` keyed the same way
set. With neither, the brand is lifted from each offender, less any in
`ignore_ips`, which a var-less `mark` never branded either.

## Where it goes

**Below the `ban_var` that names the offender**, when it names no var. A
`detection_var` above it lets it load too, but a detection rule has no
offender, so a var-less `unmark` there lifts nothing.

**Below every gate that is to be able to stop it.** Only an offense that
stood when it is asked lifts anything, and a lift is not put back by a gate
below vetoing.

## When it does not hold

It always holds. A offense with no offender, a line with out the var it
keys on, or a key with no such brand lifts nothing and goes on.

## What it leaves behind

The brand gone from the galla's mark store. Over a
[Redis tablet](../tablets.md) the lift rides to every host of the fleet,
as the brand did.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `name` :: "lacks a name"
- a `name` that is not a name :: "has a name that is not a name matching /^[a-zA-Z0-9_\-]+$/"
- a `var` that is not a string :: "has a var that is not a non-empty string"
- a `vars` that is not a list of strings :: "has a vars that is not a non-empty array of non-empty strings"
- both `var` and `vars` :: "has both var and vars"
- no var, and no `ban_var` or `detection_var` above it :: "keys on the offender, and no ban_var above it names one"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

Seed the brand with `marks_before`, and assert it gone with
`marks_expected` under `absent`. See
[Proving brands and gates](../rules.md#proving-brands-and-gates) and
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for alice from 192.0.2.7 port 4711 ssh2"
      marks_before:
        - name: suspect
          key: "192.0.2.7"
      found: 1
      marks_expected:
        - name: suspect
          key: "192.0.2.7"
          absent: true
```

## See also

- [`mark`](mark.md) :: Sets the brand this lifts.
- [`forgive`](forgive.md) :: Takes back counted hits, where this takes back a brand.
- [`not_marked`](not_marked.md) :: Holds once the brand is gone.
- [marks](../rules.md#marks-cross-rule-state-keyed-by-anything) :: How rules tie together over brands.
