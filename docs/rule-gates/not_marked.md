# not_marked... sparing what already has a brand

A `not_marked` gate holds unless the key it checks, the offender by
default, has a live brand of the name. It is the inverse of
[`marked`](marked.md), and how a rule spares what another rule cleared...
count only the source and account pairs that never logged in, or leave a
known good address be.

```yaml
rule_gates:
  - not_marked: { name: cleared, vars: [ SRC, USER ] }
  - ban_var: [ SRC ]
  - not_marked: { name: known_good }
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender | a found value
- vetoes :: yes
- needs :: the galla's mark store
- repeatable :: yes, each entry is a gate of its own

## Told

- `name` :: The brand that vetoes.
- `var` :: The found var whose value is the key.
  - default :: each offender
- `vars` :: The found vars whose values joined are one compound key.
- `value_is` :: The found var the brand's stored value has to equal for it to veto.
- `value_not` :: The found var the brand's stored value has to differ from for it to veto.

`var` and `vars` exclude each other, as do `value_is` and `value_not`. A
var-less entry is checked against each offender, dropping the branded
ones. With a value compare the veto narrows to a brand of that value...
`value_is` spares a brand storing a different value, and `value_not` one
storing the same. It takes no `names`, `older_than`, `newer_than`, or
`hosts`.

## Where it goes

**Below the `ban_var` that names the offender**, when it names no var.

**In a rule listed ahead of the one that brands**, when both act on the
same line. Listed after it, the gate sees the brand the same line just
set and vetoes.

## When it does not hold

It vetoes on a live brand. A line with out the var, or vars, it keys on
holds, there being no brand to look up. An expired brand is no brand. A
value compare with the stored value or the found var missing can not be
proven either way, and still vetoes.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `name` :: "lacks a name"
- a `name` that is not a name :: "has a name that is not a name matching /^[a-zA-Z0-9_\-]+$/"
- a `var`, `value_is`, or `value_not` that is not a string :: "has a var that is not a non-empty string"
- a `vars` that is not a list of strings :: "has a vars that is not a non-empty array of non-empty strings"
- both `var` and `vars` :: "has both var and vars"
- both `value_is` and `value_not` :: "has both value_is and value_not"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

Seed the brand with `marks_before` for the negative and leave it off for
the positive, the same line both times. See
[Proving brands and gates](../rules.md#proving-brands-and-gates) and
[tests](../rules.md#tests) for the shape. A `vars` key is seeded as a list,
joined as the gate joins it.

```yaml
tests:
  positive:
    - message: "Jul 12 08:15:50 mail01 sshd[66891]: Failed password for alice from 192.0.2.7 port 34640 ssh2"
      found: 1
  negative:
    - message: "Jul 12 08:15:50 mail01 sshd[66891]: Failed password for alice from 192.0.2.7 port 34640 ssh2"
      marks_before:
        - name: cleared
          key: [ "192.0.2.7", alice ]
      found: 0
```

## See also

- [`marked`](marked.md) :: The inverse, holding when the brand is set.
- [`mark`](mark.md) :: Sets the brand this spares.
- [`unmark`](unmark.md) :: Lifts a brand, after which this holds again.
- [`not_tracked`](not_tracked.md) :: The same question asked of a tracked record.
- [marks](../rules.md#marks-cross-rule-state-keyed-by-anything) :: The cleared pair example, Sagan's `isnotset`.
