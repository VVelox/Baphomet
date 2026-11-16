# condition... named selections folded into one judgment

A `condition` gate holds when its expression over its named selections
does. It is the boolean form of what a [`gate`](gate.md) says flat, giving
the OR, the nesting, and the N-of-M a flat list can not express... the
Sigma detection model. A rule has this or a `gate`, never both.

```yaml
rule_gates:
  - condition:
      condition: "auth and admin and not trust"
      selections:
        auth:  [ { field: event, op: eq, value: authFailure } ]
        admin: [ { field: user,  op: eq, values: [ root, admin ] } ]
        trust: [ { field: src,   op: cidr, value: 10.0.0.0/8 } ]
  - ban_var: [ src ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: the line
- vetoes :: yes
- needs :: nothing
- repeatable :: no

## Told

- `selections` :: A hash of selection name to a list of entries, as a
      [`gate`](gate.md) takes.
- `condition` :: The expression over the selection names, a string.

Both are required. There is no `selections` gate of its own... the
selections are told to the `condition` gate beside the expression.

Each selection is a list of `gate` entries, legacy or typed, ANDed together,
the reserved `%%%ANY%%%`, `%%%ANY:prefix%%%`, and `MESSAGE` fields
included. A selection name is a plain identifier, a letter or `_` and then
letters, digits, and `_`, and none of the words the expression reads as its
own: `and`, `or`, `not`, `of`, `them`, and `all`, in any case.

The expression composes the selections with `and`, `or`, `not`, and
parentheses, binding in that order, `not` the tightest. The quantifiers
count selections that hold:

- `all of them` :: Every selection.
- `1 of them` :: Any one... `N of them` for any N.
- `N of <prefix>*` :: N of the selections whose names start with
      `prefix`.
- `all of <prefix>*` :: Every one of them.

The words read the same in any case. A selection is only judged when the
expression gets to it, and only once, so an `and` whose first arm failed or
an `or` whose first arm held never pays for the rest.

## Where it goes

It judges what stands when it is asked, the line's fields above the matcher
and the offense below it, the same as a [`gate`](gate.md). On a syslog or
raw rule that means below the `message_regexp`, `message_json`, or `mungers`
that give it fields... a syslog line has none of its own before them.

## When it does not hold

The offense is refused. The line is not turned away outright, so a `track`
below it still harvests, but nothing is counted.

## Refused at load

- a `gate` in the same rule :: is beside a condition gate, and the two are
      two forms of the same thing
- a second `condition` :: is the second condition gate of the rule, which
      can have the one
- no `condition` or no `selections`, or a key beside them :: lacks a
      condition / lacks a selections / has the unknown key
- an empty `selections` :: has a selections that is empty
- a selection name that is no plain identifier, or is one of the
      expression's words :: is not a plain identifier
- a selection that is not a list of entries :: anything a `gate` list is
      refused for, the selection named
- an expression that is empty :: is not a non-empty string
- a name no selection has :: references the unknown selection
- an unbalanced paren :: has an unbalanced paren
- an expression that stops short :: ends unexpectedly
- a word out of place :: has a misplaced
- tokens after a whole expression :: has trailing tokens after
- an `of` with nothing after it :: has an "of" with no target
- an `of` target that is no selection and no `*` pattern :: is not a
      selection or a *-pattern
- a `*` pattern that covers no selection :: covers no selections
- `0 of` :: asks for 0 of, which is vacuously true
- more than the target covers :: asks for N of M selections, which can
      never be met

A pattern covering nothing is refused rather than read as true, as
`all of` over nothing would make a typo match everything.

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture. Write a positive test for each arm of an `or` and a
negative one for each `not`, so every selection is shown to do its part.
See [tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: '{"event":"authFailure","user":"root","src":"198.51.100.7"}'
      found: 1
  negative:
    # trusted, so the not trust arm fails
    - message: '{"event":"authFailure","user":"root","src":"10.1.2.3"}'
      found: 0
    - message: '{"event":"authFailure","user":"morgan","src":"198.51.100.7"}'
      found: 0
```

## Shipped rules using it

- `raw/fortinet-vpn-auth` :: `ssl_vpn or ppp_auth`, two log ids each with
      a test of its own.
- `raw/huawei-auth-bruteforce` :: `ssh or shell or ftp or web` over the
      huawei munger's module and mnemonic.
- `syslog/baphomet_errors` and most of the other `_errors` rules ::
      `1 of them` over a munger's fields, with no `message_regexp`.
- `syslog/named_errors` :: `has_zone and 1 of fail_*`, a prefix
      quantifier behind a selection every hit needs.
- `raw/fortinet-attack` and `raw/fortinet-policy` :: `modern or legacy`,
      the one event under its `logid` and its older `log_id` form.

## See also

- [`gate`](gate.md) :: The flat form, never beside it.
- [`keywords`](keywords.md) :: ANDed with it.
- [the gate / selections / condition / keywords family](../rules.md#gate--selections--condition--keywords)
