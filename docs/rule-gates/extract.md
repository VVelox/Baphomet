# extract... a capture out of any field

An `extract` gate matches a regexp against a field and lifts its named
captures into found vars. `message_regexp` only ever reads the message, and
the `re` op of a `gate` tests a field and keeps nothing of it. This is how a
json or http rule takes the domain out of an address, or a part of a path
out of a request, to key or count on.

```yaml
rule_gates:
  - gate:
      - { field: event, value: login_failed }
  - extract: { var: user, regexp: '@(?<DOMAIN>[^@]+)$' }
  - after: { by: DOMAIN, count: 50, seconds: 600 }
  - ban_var: [ ip ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: a found value
- vetoes :: no, it only lifts, unless `on_miss` is `fail`
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `var` :: The field to match against.
- `regexp` :: The regexp, with at least one named capture.
- `on_miss` :: What a field it does not match does, `pass` or `fail`.
  - default :: `pass`

The [tokens](message_regexp.md) `message_regexp` takes work in the
regexp too, and a token's capture counts as a named one. A token written
twice captures under its name all the same.

## Where it goes

It reads what stands when it is asked. Above the matcher it lifts into the
line's fields, which the offense is then made of. Below, into the offense,
captures and all, so it can take apart what a `message_regexp` caught. Put
it above whatever reads what it lifts... a `match` reading a lifted field
has to be below it, and so does a line gate keyed on one. The offense gates
see the lift wherever they are written.

A field it lifts can be named by the `match` and `ignore` of an http rule,
which otherwise only take the fields of the log format.

## When it does not hold

A field the regexp does not match, that is not there, or that is not a
plain string, lifts nothing. With `on_miss` at `pass` the line goes on as if
the gate were not there, and whatever reads the var it would have lifted
finds it missing. With `on_miss` at `fail` the line is turned away
outright, nothing below it asked and nothing harvested. Where several
offenses stand, one match among them is enough to let the line by.

## What it leaves behind

The named captures, as found vars in the offense or the line's fields, read
by every gate below it and every offense gate. A capture is never lifted
over a value already there. Nothing outlives the line.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not know :: "has the unknown key ..."
- no `var` or no `regexp` :: "lacks a ..."
- a `var` or `regexp` that is not a string :: "has a ... that is not a non-empty string"
- an `on_miss` that is neither `pass` nor `fail` :: "has a on_miss that is not one of pass or fail"
- a regexp that does not compile :: "does not compile"
- a regexp naming an unknown token :: "uses the unknown token ..."
- a regexp with no named capture :: "has a regexp with no named capture, which would lift nothing"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture. A positive test's `data` names the lifted var, which
is the proof it was lifted. Under the `after` of the rule above, a positive
test needs fifty lines in its `messages` before anything is found, so this
shows the lift on its own. See [tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - gate:
      - { field: event, value: login_failed }
  - extract: { var: user, regexp: '@(?<DOMAIN>[^@]+)$' }
  - ban_var: [ ip ]
tests:
  positive:
    - message: '{"event":"login_failed","user":"morgan@example.org","ip":"192.0.2.20"}'
      found: 1
      data:
        DOMAIN: "example.org"
```

## See also

- [`normalize`](normalize.md) :: Lifts a cleaned copy of a path the same way, for a `match` below it.
- [`digest`](digest.md) :: Hashes a found value in place, which may be one this lifted.
- [`after`](after.md) :: A count keyed on what it lifts.
- [`gate`](gate.md) :: Its `re` op tests a field and keeps nothing.
