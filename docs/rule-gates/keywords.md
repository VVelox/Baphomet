# keywords... a string searched for across a line's fields

A `keywords` gate holds when any of its values is found in what it
searches, every field of the line by default. It is the shorthand for a
`contains` fanned over many fields, for when the string that gives a line
away could be in any of them, ANDed with whatever other gates the rule has
and able to stand alone as the whole matcher.

```yaml
rule_gates:
  - keywords: [ mimikatz, sekurlsa, "Invoke-Mimikatz" ]
  - ban_var: [ src_ip ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: the line
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

A list of the values to search every field for, or a hash of:

- `values` :: The values to search for, a non-empty list.
- `in` :: Where to search... a field path, a `%%%ANY:prefix%%%` subtree, or `%%%ANY%%%`, every field.
  - default :: `%%%ANY%%%`

The hash form scopes the search, so nothing unrelated is searched when the
path is known:

```yaml
rule_gates:
  - keywords:
      in: process.command_line
      values: [ mimikatz ]
```

It is exactly `{ field: <in>, op: contains, values: <values> }` as a
[`gate`](gate.md) entry, and the search is case-sensitive like every compare
there. A rule wanting it folded, decoded, or negated writes that `gate`
entry out with `nocase`, `decode`, or `negate`. On syslog and raw,
`%%%ANY%%%` searches the message as well as the fields.

## Where it goes

It judges what stands when it is asked, the line's fields above the matcher
and the offense below it, the same as a [`gate`](gate.md). On a syslog or
raw rule that means below the `message_regexp`, `message_json`, or `mungers`
that give it fields... a syslog line has none of its own before them.

## When it does not hold

The offense is refused. The line is not turned away outright, so a `track`
below it still harvests, but nothing is counted.

## Refused at load

- neither a list nor a hash :: "is not a list of strings or a table"
- a hash key other than `in` and `values` :: "has the unknown key ..."
- an `in` that is not a non-empty string :: "has a in that is not a non-empty string"
- no `values`, or an empty one :: "lacks a non-empty values list"
- a value that is not a scalar :: "has a non-scalar value"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture. A negative test with the keyword in a field the `in`
does not reach proves the scope. See [tests](../rules.md#tests) for the
shape.

```yaml
rule_gates:
  - keywords:
      in: process.command_line
      values: [ mimikatz ]
  - ban_var: [ src_ip ]
tests:
  positive:
    - message: '{"src_ip":"192.0.2.10","process":{"command_line":"mimikatz.exe sekurlsa::logonpasswords"}}'
      found: 1
  negative:
    - message: '{"src_ip":"192.0.2.11","process":{"command_line":"notepad.exe"},"note":"mimikatz"}'
      found: 0
```

## See also

- [`gate`](gate.md) :: The long form, for a search that has to fold case, decode, or negate.
- [`condition`](condition.md) :: ANDed with it like a `gate` is.
- [the gate / selections / condition / keywords family](../rules.md#gate--selections--condition--keywords)
