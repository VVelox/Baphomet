# ignore... a field that is never an offense

An `ignore` gate turns a line away outright when any of its entries
matches, each naming a field of the line and a regexp. It is
[`ignore_regexp`](ignore_regexp.md) for the field types, and a rule wants
it for the same reason... the exceptions are easier named than excluded
from the matcher. The audit bot that walks every path, the IDS signature
that fires on stream noise rather than attack.

```yaml
rule_gates:
  - ignore:
      - { field: alert.signature, regexp: '^SURICATA STREAM' }
  - gate:
      - { field: event_type, values: [ alert ] }
  - ban_var: [ src_ip ]
```

## At a glance

- phase :: line
- rule types :: http, json
- keys on :: the line
- vetoes :: yes
- needs :: nothing, or Log::Munger for a primitive fragment
- repeatable :: yes, each entry is a gate of its own

## Told

A non-empty list of entries, any one of which matching turns the line away,
each a hash of...

- `field` :: The field of the line to read.
- `regexp` :: The regexp the field has to match.

**On http** the field has to be one an access log line has, or one a gate
of the rule lifts, and the regexp is plain Perl. A lifted field is read
only once the gate lifting it has been asked, so it has to stand above.

**On json** the field is a flattened dotted path of the record as the
parser flattened it, and the regexp may use the `%%%%TOKEN%%%%` offender
tokens and primitive fragments, nothing being captured from either. A field a
gate above it lifts is not read... only the record's own.

A field the line does not have never matches, so it never turns the line
away.

## Where it goes

**Leading the list.** It reads nothing but the parsed line, so it costs
least written first, where a line it turns away has had nothing made for
it. Above a [`capture`](capture.md) it keeps the line from being stored as
context, and from completing an offense left waiting. On json it, like
`capture`, `key`, and `track`, takes the rule out of the record index,
which only pins a rule whose `gate` alone decides what it does with a
record... the rule is then offered every record of the watcher.

## When it does not hold

The line is turned away outright. Nothing below is asked... no context is
stored, no deferred offense completes, nothing is harvested... and the line
goes on to the rules after it.

## Refused at load

- not a non-empty list of hashes :: "is not a non-empty array", "entry N is not a hash"
- an entry with out `field` or `regexp`, or with any other key :: "lacks a ...", "has the unknown key ..."
- a `field` or `regexp` that is not a scalar :: "has a field that is not ..."
- on http, a field the line does not have and no gate lifts :: "names the unknown field ..."
- on json, a regexp naming an unknown token :: "uses the unknown token ..."
- a regexp that will not compile :: "does not compile"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

No fixture. A negative per entry, a line the rest of the rule would have
taken, proves the exception holds. See [tests](../rules.md#tests) for the
shape.

```yaml
tests:
  positive:
    - message: '{"event_type":"alert","src_ip":"203.0.113.50","alert":{"signature":"ET SCAN Nmap Scripting Engine"}}'
      found: 1
      data:
        src_ip: "203.0.113.50"
  negative:
    - message: '{"event_type":"alert","src_ip":"203.0.113.50","alert":{"signature":"SURICATA STREAM ESTABLISHED packet out of window"}}'
      found: 0
```

## Shipped rules using it

- `json/suricata` :: The `SURICATA STREAM` signatures, decoder noise rather than attack.

## See also

- [`match`](match.md) :: The matcher of the same shape, written below it.
- [`ignore_regexp`](ignore_regexp.md) :: The same veto on the text types, over the message.
- [`gate`](gate.md) :: With `negate`, a veto on a field by equality, a number, or a network.
- [`status`](status.md), [`method`](method.md) :: The other cheap http refusals leading the list.
