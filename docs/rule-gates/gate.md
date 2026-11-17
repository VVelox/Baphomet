# gate... a flat list of field tests

A `gate` holds when every entry of its list does, each entry a test of one
field. It is the predicate layer of every type, ANDed with the type's own
matching... on a json or http rule it filters a line's fields ahead of the
match, and on a syslog or raw rule it refines what the `message_regexp`
caught.

```yaml
rule_gates:
  - gate:
      - field: event_type
        values: [ alert ]
      - field: alert.category
        values: [ "//Attack$//", "Misc activity" ]
  - ban_var: [ src_ip ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: the line
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own, and two are ANDed

## Told

A list of entries, ANDed. Each is a hash with a `field`, in one of two
forms.

The legacy form is `{field, values: [ ... ]}`. A values entry starting and
ending with `//` is a regexp, and everything else is string equality.

The typed form is opt-in, detected by the presence of an `op`, `value`,
`all`, `negate`, `nocase`, `fieldref`, `times`, `measure`, `of`, or
`decode` key. A plain `field`/`values` entry
stays the legacy form.

```yaml
rule_gates:
  - gate:
      - { field: event,     op: eq,       value: auth_fail }
      - { field: bytes_out, op: gt,       value: 1000000 }
      - { field: src,       op: cidr,     values: [ 10.0.0.0/8, 2001:db8::/32 ] }
      - { field: cmd,       op: contains, values: [ psexec, mimikatz ], all: false }
      - { field: user,      op: eq,       value: healthcheck, negate: true }
```

- `field` :: The field the entry tests.
- `op` :: The operator.
  - default :: `eq`
  - `eq` / `contains` / `startswith` / `endswith` :: The string tests.
  - `re` :: A regexp, [tokens](message_regexp.md) included.
  - `gt` / `lt` / `ge` / `le` :: Numeric.
  - `cidr` :: IPv4 or IPv6 membership.
  - `exists` :: The field is present, whatever its value.
- `value` / `values` :: One scalar or a non-empty list.
- `fieldref` :: Another field to compare against in place of a literal.
- `times` :: What the referenced number is multiplied by first.
  - default :: 1
- `measure` :: What of the value a numeric op compares... `length`, `entropy`, or `count`.
- `of` :: The regexp a `measure` of `count` counts.
- `all` :: Require every value to match rather than any.
  - default :: false
- `negate` :: Invert the entry.
  - default :: false
- `nocase` :: Case-fold the compare.
  - default :: false
- `decode` :: Transforms run left to right over the value before the operator.

An entry holds if any of its values does, or all of them when `all` is
true. A field the line does not have never matches, except under a
`negate`... a negated entry also holds when the field is absent, matching
Sigma's field-absent semantics. Under `exists` that makes `negate` the
field-absent test, Sigma's `|exists: false`, and `exists` takes no value,
`fieldref`, `decode`, `nocase`, or `all`.

The numeric ops read the field as a number, and one that is not a number is
treated as missing. Their values have to be numbers.

`fieldref` is how a rule says two fields must agree, or with `negate` must
not... `{ field: auth_user, op: eq, fieldref: cert_user }`, Sigma's
`|fieldref`. It stands in for `value`/`values`, and setting it beside one is
an error. `eq`, `contains`, `startswith`, and `endswith` take it, and so do
`gt`, `lt`, `ge`, and `le`, for which the referenced field has to be a
number. A referenced field the line does not have is a non-match. It folds
under `nocase` and its source decodes under `decode` like any other compare.

`times` only goes beside a `fieldref` under a numeric op, holding one field
to a share of another... `{ field: errors, op: gt, fieldref: requests,
times: 0.9 }` is errors above nine in ten of requests.

`measure` only goes beside a numeric op. `length` is how many bytes long the
value is, `entropy` how many bits of it a byte carries, 0 for one byte over
and over up to 8, and `count` how many times the regexp in `of` matches in
it. A 400-byte account name, or a random-looking host name, is rarely a
person's: `{ field: user, measure: length, op: gt, value: 64 }`. It is taken
after any `decode`. No value scores more entropy than the log2 of its
length, so twenty bytes of anything are 4.3 at the most, and a mark on a
short field has to sit lower.

`of` takes the [tokens](message_regexp.md) and folds under
`nocase`. Three `../` in one path, or two SQL words in one query, is
another thing from one:
`{ field: query, measure: count, of: '(?i)\b(?:union|select)\b', op: ge, value: 2 }`.

Baphomet matches case-sensitively, so `nocase` is what gives Sigma's
default-insensitive matching, and a Sigma `|cased` field is just the
default. It applies to the string ops and to `re`, and is an error on the
numeric and cidr ops, where it means nothing.

The `decode` transforms are `base64`, `base64offset` (the three alignment
candidates), `utf16le` / `utf16be` / `utf16` (`wide` being an alias for
`utf16le`), `windash`, `url`, `lower`, and `upper`. A transform that can not
decode a value drops that candidate, so a bad decode simply does not match.
`decode: [ base64, utf16le ]` with `op: contains` is the PowerShell `-enc`
shape.

What a `field` names depends on the type... a regexp capture (syslog, raw),
a flattened dotted path (json), a parsed access or error log field (http,
http_error), or what `message_json` and `mungers` laid down. Three names are
reserved:

- `%%%ANY%%%` :: Fans the test over every field value and, on syslog and raw, the message.
- `%%%ANY:<prefix>%%%` :: Fans it over just the fields at or under `prefix`.
- `MESSAGE` :: On syslog and raw, the whole message.

A fanned entry holds when any value it fans over does, and a `negate` on one
inverts the whole fan, so it holds when no field matched. A `fieldref` under
a fan is an error, the fan having no one value to compare it to. The
[`keywords`](keywords.md) gate is the shorthand for a `contains` fanned this
way.

## Where it goes

It judges what stands when it is asked. Above the matcher it judges the
line's fields, and a line it refuses is not matched at all. Below the
matcher it judges the offense, captures and all.

On a json or http rule that makes it a filter ahead of the `match`. On a
syslog or raw rule it goes below the `message_regexp`, or below the
`message_json` or `mungers` that lay down the fields it reads... a syslog
line has no fields of its own, so a `gate` above all of them judges nothing
and lets every line by. A syslog or raw rule with no `message_regexp` or
`stages`, and no `message_json` or `mungers` either, does not load, having
nothing for its gate to judge.

On a json rule, the field values the plain equality entries pin are what
the galla indexes a watcher's rules by, so a line whose `event_type` no
rule pins is never offered to them. Only a legacy entry with no `//regexp//`
pins anything, and two on one field pin only the values in both. A rule
with a `capture`, `ignore`, `key`, or `track` is not indexed this way.

## When it does not hold

The offense is refused. The line is not turned away outright, so a `track`
below it still harvests, but nothing is counted and the rule did not fire.

## Refused at load

- a `condition` gate in the same rule :: "is beside a condition gate, and the two are two forms of the same thing"
- a list that is empty or not a list :: "is not a array or is empty"
- an entry with no `field` :: "is not a hash with a field"
- a legacy entry with no `values` list :: "is not a hash with a field and a values array"
- a key neither form knows :: "has the unknown key ..."
- a legacy value that is not a string :: "contains a non-string entry"
- a legacy `//regexp//` that does not compile :: "does not compile"
- an `op` there is none of :: "has the unknown op ..."
- `nocase` on a numeric or cidr op :: "nocase does not apply to the ... op"
- an empty `fieldref` :: "fieldref is not a non-empty field name"
- `fieldref` beside a `value` :: "sets both fieldref and a literal value"
- `fieldref` under an op that can not take it :: "fieldref works only with the eq, contains, startswith, endswith, gt, lt, ge, and le ops"
- `fieldref` under `%%%ANY%%%` or `%%%ANY:prefix%%%` :: "pairs fieldref with a keyword field, which can never match"
- `measure` not one of the three :: "measure is not one of length, entropy, or count"
- `measure` under a non-numeric op :: "measure works only with the gt, lt, ge, and le ops"
- `of` with out a `measure` of `count` :: "of works only with a measure of count"
- a `measure` of `count` with no `of` :: "has a measure of count with no of, the regexp to count"
- `times` with out a `fieldref` under a numeric op :: "times works only with a fieldref under the gt, lt, ge, and le ops"
- `times` not a positive number :: "times is not a positive number"
- `exists` with a value, `fieldref`, `decode`, `nocase`, or `all` :: "the exists op takes no value, fieldref, decode, nocase, or all"
- no `value` or `values` :: "lacks a value or values"
- an empty `values` :: "values is not a non-empty array"
- a value that is not a scalar :: "has a non-scalar value"
- a numeric op with a value that is no number :: "needs numeric values, got ..."
- an empty value under `cidr` :: "contains a empty or non-string entry"
- a value under `cidr` that is not an address or a CIDR :: "entry "..." is not a IPv4 or IPv6 address or CIDR"
- a CIDR with a prefix the family has no bits for :: "entry "..." has a invalid prefix length"
- `decode` empty or not a list :: "decode is not a non-empty array"
- `decode` naming a transform there is none of :: "has the unknown decode transform ..."
- a `re` value or an `of` that does not compile :: "does not compile"
- a `re` value or an `of` naming an unknown token :: "uses the unknown token ..."

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture. Positive tests are the lines that pass every entry,
negative ones the near-misses... the right event with the wrong category, a
negated value present. See [tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: '{"event_type":"alert","src_ip":"192.0.2.66","alert":{"category":"Misc Attack"}}'
      found: 1
      data:
        src_ip: "192.0.2.66"
  negative:
    - message: '{"event_type":"flow","src_ip":"192.0.2.67","alert":{"category":"Misc Attack"}}'
      found: 0
```

## Shipped rules using it

- `%json/suricata-all%` :: Each classtype rule pins `event_type` and `alert.category`, which is also what indexes them.
- `json/caddy-botsearch` :: A `status` filter ahead of the `match`.
- `syslog/postfix-harvest` :: Typed `eq` and `re` entries over the postfix munger's fields, with no `message_regexp` at all.
- `syslog/freeradius-auth` and `syslog/kernel_errors` :: `exists` and `re` entries over munger fields as the whole matcher.
- `raw/sonicwall-attack` :: One `re` over the decomposed `sw_msg` in place of a regexp over the line.

## See also

- [`condition`](condition.md) :: The boolean form of the same thing, never beside it.
- [`keywords`](keywords.md) :: The shorthand for a `contains` fanned over many fields, ANDed with it.
- [`match`](match.md) :: What makes the offense of a json or http line, below the `gate` that filters it.
- [the gate / selections / condition / keywords family](../rules.md#gate--selections--condition--keywords) :: The four forms side by side, in the type overview.
