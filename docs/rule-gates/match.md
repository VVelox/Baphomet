# match... the offense, out of a line's fields

A `match` gate is the matcher of the field types. Its entries each name a
field of the line and a regexp, tried in order, the first to match making
the line's offense. A line none of them matches makes no offense. On a json
rule a regexp may use the `%%%%TOKEN%%%%` shortcuts, which is how an
address is dug out of a field that holds more than the address, a
`"remote":"192.0.2.5:54321"` say. On a http rule it picks the requests
worth counting out of a log where the offender is already the parsed
`host`.

```yaml
rule_gates:
  - status: [ 401, 403, 404 ]
  - match:
      - { field: path, regexp: '^/wp-login\.php' }
      - { field: path, regexp: '\.(?:env|git)(?:$|/)' }
  - ban_var: [ host ]
```

## At a glance

- phase :: line
- rule types :: http, json
- keys on :: the line
- vetoes :: yes
- needs :: nothing, or Log::Munger for a primitive fragment
- repeatable :: no

## Told

A non-empty list of entries, ORed, the first to match winning, each a hash
of...

- `field` :: The field of the line to read.
- `regexp` :: The regexp the field has to match.

**On http** the field has to be one an access log line has... `host`,
`ident`, `user`, `time`, `request`, `method`, `path`, `protocol`,
`status`, `bytes`, `referer`, `user_agent`, or `format`... or one a gate
of the rule lifts, an `into` or an `extract` capture. The regexp is plain
Perl with no tokens, and the offense's data is the line's fields, a named
capture in the regexp going nowhere.

**On json** the field is a flattened dotted path, `attr.remote` or
`tags.0`. The regexp is tokened as
[`message_regexp`](message_regexp.md)'s is, offender tokens and primitive
fragments both, and the offense's data is its captures with the record's
fields laid over them, so a capture named like a field of the record is
overwritten by it. A field the line does not have never matches.

A rule with out one makes its offense of the line's fields once every gate
has let them by, so `match` is optional where a [`gate`](gate.md),
[`condition`](condition.md), [`keywords`](keywords.md), `status`, or
`method` judges. A rule with neither is refused.

## Where it goes

**Below the gates that judge the line's fields.** A `gate` above it judges
the fields before it is asked, so a line already refused is not matched at
all... the json idiom, a `gate` pinning the event and a `match` digging out
the address, reads in that order. On json a [`capture`](capture.md) goes
above it, as a line it does not match ends the rule's walk, and a `key`
goes below it, resolving the offense it made.

## When it does not hold

A line none of its entries matches makes no offense, and the rule stops
there for the line, which goes on to the rules after it.

## What it leaves behind

The offense's data... on http the line's fields, on json its captures
under the record's fields. Every gate below reads it, `ban_var` and
`detection_var` included, and it is what the EVE `found` carries. Which
entry matched goes down as the offense's `regexp`, counted from zero.

## Refused at load

- not a non-empty list of hashes :: "is not a non-empty array", "entry N is not a hash"
- an entry with out `field` or `regexp`, or with any other key :: "lacks a ...", "has the unknown key ..."
- a `field` or `regexp` that is not a scalar :: "has a field that is not ..."
- on http, a field the line does not have and no gate lifts :: "names the unknown field ..."
- on json, a regexp naming an unknown token :: "uses the unknown token ..."
- a regexp that will not compile :: "does not compile"
- a second `match` in the rule :: "is the second match gate of the rule, which can have the one"
- a rule with no `match` and nothing that judges :: "has no gate that makes a offense of a line or judges one ..."

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

No fixture. Tests default to the `http_access` parser on http and the
`json` parser on json, each json message one line of JSON. One positive
per entry, asserting the offender in `data`. See
[tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - gate:
      - { field: msg, values: [ "Authentication failed" ] }
  - match:
      - { field: attr.remote, regexp: '^%%%%SRC%%%%:\d+$' }
  - ban_var: [ SRC ]
tests:
  positive:
    - message: '{"c":"ACCESS","msg":"Authentication failed","attr":{"remote":"192.0.2.5:54321"}}'
      found: 1
      data:
        SRC: "192.0.2.5"
  negative:
    - message: '{"c":"ACCESS","msg":"Authentication failed","attr":{"remote":"not-an-address"}}'
      found: 0
      undefed: ["SRC"]
```

## Shipped rules using it

- `%http/scanners%` :: Paths and user agents on access logs, `http/botsearch` beside a `status`, `http/badbots` beside a `method`.
- `http/fakegooglebot` :: The Googlebot user agent, alone, `reverse_dns` below it judging the claim.
- `json/mongodb-auth` :: The address dug out of `attr.remote` with `SRC`, below a `gate` on the event.
- `json/caddy-botsearch` :: Probe paths in `request.uri`, `ban_var` naming the client field outright.
- `json/cowrie` :: `SRC` over the bare `src_ip`, so the offender is proven an address.

## See also

- [`ignore`](ignore.md) :: The veto of the same shape, written above it.
- [`message_regexp`](message_regexp.md) :: The matcher of the text types.
- [`gate`](gate.md), [`condition`](condition.md), [`keywords`](keywords.md) :: The predicate layer it is ANDed with.
- [`status`](status.md), [`method`](method.md) :: The cheap http refusals above it.
- [`capture`](capture.md), [`key`](key.md) :: Correlation on json, around it.
- [json rules](../rules.md#json-rules), [http rules](../rules.md#http-rules) :: The types it belongs to.
