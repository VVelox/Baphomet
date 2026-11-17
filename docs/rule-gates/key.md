# key... a json offense resolved through its context

A `key` gate resolves a json rule's offense through the context a
[`capture`](capture.md) gate of the rule kept under the same key, the
stored record going under the offense's own data. An offense whose key has
no context yet is not an offense on this record... it is dropped, or with
a `defer` left waiting that long for a capture record to bring the context.
It is what lets a json rule count an auth failure against an address the
failure's own record never carried.

```yaml
rule_gates:
  - capture:
      - gate: [ { field: msg, values: [ "Connection ended" ] } ]
        match:
          - { field: attr.remote, regexp: '^%%%%SRC%%%%:\d+$' }
        key: [ ctx ]
        ttl: 120
  - gate:
      - { field: msg, values: [ "Authentication failed" ] }
  - key: { key: [ ctx ], defer: 60 }
  - ban_var: [ SRC ]
```

## At a glance

- phase :: line
- rule types :: json
- keys on :: the line
- vetoes :: yes
- needs :: nothing
- repeatable :: no

## Told

The key alone, a field path or capture name or a list of them joined into
one key, or a hash of...

- `key` :: The field, or the list of them.
- `defer` :: Seconds an offense whose key has no context waits for a capture record to bring it.
  - default :: none, an unresolved offense is dropped

A key component names a field of the offense's data, the record's
flattened fields and any `match` captures alike. The `syslog.*` names are
the [`message_json`](message_json.md) envelope's and not a json record's,
so a key naming one is refused.

An offense goes one of four ways...

- a key component is missing :: Nothing to resolve by, and the offense stands as it is.
- the key resolves and context is stored :: The stored record goes under the offense's data, which wins, and the offense stands.
- the key resolves, no context yet, `defer` set :: The offense is parked to wait, and is not an offense on this record.
- the key resolves, no context yet, no `defer` :: The offense is dropped.

## Where it goes

**Below the gates that make and judge the offense.** It reads the offense
they leave standing. Above a `match` there is no offense yet and it does
nothing at all. Above a `gate` it parks offenses the `gate` would have
refused, and since a completed offense is not judged by the line gates
again, those count when their context comes.

## When it does not hold

An offense whose key has no context is not an offense on this record, and
the rule stops there for it... with no other offense standing the record
goes on to the rules after it. A parked offense counts nothing until a
capture record completes it, and one whose `defer` runs out first is
dropped with out a trace.

## What it leaves behind

The resolved offense's data, the context record's fields and captures
under the offense's own. Every gate below reads it, `ban_var` included.

A parked offense waits under its key in the rule's correlation store, per
watcher, at most 100 per key, the oldest dropped to make room. It parks
its whole data, the record's fields with it, so the offense a capture
record completes keeps everything its own record had. The store is written
to the context tablet at each checkpoint and read back at start, anything
expired by then dropped, so a waiting offense can survive a restart.

A rule with a `key` is out of the record index, which only pins a rule
whose `gate` alone decides what it does with a record... it is offered
every record of the watcher.

## Refused at load

- a hash with out `key`, an unknown key, or a `defer` that is not a positive int of seconds :: "lacks a key", "has the unknown key ...", "has a defer that is not ..."
- a key that is neither a string nor a list, an empty list, or a component that is not a non-empty string :: "has a key that is not a string or a array", "has a empty key array", "has a key component that is not a non-empty string"
- a `syslog.*` key component :: "keys on ..., which is not a envelope field this rule type carries"
- a second `key` in the rule :: "is the second key gate of the rule, which can have the one"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

The `messages:` test form, as for [`capture`](capture.md)... both arrival
orders, an `advance` past the `defer`, and an offense whose context never
comes, which with out a `defer` is a negative on its own. See
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  negative:
    # no connection has ended under conn10, so there is no one to count it against
    - message: '{"c":"ACCESS","ctx":"conn10","msg":"Authentication failed","attr":{"user":"admin"}}'
      found: 0
```

## Shipped rules using it

None.

## See also

- [`capture`](capture.md) :: The context it resolves through, and what completes a parked offense.
- [`message_regexp`](message_regexp.md) :: The text types key each entry instead.
- [`gate`](gate.md), [`match`](match.md) :: What makes and judges the offense above it.
- [correlation on json](../rules.md#correlation-on-json-capture-key-defer) :: The json overview, beside the text types'.
