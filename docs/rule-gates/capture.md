# capture... the address, from a json record that is not the offense

A `capture` gate harvests context on a json rule. A record one of its
entries takes is kept whole under that entry's key, where the rule's
[`key`](key.md) gate finds it for an offense of the same key. And an
offense the `key` gate left waiting on that key completes here, the moment
the context arrives. Structured logs split events too... a service that
logs the auth failure as one JSON event and the connection's address as
another, the two sharing a connection id, is the text-log problem over
again.

```yaml
rule_gates:
  - capture:
      - gate:
          - field: msg
            values: [ "Connection ended" ]
        match:
          - field: attr.remote
            regexp: '^%%%%SRC%%%%:\d+$'
        key: [ ctx ]
        ttl: 120
  - gate:
      - field: c
        values: [ ACCESS ]
      - field: msg
        values: [ "Authentication failed" ]
  - key: { key: [ ctx ], defer: 60 }
  - ban_var:
      - SRC
```

## At a glance

- phase :: line
- rule types :: json
- keys on :: the line
- vetoes :: no, it only stores
- needs :: nothing, or Log::Munger for a primitive fragment
- repeatable :: yes, each entry is a gate of its own

## Told

A non-empty list of entries, every one tried against the record, each a
hash of...

- `key` :: The field the context is kept under, or a list of them joined into one key.
- `gate` :: A list as the [`gate`](gate.md) gate takes, which the record has to pass.
- `match` :: A list of `field` and `regexp` hashes, the first to match taking the record, its captures kept with the fields.
- `ttl` :: Seconds the context is kept.
  - default :: 60

Each entry needs a `gate`, a `match`, or both, or it would harvest every
record. A context record is rarely shaped like the offense, so an entry
judges a record by its own `gate` and `match` and never by the rule's. The
`match` regexps are tokened as a json [`match`](match.md)'s are.

What is kept is the whole event... the `match` captures with the record's
flattened fields laid over them, the fields winning, so the key may name
either a field path or a capture. Every key component has to resolve, or
the entry keeps nothing. The `syslog.*` names are the
[`message_json`](message_json.md) envelope's and not a json record's, so a
key naming one is refused. A later record of the same key replaces what an
earlier one kept, and kept context is not used up... it resolves every
offense of its key until its `ttl` runs out.

## Where it goes

**Leading the list, above the rule's `gate` and `match`.** A capture record
is usually one the rule's own `gate` or `match` refuses, and a refused
record with nothing standing ends the rule's walk, so a `capture` written
below them is never asked of the records it is there for. An
[`ignore`](ignore.md) above it keeps a record from being stored, and from
completing an offense left waiting.

A rule with a `capture` is out of the record index, which only pins a rule
whose `gate` alone decides what it does with a record... it is offered
every record of the watcher.

## When it does not hold

It turns no record away and judges no offense. A record none of its
entries takes is passed on as it was.

An offense it completes was judged by the rule's line gates when the `key`
gate left it waiting, and is not judged by them again... the offense gates
below, `ban_var` on, still judge it. One left waiting whose context never
comes, or comes after the `defer` ran out, is dropped with out ever having
counted.

## What it leaves behind

Context in the rule's correlation store, per watcher, the whole event under
its key until the `ttl` runs out. At most 10000 keys are kept per watcher,
the expired pruned and then the soonest to expire evicted past that.

An offense it completes is the waiting offense's data over the context
record's, the offense's own winning. It stands beside whatever the record
itself comes to.

The store is written to the context tablet at each checkpoint and read
back at start, anything expired by then dropped, so both the context and
the offenses waiting on it can survive a restart.

## Refused at load

- not a non-empty list of hashes :: "is not a non-empty array", "entry N is not a hash"
- an entry with out `key`, an unknown key, or a `ttl` that is not a positive int of seconds :: "lacks a key", "has the unknown key ...", "has a ttl that is not ..."
- an entry with neither `gate` nor `match` :: "has neither gate nor match, so it would harvest every line"
- a key that is neither a string nor a list, an empty list, or a component that is not a non-empty string :: "has a key that is not a string or a array", "has a empty key array", "has a key component that is not a non-empty string"
- a `syslog.*` key component :: "keys on ..., which is not a envelope field this rule type carries"
- an entry's `gate` that the [`gate`](gate.md) gate would refuse :: as that gate words it, led by "... entry N gate"
- an entry's `match` not a non-empty list of `field` and `regexp` hashes :: "match is not a non-empty array", "match entry N lacks a ..."
- a `match` regexp naming an unknown token, or one that will not compile :: "uses the unknown token ...", "does not compile"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

The `messages:` test form, the records fed in order, each one line of JSON.
Prove both arrival orders, a context that comes too late with an `advance`
past the `defer`, and an offense whose context never comes. See
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    # the offense first, waiting on the end of its connection
    - messages:
        - '{"c":"ACCESS","ctx":"conn7","msg":"Authentication failed","attr":{"user":"admin"}}'
        - '{"c":"NETWORK","ctx":"conn7","msg":"Connection ended","attr":{"remote":"192.0.2.35:53276"}}'
      found: 1
      data:
        SRC: "192.0.2.35"
    # the context first
    - messages:
        - '{"c":"NETWORK","ctx":"conn8","msg":"Connection ended","attr":{"remote":"192.0.2.36:53277"}}'
        - '{"c":"ACCESS","ctx":"conn8","msg":"Authentication failed","attr":{"user":"admin"}}'
      found: 1
      data:
        SRC: "192.0.2.36"
  negative:
    # the connection ends past the defer
    - messages:
        - '{"c":"ACCESS","ctx":"conn9","msg":"Authentication failed","attr":{"user":"admin"}}'
        - message: '{"c":"NETWORK","ctx":"conn9","msg":"Connection ended","attr":{"remote":"192.0.2.37:53278"}}'
          advance: 61
      found: 0
```

## See also

- [`key`](key.md) :: The gate that resolves an offense through it and leaves one waiting on it.
- [`capture_regexp`](capture_regexp.md) :: The same harvest on syslog and raw, over the message.
- [`gate`](gate.md), [`match`](match.md) :: What an entry judges a record by.
- [correlation on json](../rules.md#correlation-on-json-capture-key-defer) :: The json overview, beside the text types'.
