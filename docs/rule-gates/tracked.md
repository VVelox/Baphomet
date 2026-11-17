# tracked... judging a line by the record of its transaction

A `tracked` gate reads the
[tracked record](../rules.md#tracked-records-state-that-accumulates-across-lines)
a line is part of, and either judges the line by it, lifts fields of it
into what the line found, or both. The line that finally says something
worth banning on is rarely the one that said who to ban... a postfix bounce
on the `local` line an hour after the `smtpd` line that named the client.
`into` is how the address on that earlier line reaches this one's
`ban_var`.

```yaml
rule_gates:
  - daemons: [ postfix/local ]
  - message_regexp:
      - '^(?<postfix_queueid>[0-9A-F]+): to=<[^>]*>, status=(?<postfix_status>bounced)'
  - tracked:
      name: mail-queue
      where:
        - { field: postfix_sasl_username, op: exists }
      into: [ postfix_client_ip ]
  - track: { name: mail-queue, key: postfix_queueid, fields: [ postfix_status ] }
  - ban_var: [ postfix_client_ip ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: a found value, the key of the record's `track`
- vetoes :: yes
- needs :: a `track` of the rule declaring the record
- repeatable :: yes, each entry is a gate of its own

## Told

- `name` :: The record, one a `track` of the rule declares.
- `where` :: A list of predicate entries, as [`gate`](gate.md) takes, judged against the stored record.
- `into` :: The fields of the record to lift into what the line found.

At least one of `where` and `into`. It takes no key of its own, using the
one the `track` of the same name declared, wherever that sits in the list.
The `where` is judged against the record and not the line, so a field no
line ever gave fails every operator but `exists`, which makes
`{ op: exists, negate: true }` the never-appeared test. A lifted field
never lands over one the line already has, a capture of the same name
always winning.

## Where it goes

**Above the `track` that writes the record**, so the read precedes the
write and a `where` judges the history rather than what this line just
filed.

**Above the line gates that read what `into` lifts.** A line gate written
above the `tracked` is asked before the lift and does not see the field.
The offense gates always see it, `ban_var` among them, as every line gate
is asked before any of them.

**Below the matcher, when the key is a capture.** Above it the key does not
resolve, and the gate holds with out reading anything.

## When it does not hold

What it finds decides it.

| the key | the record | `where` | what happens |
|---|---|---|---|
| does not resolve | — | — | holds |
| resolves | none | given | vetoes |
| resolves | none | not given | holds, lifting nothing |
| resolves | live | given | holds and lifts `into` when the record passes the `where`, else vetoes |
| resolves | live | not given | holds and lifts `into` |

A key that does not resolve holds because a line may rightly lack one...
a `NOQUEUE` reject has no queue id and must sail through. A record that
is not there under a `where` vetoes, failing closed as `country` and
`namtar_list` do. With no `where` and no record nothing lifts, so a
`ban_var` naming a lifted field finds nothing.

A line with no tracked store is read as having no records. A veto refuses
the offense and does not turn the line away, so a `track` below still
harvests the line. An offense a earlier line left waiting, through
[correlation](../rules.md#correlation-offense-and-address-on-different-lines),
was judged already, so the gate does not veto it and only lifts into it.

## What it leaves behind

The `into` fields, lifted into the offense, or into the line's own fields
while the matcher has made no offense yet. The line gates below it and
every offense gate can read them.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `name` :: "lacks a name"
- a `name` that is not a name :: "has a name that is not a name matching /^[a-zA-Z0-9_\-]+$/"
- an `into` that is not a list of strings :: "has a into that is not a non-empty array of non-empty strings"
- neither `where` nor `into` :: "has neither where nor into, so it does nothing"
- a `where` entry `gate` would refuse :: refused as `gate` refuses it, the message led by "... where"
- no `track` of the rule declaring the record :: "names the record "...", which the rule declares no track for"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

`tracked_before` seeds a record, each entry a `name`, a `key` (a string,
or a list for a compound key), the `fields` it holds, and an optional
`ttl`. Prove it both ways... the seeded line fires, and the same line
unseeded does not. Better still, where the rule owns the harvest too, a
multiline `messages:` test walks the harvest line and the reading line
through one scope. See
[Proving brands and gates](../rules.md#proving-brands-and-gates) and
[tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - daemons: [ postfix/local ]
  - message_regexp:
      - '^(?<postfix_queueid>[0-9A-F]+): to=<[^>]*>, status=(?<postfix_status>bounced)'
  - tracked:
      name: mail-queue
      where:
        - { field: postfix_sasl_username, op: exists }
      into: [ postfix_client_ip ]
  - track: { name: mail-queue, key: postfix_queueid, fields: [ postfix_status ] }
  - ban_var: [ postfix_client_ip ]
tests:
  positive:
    - message: "Jan  2 04:00:00 mx1 postfix/local[222]: 1C36D185729: to=<victim@example.org>, status=bounced"
      tracked_before:
        - name: mail-queue
          key: 1C36D185729
          fields: { postfix_client_ip: "203.0.113.9", postfix_sasl_username: alice }
      data:
        postfix_client_ip: "203.0.113.9"   # lifted by into, never on this line
  negative:
    # the same line unseeded... a where over no history fails closed
    - message: "Jan  2 04:00:00 mx1 postfix/local[222]: 1C36D185729: to=<victim@example.org>, status=bounced"
      found: 0
```

## See also

- [`track`](track.md) :: Declares and writes the record this reads.
- [`not_tracked`](not_tracked.md) :: Holds only when there is no live record at all.
- [`marked`](marked.md) :: The same read over a one-scalar brand.
- [tracked records](../rules.md#tracked-records-state-that-accumulates-across-lines) :: The postfix story the three gates tell together.
