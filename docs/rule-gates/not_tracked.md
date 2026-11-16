# not_tracked... a line with no record of its transaction

A `not_tracked` gate holds only when the line is part of no live
[tracked record](../rules.md#tracked-records-state-that-accumulates-across-lines).
It is "this transaction has never been seen", a stage line turning up with
no earlier stage behind it. A record that exists but does not say what is
wanted is a different question, and is a `tracked` with a negated `where`.

```yaml
rule_gates:
  - not_tracked: { name: mail-queue }
  - track: { name: mail-queue, key: postfix_queueid, fields: [] }
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

It takes nothing else, the key being the one the `track` of the same name
declared.

## Where it goes

**Above the `track` that writes the record.** Below it, the line has just
made the record the gate looks for, and it can never hold.

**Below the matcher, when the key is a capture.** Above it the key does not
resolve, and the gate holds with out reading anything.

## When it does not hold

It vetoes only when the key resolves and a live record is under it. A line
with no value for the key holds, being part of no transaction, and so does
a line with no tracked store, which is read as having no records. A
expired record is no record. A veto refuses the offense and does not turn
the line away, so a `track` below still harvests the line. An offense a
earlier line left waiting is let by, having been judged already.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take, a `where` among them :: "has the unknown key ..."
- no `name` :: "lacks a name"
- a `name` that is not a name :: "has a name that is not a name matching /^[a-zA-Z0-9_\-]+$/"
- no `track` of the rule declaring the record :: "names the record "...", which the rule declares no track for"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

Seed a record with `tracked_before` for the negative and leave it off for
the positive, the same line both times. See
[Proving brands and gates](../rules.md#proving-brands-and-gates) and
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  negative:
    - message: "Jan  2 04:00:00 mx1 postfix/local[222]: 1C36D185729: to=<victim@example.org>, status=bounced"
      tracked_before:
        - name: mail-queue
          key: 1C36D185729
          fields: {}
      found: 0
```

## See also

- [`track`](track.md) :: Declares and writes the record this asks after.
- [`tracked`](tracked.md) :: Reads a record that exists, judging or lifting from it.
- [`not_marked`](not_marked.md) :: The same question asked of a brand.
