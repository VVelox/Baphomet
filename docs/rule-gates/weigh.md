# weigh... worth more, or less

A `weigh` gate multiplies the weight a hit is counted with, where every
other gate vetoes or lets by. A failure against an administrator's account
is worth more than one against anyone else's, and the rule counting them can
say so with out a second rule to do it in.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for (?<USER>\S+) from %%%%SRC%%%%'
  - weigh: { times: 3, when: [ { field: USER, op: eq, values: [ root, admin ] } ] }
  - ban_var: [ SRC ]
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: nothing, or a found value with `by`
- vetoes :: no, it only weighs
- needs :: the watcher's `allow_per_rule_thresholds`, or a `weight` for the rule in the operator's `rule_config`
- repeatable :: yes, each entry is a gate of its own

## Told

- `times` / `by` :: Exactly one. The number to multiply by, or the found var holding it.
- `when` :: A list of entries as a [`gate`](gate.md) takes, every one of which has to hold for it to multiply.

A `by` var that is not a number above nothing leaves the weight as it was.
With out a `when` it always multiplies. The `when` is judged over the
offense's found data.

Several multiply one after another, and over the rule's own
[`weight`](../rules.md#max_score--find_time--ban_time--weight). A `weight: 2`
rule with a `weigh: { times: 3 }` counts a hit at 6.

## Where it goes

It reads no offender, so it may sit anywhere among the offense gates. A
`by` or a `when` reading a field an offense gate lifts, as a `country`
with an `into` does, goes below that gate.

## When it does not hold

It vetoes nothing, so it always lets the offense on.

It is honored where the rule's own `weight` is... on a watcher with
`allow_per_rule_thresholds`, or when the operator's `rule_config` gives the
rule a `weight`. With out that consent every hit weighs 1, a `weigh` gate
included, so a shipped rule can not reshape the counting. A rule counting
[`distinct`](../rules.md#distinct-counting-how-many-not-how-often) values
has no weights to multiply. See
[allow_per_rule_thresholds](../configuration.md#kurs-and-watchers) and
[per-rule config overrides](../configuration.md#per-rule-config-overrides).

## What it leaves behind

The weight the hit is deposited with, which reaches `max_score` sooner or
later than it would have, and which a [`scored`](scored.md) gate on any
rule reads back while the hit is live.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- both `times` and `by` :: "has both times and by"
- neither `times` nor `by` :: "has neither times nor by"
- a `times` that is not a number over nothing :: "has a times that is not a positive number"
- a `by` that is not a string :: "has a by that is not a non-empty string"
- a `when` a `gate` would not take :: what the `gate` refuses it for, its lead in ending "when"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

The counts are the galla's, so a rule's embedded tests run the gate but can
not show what it weighed. A test proves only that it lets the offense on,
`when` or no `when`. What it weighed is seen galla-side, in the score
`baphomet accused` reports and the EVE event's `score`. See
[tests](../rules.md#tests) for the shape.

## See also

- [`scored`](scored.md) :: Reads back the weights this sets, over every rule.
- [`account`](account.md) :: Tells an administrator's account by its `group`, where this weighs it by name.
- [weight](../rules.md#max_score--find_time--ban_time--weight) :: The rule's own weight, which this multiplies.
