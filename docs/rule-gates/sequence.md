# sequence... brands set in order

A `sequence` gate holds when every brand it names is live for the key it
checks, the offender by default, and they were first set in the order
listed. `marked` asks whether brands are set; this asks whether they
happened in order... scanned, then exploited, each stage branded by a
`mark_only` rule or by the rules that already brand it.

```yaml
rule_gates:
  - sequence:
      marks: [ recon, exploit_attempt ]
      var: src_ip
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender | a found value
- vetoes :: yes
- needs :: the galla's mark store
- repeatable :: yes, each entry is a gate of its own

## Told

- `marks` :: Two or more brands, in the order they have to have been set.
- `var` :: The found var whose value is the key.
  - default :: each offender
- `vars` :: The found vars whose values joined are one compound key.

`var` and `vars` exclude each other, and key as they do on a
[`mark`](mark.md). Each brand is ordered by when it was first set, which
setting it again does not move. Two set in the same instant count as in
order. All the stages present in any order is the plain `marked` gate,
one entry per brand.

## Where it goes

**Below the `ban_var` that names the offender**, when it names no var.

**In a rule listed ahead of the ones it upgrades.** A vetoed line falls
through to them untouched, and a held one has this rule speak instead.

## When it does not hold

It fails closed. A line with out the var, or vars, it keys on vetoes, as
does a stage missing, expired, or set before the one listed ahead of it. A
brand with no saying when it was set is not ordered against the others,
only required to be live.

The first-set time survives a restart and rides the fleet mark sync of a
[Redis tablet](../tablets.md), so a fleet-shared sequence correlates
stages seen on different machines.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `marks` :: "lacks a marks"
- a `marks` of fewer than two names :: "has a marks that is not a array of at least two mark names"
- a `var` that is not a string :: "has a var that is not a non-empty string"
- a `vars` that is not a list of strings :: "has a vars that is not a non-empty array of non-empty strings"
- both `var` and `vars` :: "has both var and vars"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

Seed the stages with `marks_before`, each with an explicit `set` time.
Prove it fires in order and, with the same two seeds and the times
swapped, that it does not out of order. See
[Proving order and time](../rules.md#proving-order-and-time) and
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: '{"timestamp":"2026-07-12T08:15:50.123456+0000","event_type":"alert","src_ip":"192.0.2.66","src_port":4444,"dest_ip":"203.0.113.5","dest_port":80,"proto":"TCP","alert":{"signature_id":2101219,"signature":"TEST escalation","category":"Web Application Attack","severity":1}}'
      marks_before:
        - name: recon
          key: "192.0.2.66"
          set: 1000000000
        - name: exploit_attempt
          key: "192.0.2.66"
          set: 1000000100
      found: 1
  negative:
    # exploited, then scanned... the wrong order
    - message: '{"timestamp":"2026-07-12T08:15:50.123456+0000","event_type":"alert","src_ip":"192.0.2.66","src_port":4444,"dest_ip":"203.0.113.5","dest_port":80,"proto":"TCP","alert":{"signature_id":2101219,"signature":"TEST escalation","category":"Web Application Attack","severity":1}}'
      marks_before:
        - name: recon
          key: "192.0.2.66"
          set: 1000000100
        - name: exploit_attempt
          key: "192.0.2.66"
          set: 1000000000
      found: 0
```

## Shipped rules using it

- `json/suricata-escalation` :: Any Suricata alert from a source holding `recon` then `exploit_attempt`, scanned then exploited.

## See also

- [`marked`](marked.md) :: The same brands, present in any order.
- [`mark`](mark.md) :: Sets each stage's brand.
- [marks](../rules.md#marks-cross-rule-state-keyed-by-anything) :: How rules tie together over brands.
- [the standard brands](../rules.md#the-standard-brands) :: Where `recon` and `exploit_attempt` come from.
