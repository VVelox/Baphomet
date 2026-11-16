# ban_not_internal... sparing your own hosts

A `ban_not_internal` gate drops from an offense each offender that is one
of your own hosts. Some sources, Suricata's eve.json above all, log both
ends of a flow, and which one is the offender depends on where in the
stream the alert fired. A rule whose `ban_var` names both endpoints, with
this below it, banishes only the ends that are not yours.

```yaml
rule_gates:
  - ban_var:
      - src_ip
      - dest_ip
  - ban_not_internal: true
```

An inbound attack bans the external src, an outbound callout bans the
external dest, a transit flow bans both, and a host-to-host flow bans
neither.

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender
- vetoes :: no, it only drops offenders
- needs :: the `internal` config field
- repeatable :: yes, though a second does nothing the first did not

## Told

`true` to spare your own hosts. Anything false and the gate is left out
when the rule is bound, as if it were not written.

Your own hosts are the `internal` config field, global and per kur, which
defaults to the `ignore_ips` list (see
[configuration](../configuration.md#counting-and-banning)). Set `internal`
wider than `ignore_ips`, say all of RFC 1918, to spare internal clients
from a rule without globally ignoring them. An ignored IP is never
banished regardless.

It works on every type, not just the multi-endpoint case. With a single
offender... a `ban_var` naming one var, as the `host` of an http rule or
the `client` of an http_error one is... it skips the ban when that
offender is one of your own. Anything whose ban target is an IP can carry
it.

## Where it goes

Below the `ban_var`. It does not need one above it to load, but above one
there is nobody named yet to spare, and it quietly does nothing.

Where it sits among the offender-keyed gates changes what they see. Below
them, they judge your own hosts too, and a `country` gate, failing closed
on a private address the database can not place, vetoes an offense whose
every offender was internal. Right under the `ban_var`, they never see your own
hosts, and an offense left with nobody is let by.

On a [detection rule](detection_var.md) it loads and does nothing, a
detection rule banishing nobody.

## When it does not hold

It never vetoes. An offense left with no offender still stands... it
consumes the line, writes its `found` event, and counts against no one. So
a host-to-host flow is not passed on to the rules listed after this one.

## Refused at load

- told a list or a hash :: "is not a boolean"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A rule's tests can not prove it. Your own hosts are config, and a rule
file has none of it, so in a test the gate is unjudged and drops nobody.
Prove the rule names both ends with `data`, and leave the sparing to the
galla. See [tests](../rules.md#tests).

## Shipped rules using it

- `%json/suricata-all%` :: Every Suricata classtype rule, naming `src_ip` and `dest_ip`.
- `raw/fortinet-attack` :: An outbound hit puts your own host in `srcip=`.
- `raw/palo-alto-threat-exploit` and `raw/palo-alto-threat-virus` :: Both ends captured, `SRC` and `DEST`, as with Suricata.

## See also

- [`ban_var`](ban_var.md) :: Names the offenders it drops from.
- [`address`](address.md) :: Spares the kinds of address no list of yours needs to name, where this spares the hosts you listed.
- [the order it runs in](../rules.md#the-order-it-runs-in) :: Where the offenders are settled, it among them.
