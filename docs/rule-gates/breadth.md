# breadth... counted by many rules

A `breadth` gate holds when at least `rules` different rules have live hits
against an address, the rule it is of counted among them. A scanner that
tries ssh, ftp, and the web panel once each stays under every count a rule
keeps, and has been counted by three.

```yaml
max_score: 1
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - breadth: { rules: 3, seconds: 3600 }
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `var`
- vetoes :: yes
- needs :: the hits the galla is counting
- repeatable :: yes, each entry is a gate of its own

## Told

- `rules` :: How many different rules it takes, two or more.
- `seconds` :: How far back a hit is read.
- `of` :: The rules whose hits are counted, in place of all of them.
- `var` :: The found var holding the address, in place of the offender.

A bare `of` is a list of one. The rule the gate is of is counted whether or
not `of` names it, so a `rules: 2` holds on the first hit of this rule once
any one other has a live hit.

It reads the hits the galla is counting, the shared bucket and each rule's
own, observe mode's and detection rules' included. So a hit a ban already
cleared, or one older than its rule's `find_time`, is not there to read,
and `seconds` past the longest `find_time` reads no further back. The
rule's own hit on this line is counted, though it is not in the counts yet.

## Where it goes

With out a `var` it keys on the offender, so it goes below the `ban_var`
that names one, and is asked of each. With a `var` it is asked once for the
offense, and is the only way a detection rule can have a `breadth` gate.

Listed ahead of the service's ordinary rules, with a `max_score: 1`, it
banishes the address on the first hit of the third service, and lets every
other line fall through to be counted as before.

## When it does not hold

An offender it does not hold for is dropped, and an offense left with none
is vetoed, its line going on to the rules after this one.

It fails closed. A `var` the offense lacks holds nobody. A hit restored
from a tablet written before the counts said which rule made it is no
rule's, and counts toward nothing here.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `rules` or no `seconds` :: "lacks a ..."
- a `rules` under two, or not a whole number :: "has a rules that is not a int of two or more"
- a `seconds` that is not a whole number of one or more :: "has a seconds that is not a positive int of seconds"
- an `of` that is not a rule name or a list of them :: "has a of that is not a rule name or a non-empty array of them"
- a `var` that is not a string :: "has a var that is not a non-empty string"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A `rules_hit` fixture stands in for the galla's counts, a map of address to
the rules that have hits against it. It answers the same however far back
the gate reads, so `seconds` is proved galla-side only. With out the
fixture the gate is skipped. See [tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    # two other services and this one are three
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for neti from 203.0.113.9 port 4711 ssh2"
      rules_hit:
        "203.0.113.9": [ syslog/vsftpd, syslog/dovecot ]
      found: 1
  negative:
    # one other and this one are two
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for neti from 203.0.113.10 port 4711 ssh2"
      rules_hit:
        "203.0.113.10": [ syslog/vsftpd ]
      found: 0
```

## See also

- [`scored`](scored.md) :: How much the rules have counted an address for, where this is how many rules.
- [`banished`](banished.md) :: What an address has been banished for already, where this reads hits not yet banished on.
- [distinct](../rules.md#distinct-counting-how-many-not-how-often) :: Breadth within one rule, counting the different values it saw.
