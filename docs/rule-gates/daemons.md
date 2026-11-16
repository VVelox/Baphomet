# daemons... which daemons a syslog rule reads

A `daemons` gate turns a syslog line away unless the daemon that logged it
is one of the ones named. Every syslog rule has to have one. Leading the
list, it is also what the galla indexes a watcher's rules by, so a line
cron logged is never even offered to the sshd rules... the cheapest
refusal there is on a busy shared log, and why the regexps of a syslog
rule are only ever tried against lines of the daemons they were written
for.

```yaml
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^[iI](?:llegal|nvalid) user .*? from %%%%SRC%%%%'
  - ban_var: [ SRC ]
```

## At a glance

- phase :: line
- rule types :: syslog
- keys on :: the line
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

A non-empty list, each entry one of...

- `<daemon>` :: A string the daemon has to equal.
- `//<regexp>//` :: A regexp the daemon has to match.

An entry starting and ending with `//` is a regexp... `//^sshd//` is the
regexp `^sshd`. It is not anchored for you, so `//sshd//` takes
`sshd-session` and `openssh-sshd` alike. Everything else is a plain string
equality check. A line the parser found no daemon in is turned away.

Two `daemons` gates are ANDed, a daemon having to get by both.

## Where it goes

**Leading the list.** The rule index reads only the `daemons` gates in the
run of gates leading the list that read nothing but the parsed line...
`daemons` and `ignore_regexp` on a syslog rule, in either order. One
written below anything else, a `mungers` say, still turns lines away, but
the rule is offered every line the watcher reads and asks it of each, and
whatever stands above it has already run on lines it then refuses.

## When it does not hold

The line is turned away outright. Nothing below is asked... no context is
stored, no sequence advances, nothing is harvested... and the line goes on
to the rules after it. A rule indexed by its `daemons` is never offered the
line at all, which comes to the same thing.

## Refused at load

- not a list, or an empty one :: "is not a array or is empty"
- an entry that is not a string :: "contains a non-string entry"
- a `//regexp//` that will not compile :: "entry ... does not compile"
- a syslog rule with out one :: "has no daemons gate, which a syslog rule has to have"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

No fixture. The near-miss it fences in is the right message from the wrong
daemon, which belongs among the negatives. Tests of a syslog rule default
to the `bsd_syslog` parser, which is what puts the daemon on the line. See
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  negative:
    # right message, wrong daemon
    - message: "Jul 12 08:25:49 mail01 cron[1234]: Failed password for invalid user admin from 192.0.2.7 port 4711 ssh2"
      found: 0
      undefed: ["SRC"]
```

## Shipped rules using it

Every syslog rule leads with one.

- `%syslog/ssh%` :: `sshd` and `sshd-session`, plain names.
- `syslog/sendmail-reject` :: The three names sendmail logs under.
- `syslog/postfix` :: One regexp over every `postfix/<service>`, multi-instance names included.
- `syslog/dovecot` :: Two regexps, `dovecot` and its auth workers.
- `syslog/pam-generic` :: `//.//`, any daemon at all, pam logging under whatever links it.

## See also

- [`ignore_regexp`](ignore_regexp.md) :: The other cheap refusal leading a syslog list, on the message rather than the daemon.
- [`message_regexp`](message_regexp.md) :: The matcher that only sees the lines this lets by.
- [`status`](status.md), [`method`](method.md), [`level`](level.md), [`module`](module.md) :: The same string-or-`//regexp//` refusal on the http and http_error types.
- [syslog rules](../rules.md#syslog-rules) :: The type it belongs to.
