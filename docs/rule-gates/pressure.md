# pressure... a rule for when it is under attack

A `pressure` gate lets a line by only while the watcher's rules are
matching above a mark, and turns it away otherwise. It is for a harsher
copy of a rule, listed ahead of the one it shadows, that only has its say
during an attack.

```yaml
# syslog/sshd-siege, your own harsher copy of syslog/sshd, listed ahead of it
max_score: 2
rule_gates:
  - pressure: { above: 200, seconds: 60, hold: 300 }
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: the clock, and the count of matched lines
- vetoes :: yes, it turns the line away
- needs :: the galla's count of matched lines
- repeatable :: yes, each entry is a gate of its own

## Told

- `above` :: How many matched lines it takes more than.
- `seconds` :: How far back they are counted over.
- `times` :: How many times what is usual the count has to be more than.
- `baseline` :: How many seconds before the `seconds` what is usual is read over.
- `hold` :: Seconds the gate goes on letting lines by after the count was last above the mark.
  - default :: 0
- `scope` :: What is counted over, `watcher` or `galla`.
  - default :: `watcher`

`seconds` is required, and so is `above` or `times`. `times` and `baseline`
only go together. Beside a `times`, `above` is the least the count may be
for the `times` to be asked. `hold` keeps a lull between two waves from
shutting the gate. A `hold` of 0, the default, shuts it the moment the
count drops back under the mark.

A count for a mark wants setting for each host, a busy mail server and a
quiet bastion being nothing alike. `times` sets itself, what is usual
being what the `baseline` seconds before the `seconds` came to, evened out
to as long:

```yaml
  - pressure: { times: 5, above: 20, seconds: 60, baseline: 3600 }
```

That is five times the last hour's minute, and twenty at the least. Keep
the `above`... a host that matched one line in the hour is five times over
with a second, and with nothing matched in the baseline at all there is no
saying what is usual and the gate stays shut, which is where a galla is
for its first while after a restart.

## Where it goes

First. Written first it turns a line away before anything else is done with
it, and a family of harsher rules costs next to nothing while there is no
attack. It is one of the early gates, asked before the rest of the line is
made, so a `daemons` gate right below it still leads for the rule index.
The rule itself goes ahead of the one it shadows in the watcher's list, so
it has the line first.

## When it does not hold

The line is turned away outright, so nothing below it is asked and nothing
is harvested. The rule it shadows then has the line as usual.

**It can be turned against you.** Whoever drives the count up makes the
harsher thresholds everyone's, so a real user's two typos during an attack
become a ban, and a password rotation day does the same with no attacker
at all. Run one as a detection rule first.

## What it leaves behind

What is counted is the lines some banning rule named an offender on,
whatever the gates below its `ban_var` then made of the offender, each once
however many rules did, on the gate's watcher or over the whole galla.
A rule that only sights or only brands is no sign of an attack and is not
counted. A line the harsher rule took is counted like any other, so the
gate letting lines by does not lower what it reads and it does not flap.
The count is kept in spans of ten seconds, so it is exact to that and no
finer, and is kept only as far back as the gate reading furthest asks. It
is held in memory, and forgotten at a restart.

The galla logs a line each time a gate opens or shuts... `The rule
"syslog/sshd-siege" of the watcher "auth" is under pressure, 240 matched
lines in the last 60 seconds`, and `is no longer under pressure` when it
shuts.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not know :: "has the unknown key ..."
- no `seconds` :: "lacks a seconds"
- neither `above` nor `times` :: "has neither above nor times"
- a `times` with out a `baseline`, or a `baseline` with out a `times` :: "has a times with out a baseline, or a baseline with out a times"
- an `above` that is not a positive whole number :: "has a above that is not a positive int"
- a `times` that is not a positive number :: "has a times that is not a positive number"
- a `seconds` or `baseline` that is not a positive whole number :: "has a ... that is not a positive int of seconds"
- a `hold` that is not a whole number of zero or more :: "has a hold that is not a non-negative int of seconds"
- a `scope` that is neither `watcher` nor `galla` :: "has a scope that is not one of watcher or galla"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A test gives the count the gate reads as a `pressure` fixture, the same
however far back it asks. It answers the baseline the same as the
`seconds`, so a `times` threshold is proved galla-side only. With none the
gate is skipped and the line let by. See [tests](../rules.md#tests) for the
shape.

```yaml
tests:
  positive:
    - message: "Jul 12 08:15:50 bastion sshd[4012]: Failed password for morgan from 198.51.100.23 port 51122 ssh2"
      pressure: 201
  negative:
    - message: "Jul 12 08:15:50 bastion sshd[4012]: Failed password for morgan from 198.51.100.23 port 51122 ssh2"
      pressure: 200
```

## See also

- [`startup`](startup.md) :: The other gate that reads nothing of the line.
- [`breadth`](breadth.md) and [`scored`](scored.md) :: Counts over every rule as well, but of one address rather than of a watcher's lines.
- [detection_var](detection_var.md) :: How to run it watching before it acts.
