# detection_var... counting by a thing, banishing nobody

A `detection_var` gate is the parallel of [`ban_var`](ban_var.md) for a
**detection-only rule**. It names the captures or fields to count by, under
no obligation to be an address... a username, a hostname, a URI, a
service, or an IP when that is what you want. Its being in a rule's list,
in place of a `ban_var`, is what makes the rule detection-only. The rule
runs the whole match, count, and threshold path like any other, and never
banishes. This is Sagan/Wazuh-style detection... alerting on a thing with
no address to banish, a policy tripwire, a config change, a service crash.

```yaml
# count by the offending username, banish nobody
rule_gates:
  - daemons: [ su ]
  - message_regexp:
      - '^FAILED SU \(to \S+\) (?<USER>\S+) on \S+'
  - detection_var: [ USER ]
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: a found value, each var it is told
- vetoes :: no, it only names
- needs :: nothing
- repeatable :: no, a rule names who it counts against once

## Told

A list of one or more vars, resolved as `ban_var` resolves them. A bare
string is not taken as a list of one. A var the offense has no value for,
or holds empty, names nothing.

## Where it goes

Wherever a `ban_var` would. A detection rule has no offender, so every
gate in its list that judges a value has to name the var it checks. One
keyed by the offender would never be asked, and the rule does not load
with it. [`ban_not_internal`](ban_not_internal.md) is the exception... it
loads, and does nothing on a detection rule.

## When it does not hold

It always holds. An offense it names nothing for still stands, consumes
the line, and writes its `sighting`.

## What it leaves behind

Each match writes a `sighting` to EVE, and a subject crossing `max_score`
within `find_time` writes a `sighted` whose `subjects_crossed` names the
var that did it, never touching Kur. Counting rides the shadow buckets, so
a detection rule can never nudge a real ban over its threshold, and
`ignore_ips` does not apply.

Because a detection rule writes only to EVE, loading one forces
`eve_enable` on, logged at start, so it is never a silent no-op. See
[eve](../eve.md) for the event shapes.

## Refused at load

- told other than a list of names :: "is not a non-empty array of non-empty strings"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A test proves it as any other rule, `found` counting the sightings and
`data` asserting what was named. See [tests](../rules.md#tests).

```yaml
tests:
  positive:
    - message: "Jul 12 08:25:49 mail01 su[2278]: FAILED SU (to root) moth3r on pts/1"
      found: 1
      data:
        USER: "moth3r"
```

## Shipped rules using it

- `syslog/su` and `syslog/sudo-policy` :: Count failures by the account, banishing nobody.
- `syslog/sshd-foreign-login` :: Sights a login from abroad, a traveler or a takeover the rule can not tell apart.
- `syslog/systemd-flap` :: Counts by the unit that keeps restarting.
- `%syslog/linux-audit%` :: The detection sweep of the audit trail rides it, beside the family's ban rules.

## See also

- [`ban_var`](ban_var.md) :: The same naming for a rule that banishes.
- [`country`](country.md) :: Named with `vars`, the way a detection rule has to name it.
- [eve_only](../rules.md#eve_only) :: Observe mode, a would-be ban held back and shown as an `alert`, still keyed to an offender IP... not a detection rule, which counts any subject and never bans.
