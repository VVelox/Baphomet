# active_time... only in, or out of, certain hours

An `active_time` gate only lets a match count when the time falls in, or
out of, named windows... an admin login that is routine at midday and
worth a ban at 03:00. The windows are defined in the config's
`active_time`, layered per watcher, so a rule stays policy-neutral.

```yaml
rule_gates:
  - active_time:
      is: [ business, mixed ]     # count only when the time is in ANY of these (union)
      # xor  isnot: [ overnight ] # count only when in NONE of them
      vars: [ ts ]                # optional: which found value holds the time; default = now
max_score: 1
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the clock, or a found value with `vars`
- vetoes :: yes
- needs :: the `active_time` windows it names
- repeatable :: yes, each entry is a gate of its own

## Told

- `is` / `isnot` :: Exactly one. The name of a window, or a list of them, out of the watcher's `active_time`.
- `vars` :: The found var, or a list of them, holding the times to check, in place of now.

Several windows are unioned. With `vars`, every time named has to pass.
A window is days of the week, hours, or both (see
[active time windows](../configuration.md#active-time-windows)).

With out `vars` the gate checks the time the galla read the line, the
usual case. A found time is read as an epoch, all digits, a journal's
milliseconds or microseconds scaled down to seconds, or as an ISO 8601
datetime down to the second. An epoch is judged in the system's local
time. An ISO datetime is judged at its face value, the zone it names
dropped and not converted, so `2026-07-12T08:15:50Z` is 08:15 wherever
the galla runs. A log's raw timestamp string is rarely one of those, so `vars` suits
JSON or EVE lines carrying a machine timestamp. Leave it off to gate on
now.

## Where it goes

Anywhere among the offense gates. Time is a property of the line and not
of an offender, so the gate is asked once of the whole offense, `vars` or
not, and needs no `ban_var` above it. It looks nothing up, so it is cheap
to put first.

## When it does not hold

A veto drops the offense, and the line goes on to the rules listed after
this one.

A found time that is missing, or that does not parse, **fails closed**.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- an `is` or `isnot` that is not window names :: "has a is that is not a name matching /^[a-zA-Z0-9_\-]+$/ or a non-empty array of them"
- a `vars` that is not a name or a list of them :: "has a vars that is not a non-empty string or a non-empty array of them"
- both `is` and `isnot` :: "has both is and isnot"
- neither `is` nor `isnot` :: "has neither is nor isnot"
- a window the watcher does not define, when bound :: "references active_time{...}, which is not a defined window for it"

The last is found when the galla binds the rule to a watcher, and the
galla will not start on it.

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A rule's tests can not prove it. Its windows are config, and a rule file
has none of it, so in a test the gate is unjudged and the rule counts as
if it were not written. It is proven galla-side only.

## Shipped rules using it

None. Which hours matter is your policy.

## See also

- [`epoch`](epoch.md) :: Turns a log's own timestamp into the epoch this gate can read.
- [`fresh`](fresh.md) :: Judges how old a line's time is, not what hour it is.
- [`novel`](novel.md) :: An hour the account never used, where this can only say an hour you named.
