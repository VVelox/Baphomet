# novel... a value a key has not had before

A `novel` gate holds when a key is seen with a value it has not been seen
with before, once the key has been seen often enough to have a before. An
account that has only ever logged in from one country and now logs in from
another.

```yaml
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - country: { vars: [ SRC ], into: COUNTRY }
  - novel: { name: login-country, by: USER, of: COUNTRY }
  - detection_var: [ SRC ]
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: a found value, the `by` vars joined
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `name` :: The brand the sightings are kept in.
- `by` :: The found var, or a list of them, whose values joined are the key.
- `of` :: The found var holding the value.
- `ttl` :: Seconds a value is remembered after it was last seen, after which it is new again.
  - default :: 2592000
- `after_seen` :: How many times a key has to have been seen before a value new to it holds.
  - default :: 3

A bare `by` is a list of one.

A [`not_marked`](not_marked.md) over the key and the value with a
[`mark`](mark.md) below it says nearly the same, and holds on every
account's very first login, all of a new key's values being new.
`after_seen` is what this adds... a key with no history is learned from and
not reported.

With the hour lifted by an [`epoch`](epoch.md) gate, it says a login at an
hour the account never used, where [`active_time`](active_time.md) can only
say "outside office hours" for everyone at once:

```yaml
rule_gates:
  - daemons: [ sshd ]
  - epoch: { hour_into: HOUR, zone: '-05:00' }
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - novel: { name: login-hour, by: USER, of: HOUR, after_seen: 20 }
  - detection_var: [ SRC ]
```

## Where it goes

It keys on a found value, so it is asked once for the offense, and a
detection rule may have one.

Below whatever lifts its `of`, as the `country` with an `into` above does.

Feed it only what the owner of the key can do, and below any gate that
could veto it. Every offense that reaches it is remembered, so a failed
login from anywhere would teach it values the owner never had.

## When it does not hold

A veto drops the offense, and the line goes on to the rules after this one.

It does not hold on a value the key has had with in `ttl`, or on a key
seen fewer than `after_seen` times before. It fails closed on an offense
lacking the value, or holding it empty, or lacking part of the key, and
such an offense is not remembered either.

## What it leaves behind

Every offense that reaches the gate is a sighting and is remembered,
whether or not the gate held. It keeps what it knows as
[brands](../rules.md#marks-cross-rule-state-keyed-by-anything) of its
`name`, two kinds of them... one under the key, valued with how often the
key has been seen, and one under the key and each value. Each is kept
`ttl` after it was last seen, so a key unseen that long starts over with no
history.

Being brands, they are kept across the watchers of a galla, across a
restart, and across a fleet on a Redis tablet. `baphomet marked` shows
them.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `name`, `by`, or `of` :: "lacks a ..."
- a `name` that is not a name :: "has a name that is not a name matching /^[a-zA-Z0-9_\-]+$/"
- a `by` that is not a string or a list of them :: "has a by that is not a non-empty string or a non-empty array of them"
- an `of` that is not a string :: "has a of that is not a non-empty string"
- a `ttl` that is not a whole number of one or more :: "has a ttl that is not a positive int of seconds"
- an `after_seen` that is not a whole number of one or more :: "has a after_seen that is not a positive int"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

Its sightings are brands, so the test's own mark store holds them.
`marks_before` seeds a history, the key's brand valued with how often it
was seen and one for each value it had, a list `key` joining the key and
the value as the store does. `marks_expected` shows what it learned. See
[Proving brands and gates](../rules.md#proving-brands-and-gates), and
[tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - novel: { name: login-from, by: USER, of: SRC }
  - detection_var: [ SRC ]
tests:
  positive:
    # seen three times, always from the one address, and now from another
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for neti from 203.0.113.9 port 4711 ssh2"
      marks_before:
        - { name: login-from, key: neti, value: 3 }
        - { name: login-from, key: [ neti, 192.0.2.7 ] }
      marks_expected:
        - { name: login-from, key: neti, value: 4 }
        - { name: login-from, key: [ neti, 203.0.113.9 ] }
      found: 1
  negative:
    # the address it always uses
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for neti from 192.0.2.7 port 4711 ssh2"
      marks_before:
        - { name: login-from, key: neti, value: 3 }
        - { name: login-from, key: [ neti, 192.0.2.7 ] }
      found: 0
```

## See also

- [`travel`](travel.md) :: Holds on two places too far apart, kept as brands the same way.
- [`concurrent`](concurrent.md) :: Holds on too many values at once, where this holds on one new value.
- [`not_marked`](not_marked.md) :: The same question with no history asked for.
