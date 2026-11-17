# account... a real account or a guess

An `account` gate holds when a found name is, or is not, an account of the
host, and when told to ask more of it, when the account is of the kind
asked for. sshd says `invalid user` for itself. Dovecot, postfix's SASL, and
most web apps log a failed login the same whether or not the name was real,
and the difference matters... a failure for a name that is nobody's is a
guess, and one for a real account may be its owner's typo.

```yaml
rule_gates:
  - account: { var: USER, exists: false }
  - ban_var: [ SRC ]
max_score: 1
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: a found value, the name in `var`
- vetoes :: yes
- needs :: the account database of the host the galla runs on, and its group database for a `group`
- repeatable :: yes, each entry is a gate of its own

## Told

- `var` :: The found var holding the name.
- `exists` :: `false` to hold on a name that is no account.
  - default :: `true`
- `shell` :: `nologin` to hold on an account that can not log in, or `login` to hold on one that can.
- `system` :: `true` to hold on an account the system has for itself, or `false` to hold on one a person was given.
- `system_below` :: The uid the accounts of people start at.
  - default :: 1000
- `group` :: A group, or a list of them, the account has to be in one of.
- `near` :: Beside an `exists: false`, how many letters a name that is no account may be off from one that is.

Everything asked has to be so for the gate to hold. With nothing but `var`
it holds on every account and on no other name.

`shell`, `system`, and `group` ask more of an account that is there, so
none of them can be written beside an `exists: false`, there being nothing
to ask of an account that is none. A login attempt for `www` or `daemon` is
as sure a guess as one for a name that does not exist, and `exists: false`
does not see it, the account being real:

```yaml
rule_gates:
  - account: { var: USER, shell: nologin }
  - ban_var: [ SRC ]
max_score: 1
```

An account can not log in when its shell ends in `nologin` or `false`. An
empty shell is the system's default one, which is a login.

`system: true` is the same idea by another test, the uid being below
`system_below`, for a host whose service accounts have a real shell. Root's
uid is below any mark, so it is one of the system's... pair it with
`shell: nologin` to leave root out. `system_below` is read only beside a
`system`.

A bare `group` is a list of one, and any one of them will do. A group holds
its own account, the one whose primary group it is, as well as the ones it
lists. `group: wheel` on a rule with a harsher threshold makes a failure
against an administrator worth more than one against anyone else.

`near` is the one thing that can be asked beside an `exists: false`.
`exists: false` treats the owner of `neti` typing `netti` the same as a
guess at `oracle`, and `near` tells them apart:

```yaml
rule_gates:
  - account: { var: USER, exists: false, near: 1 }    # a typo of a real one
  - ban_var: [ SRC ]
```

A letter added, dropped, or changed is one each, so two letters swapped are
two. A name that is an account exactly is no typo of it.

## Where it goes

It keys on a found value, so it is asked once for the whole offense and
needs no `ban_var` above it.

Listed ahead of the service's ordinary rule, an `exists: false` rule with a
`max_score: 1` banishes on the first guess, and every other failure falls
through to be counted as before.

## When it does not hold

A veto drops the offense, and the line goes on to the rules listed after
this one.

It fails closed. A name the offense lacks, or holds empty, fails whichever
way the gate asks, and so does an account whose shell or uid is not known
when that is what is asked. A group there is none of holds nobody. A name
no account could have, over 256 bytes or holding a control character, a
`:`, or a `/`, is never asked about and is taken as nobody's.

The accounts are those of the host the galla runs on, asked of the system's
own account database, so LDAP and the like are seen when the host is set up
to see them. Over logs shipped in from another host the gate means nothing.

Answers are cached for a minute, so an account added or removed can take
that long to be seen. The names `near` measures against are read out of the
account database once and kept five minutes, ten thousand at the most.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- no `var` :: "lacks a var"
- a `var` that is not a string :: "has a var that is not a non-empty string"
- a `shell` other than `nologin` or `login` :: "has a shell that is not one of nologin or login"
- a `system_below` or `near` that is not a whole number of one or more :: "has a ... that is not a positive int"
- a `group` that is not a string or a list of them :: "has a group that is not a non-empty string or a non-empty array of them"
- a `near` with out an `exists: false` :: "has a near with out a exists of false, a name near a account being one that is none"
- an `exists: false` beside a `shell`, `system`, or `group` :: "has a exists of false and a ..., and nothing can be asked of a account that is none"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

An `accounts` fixture stands in for the account database, a list of names,
or a hash of name to `{uid, shell, groups}` when the gate asks more than
whether there is one. Every other name is nobody's. With out the fixture
the gate is skipped. A fixture account has no primary group, so a group
holding its own account is proved galla-side only. See
[Proving lookups](../rules.md#proving-lookups), and [tests](../rules.md#tests)
for the shape.

```yaml
tests:
  positive:
    # a name that is nobody's
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for oracle from 203.0.113.9 port 4711 ssh2"
      accounts: [ neti ]
      found: 1
  negative:
    # a real account, maybe its owner's typo of the password
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for neti from 203.0.113.9 port 4711 ssh2"
      accounts: [ neti ]
      found: 0
```

A `shell` or `system` gate reads the hash form:

```yaml
      accounts:
        www: { uid: 80, shell: /usr/sbin/nologin }
        neti: { uid: 1001, shell: /bin/sh, groups: [ wheel ] }
```

## See also

- [`after`](after.md) :: Counts failures against one account, whoever they came from.
- [`weigh`](weigh.md) :: Makes a failure count for more in the same rule, where `group` takes a second rule.
- [rule_gates](../rules.md#every-gate) :: The other gates a match still has to clear.
