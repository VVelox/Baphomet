# digest... a hash in place of a name

A `digest` gate puts a keyed hash of a found value in place of it. A rule
can still key and count on an account or an address of mail, while the
brands, the tracked records, the counts, and the tablets they are kept in
hold no plaintext. The one name always comes to the one hash under the one
key, so nothing that keys on it is the worse for it, and without the key
the hash is no way back to the name.

```yaml
user_var: USER
eve_line: false
rule_gates:
  - daemons: [ dovecot ]
  - message_regexp:
      - 'auth failed.*user=<(?<USER>[^>]+)>.*rip=%%%%SRC%%%%'
  - digest: { var: USER }
  - after: { by: USER, count: 20, seconds: 600 }
  - ban_var: [ SRC ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: a found value
- vetoes :: no, it only rewrites
- needs :: the `digest_key` of the config
- repeatable :: yes, each entry is a gate of its own

## Told

- `var` :: The found var to hash.
- `into` :: The found var the hash goes into, the `var` left as it was.
  - default :: the `var`, hashed where it is

The hash is the first 16 hex digits of an HMAC-SHA256 under the
`digest_key` of the [config](../configuration.md#lookups-dns-and-geoip), a
path to a file holding a key of 16 bytes or more. With none set, a rule
with the gate does not load, and the galla does not come up. Every galla of
a fleet needs the one key, for the brands they share to agree. A new key is
a new hash for every value, so what was kept under the old hashes is
forgotten... `novel` and `travel` see every account as new.

`baphomet digest <value>` gives the hash a value comes to, for finding a
name in what `baphomet marked` shows.

## Where it goes

**Where it sits decides what sees the name.** It reads what stands when it
is asked... the offense once one has been made, or the line's fields while
there is none. Written above the matcher it hashes the field, which the
offense is then made of. Written below, the offense's value, which is where
a capture of a `message_regexp` is.

The line-phase gates above it see the value as it was. Those below it, and
every gate of the offense phase wherever it is written, see the hash. So an
`account` or `namtar_list` gate that reads the name needs the `digest`
given an `into`, to keep the name beside the hash, and a rule hashing in
place what one of them reads does not load. Nor does one hashing a var a
`ban_var` names, a ban having to be of the address itself.

## When it does not hold

It always lets the line by. A `var` the line does not have, or one that is
not a plain string, is left alone and nothing is written to the `into`.

## What it leaves behind

The hash, in the `into` or in the `var` itself. Whatever keys on it below...
a brand, a tracked record, a count... keeps the hash and never the name,
and those survive a restart as they always do.

**It does not keep the name out of the EVE log** on its own. An event
carries the line the match was found in, and that has the name in it. A
rule's [`eve_line`](../rules.md#eve_line) of false leaves the line out. A
`digest` with an `into` leaves the name in the found data as well, and so
in the event's `found`. Hash in place, with no `into`, for the event to
hold none of it.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not know :: "has the unknown key ..."
- no `var` :: "lacks a var"
- a `var` or `into` that is not a string :: "has a ... that is not a non-empty string"
- an `into`, or with none the `var`, that a `ban_var` of the rule names :: "which a ban_var names, and a ban has to be of the address itself"
- hashing in place a var an `account` or `namtar_list` gate reads :: "gate that reads it would only ever see the hash... give it a into"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A test gives the key as a `digest_key` fixture, standing in for the
config's. With none the gate is skipped and the value is left as it was, so
a test with no fixture still proves the matcher. Under the `after` of the
rule above, a positive test needs twenty lines in its `messages`, so this
shows the hash on its own, with an `into` to keep both. See
[tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - daemons: [ dovecot ]
  - message_regexp:
      - 'auth failed.*user=<(?<USER>[^>]+)>.*rip=%%%%SRC%%%%'
  - digest: { var: USER, into: USER_ID }
  - ban_var: [ SRC ]
tests:
  positive:
    - message: "Jul 12 08:15:50 mail01 dovecot: auth failed, 1 attempts in 2 secs: user=<morgan>, method=PLAIN, rip=192.0.2.40, lip=192.0.2.1"
      digest_key: "a key of sixteen bytes or more"
      data:
        USER: "morgan"
        USER_ID: "54ca1a8862b5b0b9"
```

The hash in a `data` assertion is what `baphomet digest` gives under a
config whose `digest_key` file holds the test's key.

## See also

- [`account`](account.md) :: Reads the name, so needs an `into` beside a `digest`.
- [`namtar_list`](namtar_list.md) :: The same.
- [`after`](after.md) :: Counts on the hash as well as on the name.
- [`novel`](novel.md) and [`travel`](travel.md) :: What a new key makes forget.
