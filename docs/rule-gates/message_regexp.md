# message_regexp... the offense, out of a line's message

A `message_regexp` gate is the matcher of the text types. Its regexps are
tried in order against the line's message, the first to match making the
line's offense, its named captures the offense's data. A line none of them
matches makes no offense. On syslog and raw a regexp may use the
`%%%%TOKEN%%%%` shortcuts, which is how the address a ban aims at is dug
out of free text, and an entry may be keyed to correlate an offense with an
address logged on a different line.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Invalid user .*? from %%%%SRC%%%% port \d+'
      - '^Failed password for .*? from %%%%SRC%%%% port \d+'
  - ban_var: [ SRC ]
```

## At a glance

- phase :: line
- rule types :: syslog, raw, http_error
- keys on :: the line
- vetoes :: yes
- needs :: nothing, or Log::Munger for a primitive fragment
- repeatable :: no

## Told

A non-empty list, each entry a regexp string or, on syslog and raw, a hash
of...

- `regexp` :: The regexp.
- `key` :: The capture the offense is keyed by, or a list of them joined into one key.
- `defer` :: Seconds an offense whose key has no context waits for a capture line to bring it.
  - default :: none, an unresolved offense is passed over

What the regexp is matched against is the message... on syslog the part
after `daemon[pid]: `, on raw the whole line, on http_error what follows
the `[client ip]` and any `AHnnnnn:` code for apache, and the free text
left once the trailing `, client: ..., server: ...` pairs are peeled off for
nginx. The first entry to match wins, which one it was going down as the
offense's `regexp`.

**Syslog and raw are tokened.** A regexp is Perl plus `%%%%TOKEN%%%%`
tokens, of two kinds: the offender tokens, which capture, and the
[primitive fragments](#primitive-fragments-building-blocks-not-captures),
which do not. Each offender token compiles to a named capture whose name is
the field...

| token | matches |
| --- | --- |
| `HOST` | a domain name, IPv4 address, or IPv6 address |
| `SUBNET` | a IPv4 or IPv6 subnet or address |
| `IP4` | a IPv4 address |
| `IP6` | a IPv6 address |
| `ADDR` | a IPv4 or IPv6 address |
| `DNS` | a domainname |
| `SRC` / `DEST` | a IPv4 or IPv6 address... meant to be used in combination |

A regexp that uses both `SRC` and `DEST` only counts as matched when both
captured. An offender token may appear more than once in one regexp...
whichever occurrence matched is what comes out under the token name, a
repeat being numbered internally since Perl forbids a duplicate capture
name. The captured value is what `ban_var` or `detection_var` names. The
captures win over a field of the same name that
[`mungers`](mungers.md) or [`message_json`](message_json.md) laid down, and
everything those decoded that the regexp did not recapture rides along in
the offense's data.

**http_error is plain.** Every entry is a string, a plain Perl regexp with
no tokens and no key. Named captures still go into the data, but the
parsed line's fields... `client`, `level`, `module`, `message`, and the
rest... win over a capture of the same name, so a capture can not
overwrite the client the parser split out.

### Primitive fragments... building blocks, not captures

The other `%%%%NAME%%%%` kind is a primitive fragment: a named regexp
building block (`INT`, `WORD`, `USERNAME`, `HOSTNAME`, `MONTH`,
`SYSLOGTIMESTAMP`, `TIMESTAMP_ISO8601`, `QUOTEDSTRING`, `GREEDYDATA`, and
~60 more) that expands to a bare, non-capturing `(?:...)` sub-pattern. It
contributes no field... it is there so a pattern can lean on a curated,
tested regexp for a timestamp or a username instead of hand-rolling it. The
library is [Log-Munger](https://github.com/LilithSec/Log-Munger)'s `base`
primitives, resolved through
[`App::Baphomet::Primitives`](https://metacpan.org/pod/App::Baphomet::Primitives)
the first time a rule reaches for a fragment, then cached under the galla's
tablet dir and re-resolved only when the Log-Munger version or its `base`
file changes. So the parse-and-template cost is paid once for the fleet,
and a deployment using only the offender tokens never loads Log-Munger at
all. The fragments are validated by Log-Munger's own tests, so they arrive
known-good.

Because a fragment captures nothing, wrap one in your own named capture
when you want its value as a field... the fragment writes the pattern, the
capture names the field:

```yaml
rule_gates:
  - message_regexp:
      # SYSLOGTIMESTAMP and INT are fragments (no field); SRC and the wrapped
      # USER are captures
      - '^%%%%SYSLOGTIMESTAMP%%%% \S+ myapp\[%%%%INT%%%%\]: login (?<USER>%%%%USERNAME%%%%) from %%%%SRC%%%%'
```

An offender token wins any name collision, and an unknown name in either
set is a load error. A fragment may repeat freely, having no capture name
to clash. The same tokens and fragments work in
[`ignore_regexp`](ignore_regexp.md), [`capture_regexp`](capture_regexp.md),
the stages of [`stages`](stages.md), and the `match` entries of a json
rule.

### Keyed entries

A hash entry ties its offense to the context a
[`capture_regexp`](capture_regexp.md) of the same rule keeps, for a daemon
that logs the offense on one line and the address on another. A `key` names
captures of the entry's own regexp and, on syslog, may name the reserved
envelope fields `syslog.daemon`, `syslog.host`, and `syslog.pid`, so lines
that share nothing but the logging process correlate by its session.

A keyed entry that matches goes one of four ways...

- every key component resolves and context is stored :: The stored captures go under the entry's own, which win, and that is the offense.
- a key component is missing :: The entry is a plain unkeyed offense, its captures as they stand.
- the key resolves, no context yet, `defer` set :: The offense is parked to wait for a capture line, and the entries after it are not tried.
- the key resolves, no context yet, no `defer` :: The entry is passed over and the entries after it are tried.

A line whose every match was passed over makes no offense. Stored context
is not used up... it resolves every offense of its key until its `ttl`
runs out. The whole of the two-line story, both arrival orders and the
envelope keys, is under
[correlation](../rules.md#correlation-offense-and-address-on-different-lines).

## Where it goes

**Below `daemons`, `ignore_regexp`, `mungers`, and `message_json`.** It
reads what stands when it is asked, so the fields of a `mungers` or
`message_json` written below it never reach its offense's data.

**Below the `capture_regexp` it keys to.** A line none of its entries
matches ends the rule's walk, so a `capture_regexp` written below it is
never asked of the capture lines, which are exactly the lines it does not
match.

**Above the gates that judge its captures.** A line gate that judges, a
`gate` or `condition` say, judges the line's fields above it and the
captures below it. One above it that refuses the line means it is never
matched at all.

## When it does not hold

A line none of its entries matches, or whose keyed match was passed over,
makes no offense and the rule stops there for the line. A parked offense is
not an offense yet either... the line that parked it counts nothing, and
the offense stands only when the capture line comes, judged then by the
gates below the `capture_regexp`. One whose `defer` runs out first is
dropped with out a trace.

## What it leaves behind

The offense's data... its captures, any context its key resolved, and on
syslog and raw the fields `mungers` and `message_json` laid down
underneath. Every gate below reads it, `ban_var` and `detection_var`
included, and it is what the EVE `found` carries.

A parked offense waits under its key in the rule's correlation store, per
watcher, at most 100 per key, the oldest dropped to make room. It parks
its regexp's captures and, beside them, the fields `mungers` and
`message_json` made of its line, so a completed offense has its own
line's decode (see [`capture_regexp`](capture_regexp.md)). The store is written to the context tablet at each checkpoint and
read back at start, anything expired by then dropped, so a deferred
offense can survive a restart.

## Refused at load

- not a list, or an empty one :: "is not a array or is empty"
- an entry that is neither a string nor a hash, on syslog or raw :: "is not a string or a hash"
- an entry that is not a string, on http_error :: "is not a string"
- a hash entry with out `regexp` or `key`, an unknown key, or a `defer` that is not a positive int of seconds :: "lacks a ...", "has the unknown key ...", "has a defer that is not ..."
- a key that is neither a string nor a list, an empty list, or a component that is not a non-empty string :: "has a key that is not a string or a array", "has a empty key array", "has a key component that is not a non-empty string"
- a `syslog.*` key component on a raw rule, or one the envelope does not have :: "keys on ..., which is not a envelope field this rule type carries"
- a regexp naming a token that is neither an offender token nor a fragment :: "uses the unknown token ..."
- a regexp that will not compile :: "does not compile"
- a second `message_regexp` in the rule :: "is the second message_regexp gate of the rule, which can have the one"
- a http_error rule with out one :: "has no message_regexp gate, which a http_error rule has to have"
- a syslog or raw rule with neither it nor `stages`, and no `mungers` or `message_json` to give a gate fields :: "has no message_regexp or stages gate, and no message_json or mungers gate ..."
- one beside a `stages` gate :: "is beside message_regexp... stages are the whole matcher"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

No fixture. One positive per entry, each with a `data` block asserting the
offender, and near-miss negatives with `undefed`... the discipline is under
[writing them](../rules.md#writing-them-the-matcher-and-its-near-misses).

A keyed entry needs the `messages:` form, the lines fed in order, the
capture line and the offense line in both orders where the daemon allows
both.

```yaml
tests:
  positive:
    - messages:
        - "Jul  8 02:10:03 ldap-server slapd[1183]: conn=2048 fd=30 ACCEPT from IP=203.0.113.7:52001 (IP=0.0.0.0:636)"
        - "Jul  8 02:10:04 ldap-server slapd[1183]: conn=2048 op=1 RESULT tag=97 err=49 text="
      found: 1
      data:
        SRC: "203.0.113.7"
```

**A regexp of the risky shape is warned about.** When a syslog or raw
pattern puts a lazy unbounded wildcard between its head and its offender
token, and nothing anchors the token's tail, whichever candidate appears
first is the one banned, so a client that can write ahead of the real
field picks the ban target. The loader names the first such regexp, and a
rule with no `tests.injection` to answer it is warned about. It is a
warning, not a refusal... see
[injection tests](../rules.md#injection-tests-who-picks-the-offender).
http_error regexps are not checked.

## Shipped rules using it

Nearly every syslog, raw, and http_error rule.

- `%syslog/ssh%` :: Tokened regexps anchored past the address on the `port`/`preauth` tail.
- `syslog/slapd` :: A keyed entry deferring on the `conn=` id.
- `syslog/sendmail-reject` :: Plain entries and one keyed on the queue id, the No such user pair.
- `syslog/sshd-ddos` :: Entries keyed on `syslog.host`, `syslog.daemon`, and `syslog.pid`, for kex failures that log no address.
- `raw/mongodb-auth-legacy` :: Offense-first correlation on the `[connN]` id.
- `%http_error/apache%`, `%http_error/nginx%` :: Plain regexps over the error message.

## See also

- [`capture_regexp`](capture_regexp.md) :: The context a keyed entry resolves through, and what completes a parked one.
- [`ignore_regexp`](ignore_regexp.md) :: The veto with the same regexps, written above it.
- [`stages`](stages.md) :: The ordered-sequence matcher that takes its place.
- [`mungers`](mungers.md), [`message_json`](message_json.md) :: The fields laid under its captures.
- [`match`](match.md) :: The matcher of the field types, http and json.
- [`ban_var`](ban_var.md), [`detection_var`](detection_var.md) :: What names the capture the offense counts against.
- [correlation](../rules.md#correlation-offense-and-address-on-different-lines) :: Offense and address on different lines.
- [how the types differ](../rules.md#how-the-types-differ) :: Where tokens work and where they do not.
