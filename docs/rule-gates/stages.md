# stages... an ordered sequence with in one rule

A `stages` gate matches a sequence rather than a line. Its stages are hit
in order, each by a line one of its regexps matches, as many times as it
asks, inside the time and line bounds it sets, and only the line that
completes the last stage makes an offense. It is the whole matcher of the
rule it is in. A rule wants it where no single line is the offense...
failures and then a success from the same source, the compromised
credential alarm one typo never trips, or a service restarted three times
in two minutes.

```yaml
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - stages:
      per: [ SRC ]
      stages:
        - message_regexp:
            - '^Failed (?:password|publickey) for .* from %%%%SRC%%%%'
          count: 5
          within: 300
        - message_regexp:
            - '^Accepted \w+ for .* from %%%%SRC%%%%'
          within: 60
  - detection_var: [ SRC ]
```

## At a glance

- phase :: line
- rule types :: syslog, raw
- keys on :: the line
- vetoes :: yes
- needs :: nothing, or Log::Munger for a primitive fragment
- repeatable :: no

## Told

A hash of...

- `stages` :: The non-empty list of stages, in the order they are to be hit.
- `per` :: What the sequences are kept apart by, a capture or a list of them joined into one key.
  - default :: one sequence per followed log file

Each stage is a hash of...

- `message_regexp` :: A non-empty list of regexp strings, any one of which hits the stage.
- `count` :: How many hits complete the stage.
  - default :: 1
- `within` :: The most seconds since the sequence's last hit.
  - default :: none
- `skip` :: The most log lines that may come between the sequence's last hit and this one.
  - default :: none

A stage with no `within` still expires a sequence that has waited 600
seconds on it.

The stages' regexps are tokened as [`message_regexp`](message_regexp.md)'s
are, offender tokens and primitive fragments both, but every entry is a
plain string, there being no keyed form. A `per` component names a capture
of the stages' regexps and, on syslog, may name the reserved envelope
fields `syslog.host`, `syslog.daemon`, and `syslog.pid`. A single counted
stage keyed `per: [ syslog.host, syslog.daemon, syslog.pid ]` counts
repetition within one daemon session, a far sharper signal than per-IP
counting across the whole window. Raw has no envelope, so a raw `per` keys
on captures only.

**How a line feeds the sequences.** A line hitting the stage its key's
sequence waits on advances it, counted toward that stage's `count`, the
stage done once the count is met. A hit landing past its stage's `within`
or `skip` kills the sequence, and the line may then open a fresh one. A
line hitting the first stage opens a sequence only when none is under way
for its key, so failures past the count never reset a rule that is waiting
for the success. A line hitting some later stage its key's sequence is not
waiting on is passed over. A line with out a value for every `per`
component joins no sequence.

**With out `per`** the state is one slot per followed file... pure
adjacency. That is only sound for a serialized log, a single-worker daemon
or a one-connection-at-a-time service. Any multi-client daemon interleaves
sessions and adjacency would stitch one client's stage to another's, so
prefer `per` wherever a key exists and say so loudly in a keyless rule's
header.

## Where it goes

**Below `daemons`, `ignore_regexp`, and `mungers`.** An
[`ignore_regexp`](ignore_regexp.md) above it keeps a line from feeding any
sequence. A [`mungers`](mungers.md) above it lays the completing line's
decoded fields under the sequence's captures.

**Above the gates that judge the completed sequence.** A line gate that
judges written above it judges each line before it can feed a sequence,
and one it refuses feeds none. Written below, it judges the offense the
completing line made.

## When it does not hold

Every line that does not complete a sequence makes no offense, the hits
that opened and advanced one included. They do not consume the line, so
the plain rules beside a staged one still count what it watches... an
`sshd` rule counts the failures a `sshd-worked` rule is gathering toward
its alarm.

## What it leaves behind

The completing line's offense. Its data is the captures of every hit
merged, a later hit winning, with the fields `mungers` decoded of the
completing line underneath. The EVE event carries a `stages` array of every
hit, each its stage index, the time, and the line, beside the usual fields,
the `raw` being the completing line.

The sequences under way, kept per watcher, at most 10000 per watcher, the
soonest to expire evicted past that, and swept once the stage they wait on
has gone its `within`, or 600 seconds, with out a hit. They are in memory
only... a restart forgets a half-built sequence.

## Refused at load

- not a hash, a key other than `stages` and `per`, or no `stages` :: "is not a hash", "has the unknown key ...", "lacks a stages"
- `stages` not a non-empty list of hashes :: "is not a non-empty array", "entry N is not a hash"
- a stage with out `message_regexp`, an unknown key, or a `message_regexp` that is not a non-empty list of strings :: "lacks a message_regexp", "has the unknown key ...", "is not a non-empty array of regexp strings"
- a `count`, `within`, or `skip` that is not a positive int :: "has a ... that is not a positive int"
- a `per` that is neither a string nor a list, an empty list, or a component that is not a non-empty string :: "has a key that is not a string or a array", "has a empty key array", "has a key component that is not a non-empty string"
- a `syslog.*` `per` component on a raw rule, or any other than `syslog.daemon`, `syslog.host`, and `syslog.pid` on a syslog rule :: "keys on ..., which is not a envelope field this rule type carries"
- a regexp naming an unknown token, or one that will not compile :: "uses the unknown token ...", "does not compile"
- beside a `message_regexp`, a `capture_regexp`, or a `message_json` told true :: "... stages are the whole matcher"
- a second `stages` in the rule :: "is the second stages gate of the rule, which can have the one"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

Sequences prove themselves through the `messages:` test form, its line
order being the sequence and driving `skip`, and `found` the count across
it. A `within` is proven with the hash form of a `messages` entry, an
`advance` moving the virtual clock past it before a line, and a `.t`
against the rule object can probe the sweep (see `t/rule-stages.t`). See
[proving order and time](../rules.md#proving-order-and-time).

```yaml
tests:
  positive:
    - messages:
        - "Jul 12 08:15:50 mail01 sshd[2278]: Failed password for root from 192.0.2.7 port 4711 ssh2"
        - "Jul 12 08:15:51 mail01 sshd[2280]: Failed password for root from 192.0.2.7 port 4712 ssh2"
        - "Jul 12 08:15:52 mail01 sshd[2282]: Failed password for root from 192.0.2.7 port 4713 ssh2"
        - "Jul 12 08:15:53 mail01 sshd[2284]: Failed password for root from 192.0.2.7 port 4714 ssh2"
        - "Jul 12 08:15:54 mail01 sshd[2286]: Failed password for root from 192.0.2.7 port 4715 ssh2"
        - "Jul 12 08:15:57 mail01 sshd[2288]: Accepted password for root from 192.0.2.7 port 4716 ssh2"
      found: 1
      data:
        SRC: "192.0.2.7"
  negative:
    # the success came too late
    - messages:
        - "Jul 12 08:15:50 mail01 sshd[2278]: Failed password for root from 192.0.2.7 port 4711 ssh2"
        - "Jul 12 08:15:51 mail01 sshd[2280]: Failed password for root from 192.0.2.7 port 4712 ssh2"
        - "Jul 12 08:15:52 mail01 sshd[2282]: Failed password for root from 192.0.2.7 port 4713 ssh2"
        - "Jul 12 08:15:53 mail01 sshd[2284]: Failed password for root from 192.0.2.7 port 4714 ssh2"
        - "Jul 12 08:15:54 mail01 sshd[2286]: Failed password for root from 192.0.2.7 port 4715 ssh2"
        - message: "Jul 12 08:17:57 mail01 sshd[2288]: Accepted password for root from 192.0.2.7 port 4716 ssh2"
          advance: 120
      found: 0
```

## Shipped rules using it

- `syslog/sshd-worked` :: Five failures, then a success from the same source, keyed `per: [ SRC ]`, a detection.
- `syslog/systemd-flap` :: One stage counted three times in two minutes, keyed on the host and the unit.

## See also

- [`message_regexp`](message_regexp.md) :: The one-line matcher it takes the place of.
- [`capture_regexp`](capture_regexp.md) :: Correlation, which merges data across lines but knows no order and counts nothing.
- [`mungers`](mungers.md) :: What enriches the completing line.
- [`ignore_regexp`](ignore_regexp.md) :: Still vetoes lines above it.
- [stages](../rules.md#stages-ordered-sequences-with-in-one-rule) :: Sequences beside correlation, in the type overview.
