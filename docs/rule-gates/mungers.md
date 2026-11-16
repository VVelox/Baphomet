# mungers... a line read into fields by Log-Munger

A `mungers` gate runs the line through the named
[Log-Munger](https://github.com/LilithSec/Log-Munger) decoders and lays
the fields they decode down as the line's fields, for every gate below to
read. Beside a `message_regexp` it enriches... the offense arrives with the
daemon's own fields decoded beside the captures. With out one it can be
the matcher, a `gate` judging the decoded fields and `ban_var` naming one,
which is how a appliance rule names the field the appliance wrote as its
offender instead of scanning a line whose other values the client chose.

```yaml
# a sshd rule that leans on Log-Munger's sshd decoder for the ssh_* fields
rule_gates:
  - daemons: [sshd]
  - mungers: [sshd]
  - message_regexp:
      - 'Failed password for (?:invalid user )?\S+ from %%%%SRC%%%% port'
  - ban_var: [SRC]
```

## At a glance

- phase :: line
- rule types :: syslog, raw
- keys on :: the line
- vetoes :: no, it only lifts
- needs :: Log::Munger, with the named rule files
- repeatable :: yes, each entry is a gate of its own

## Told

A non-empty list of decoder names.

- `<name>` :: A Log-Munger rule file (`sshd`, `postfix`, `fortinet`, ...), named with out its `.yaml`.

Name only the leaf decoder that applies. Log-Munger resolves a file's own
dependencies, so `base` is never named. The names are kept sorted and each
once, and a set builds one processor, memoized and shared by every rule
naming the same set, so a fleet of sshd rules pays the compile once. The
decode is kept on the parsed line too, so each set decodes a line once
however many rules of the watcher name it.

The line is handed over as the fields the parser already split out... the
message, and on a syslog line the daemon as Log-Munger's program, the
level as its priority, and the facility as its facility, so a decoder's
own program gate does the work it was written to. A raw rule has only its
message to give. The decoder's first matching rule decides, and its
captures are the fields.

## Where it goes

**Above the `message_regexp`, and above every gate that reads its
fields.** Written above, the munger runs first, its fields laid down
underneath, and the `message_regexp` captures then overwrite any of the
same name... the rule choosing its own read of that one field, on purpose.
Everything the munger decoded that the regexp did not recapture rides
along. Written below the `message_regexp`, the offense is made before
there is anything decoded, and none of it reaches the offense's data.
A `gate` above it on a syslog or raw rule is asked while the line has no
fields, finds nothing to judge, and lets every line by.

Below `daemons`, so the rule index still reads the `daemons` and a line
from another daemon is never decoded at all. Its fields go under any
already laid down, and a [`message_json`](message_json.md) lays its own
over any already there, so beside one the JSON wins a clash whichever is
written first.

## When it does not hold

It never turns a line away. A line the decoders make nothing of is left as
it was, with no fields... beside a `message_regexp` the offense is the
captures alone, and as the matcher a `gate` then finds nothing to pass and
the line makes no offense.

The dependency is optional but not fail-soft. A rule that asks for
enrichment it can not get is a misconfiguration, so a missing Log::Munger,
or a decoder that will not resolve, is fatal... the galla builds every
set's processor as it starts, and one that will not build is an `err` to
the log naming the set and a galla that refuses to start, never a silent
skip or a surprise mid-line. A rule whose matcher is its
munger would otherwise veto every line and never fire.

## What it leaves behind

The decoded fields, as the line's fields. Every gate below reads them...
the predicate gates, the marks, `ban_var` and `detection_var`, the
promoted vars, and the EVE `found`, no rule-format change.

On a [staged](stages.md) rule the completed sequence is enriched from its
final, completing line, the same line whose `raw` the event carries, the
sequence's own captures winning a clash.

**A deferred offense keeps its own line's fields.** An offense a keyed
`message_regexp` parks to wait for its address is parked with what the
munger made of its line. When the [`capture_regexp`](capture_regexp.md)
line completes it, the capture line's decoded fields go underneath and
only fill what the offense line left unset.

## Refused at load

- not a non-empty list of non-empty strings :: "is not a non-empty array of non-empty strings"
- Log::Munger not loadable :: "names mungers (...) but Log::Munger is not loadable"
- a decoder that will not load :: "names mungers (...) that could not be loaded"
- a syslog or raw rule with no `message_regexp` or `stages` that also has nothing to judge the fields :: "has no gate that makes a offense of a line or judges one ..."

The two of Log::Munger come when the processor is first built... by the
rule's own tests at load, the first of them to run a line through it, and
for every set again as the galla starts, which refuses to start over one.

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

No fixture... the tests run the real decoder, so Log::Munger has to be
installed with the rule files the rule names, not merely present, and a
missing or wrong decoder fails at load rather than matching nothing in the
field. Assert the decoded fields in `data` beside the captures. See
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: "Jul 12 08:15:50 mail01 sshd[2278]: Failed password for root from 192.0.2.7 port 4711 ssh2"
      found: 1
      data:
        SRC: "192.0.2.7"
        ssh_src_ip: "192.0.2.7"
```

An appliance rule whose matcher is its munger carries an injection test
with the offender's key typed into a client-chosen value, proving the
offender stays the field the appliance wrote. See
[injection tests](../rules.md#injection-tests-who-picks-the-offender).

## Shipped rules using it

- `%syslog/ssh%`, `syslog/sshd-worked` :: The `sshd` decoder enriching failures, and a staged sequence from its completing line.
- `syslog/sendmail-reject`, `syslog/sshd-ddos` :: Enrichment beside correlation, a deferred offense keeping its own line's decode.
- `raw/fortinet-*`, `raw/sonicwall-*`, `raw/huawei-*` :: The decoder as the matcher, a `gate` or `condition` on the `key=value` ledger and `ban_var` on a decoded field.
- `syslog/*_errors` :: Daemon error detections judged on decoded fields with no regexp.
- `syslog/pam-generic` :: The `pam` decoder naming the service and account a regexp steps over.

## See also

- [`message_regexp`](message_regexp.md) :: The captures laid over its fields.
- [`message_json`](message_json.md) :: The other road to fields out of a message.
- [`gate`](gate.md), [`condition`](condition.md) :: What judges its fields when it is the matcher.
- [`capture_regexp`](capture_regexp.md) :: What completes a deferred offense, and whose fields win.
- [enriching a match](../rules.md#enriching-a-match-mungers) :: Mungers and the primitive fragments, side by side.
- [a munger as the matcher](../rules.md#a-munger-as-the-matcher) :: The appliance families, and why no regexp is safer there.
