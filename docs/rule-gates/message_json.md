# message_json... a JSON message read into fields

A `message_json` gate decodes a syslog message that is a JSON object and
lays it down as the line's fields, flattened into dotted paths the way a
`json` rule's record is. The gates below test those fields by path, and
the syslog envelope stays reachable beside them under reserved names. It
is the bridge to the json machinery for a daemon that writes JSON to
syslog, where the record would otherwise be one long string to scan with
regexps, and a forgery typed into one of its values could steer the scan.

```yaml
rule_gates:
  - daemons: [ authelia ]
  - message_json: true
  - gate:
      - { field: msg, op: re, value: '^Unsuccessful \S+ authentication attempt by user ' }
  - ban_var: [ remote_ip ]
```

## At a glance

- phase :: line
- rule types :: syslog
- keys on :: the line
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

A boolean. True decodes the message, false leaves the gate out of the rule
as though it were not written.

The fields are the object flattened as the json parser flattens a record...
`attr.remote`, `request.client_ip`, `tags.0`. Beside them go the envelope
fields the line has...

- `syslog.daemon` :: The daemon that logged it.
- `syslog.host` :: The host in the syslog header.
- `syslog.pid` :: The pid, when one was logged.
- `syslog.time` :: The time in the syslog header.
- `syslog.message` :: The message, as the undecoded text.

The decode is kept on the parsed line, so every `message_json` rule of a
watcher shares the one.

With it on, `message_regexp` is optional, the [`gate`](gate.md),
[`condition`](condition.md), or [`keywords`](keywords.md) below being the
matcher and `ban_var` naming a field. With a `message_regexp` too, the
regexp is the matcher over the undecoded message and its captures win over
a decoded field of the same name, the decoded fields riding along in the
offense's data underneath them.

## Where it goes

**Above the gates that read its fields.** A `gate` above it is asked while
the line has no fields at all, finds nothing to judge, and lets every line
by... the rule then counts what its author gated off. A `message_regexp`
above it makes an offense the decoded fields never reach. Beside a
[`mungers`](mungers.md) the JSON wins a clash whichever is written first,
its fields going over any already laid down and the munger's under.

## When it does not hold

A line whose message is not a JSON object is not the shape the rule was
told to expect, and is turned away outright, whatever a `message_regexp`
below would have made of it. Nothing below is asked, and the line goes on
to the rules after it... a daemon that logs both text and JSON lines needs
a rule for each.

## What it leaves behind

The decoded fields and the `syslog.*` envelope, laid down as the line's
fields for the gates below to read, `ban_var` and `detection_var`
included. A rule with no `message_regexp` makes its offense of them, so
they are the offense's data and what the EVE `found` carries.

## Refused at load

- told something other than a scalar :: "is not a boolean"
- one beside a [`stages`](stages.md) gate, unless told false :: "is beside message_json... stages are the whole matcher"
- told true with no `message_regexp` and nothing to judge the fields :: "has no gate that makes a offense of a line or judges one ..."

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

No fixture. Positives carry the JSON as the message of a full syslog line,
negatives the success beside the failure and the daemon's text format, and
an injection test the key forged into a value. See
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: 'Jun 24 15:49:11 server authelia[1234]: {"level":"error","remote_ip":"192.0.2.100","msg":"Unsuccessful WebAuthn authentication attempt by user ''alice''","time":"2025-06-24T15:49:10+02:00"}'
      found: 1
      data:
        remote_ip: "192.0.2.100"
  negative:
    # the text format is not JSON, and is turned away
    - message: 'Jun 24 15:47:29 server authelia[1234]: time="2025-06-24T15:47:29+02:00" level=error msg="Unsuccessful 1FA authentication attempt by user ''example''" remote_ip=192.0.2.4'
      found: 0
```

## Shipped rules using it

- `syslog/authelia-json` :: Authelia's JSON log over syslog, a `message_regexp` digging out the `remote_ip` and a typed `gate` on `msg`.

## See also

- [`mungers`](mungers.md) :: The other road to fields out of a message, a Log-Munger decoder rather than JSON.
- [`gate`](gate.md), [`condition`](condition.md), [`keywords`](keywords.md) :: What judges its fields.
- [`message_regexp`](message_regexp.md) :: Optional beside it, its captures winning.
- [json rules](../rules.md#json-rules) :: The type whose flattening it borrows.
