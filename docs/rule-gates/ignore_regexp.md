# ignore_regexp... a message that is never an offense

An `ignore_regexp` gate turns a line away outright when any of its regexps
matches the line's message, whatever the regexps below it would have said.
It is fail2ban's `ignoreregex`. A rule wants one where the matcher is broad
and the exceptions are easier named than excluded from it... the ACL
rejection that is policy and not attack, the threat a firewall already
reset, the low severity events of a appliance family.

```yaml
rule_gates:
  - daemons: [ asterisk ]
  - ignore_regexp:
      - 'Registration from ''\S+'' failed for ''%%%%SRC%%%%:\d+'' - ACL rule'
  - message_regexp:
      - 'Registration from ''\S+'' failed for ''%%%%SRC%%%%:\d+'' - '
  - ban_var: [ SRC ]
```

## At a glance

- phase :: line
- rule types :: syslog, raw, http_error
- keys on :: the line
- vetoes :: yes
- needs :: nothing, or Log::Munger for a primitive fragment
- repeatable :: yes, each entry is a gate of its own

## Told

A list of regexp strings, any one of which matching turns the line away.

The regexps run against the same message [`message_regexp`](message_regexp.md)
does. On syslog and raw a regexp may use the `%%%%TOKEN%%%%` offender tokens
and the primitive fragments, nothing being captured from either. On
http_error it is a plain Perl regexp. An empty list is legal and turns
nothing away.

## Where it goes

**Above what it is to stop.** It reads nothing but the parsed line, so it
costs least leading the list beside `daemons`, where a line it turns away
has had nothing made for it and the rule index still reads the `daemons`.
Written below a [`capture_regexp`](capture_regexp.md), the context is
stored on a line the rule was told to ignore, and a deferred offense that
line completes stands. Written below a [`message_regexp`](message_regexp.md),
it still turns the line away, but a keyed offense has already been parked
by then. Above a [`stages`](stages.md) it keeps the line from feeding any
sequence.

## When it does not hold

The line is turned away outright. Nothing below is asked... no context is
stored, no sequence advances, no deferred offense completes, nothing is
harvested... and the line goes on to the rules after it.

## Refused at load

- not a list :: "is not a array"
- an entry that is not a string :: "contains a non-string entry"
- a regexp naming a token that is neither an offender token nor a fragment, on syslog or raw :: "uses the unknown token ..."
- a regexp that will not compile :: "does not compile"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

No fixture. A negative per regexp, a line the matcher alone would have
taken, is what proves the exception holds. See [tests](../rules.md#tests)
for the shape.

```yaml
tests:
  negative:
    # the message_regexp alone would take it, but a ACL refusal is policy
    - message: "Jul 12 08:15:50 pbx01 asterisk[811]: NOTICE[811]: chan_sip.c:28155 in handle_request_register: Registration from '<sip:100@192.0.2.1>' failed for '192.0.2.44:5060' - ACL rule"
      found: 0
      undefed: ["SRC"]
```

## Shipped rules using it

- `syslog/monit` :: The denial with an empty username, the ignoreregex fail2ban's filter suggests.
- `raw/fortinet-attack` :: Low and info severity events, the anonymous cipher signature, and URL blocks, ahead of the munger-read condition.
- `raw/fortinet-system` :: Cleared alarms, logouts, and port changes, the routine half of the system log.
- `raw/palo-alto-threat-exploit` :: Threats the firewall already reset both ways.
- `raw/palo-alto-threat-infected` :: Blocks of online personal storage, a category and not a infection.

## See also

- [`message_regexp`](message_regexp.md) :: The matcher it vetoes for.
- [`ignore`](ignore.md) :: The same veto on the field types, http and json, a field named per entry.
- [`daemons`](daemons.md) :: The other cheap refusal leading a syslog list.
- [`gate`](gate.md) :: With `negate`, a veto on a parsed or decoded field rather than the message.
