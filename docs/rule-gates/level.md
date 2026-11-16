# level... which log levels a http_error rule reads

A `level` gate turns an error log line away unless its log level is one of
the ones named. A rule wants it because the same words turn up at more than
one level... a server's own `notice` about a module and the `error` a
client's request caused can read alike, and only the one at the level the
server reports refusals at is evidence against a client.

```yaml
rule_gates:
  - level: [ error ]
  - message_regexp:
      - '^user "(?:[^"]+|.*?)":? (?:password mismatch|was not found in "[^"]*")'
  - ban_var: [ client ]
```

## At a glance

- phase :: line
- rule types :: http_error
- keys on :: the line
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

A non-empty list, each entry one of...

- `<level>` :: A string the level has to equal.
- `//<regexp>//` :: A regexp the level has to match.

The level is the one the parser read... `error`, `warn`, `notice`, and the
like, from apache's `[error]` or `[auth_basic:error]` and nginx's
`[error]`. A line the parser found no level in is turned away. Two `level`
gates are ANDed.

## Where it goes

**Leading the list.** It reads nothing but the parsed line, so it costs
least written first, beside [`module`](module.md) and
[`ignore_regexp`](ignore_regexp.md), where a line it turns away has had
nothing made for it.

## When it does not hold

The line is turned away outright. Nothing below is asked, and the line goes
on to the rules after it.

## Refused at load

- not a list, or an empty one :: "is not a array or is empty"
- an entry that is not a string :: "contains a non-string entry"
- a `//regexp//` that will not compile :: "entry ... does not compile"

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

No fixture. Tests of a http_error rule default to the `apache_error`
parser, and a rule-wide `test_parser: nginx_error` switches them. A
negative of the same message at another level proves the gate. See
[tests](../rules.md#tests) for the shape.

```yaml
test_parser: nginx_error
tests:
  positive:
    - message: '2012/04/09 11:53:36 [error] 2865#0: *66647 user "xyz": password mismatch, client: 192.0.2.10, server: www.example.org, request: "GET / HTTP/1.1", host: "www.example.org"'
      found: 1
      data:
        client: "192.0.2.10"
  negative:
    - message: '2012/04/09 11:53:36 [info] 2865#0: *66647 user "xyz": password mismatch, client: 192.0.2.10, server: www.example.org, request: "GET / HTTP/1.1", host: "www.example.org"'
      found: 0
```

## Shipped rules using it

Every shipped http_error rule but `http_error/zoneminder` has one.

- `%http_error/nginx%` :: `error`, and `nginx-limit-req` takes `warn` too, nginx logging its delays there.
- `%http_error/apache%` :: `error`, the level apache logs auth failures and refusals at.

## See also

- [`module`](module.md) :: The other error log field gate, ANDed with it.
- [`message_regexp`](message_regexp.md) :: The matcher of the lines it lets by.
- [`status`](status.md) :: The same refusal on the http type.
- [http_error rules](../rules.md#http_error-rules) :: The type it belongs to.
