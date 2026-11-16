# method... which HTTP methods a http rule reads

A `method` gate turns an access log line away unless the HTTP method of the
request is one of the ones named. A rule wants it where the method is part
of the evidence... a login form is a POST, and a scanner's GET of the same
path is another thing, or where a match on the path should not be fooled by
a method the server would never have acted on.

```yaml
rule_gates:
  - method: [ GET, POST ]
  - match:
      - { field: path, regexp: '^/wp-login\.php' }
  - ban_var: [ host ]
```

## At a glance

- phase :: line
- rule types :: http
- keys on :: the line
- vetoes :: yes
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

A non-empty list, each entry one of...

- `<method>` :: A string the method has to equal.
- `//<regexp>//` :: A regexp the method has to match.

The compare is case-sensitive, as servers log the method the client sent...
`GET` does not take a `get`, and `//^(?i:get)$//` does. A line whose
request could not be read has no method and is turned away. Two `method`
gates are ANDed.

## Where it goes

**Leading the list.** It reads nothing but the parsed line, so it costs
least written first, beside [`status`](status.md) and
[`ignore`](ignore.md), where a line it turns away has had nothing made for
it.

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

No fixture. Tests of a http rule default to the `http_access` parser. A
negative of the same path under another method proves the gate. See
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: '203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "POST /wp-login.php HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
      found: 1
      data:
        host: "203.0.113.9"
  negative:
    - message: '203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "OPTIONS /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"'
      found: 0
```

## Shipped rules using it

- `http/badbots` :: GET, POST, and HEAD, beside a `match` on the user agent.
- `http/php-url-fopen` :: GET and POST, beside a `match` on the path.
- `http/apache-pass` :: GET of the knocking path, beside a `status`.

## See also

- [`status`](status.md) :: The other access log field gate, ANDed with it.
- [`match`](match.md) :: What narrows the lines it lets by.
- [`module`](module.md) :: The same refusal on the http_error type.
- [http rules](../rules.md#http-rules) :: The type it belongs to.
