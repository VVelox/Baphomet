# status... which HTTP statuses a http rule reads

A `status` gate turns an access log line away unless the HTTP status of
the request is one of the ones named. A rule wants it to say which answers
are the evidence... a 401 is a failed login, a 404 a probe for something
that is not there. With nothing below it to narrow further it is the whole
of the judgment, every line of that status an offense.

```yaml
rule_gates:
  - status: [ 404 ]
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

- `<status>` :: A status the line's status has to equal, as a string.
- `//<regexp>//` :: A regexp the status has to match.

A status is matched as a string, so it is `404` and never a range of
numbers... `//^5//` is how every server error is named, and `//^4//` every
client error. A number YAML reads as an int compares the same as the
string. Two `status` gates are ANDed.

## Where it goes

**Leading the list.** It reads nothing but the parsed line, so it costs
least written first, beside [`method`](method.md) and
[`ignore`](ignore.md), where a line it turns away has had nothing made for
it.

## When it does not hold

The line is turned away outright. Nothing below is asked, and the line goes
on to the rules after it.

## Refused at load

- not a list, or an empty one :: "is not a array or is empty"
- an entry that is not a string or number :: "contains a non-string entry"
- a `//regexp//` that will not compile :: "entry ... does not compile"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

No fixture. Tests of a http rule default to the `http_access` parser. A
negative of the same request with another status proves the gate. See
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: '203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "GET /.env HTTP/1.1" 404 196 "-" "curl/8.0"'
      found: 1
      data:
        host: "203.0.113.9"
  negative:
    - message: '203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "GET /.env HTTP/1.1" 200 196 "-" "curl/8.0"'
      found: 0
```

## Shipped rules using it

- `http/path-scan` :: Every 404, alone, the count doing the rest.
- `http/botsearch` :: 401, 403, and 404, narrowed by a `match` on the paths scanners probe.
- `http/openhab` :: 401 from openHAB's auth.
- `http/apache-pass` :: 200 on the knocking path, beside a `method`.

## See also

- [`method`](method.md) :: The other access log field gate, ANDed with it.
- [`match`](match.md) :: What narrows the lines it lets by.
- [`level`](level.md) :: The same refusal on the http_error type.
- [http rules](../rules.md#http-rules) :: The type it belongs to.
