# module... which apache module logged it

A `module` gate turns an error log line away unless the module that logged
it is one of the ones named. Apache 2.4 writes the module beside the level,
`[auth_basic:error]`, so a rule can say an auth failure is one the
`auth_basic` module reported and not some other module's line that reads
alike.

```yaml
rule_gates:
  - level: [ error ]
  - module: [ auth_basic ]
  - message_regexp:
      - '^user \S*: authentication failure for '
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

- `<module>` :: A string the module has to equal.
- `//<regexp>//` :: A regexp the module has to match.

Two `module` gates are ANDed.

**A module gate makes a rule apache 2.4 only.** A line with out a module is
turned away, and that is every apache 2.2 line, every 2.4 prefork line of
the empty `[:error]` form, and every nginx line. A rule meant for both
servers, or both apache versions, leaves it out and narrows by its
`message_regexp` instead.

## Where it goes

**Leading the list.** It reads nothing but the parsed line, so it costs
least written first, beside [`level`](level.md) and
[`ignore_regexp`](ignore_regexp.md), where a line it turns away has had
nothing made for it.

## When it does not hold

The line is turned away outright. Nothing below is asked, and the line goes
on to the rules after it.

## Refused at load

- not a list, or an empty one :: "is not a array or is empty"
- an entry that is not a string :: "contains a non-string entry"
- a `//regexp//` that will not compile :: "entry ... does not compile"

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

No fixture. Tests of a http_error rule default to the `apache_error`
parser. A negative of the same message in the 2.2 shape, with no module,
records that the rule is 2.4 only on purpose. See
[tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: '[Thu Jun 27 11:55:44.569531 2013] [auth_basic:error] [pid 4101:tid 2992] [client 192.0.2.4:23456] AH01617: user foo: authentication failure for "/": Password Mismatch'
      found: 1
      data:
        client: "192.0.2.4"
  negative:
    # the 2.2 shape has no module
    - message: '[Wed Jul 17 22:18:52 2013] [error] [client 192.0.2.4] user foo: authentication failure for "/basic/file": Password Mismatch'
      found: 0
```

## Shipped rules using it

None. The shipped apache rules match the 2.2 and 2.4 shapes alike, so none
narrows by module.

## See also

- [`level`](level.md) :: The other error log field gate, ANDed with it.
- [`message_regexp`](message_regexp.md) :: The matcher of the lines it lets by.
- [`method`](method.md) :: The same refusal on the http type.
- [http_error rules](../rules.md#http_error-rules) :: The type it belongs to.
