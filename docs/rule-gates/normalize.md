# normalize... the path a server would make of it

A `normalize` gate lifts a copy of a request path, made the way a server
makes it before it looks for the file. A rule matching on the copy is not
got round by writing the one path another way... `/%77p-login.php`,
`//wp-login.php`, and `/x/../wp-login.php` are all `/wp-login.php`. The path
it was given is left as it was, so the event still says what was sent.

```yaml
rule_gates:
  - status: [ 200, 404 ]
  - normalize: { var: path, into: PATH, ops: [ url, slashes, dot_segment, lower, query ] }
  - match:
      - field: PATH
        regexp: '/wp-(?:login|signup|admin)\.php$'
  - ban_var: [ host ]
```

## At a glance

- phase :: line
- rule types :: every type
- keys on :: a found value
- vetoes :: no, it only lifts
- needs :: nothing
- repeatable :: yes, each entry is a gate of its own

## Told

- `var` :: The found var holding the path.
- `into` :: The found var the copy is lifted into.
- `ops` :: The steps to do, a non-empty list of the names below.

The path is split from its query at the first `?` or `#` ahead of anything
else, as a server splits it, so a `%3f` is never taken for the start of a
query and `/../` in a query is never resolved. The steps run over the path
alone, and always in the order below whatever order `ops` names them in, as
a step done ahead of the one it depends on would leave standing what it was
for... `dot_segment` ahead of `url` would leave `%2e%2e` a segment.

- `url` :: Percent decoding, done again while it changes things, three
      times at the most.
- `overlong` :: The overlong UTF-8 forms of an ASCII byte, and IIS's
      `%u00XX` form, made the byte they stand for.
- `nul` :: Everything from a NUL on cut off.
- `backslash` :: Each `\` made a `/`, as IIS takes it.
- `slashes` :: Each run of `/` made one.
- `params` :: The `;name=value` parameters of each segment cut off.
- `dot_segment` :: The `.` and `..` segments resolved as a server resolves
      them, a `..` above `/` dropped.
- `dot_segment_below` :: The same, but a `..` above `/` kept.
- `lower` :: Lower case, for a server that does not tell the cases apart.
- `query` :: The query left off.

`url` decoding twice is how a filter that decodes once is got past a
backend that decodes twice... `%2577` is `%77` once and `w` twice.
`overlong` makes IIS's `%u002f` a `/` on its own, and `%c0%af` one once
`url` has decoded it to its two bytes. `nul` is for a backend that reads a
path as a C string, where `/x.php%00.jpg`, decoded, is `/x.php`.
`params` is for Tomcat, whose `/admin;x=1/` is `/admin/`. With out `query`
the query is put back after the path as it was given.

`dot_segment` makes `/../../etc/passwd` `/etc/passwd`. `dot_segment_below`
makes `/a/../../etc/passwd` `/../etc/passwd`, so a rule can see the climb
was tried, and it is never named beside `dot_segment`. It is for a rule
about the climb its self:

```yaml
rule_gates:
  - normalize: { var: path, into: PATH, ops: [ url, overlong, backslash, dot_segment_below ] }
  - match:
      - field: PATH
        regexp: '^/\.\./'
  - ban_var: [ host ]
```

**Do only what the server does.** A step the server does not take makes a
path it never served... a rule lowercasing for a server that tells the
cases apart, or decoding twice for one that decodes once, sees a hit where
the server answered 404 or 400 to something else entirely. So no step is
done unless named, and a rule pairs the gate with the `status` a real hit
gets.

## Where it goes

Above the `match` that reads the copy. It reads what stands when it is
asked, the line's fields while no offense has been made and the offense
once one has, so written below the `match` it lifts into an offense the
`match` has already judged without it.

An `into` it lifts can be named by the `match` and `ignore` of an http
rule, which otherwise only take the fields of the log format.

## When it does not hold

It always lets the line by. A `var` the line does not have, or one that is
not a plain string, lifts nothing, and a `match` on the `into` then finds
the field missing.

## What it leaves behind

The copy, in the `into`, read by every gate below it and every offense gate.
It is never lifted over a value already there, so an `into` naming a field
the line has is never written. Nothing outlives the line.

## Refused at load

- no `var`, `into`, or `ops`, or a key it does not know :: lacks a var /
      lacks a into / lacks a ops / has the unknown key
- `ops` empty, or naming a step there is none of :: has a ops that is not a
      non-empty array of url, overlong, ...
- a step named twice :: names the op twice
- `dot_segment` beside `dot_segment_below` :: names both dot_segment and
      dot_segment_below

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

It needs no fixture. A positive test for each spelling the rule is meant to
see through, and a negative one with the trick in the query, prove the steps
and the split. See [tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    - message: '192.0.2.30 - - [12/Jul/2026:08:15:50 -0500] "GET /x/..//%77P-login.php HTTP/1.1" 404 196 "-" "curl/8.0"'
      found: 1
      data:
        PATH: "/wp-login.php"
  negative:
    - message: '192.0.2.31 - - [12/Jul/2026:08:15:51 -0500] "GET /index.php?next=/wp-login.php HTTP/1.1" 404 196 "-" "curl/8.0"'
      found: 0
```

## See also

- [`extract`](extract.md) :: Lifts captures out of a field the same way.
- [`match`](match.md) :: What reads the copy.
- [`status`](status.md) :: What a real hit gets, to pair it with.
