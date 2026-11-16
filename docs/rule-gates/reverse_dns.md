# reverse_dns... the client is who its address says

A `reverse_dns` gate compares the PTR names of an address against a regexp
or against another found value, negatable... how a claim in the log is
checked against what DNS says about the client. It is the gate that
finally ports fail2ban's `apache-fakegooglebot`, shipped as
`http/fakegooglebot`: a user-agent claiming Googlebot whose client does
not reverse into Google's domains is a pretender.

```yaml
rule_gates:
  - match:
      - field: user_agent
        regexp: '(?i:Googlebot)'
  - ban_var: [ host ]
  - reverse_dns:
      matches: '\.google(?:bot)?\.com$'   # regexp over the PTR names
      negate: true                        # count when it does NOT hold
max_score: 1
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `var`
- vetoes :: yes
- needs :: `enable_rdns`, on by default, and the optional `Net::DNS` and `POE::Component::Client::DNS` modules
- repeatable :: yes, each entry is a gate of its own

## Told

- `matches` :: A Perl regexp some PTR name has to match.
- `matches_var` :: The found var some PTR name has to equal, case and a trailing dot aside.
- `var` :: The found var holding the address to check, in place of the offender.
- `negate` :: True to hold when the comparison does not.
- `forward_confirm` :: False to take a PTR name at its word.
  - default :: true
- `on_nxdomain` :: What a lookup that answered no names does, `compare`, `pass`, or `fail`.
  - default :: `compare`
- `on_servfail` :: What a lookup that failed does, `compare`, `pass`, or `fail`.
  - default :: `fail`
- `into` :: The found var a PTR name of the address is lifted into when the gate holds.

Exactly one of `matches` or `matches_var`.

```yaml
rule_gates:
  - reverse_dns:
      var: PEER                 # gate a named found value
      matches_var: HELO         # ... against another found value
      forward_confirm: false
  - ban_var: [ SRC ]
```

**Forward confirmation is on by default.** An attacker controls their own
PTR, so with out it a negated Google pattern is evaded by pointing your
PTR at `anything.googlebot.com`. A PTR name only takes part when it
resolves back to the address it came from... a spoofed PTR is as good as
absent. `forward_confirm: false` is for cheap heuristics only.

`compare` runs the comparison over whatever names there are, none for an
authoritative absence. `pass` satisfies the entry outright and `fail`
vetoes outright. The two are terminal... `negate` never touches them, so
"on SERVFAIL, pass" lets the line through on both a positive and a negated
gate. `on_nxdomain: pass` on a positive gate spells "in my domain, or no
PTR at all" in one entry. `on_servfail` also governs a forward lookup that
fails, where `compare` leaves that one name unconfirmed and carries on.

## Where it goes

With no `var` it keys on the offender, so it goes below the `ban_var` and
checks each offender it names. With a `var` it is asked once of the whole
offense.

Lookups happen per offense, not per line, bounded by `rdns_timeout` and
cached for a minute. Still, keep the gate behind a cheap matcher, never on
a rule that matches everything, and the last of the gates that judge, so a
cheaper gate's veto spares the lookup.

## When it does not hold

A veto drops the offense, or with no `var` drops the offender it does not
hold for, the offense vetoed only when none are left. A vetoed offense
does not consume the line, which is what lets a legitimate Googlebot it
cleared go on to match a benign rule listed after it.

**Absence is an answer, failure is not... by default, and per rule.** An
authoritative empty PTR set compares false, so `negate` counts the client
with no reverse DNS at all, which is most fake bots. A timeout or SERVFAIL
vetoes regardless of `negate`, so an outage can never get the real
Googlebot banished.

Beware `on_servfail: pass` or `compare` on a negated gate. It trades that
guarantee for coverage, meaning a DNS outage counts everyone, which is
fail2ban's flaw made opt-in and labeled.

Everything else always fails closed: no resolver, `enable_rdns` off, the
modules not loadable, a value that is not an address, and a
`matches_var` the offense lacks or holds empty. A galla with reverse_dns
gated rules and no way to ask says so loudly at start (see
[configuration](../configuration.md#lookups-dns-and-geoip)).

Under a running galla the lookups go through a background engine, so an
address not in the cache is a lookup that has not answered yet, settled by
`on_servfail`. By default the first line from a cold address does not
count, and the next one, once the answer has landed, does.

## What it leaves behind

With an `into`, the name the comparison hit on, or under `negate`, where it
holds on hitting none, the first name that took part. It needs a `var`,
under the rules [`country`'s `into`](country.md#told) has, never lifts
over a value the offense already has, and an address with no name to give
lifts nothing.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- a `var`, `matches`, `matches_var`, or `into` that is not a string :: "has a ... that is not a non-empty string"
- an `on_nxdomain` or `on_servfail` other than the three :: "has a ... that is not one of pass, fail, or compare"
- both `matches` and `matches_var` :: "has both matches and matches_var"
- neither `matches` nor `matches_var` :: "has neither matches nor matches_var"
- an `into` with no `var` :: "has a into, which needs a var to lift the name of"
- a `matches` that does not compile :: "matches does not compile..."

Beyond these, every gate is refused for what
[every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A `dns` fixture stands in for the resolver... `ptr` maps an address to its
names and `forward` a name to its addresses, each answer a list,
`nxdomain`, or `servfail`. Anything unfixtured answers servfail. With out
the fixture the gate is skipped, and a fixture of only a `dnsbl` map
leaves it skipped too. See [proving lookups](../rules.md#proving-lookups),
and [tests](../rules.md#tests) for the shape.

```yaml
tests:
  positive:
    # a spoofed PTR claiming googlebot.com that does not resolve back
    - message: '203.0.113.11 - - [12/Jul/2026:08:15:50 -0500] "GET /wp-login.php HTTP/1.1" 404 196 "-" "Mozilla/5.0 (compatible; Googlebot/2.1)"'
      dns:
        ptr:
          "203.0.113.11": [ "crawl-66-249-66-1.googlebot.com" ]
        forward:
          "crawl-66-249-66-1.googlebot.com": [ "66.249.66.1" ]
      found: 1
  negative:
    # a resolver outage holds the rule back rather than misaiming it
    - message: '203.0.113.12 - - [12/Jul/2026:08:15:50 -0500] "GET /wp-login.php HTTP/1.1" 404 196 "-" "Mozilla/5.0 (compatible; Googlebot/2.1)"'
      dns:
        ptr:
          "203.0.113.12": servfail
      found: 0
```

Cover the judgment's whole ladder: the confirmed hit, the authoritative
absence, the spoof that fails forward confirmation, the legitimate name
spared, and the outage.

## Shipped rules using it

- `http/fakegooglebot` :: A Googlebot user-agent whose client does not forward-confirm into Google's domains, banished on the first request.

## See also

- [`dnsbl`](dnsbl.md) :: Rides the same lookup machinery to ask a blocklist about an address.
- [usedns](../usedns.md) :: The other direction, resolving a hostname offender, under a consent of its own.
- [the order it runs in](../rules.md#the-order-it-runs-in) :: Why a veto lets the line fall through.
