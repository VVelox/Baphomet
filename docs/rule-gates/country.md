# country... narrowing an offense by geography

A `country` gate only lets a match count when the offender, or some
captured address, is in (or not in) a set of countries. It is how a
geography policy is laid over any offense rule... a login from outside the
countries you do business in, a callout to one you never talk to.

```yaml
rule_gates:
  - ban_var: [ SRC ]
  - country:
      isnot:                              # count only if NOT in these
        - "%%%country_codes{allowed}%%%"  # import a named list from the config
        - "MX"                            # literal 2-letter codes compose too
max_score: 1
```

## At a glance

- phase :: offense
- rule types :: every type
- keys on :: the offender, or a found value with `vars`
- vetoes :: yes
- needs :: `geoip_db` and the optional `IP::Geolocation::MMDB` module, and `country_codes` for what it imports
- repeatable :: yes, each entry is a gate of its own

## Told

- `is` :: The countries the address has to be in.
- `isnot` :: The countries the address has to be out of.
- `vars` :: The found var, or a list of them, holding the addresses to check, in place of the offender.
- `into` :: The found var the country code is lifted into.

`is` or `isnot`, never both. Each entry is a literal ISO 3166 2-letter
code, any case, or the `%%%country_codes{name}%%%` token, which splices in
a named list from the config, layered per watcher (see
[country code lists](../configuration.md#country-code-lists))... so a
shipped rule stays geography-neutral and the operator owns the policy. A
bare string is taken as a list of one.

With `vars`, every address named has to pass. A rule wanting to gate both
a captured address and the offender names the gate twice:

```yaml
rule_gates:
  - country:
      is: [ "%%%country_codes{yours}%%%" ]
      vars: [ dest_ip ]        # gate on the dest's country, still ban the src
  - ban_var: [ src_ip ]
```

`into` needs exactly one entry in `vars`. An offense may have several
offenders, each in a country of its own, and the var holds one value. With
an `into`, `is` and `isnot` are both optional. A gate with neither judges
nothing and vetoes nothing, and an address that does not locate leaves the
var unset. This is one account seen from two countries inside an hour:

```yaml
max_score: 2
find_time: 3600
distinct: { of: COUNTRY, by: USER }
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - country: { vars: [ SRC ], into: COUNTRY }
  - detection_var: [ SRC ]
```

It counts countries and not distance, so a VPN or a border town will trip
it, which is why it only sights. For distance, see [`travel`](travel.md).

## Where it goes

With no `vars` it keys on the offender, so it goes below the `ban_var`,
and is asked of each candidate, filtering which offenders count. With
`vars` it is asked once of the whole offense and needs no `ban_var` above
it. On a [detection rule](detection_var.md) it has to name `vars`.

A [`mark`](mark.md) above it brands the offender it then spares. Put the
mark below.

Of the gates that judge, it is a local database lookup, cheaper than any
gate that goes to DNS, so it goes above those.

## When it does not hold

A veto drops the offense, or with no `vars` drops the offender it does not
hold for, the offense vetoed only when none are left. A vetoed offense does
not consume the line, which goes on to the rules listed after this one.

It always **fails closed**. An address that does not locate, a var the
offense lacks, or a missing database blocks the count rather than risking
a wrong ban, so an `isnot` gate never banishes an address the database has
a gap for. Private addresses never locate. A galla with country-gated rules
and no loadable database says so loudly at start. Lookups are cached for a
minute.

## What it leaves behind

With an `into`, the code, upcased, in that var. It never lifts over a
value the offense already has. Only what is asked once there is an offense
can read it... [`distinct`](../rules.md#distinct-counting-how-many-not-how-often),
the mark gates, [`namtar_list`](namtar_list.md), and the EVE event.
[`gate`](gate.md), `condition`, `keywords`, and [`track`](track.md) are
asked of the line, before any `country` gate is. `distinct`, `mark`, and
`marked` each fail closed on an unset var for themselves.

The same lift lets a `mark` store the code as its `value_var` and a
[`marked`](marked.md) compare against it with `value_not`... a login from a
country the account did not last use.

## Refused at load

- told other than a hash :: "is not a hash"
- a key it does not take :: "has the unknown key ..."
- an `is` or `isnot` that is not codes or imports :: "has a is that is not a 2-letter code or a %%%country_codes{name}%%% import, or a non-empty array of them"
- a `vars` that is not a name or a list of them :: "has a vars that is not a non-empty string or a non-empty array of them"
- both `is` and `isnot` :: "has both is and isnot"
- none of `is`, `isnot`, or `into` :: "has none of is, isnot, or into"
- an `into` that is not a string :: "has a into that is not a non-empty string"
- an `into` with other than one var :: "has a into, which needs exactly one var to lift the country of"
- an import of a list the watcher does not define, when bound :: "imports country_codes{...}, which is not a defined list for it"

The last is found when the galla binds the rule to a watcher, and the
galla will not start on it.

It is also refused for
[what every gate is refused for](../rules.md#what-every-gate-is-refused-for).

## Proving it

A `geo` fixture stands in for the database... a `countries` map placing
each address, `unknown` for one it would not, and a `lists` map standing
in for the config's `country_codes`. With out one the gate is skipped, and
a fixture of only `asns` or `locations` leaves it skipped too. See
[proving lookups](../rules.md#proving-lookups), and
[tests](../rules.md#tests) for the shape.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Accepted \S+ for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - country:
      isnot:
        - "%%%country_codes{allowed}%%%"
        - "MX"
max_score: 1
tests:
  positive:
    # a login from abroad... the isnot gate lets it count
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for root from 203.0.113.9 port 4711 ssh2"
      geo:
        countries:
          "203.0.113.9": NL
        lists:
          allowed: [ US ]
      found: 1
  negative:
    # a login from a country you do business in
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for root from 198.51.100.4 port 4711 ssh2"
      geo:
        countries:
          "198.51.100.4": US
        lists:
          allowed: [ US ]
      found: 0
    # MX, listed literally
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for root from 192.0.2.8 port 4711 ssh2"
      geo:
        countries:
          "192.0.2.8": MX
        lists:
          allowed: [ US ]
      found: 0
    # an unplaceable address fails closed, so a database gap misses rather
    # than false-alarms
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for root from 192.0.2.66 port 4711 ssh2"
      geo:
        countries:
          "192.0.2.66": unknown
        lists:
          allowed: [ US ]
      found: 0
```

Prove the allowed, the away, and the unplaceable... the last is the one that
catches a rule mistakenly written to fire on database gaps.

## Shipped rules using it

Three detection rules and one group use it, all importing
`country_codes{home}` and none shipping the policy. Each does nothing
until you both list it in a watcher and name your home countries in the
config, and the galla will not start with one listed and `home` undefined.
All of them prove their gate from their own tests with a `geo` fixture.

- `syslog/sshd-foreign-login`, `syslog/dovecot-foreign-login`, `syslog/postfix-sasl-foreign` :: Three rules, not a group, each sighting a successful login from abroad and banishing nobody.
- `%syslog/foreign-auth%` :: Fourteen rules banishing at `max_score: 1` on any authentication event from abroad, failed or successful.

The three detection rules sight only because a foreign login is a
traveler or a takeover, and the rule can not tell which.

The ban family matches each service's whole offense vocabulary *plus* that
service's successful login. It is the blunt policy, for the drive-by that
probes a few credentials and moves on faster than any per-service
threshold can answer. It banishes on a login that worked, which is
deliberate and which will banish a traveling admin mid-session, so read
the group file before listing it. Run the group or the detection rule per
service, not both... whichever is listed first consumes the successes and
the other never sees them.

Order the ban family **ahead** of the per-service rules it shadows. A
vetoed gate does not consume the line, so a domestic event falls straight
through and counts at the ordinary rule exactly as before, while foreign
traffic is peeled off the top. Listed after them, the ordinary rules
consume the failures first and only foreign successes reach it.

Beyond these, a geography policy is yours to compose... any offense rule
plus a `country` gate and your own `country_codes` lists.

## See also

- [`asn`](asn.md) :: The same question asked of the network an address is on, and written the same way.
- [`travel`](travel.md) :: How far an account went, not which border it crossed.
- [`detection_var`](detection_var.md) :: What the three foreign-login rules count by.
- [rule groups](../rules.md#rule-groups) :: Listing `%syslog/foreign-auth%` as a whole.
