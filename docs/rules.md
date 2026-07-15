# Rules

Rules are YAML files under the rules dir, by default
`/usr/local/etc/baphomet/rules`. A rule name is its relative path with out
the `.yaml`, so the rule `syslog/sshd` is the file `syslog/sshd.yaml`. The
first path component is the rule type... `syslog` for syslog lines, which
most of this page is about, and `http` for HTTP access logs, covered at
the end, `http_error` for apache/nginx error logs and `json` for JSON
application logs right after it, and `raw` for everything else, last.

A rule carries its own tests, and they are ran every time it is loaded... a
rule that fails its own tests refuses to load, failing `baphomet start`
loudly instead of silently matching nothing while logs scroll past.

## The format

```yaml
---
daemons:
  - sshd
  - sshd-session
message_regexp:
  - '^[iI](?:llegal|nvalid) user .*? from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd-session[66891]: Invalid user moth3r from 216.137.179.214 port 34640"
      found: 1
      data:
        SRC: "216.137.179.214"
  negative:
    - message: "Jul 12 08:25:49 vixen42 sshd-session[36748]: Accepted publickey for kitsune from 127.0.0.1 port 21680 ssh2: ED25519 SHA256:hjUfLIEAIR3ueytAg+XlbiVHmCQSQ6MCEdo2xYbyJ48"
      found: 0
      undefed: ["SRC"]
```

### daemons

Which daemons this rule processes. The daemon of a parsed line is checked
against this list first and if it does not match, the regexps are never
tried, which keeps rules cheap on busy shared logs. Entries starting and
ending with `//` are regexps... `//^sshd//` is the regexp `^sshd`.
Everything else is a plain string equality check.

### message_regexp

The regexps tried, in order, against the message portion of a parsed
line... the part after `daemon[pid]: `, not the whole line. The first to
match wins. These are Perl regexps plus `%%%%TOKEN%%%%` tokens, each of
which compiles to a named capture group...

| token | matches |
| --- | --- |
| `HOST` | a domain name, IPv4 address, or IPv6 address |
| `SUBNET` | a IPv4 or IPv6 subnet or address |
| `IP4` | a IPv4 address |
| `IP6` | a IPv6 address |
| `ADDR` | a IPv4 or IPv6 address |
| `DNS` | a domainname |
| `SRC` / `DEST` | a IPv4 or IPv6 address... meant to be used in combination, and when a regexp uses both, a match only regards as found if both matched |

A token may appear more than once in one regexp... whichever occurrence
matched is what comes out under the token name.

### ignore_regexp

Optional. Regexps that veto a line... checked after the daemon gate and
before `message_regexp`, and if any matches the message, the line is not
regarded as found no matter what the message regexps would of said. The
fail2ban equivalent is `ignoreregex`. Tokens work here too.

```yaml
ignore_regexp:
  - 'Registration from ''\S+'' failed for %%%%SRC%%%% - ACL rule'
```

### ban_var

The captures to use for bans. For each name here that a matching line
captured, the captured value is an IP that gets a hit registered against
it. Usually just `SRC`.

### max_score / find_time / ban_time / weight

Optional, on every rule type. The rule's own word on how it is counted
and how long the ban runs, for rules where the watcher's numbers are the
wrong fit... one shellshock probe is a verdict, five mistyped passwords
are not. These are inert unless the watcher's
`allow_per_rule_thresholds` config setting is on... the flag is the
consent, and with it given the layering becomes rule over watcher over
kur over global. A rule overriding `max_score` or `find_time` counts
into its own bucket, so its window does not touch the shared count other
rules build against the same IP, while a `ban_time`-only override counts
in the shared bucket and only bans differently.

`max_score` is a **score** to reach, not a plain retry count. Each match
deposits the rule's `weight`, a positive number defaulting to 1, and an
offender is banished once the surviving weights in the window sum to
`max_score`. So a dangerous signature can weigh 10 and banish on one hit,
a noisy one weigh 1, and several different rules against one IP accrue
together toward the one threshold, sshguard-style, instead of racing
separate counters. With every weight 1 the score is just the hit count,
exactly as before, so nothing changes for unweighted rules. `weight`,
like the thresholds, is honored only under `allow_per_rule_thresholds`.

```yaml
# one heavy hit is enough, hold the door eternally
weight: 10
max_score: 10
ban_time: 0
```

### eve_only

Optional, on every rule type, and also settable at the global, kur, and
watcher level (see [configuration](configuration)). Puts the rule in
**observe mode**: its matches are written to EVE but never count toward a
real ban. A would-be banish surfaces as an `alert` event and each match as
`noted` rather than `found`, so a new rule can be stood up and watched
before it is trusted to act... CrowdSec's simulation, on a rule. The rule's
own `eve_only` layers over the watcher-resolved one, so a deployment can be
set observe at any level and a trusted rule opt back in with
`eve_only: false`. The gates all still run; observe mode changes the
consequence, not the matching. See [eve](eve) for the event shapes.

### tests

Positive tests are lines the rule must match, negative tests are lines it
must not. Each is a hash...

| key | what |
| --- | --- |
| `message` | The full log line, as it would appear in the log. Required. |
| `parser` | The parser to parse it with. Defaults to `bsd_syslog`... stricter is better inside a rule's own tests, though `syslog` or `ietf_syslog` may be named per test. |
| `found` | Whether the rule should match, `1` or `0`. Defaults to 1 for positive and 0 for negative. |
| `data` | For positive tests, capture names to the values they should of captured. |
| `undefed` | For negative tests, capture names that should not be defined. |

## Correlation... when the offense and the address are on different lines

Some daemons log the offense and the offender's address separately, tied
by a key like a connection or queue id... pre-4.4 mongod logs
`[conn7] Failed to authenticate` with no address and later
`[conn7] end connection 192.0.2.35:53276`. syslog and raw rules handle
this with `capture_regexp` entries, which harvest context rather than
being offenses, and keyed `message_regexp` entries...

```yaml
capture_regexp:
  - regexp: '^\S+\s+\[conn(?<KEY>\d+)\] end connection %%%%SRC%%%%:\d+'
    key: KEY
    ttl: 600
message_regexp:
  - regexp: '^\S+\s+\[conn(?<KEY>\d+)\] Failed to authenticate '
    key: KEY
    defer: 600
ban_var:
  - SRC
```

A keyed offense resolves through the stored captures of a capture line
with the same key, whichever order the two arrive in... `defer` says how
long a offense may wait for its address, `ttl` how long harvested context
lives. Both directions work, so sendmail's address-first queue id pairs
and mongodb's offense-first conn id pairs are the same machinery. State is
per watcher and in memory only.

Tests for these use `messages:`, an array of lines fed through in order,
with `found` being the expected count of found results across the
sequence. See `raw/mongodb-auth-legacy` and the No such user pair in
`syslog/sendmail-reject` for shipped examples.

## Marks... cross-rule state, keyed by anything

Correlation ties lines together with in one rule. Marks tie rules
together... a mark is a named, expiring brand a rule leaves on a key that a
later rule, in the same or another watcher of that galla, can gate on. It
is how one rule remembers something for another, Sagan's xbits and
flexbits. The keys are legal on every rule type.

The key defaults to the offender IP, but any capture or field of the
matched line can be the key (`var`), and a mark can carry a value harvested
from the line too (`value_var`)... so a mark can remember not just "this
IP" but "this username", and store "the address that used it".

| key | what |
| --- | --- |
| `mark` | Array of brands to set on match, each `{name, ttl, var?, value_var?}`. `name` is the mark's name, `ttl` its life in seconds. Without `var` the brand is keyed by each offender IP, with it by that capture. `value_var` names a capture to store on the brand. |
| `unmark` | Array of brands to lift on match, each `{name, var?}`. A successful login lifting a suspicion, say. |
| `marked` | Gate array, ANDed... the result only counts if every named brand is set. Each `{name, var?, value_is?, value_not?}`. A var-keyed entry is checked against the line's captures, a var-less one against each offender IP. `value_is`/`value_not` (at most one) name a capture the stored value must equal or differ from. |
| `not_marked` | Gate array, the inverse... the result only counts if none of the named brands is set. Same keying. |
| `mark_only` | When true the rule only brands and gates, never counting toward a ban, and does not consume the line, so matching falls through to the later rules. |

A rule whose mark gates veto, like a mark_only rule, does not consume the
line either, so a branding rule and the rule that reads it can both act on
the same line by falling through.

The shipped `syslog/sshd-mark-users` and `syslog/sshd-spray` pair catch a
single account hit from more than one source... the distributed
brute-force signature per-IP counting can not see, since each source alone
stays under the threshold. The first rule brands each failed account with
the source that hit it:

```yaml
# syslog/sshd-mark-users, mark_only... brand USER with the SRC
mark_only: true
mark:
  - name: sshd-account-src
    ttl: 3600
    var: USER
    value_var: SRC
```

The second matches the same failures and fires only when the account is
already branded with a *different* source:

```yaml
# syslog/sshd-spray... a second source on a branded account
marked:
  - name: sshd-account-src
    var: USER
    value_not: SRC
max_score: 1
```

Order matters: list the reading rule (`sshd-spray`) before the branding
one (`sshd-mark-users`) in the watcher, so the gate sees the source that
established the account rather than the one the same line would re-brand
it with. Since `sshd-spray` carries `max_score: 1`, it only fires where
the kur sets `allow_per_rule_thresholds`.

Marks are galla state, so a rule's own embedded tests can not exercise
them... they prove only that the rule matches and captures. The live marks
are visible with `baphomet marked`, and survive a restart via a marks
tablet, unlike correlation context. Scope is the galla, so marks cross
watchers and rules but not kurs. Each mark name is capped, and the ignored
are never branded.

## Country gate... narrowing an offense by geography

A rule may carry a `country` gate that only lets a match count when the
offender, or some captured address, is in (or not in) a set of countries.
It needs a GeoIP database, the `geoip_db` config setting, read through the
optional `IP::Geolocation::MMDB` module.

```yaml
country:
  isnot:                              # count only if NOT in these
    - "%%%country_codes{allowed}%%%"  # import a named list from the config
    - "MX"                            # literal 2-letter codes compose too
max_score: 1
```

`is` or `isnot`, at most one. Each list entry is either a literal ISO 3166
2-letter code or the `%%%country_codes{name}%%%` token, which splices in a
named list from the config, layered per watcher... so a shipped rule stays
geography-neutral and the operator owns the policy. A bare string is taken
as a one-element list.

By default the gate checks the offender IP being counted. An optional
`vars` list checks the country of named found vars instead:

```yaml
country:
  is: [ "%%%country_codes{yours}%%%" ]
  vars: [ dest_ip ]        # gate on the dest's country, still ban the src
ban_var: [ src_ip ]
```

- **No `vars`** ... offender-keyed. Checked per ban_var candidate in the
  ban loop, filtering which offenders count, like `ban_not_internal`.
- **`vars` given** ... data-keyed. Checked once per result against the
  named found vars (resolved like `ban_var`, so JSON dotted paths work);
  all must pass, and a veto drops the whole result. Lets a rule gate on the
  geography of a value it is not banning... ban the `src_ip` of a flow only
  when the `dest_ip` is one of yours.

The gate always **fails closed**: a value that does not locate, or a
missing database, blocks the count rather than risking a wrong ban. Because
a missing database silently stops such a rule, a galla with country-gated
rules and no loadable database says so loudly at start. There is no shipped
country rule, since a geography ban is your policy, not a fail2ban port...
compose one from an offense rule plus a `country` gate and your own
`country_codes` lists.

## Namtar list gate... only the already-condemned

A `namtar_list` gate only lets a match count when a value appears on a named
blocklist, the inverse of `ignore_ips`. The lists are named in the config's
`namtar_lists`, layered per watcher and reloaded on mtime change, so a rule
can count only what a feed you supply condemns. A list is either a **CIDR
list** matched by address containment, or a **string list** matched by exact
(optionally case-folded) equality... so the gate reaches beyond IPs to any
field a rule captures, a username, a URI, a user-agent. The flavor is set on
the list in the config, not here, so a rule stays a pure matcher.

```yaml
namtar_list:
  - lists: [ threatfeed, torexits ]   # SRC on ANY of these (union)
    var: SRC
  - list: bait_users                  # a string list of honeypot accounts
    var: USER                         # check the user, still ban the offender
max_score: 1
```

The gate is a array of entries. Each names one or more lists (`lists`, or
`list` for one) and, optionally, the found var to check (resolved like
`ban_var`, so JSON dotted paths work); without a var it checks the offender
IP. A value on **any** of an entry's lists satisfies it (union), and
**every** entry must hold. An entry may even union lists of different
flavors, each value tested against each list its own way. Like the country
gate, a var entry is data-keyed and vets the whole result while a var-less
one filters offenders, so a rule can gate on a captured field it is not
banning. Paired with `max_score: 1`, one hit on a listed value is enough.

The gate **fails closed**: an address on no list, or a list whose file is
unreadable or empty, blocks the count... an absent feed banishes nobody,
never everybody. `ignore_ips` still wins absolutely, so an ignored address
is never banished even when it is also blocklisted. There is no shipped
namtar rule, since which addresses are condemned is your policy... compose
one from an offense rule, a `namtar_list` gate, and your own feeds.

## Active time gate... only in, or out of, certain hours

A `active_time` gate only lets a match count when the time falls in, or out
of, named windows... an admin login that is routine at midday and worth a
ban at 03:00. The windows are defined in the config's `active_time`,
layered per watcher.

```yaml
active_time:
  is: [ business, mixed ]     # count only when the time is in ANY of these (union)
  # xor  isnot: [ overnight ] # count only when in NONE of them
  vars: [ ts ]                # optional: which found value holds the time; default = now
max_score: 1
```

`is` or `isnot`, at most one, each a list of window names resolved against
the watcher's config. Multiple windows are unioned. **`vars`** names which
found value(s) hold the time to check; without it the gate checks the
**current time**, the usual case. A value is read as an epoch (all digits;
journal microseconds scaled down) or an ISO 8601 datetime... anything else,
or a missing value, **fails closed**. Because a log's raw timestamp string
is rarely one of those, `vars` suits JSON or EVE lines carrying a machine
timestamp; leave it off to gate on now.

Unlike the other gates, active_time is never per-offender... time is a
property of the line, so the gate is checked once per result and vetoes the
whole result. Times are the system's local time. There is no shipped
active_time rule, since which hours matter is your policy.

## http rules

Rules of the `http` type work on lines parsed by the `http_access` parser
(common and combined access logs). There is nothing to extract... the
client is already the `host` field of the parsed line, so a http rule just
decides which lines are offenses, and what gets banned is always `host`.

```yaml
---
# gates... optional, ANDed, same string-or-//regexp// convention
status:
  - 401
  - 403
  - //^5//
method:
  - GET
  - POST
# matches... ORed, first hit wins, each naming the parsed field it runs against
match:
  - field: user_agent
    regexp: '(?i:masscan|zgrab|sqlmap)'
  - field: path
    regexp: '\.(?:env|git)(?:$|/)'
# ignores... same shape, a hit vetoes the line
ignore:
  - field: user_agent
    regexp: 'FriendlyAuditBot'
tests:
  positive:
    - message: '203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "GET /.env HTTP/1.1" 404 196 "-" "zgrab/0.x"'
      found: 1
      data:
        host: "203.0.113.9"
```

The matchable fields are host, ident, user, time, request, method, path,
protocol, status, bytes, referer, user_agent, and format. Gates-only rules
(every 401, say) are legal... a rule with neither gates nor matches is a
error. Tests default to the `http_access` parser. See
[`App::Baphomet::Rules::HTTP`](https://metacpan.org/pod/App::Baphomet::Rules::HTTP)
for the full reference.

## http_error rules

Rules of the `http_error` type work on lines parsed by the `apache_error`
or `nginx_error` parsers. As with http rules, the offender is already the
`client` field of the parsed line and is what gets banned, and lines with
no client (startup notices) are never offenses. As with syslog rules, the
matching is `message_regexp`/`ignore_regexp` against the message free
text... for apache that is what follows the `[client ip]` and the
optional `AHnnnnn:` code, and for nginx the trailing
`, client: ..., server: ...` pairs are peeled into fields first, so the
regexps stay clean of them.

```yaml
---
level:                   # optional gates, ANDed, string-or-//regexp//
  - error
module:                  # apache 2.4 module... a module gate makes a rule 2.4 only
  - auth_basic
message_regexp:
  - '^user \S*: password mismatch'
ignore_regexp:
  - 'from the health checker'
test_parser: nginx_error # per rule test parser default... apache_error if unset
tests:
  positive:
    - message: '[Wed Jul 17 22:18:52 2013] [error] [client 127.0.0.1] user username: authentication failure for "/basic/file": Password Mismatch'
      found: 1
      data:
        client: "127.0.0.1"
```

Named captures in a winning regexp get merged into `data`. See
[`App::Baphomet::Rules::HTTPError`](https://metacpan.org/pod/App::Baphomet::Rules::HTTPError)
for the full reference.

## Banning the external end of a flow

Some sources, Suricata's eve.json above all, log both ends of a flow and
which one is the offender depends on where in the stream the alert fired.
A rule that lists both endpoints as ban_vars and sets `ban_not_internal`
banishes only the ends that are not one of your own hosts...

```yaml
ban_var:
  - src_ip
  - dest_ip
ban_not_internal: true
```

Your own hosts are the `internal` config field, which defaults to the
`ignore_ips` list. So an inbound attack bans the external src, an outbound
callout bans the external dest, a transit flow bans both, and a
host-to-host flow bans neither. A ignored IP is never banished regardless,
so the banished end is by extension not ignored either. Works on syslog,
raw, and json rules... anywhere a rule has more than one endpoint ban_var.

## json rules

Rules of the `json` type work on lines parsed by the `json` parser, which
flattens whatever the application logged into dotted field paths
(`attr.remote`, `request.client_ip`, `tags.0`). The rule says which fields
matter... ANDed `gate` entries pinning fields to value lists
(string-or-`//regexp//`), ORed first-match-wins `match` entries running
regexps (tokens included) against named fields, and vetoing `ignore`
entries of the same shape. A rule needs at least a gate or a match.

`ban_var` resolves against the found line's data, which is the flattened
fields merged with the winning match's captures... so it may name a token
capture like `SRC` when the address has to be dug out of a string like
`"remote":"192.0.2.5:54321"`, or a field path like `request.client_ip`
when the log hands the address over bare.

```yaml
---
gate:
  - field: c
    values: [ ACCESS ]
  - field: msg
    values: [ "Authentication failed" ]
match:
  - field: attr.remote
    regexp: '^%%%%SRC%%%%:\d+$'
ban_var:
  - SRC
tests:
  positive:
    - message: '{"c":"ACCESS","msg":"Authentication failed","attr":{"remote":"192.0.2.5:54321"}}'
      found: 1
      data:
        SRC: "192.0.2.5"
```

Tests default to the `json` parser, each message being one line of JSON.
See [`App::Baphomet::Rules::JSON`](https://metacpan.org/pod/App::Baphomet::Rules::JSON)
for the full reference.

## raw rules

Rules of the `raw` type work on lines from the `raw` parser, the no-op
escape hatch where the whole line is the message. A raw rule is a syslog
rule with out the daemons gate... the same `message_regexp` with the same
tokens, the same `ignore_regexp`, and the same `ban_var`. Tests default to
the `raw` parser.

```yaml
---
message_regexp:
  - '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} auth failure from %%%%SRC%%%%$'
ban_var:
  - SRC
tests:
  positive:
    - message: "2026-07-12 08:15:50 auth failure from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
```

The missing gate has a real cost... **every regexp runs against every
line** of the log. Anchor with `^` and lead each regexp with the log's own
timestamp shape, which restores most of the gate's cheap rejection, and
keep raw watchers on single purpose app logs rather than busy shared ones.

## Writing one

Start from a real log line and work backwards...

```shell
# see how the line parses and whether the rule matches
baphomet test_line --rules-dir ./rules --rule syslog/myrule \
    'Jul 12 08:15:50 vixen42 mydaemon[123]: auth failure from 1.2.3.4'

# run a rule's own tests
baphomet check_rules --rules-dir ./rules syslog/myrule

# run every rule's tests
baphomet check_rules
```

`test_line` loads the rule with its tests skipped, so a rule you are midway
through writing can still be poked at.

Things worth knowing...

- Anchor with `^` where you can... it keeps a regexp from matching inside
  quoted or logged-through content, like sshd logging a client supplied
  string.
- The fail2ban filters (`config/filter.d/` in its source) are a rich vein
  of patterns to translate. Drop their `<HOST>` style tags in favor of the
  tokens above and their `%(...)s` includes in favor of spelling things
  out.
- Every regexp should have at least one positive test, and lines that look
  temptingly close but must not match (successful logins above all) make
  the best negative tests.
- Rules load once at start. After editing one, restart baphomet or verify
  first with `check_rules`.
