# Rules

Rules are YAML files. A rule name is its relative path with out the `.yaml`,
so the rule `syslog/sshd` is the file `syslog/sshd.yaml`. The first path
component is the rule **type**, which decides how a line becomes an offense:

| type | works on |
| --- | --- |
| `syslog` | syslog lines, `daemon[pid]: message` shaped |
| `raw` | whole lines of any shape, the escape hatch |
| `http` | HTTP access logs (common/combined) |
| `http_error` | apache and nginx error logs |
| `json` | JSON application logs |

Most of a rule is the same whatever its type... it names an offender, says
how it is counted, carries triage metadata, and can be refined by shared
gates. Only the **matcher**, how a line is judged an offense, changes from
type to type. This page covers the common parts first, then how the types
differ, then a writing guide for each.

A rule carries its own tests, and they are ran every time it is loaded... a
rule that fails its own tests refuses to load, failing `baphomet start`
loudly instead of silently matching nothing while logs scroll past.

## Where rules live

Rules are resolved across two places, in order:

1. The **site override dir**, `rules_dir` from the config,
   `/usr/local/etc/baphomet/rules` by default. It need not exist.
2. The **shipped rules**, installed with the dist under its
   [`File::ShareDir`](https://metacpan.org/pod/File::ShareDir) share dir by
   `make install`, and resolved from there at run time.

A name is looked up in the override dir first, so a file there shadows the
shipped rule of the same name. This is how a site overrides a shipped rule or
adds its own without touching what ships... drop
`syslog/sshd.yaml` under the override dir to replace the shipped `syslog/sshd`,
or add `syslog/mydaemon.yaml` for one that does not ship. Names absent from
the override dir fall through to the shipped set, so a fresh install needs
nothing copied into place... the shipped rules answer on their own. See the
[catalog](rules-catalog.md) for what ships.

## Anatomy of a rule

Every rule, whatever its type, is a YAML hash that does four things:

1. **Matches** ... decides which lines are offenses. This is the one part
   that differs by type, covered under [how the types differ](#how-the-types-differ)
   and each type's own section below.
2. **Names the offender** ... who or what the offense counts against, with
   [`ban_var`](#ban_var) or [`detection_var`](#detection_var).
3. **Counts** ... how hits accumulate and when a ban fires, with
   [`max_score`/`find_time`/`ban_time`/`weight`](#max_score--find_time--ban_time--weight)
   and [`eve_only`](#eve_only).
4. **Describes and proves itself** ... [triage metadata](#triage-metadata)
   for EVE, and its own [tests](#tests).

Optionally it also carries [gates](#refining-a-match-the-gates) that refine a
match after the fact... marks, geography, blocklists, time of day, reverse
DNS. Those are shared by every type.

Here is a whole syslog rule. Everything but the `daemons`/`message_regexp`
matcher is common to all five types:

```yaml
---
daemons:                       # syslog's matcher... a daemon gate,
  - sshd                       #   then the regexps below
  - sshd-session
message_regexp:
  - '^[iI](?:llegal|nvalid) user .*? from %%%%SRC%%%%'
ban_var:                       # common... who to count and ban
  - SRC
msg: "[SSHD] invalid user"     # common... triage metadata
severity: high
classtype: brute-force
tests:                         # common... proven every load
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

## Naming the offender

### ban_var

The captures or fields whose value is the offender, the thing a hit is
registered against and, at the threshold, banished. For each name here that
a matched line carries a value for, that value gets counted. Usually just
`SRC`. How the names resolve depends on the type... a regexp capture on
syslog/raw, a flattened field or capture on json; the http and http_error
types do not use `ban_var` at all, their offender is fixed (see
[how the types differ](#how-the-types-differ)). A rule names `ban_var` or
`detection_var`, never both.

### detection_var

The parallel of `ban_var` for a **detection-only rule**. It names the
captures or fields to count by, under no obligation to be a address... a
username, a hostname, a URI, a service, or a IP when that is what you want.
The presence of `detection_var` (in place of `ban_var`) is what makes a rule
detection-only: it runs the whole match/count/threshold path like any other
rule, but never banishes. Each match writes a `sighting` to EVE, and a
subject crossing `max_score` within `find_time` writes a `sighted` naming it,
never touching Kur. Counting rides the shadow buckets, so a detection rule
can never nudge a real ban over its threshold, and `ignore_ips` does not
apply. This is Sagan/Wazuh-style detection... alerting on a thing with no
address to banish, a policy tripwire, a config change, a service crash.

Because a detection rule writes only to EVE, loading one forces `eve_enable`
on (logged at start) so it is never a silent no-op. On the http and
http_error types, which count `host`/`client` by default, a `detection_var`
overrides that to count by whatever it names. See [eve](eve) for the event
shapes.

```yaml
# count by the offending username, banish nobody
detection_var:
  - USER
```

### ban_not_internal

Some sources, Suricata's eve.json above all, log both ends of a flow, and
which one is the offender depends on where in the stream the alert fired. A
rule that lists both endpoints as `ban_var`s and sets `ban_not_internal`
banishes only the ends that are not one of your own hosts:

```yaml
ban_var:
  - src_ip
  - dest_ip
ban_not_internal: true
```

Your own hosts are the `internal` config field, which defaults to the
`ignore_ips` list. So an inbound attack bans the external src, an outbound
callout bans the external dest, a transit flow bans both, and a
host-to-host flow bans neither. A ignored IP is never banished regardless.

It works on every type, not just the multi-endpoint case: with a single
offender... one `ban_var`, or the http/http_error fixed `host`/`client`... it
simply skips the ban when that offender is one of your own. Set `internal`
wider than `ignore_ips` (say all of RFC 1918) to spare internal clients from a
rule without globally ignoring them. Anything whose ban target is an IP can
carry it.

## How it is counted

### max_score / find_time / ban_time / weight

Optional, on every rule type. The rule's own word on how it is counted and
how long the ban runs, for rules where the watcher's numbers are the wrong
fit... one shellshock probe is a verdict, five mistyped passwords are not.
These are inert unless the watcher's `allow_per_rule_thresholds` config
setting is on... the flag is the consent, and with it given the layering
becomes rule over watcher over kur over global. A rule overriding `max_score`
or `find_time` counts into its own bucket, so its window does not touch the
shared count other rules build against the same IP, while a `ban_time`-only
override counts in the shared bucket and only bans differently.

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
consequence, not the matching.

Observe mode differs from a [detection rule](#detection_var): observe mode is
a would-be ban held back and shown as an `alert`, still keyed to an offender
IP; a detection rule never bans at all and counts any subject, surfacing as
`sighting`/`sighted`. See [eve](eve) for the event shapes.

## Triage metadata

### msg

Optional, on every rule type. A short human-readable signature naming what
the rule detects, the Sagan/Suricata `msg` convention... a `[TAG]
description` line like `[SSHD] authentication failure` or `[SURICATA]
Attempted Administrator Privilege Gain`. It is written to every EVE event
the rule produces as the top-level `.msg` field (see [eve](eve)), so a SOC
analyst or a jq one-liner reads what tripped without decoding the raw line.
When a rule sets none, `.msg` falls back to the rule's name (`syslog/sshd`),
so it is always present. Inert to matching.

### severity / classtype / references / attack / rev

Optional triage metadata, on every rule type, all inert to matching and all
written to EVE beside `msg` when set (see [eve](eve)):

- `severity` — one of `info`/`low`/`medium`/`high`/`critical`. Emitted as
  `.severity`. When a rule sets none, the config's `default_severity`
  (global/kur/watcher, see [configuration](configuration)) fills in; absent
  that too, the field is omitted.
- `classtype` — a category string, the Snort/Sagan/Suricata classtype (e.g.
  `brute-force`, `web-application-attack`, `trojan-activity`). Free-form.
- `references` — an array of URLs, CVE ids, or doc links.
- `attack` — an array of MITRE ATT&CK technique ids (e.g. `T1110`).
- `rev` — the rule's revision, a non-negative integer, Suricata's
  `alert.rev`. Emitted as `.rev`, defaulting to `0`... a `0` or unset `rev`
  is an unversioned rule. Bump it when you change a rule so a downstream
  consumer can tell versions apart.

Together with `msg` these are the Suricata/Sagan `alert` metadata set,
flattened to top-level EVE fields so a stream of matches becomes triageable
detections. Every shipped rule carries a `severity` and `classtype`.

Two more `alert` fields ride along in EVE but are **not** rule keys, derived
instead by the loader, so there is nothing to set... `gid`, `0` for a shipped
rule and `1` for one from the site override dir (`rules_dir`), and `sid`, a
stable positive integer hashed from the rule name. See [eve](eve).

### src_ip_var / dest_ip_var

Optional, on every rule type, inert to matching. Each names the found var
holding an endpoint of the flow, whose value is lifted to a top-level EVE
field so a consumer reads the source and destination addresses without
digging through `found` (see [eve](eve)):

- `src_ip_var` — the var promoted to `.src_ip`. Defaults to the found var
  literally named `src_ip`.
- `dest_ip_var` — the var promoted to `.dest_ip`. Defaults to `dest_ip`.

Point either at whatever a schema uses, `flow.src_ip` for a Suricata eve
line say, since `found` flattens nesting to dotted paths. Both `.src_ip` and
`.dest_ip` are always emitted, `null` when the named var is absent, so the
fields can be leaned on. This only shapes the EVE event; who gets banished is
still [`ban_var`](#ban_var) / [`ban_not_internal`](#ban_not_internal).

## Tests

Positive tests are lines the rule must match, negative tests are lines it
must not. Each is a hash...

| key | what |
| --- | --- |
| `message` | The full log line, as it would appear in the log. Required (or `messages`, below). |
| `parser` | The parser to parse it with. Defaults per type (`bsd_syslog` for syslog, `http_access` for http, and so on)... a stricter parser is better inside a rule's own tests, and one may be named per test. |
| `found` | Whether the rule should match, `1` or `0`. Defaults to 1 for positive and 0 for negative. |
| `data` | For positive tests, capture names to the values they should of captured. |
| `undefed` | For negative tests, capture names that should not be defined. |

A test may use `messages`, an array of lines fed through in order, instead of
a single `message`, with `found` the expected count across the sequence...
this is how [correlation](#syslog-rules) rules, whose offense and address
span lines, are tested. The whole `test_parser` key sets a rule-wide default
parser for its tests.

Marks and the geography/blocklist/time gates are galla state or need outside
data, so a rule's embedded tests prove only its matching layer, not those
gates (see each gate below).

## Refining a match... the gates

After a rule matches and its offender is in hand, a set of optional gates can
still drop the count. They are the shared vocabulary layered over every
type's matcher... a match that passes the matcher but fails a gate is not an
offense.

The gates are universal, but the matcher and offender keys that precede them
are not... which is the whole shape of the types. The full support matrix, a
✓ where a type accepts a key:

| key | syslog | raw | http | http_error | json |
| --- | :---: | :---: | :---: | :---: | :---: |
| `daemons` | ✓ | — | — | — | — |
| `message_regexp` | ✓ | ✓ | — | ✓ | — |
| `ignore_regexp` | ✓ | ✓ | — | ✓ | — |
| `capture_regexp` / `capture`+`key`+`defer` (correlation) | ✓ | ✓ | — | — | ✓ |
| `stages` / `per` (staged sequences) | ✓ | ✓ | — | — | — |
| `message_json` | ✓ | — | — | — | — |
| `status` / `method` | — | — | ✓ | — | — |
| `level` / `module` | — | — | — | ✓ | — |
| `match` / `ignore` | — | — | ✓ | — | ✓ |
| `ban_var` | ✓ | ✓ | —¹ | —¹ | ✓ |
| `ban_not_internal` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `detection_var` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `gate` / `selections` / `condition` / `keywords` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `mark` / `unmark` / `marked` / `not_marked` / `mark_only` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `sequence` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `country` / `namtar_list` / `active_time` / `reverse_dns` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `max_score` / `find_time` / `ban_time` / `weight` / `eve_only` / `distinct` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `msg` / `severity` / `classtype` / `references` / `attack` / `rev` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `src_ip_var` / `dest_ip_var` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `tests` / `test_parser` | ✓ | ✓ | ✓ | ✓ | ✓ |

¹ the http and http_error types have no `ban_var`... their offender is the
parsed `host` / `client`, fixed, so only a `detection_var` overrides what they
count by. `ban_not_internal` still applies over that fixed offender, sparing it
when it is one of your own hosts.

Everything from `ban_not_internal` down is universal... any rule whose ban
target is an IP can spare your own hosts. The one asymmetry among the universal
rows is not *whether* a gate runs but *what it can key on*: a gate or
mark naming a `field`/`var`/`vars` resolves it against the matched line's
data... regexp captures on syslog, raw, and json, flattened dotted paths on
json. The http and http_error types expose no arbitrary captures, so on them a
keyed gate reaches the parsed fields and the fixed offender, not a custom
capture.

### gate / selections / condition / keywords

The predicate layer, a boolean refinement over a line's fields or captures,
ANDed ahead of the type's own matching. Every type has it.

- **`gate`** — a list of field predicates, ANDed. The legacy form is
  `{field, values: [ ... ]}` where an entry is a string equality or a
  `//regexp//`. The typed form, detected by any of an `op`, `value`, `all`,
  `negate`, `nocase`, `fieldref`, or `decode` key, is
  `{field, op, value|values, all?, negate?, nocase?, fieldref?, decode?}` with
  operators `eq`, `contains`, `startswith`, `endswith`, `re`, `gt`/`lt`/`ge`/`le`,
  `cidr`, and `exists` (the field is present, any value... `negate` makes it the
  field-absent test), an optional `decode` chain (base64, utf16, url, ...) run before
  the operator, `negate` that also holds when the field is absent, and `nocase`
  to case-fold the compare (default off, Baphomet matching case-sensitively...
  Sigma's default-insensitive match is `nocase: true`). In place of a literal
  value, `fieldref` names another field to compare against (its live value the
  needle, Sigma's `|fieldref`), so two fields can be required to agree — or,
  with `negate`, to differ.
- **`keywords`** — shorthand for a `contains` over a field, or over every
  field. A plain list searches everything; the `{in, values}` form scopes it
  to a path or subtree.
- **`selections` / `condition`** — the boolean form, and an alternative to
  `gate` (a rule uses one or the other). `selections` is a table of named
  predicate lists; `condition` composes them with `and`/`or`/`not`, parens,
  and the quantifiers `all of them`, `1 of them`, and `N of <prefix>_*`...
  the OR, nesting, and N-of-M a flat gate can not express, the Sigma model.

What a `field` names depends on the type... a regexp capture (syslog/raw), a
flattened dotted path (json), a parsed access/error-log field (http,
http_error). The reserved `%%%ANY%%%` and `%%%ANY:<prefix>%%%` fan a
predicate over every field or a subtree. See
[`App::Baphomet::Rules::JSON`](https://metacpan.org/pod/App::Baphomet::Rules::JSON)
for the full operator and decode reference.

### marks... cross-rule state, keyed by anything

Correlation (below) ties lines together with in one rule. Marks tie rules
together... a mark is a named, expiring brand a rule leaves on a key that a
later rule, in the same or another watcher of that galla, can gate on. It is
how one rule remembers something for another, Sagan's xbits and flexbits. The
keys are legal on every rule type.

The key defaults to the offender IP, but any capture or field of the matched
line can be the key (`var`), and a mark can carry a value harvested from the
line too (`value_var`)... so a mark can remember not just "this IP" but "this
username", and store "the address that used it".

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
single account hit from more than one source... the distributed brute-force
signature per-IP counting can not see, since each source alone stays under
the threshold. The first rule brands each failed account with the source that
hit it:

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

Order matters: list the reading rule (`sshd-spray`) before the branding one
(`sshd-mark-users`) in the watcher, so the gate sees the source that
established the account rather than the one the same line would re-brand it
with. Since `sshd-spray` carries `max_score: 1`, it only fires where the kur
sets `allow_per_rule_thresholds`.

Marks are galla state, so a rule's own embedded tests can not exercise
them... they prove only that the rule matches and captures. The live marks
are visible with `baphomet marked`, and survive a restart via a marks tablet,
unlike correlation context. Scope is the galla, so marks cross watchers and
rules but not kurs. Each mark name is capped, and the ignored are never
branded.

### country... narrowing an offense by geography

A rule may carry a `country` gate that only lets a match count when the
offender, or some captured address, is in (or not in) a set of countries. It
needs a GeoIP database, the `geoip_db` config setting, read through the
optional `IP::Geolocation::MMDB` module.

```yaml
country:
  isnot:                              # count only if NOT in these
    - "%%%country_codes{allowed}%%%"  # import a named list from the config
    - "MX"                            # literal 2-letter codes compose too
max_score: 1
```

`is` or `isnot`, exactly one. Each list entry is either a literal ISO 3166
2-letter code or the `%%%country_codes{name}%%%` token, which splices in a
named list from the config, layered per watcher... so a shipped rule stays
geography-neutral and the operator owns the policy. A bare string is taken as
a one-element list.

By default the gate checks the offender IP being counted. An optional `vars`
list checks the country of named found vars instead:

```yaml
country:
  is: [ "%%%country_codes{yours}%%%" ]
  vars: [ dest_ip ]        # gate on the dest's country, still ban the src
ban_var: [ src_ip ]
```

- **No `vars`** ... offender-keyed. Checked per ban_var candidate in the ban
  loop, filtering which offenders count, like `ban_not_internal`.
- **`vars` given** ... data-keyed. Checked once per result against the named
  found vars (resolved like `ban_var`, so JSON dotted paths work); all must
  pass, and a veto drops the whole result.

The gate always **fails closed**: a value that does not locate, or a missing
database, blocks the count rather than risking a wrong ban. A galla with
country-gated rules and no loadable database says so loudly at start. There
is no shipped country rule, since a geography ban is your policy... compose
one from an offense rule plus a `country` gate and your own `country_codes`
lists.

### namtar_list... only the already-condemned

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
**every** entry must hold. Like the country gate, a var entry is data-keyed
and vets the whole result while a var-less one filters offenders.

The gate **fails closed**: an address on no list, or a list whose file is
unreadable or empty, blocks the count... an absent feed banishes nobody,
never everybody. `ignore_ips` still wins absolutely. There is no shipped
namtar rule, since which addresses are condemned is your policy.

### active_time... only in, or out of, certain hours

A `active_time` gate only lets a match count when the time falls in, or out
of, named windows... an admin login that is routine at midday and worth a ban
at 03:00. The windows are defined in the config's `active_time`, layered per
watcher.

```yaml
active_time:
  is: [ business, mixed ]     # count only when the time is in ANY of these (union)
  # xor  isnot: [ overnight ] # count only when in NONE of them
  vars: [ ts ]                # optional: which found value holds the time; default = now
max_score: 1
```

`is` or `isnot`, exactly one, each a list of window names resolved against
the watcher's config. Multiple windows are unioned. **`vars`** names which
found value(s) hold the time to check; without it the gate checks the
**current time**, the usual case. A value is read as an epoch (all digits;
journal microseconds scaled down) or an ISO 8601 datetime... anything else,
or a missing value, **fails closed**. Because a log's raw timestamp string is
rarely one of those, `vars` suits JSON or EVE lines carrying a machine
timestamp; leave it off to gate on now.

Unlike the other gates, active_time is never per-offender... time is a
property of the line, so the gate is checked once per result and vetoes the
whole result. Times are the system's local time. There is no shipped
active_time rule, since which hours matter is your policy.

### reverse_dns... the client is who its address says

A `reverse_dns` gate compares the PTR names of an address against a regexp
or against another found value, negatable... how a claim in the log is
checked against what DNS says about the client. The gate that finally
ports `apache-fakegooglebot` (shipped as `http/fakegooglebot`): a
user-agent claiming Googlebot whose client does not reverse into Google's
domains is a pretender.

```yaml
reverse_dns:
  - matches: '\.google(?:bot)?\.com$'   # regexp over the PTR names
    negate: true                        # count when it does NOT hold
  - var: SRC                            # gate a named found value instead
    matches_var: HELO                   # ... against another found value
    forward_confirm: false              # default true, see below
```

An array of entries, every one required to hold. Each names exactly one of
`matches` (a Perl regexp any PTR name must satisfy) or `matches_var`
(equality against another found value, case-folded, trailing dots
stripped). A `var` entry checks that found value's address once per result,
vetoing the whole result; a var-less entry checks each offender in the ban
loop, like `country`. `negate` inverts the comparison.

**Forward confirmation is on by default.** An attacker controls their own
PTR, so with out it a negated Google pattern is evaded by pointing your
PTR at `anything.googlebot.com`. A PTR name only participates when it
resolves back to the address it came from... a spoofed PTR is as good as
absent. `forward_confirm: false` is for cheap heuristics only.

**Absence is an answer; failure is not... by default, and per rule.** An
authoritative empty PTR set compares false... so `negate` counts the
client with no reverse DNS at all, which is most fake bots. A timeout or
SERVFAIL vetoes the count regardless of `negate`, so an outage can never
get the real Googlebot banned. Both verdicts are the entry's to override:

| key | default | values |
| --- | --- | --- |
| `on_nxdomain` | `compare` | `compare` runs the comparison over the (empty) name set, `pass` satisfies the entry outright, `fail` vetoes outright |
| `on_servfail` | `fail` | the same three, governing any lookup failure in the entry... during forward confirmation, `compare` leaves that one name unconfirmed and carries on |

`pass` and `fail` are terminal... `negate` never touches them, so "on
SERVFAIL, pass" means let through on both a positive and a negated gate.
`on_nxdomain: pass` on a positive gate spells "in my domain, or no PTR at
all" in one entry. And beware `on_servfail: pass`-or-`compare` on a
negated gate... it trades the outage-can-not-misaim guarantee for
coverage, meaning a DNS outage counts everyone, which is fail2ban's flaw
made opt-in and labeled. Everything else always fails closed: no
resolver, `enable_rdns` off (see [configuration](configuration)), a
non-address value, a missing `matches_var`.

Lookups happen per match, not per line, bounded by `rdns_timeout` and
cached... still, keep the gate behind a cheap matcher, never on a rule
that matches everything. Like the other galla-state gates, a rule's
embedded tests can not exercise it... they prove the matching layer only.

## How the types differ

Everything above is shared. What each type changes is the **matcher** ... how
a raw line becomes a match, and where the offender comes from.

| type | works on (parser) | how it decides an offense | offender |
| --- | --- | --- | --- |
| `syslog` | syslog lines (`bsd_syslog`/`syslog`/`ietf_syslog`/`json_syslog`/journal) | a `daemons` gate, then `message_regexp` over the message text | `ban_var` captures |
| `raw` | whole lines (`raw`) | `message_regexp` over the whole line, no daemon gate | `ban_var` captures |
| `http` | access logs (`http_access`) | `status`/`method` gates and `match` regexps over parsed fields | always `host` |
| `http_error` | error logs (`apache_error`/`nginx_error`) | `level`/`module` gates, then `message_regexp` over the message | always `client` |
| `json` | JSON logs (`json`) | `gate`/`match` over flattened dotted fields | `ban_var` naming a field or capture |

The axes underneath that table:

- **Text or structured.** syslog, raw, and http_error match Perl regexps
  against a line's free text; http and json match against fields the parser
  already broke out (`status`, `attr.remote`). The predicate
  [gate/selections/keywords](#gate--selections--condition--keywords) layer
  refines either kind, on every type.
- **Extracted or handed over.** syslog, raw, and json dig the offender out
  with `ban_var` (a token capture, a named group, or a field path). http and
  http_error need no `ban_var`... the parser already isolated the client, so
  the offender is fixed at `host` / `client`, and a
  [`detection_var`](#detection_var) is the only reason to name a subject.
- **Tokens.** The `%%%%TOKEN%%%%` shortcuts (`SRC`, `HOST`, `ADDR`, ...)
  compile into address-matching named captures. They work in the
  `message_regexp` of syslog and raw, and in the `match` entries of json.
  http field matches and http_error `message_regexp` are plain Perl regexps,
  not tokened (http_error still merges a winning regexp's named captures into
  the data).
- **Correlation.** Offense-and-address-on-different-lines correlation is a
  syslog, raw, and json feature... `capture_regexp` and keyed
  `message_regexp` on the text types, `capture` entries and a rule-level
  `key`/`defer` keyed on fields for json. The http and http_error types
  have no need of it, every line already carrying its offender.
- **Staging.** In-rule ordered sequences... counted stages with time and
  line bounds (`stages`/`per`)... are a syslog and raw feature.
- **JSON in a syslog envelope.** `message_json` decodes a JSON message inside
  a syslog line into gateable fields, a syslog-only bridge to the json
  machinery.

The rest of this page is one section per type.

## syslog rules

A syslog rule matches the message portion of a parsed syslog line, after a
cheap daemon gate.

### daemons

Which daemons this rule processes. The daemon of a parsed line is checked
against this list first and if it does not match, the regexps are never
tried, which keeps rules cheap on busy shared logs. Entries starting and
ending with `//` are regexps... `//^sshd//` is the regexp `^sshd`.
Everything else is a plain string equality check.

### message_regexp

The regexps tried, in order, against the message portion of a parsed line...
the part after `daemon[pid]: `, not the whole line. The first to match wins.
These are Perl regexps plus `%%%%TOKEN%%%%` tokens, each of which compiles to
a named capture group:

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
matched is what comes out under the token name. The captured value is what
`ban_var` or `detection_var` names.

### ignore_regexp

Optional. Regexps that veto a line... checked after the daemon gate and
before `message_regexp`, and if any matches the message, the line is not
regarded as found no matter what the message regexps would of said. The
fail2ban equivalent is `ignoreregex`. Tokens work here too.

```yaml
ignore_regexp:
  - 'Registration from ''\S+'' failed for %%%%SRC%%%% - ACL rule'
```

### message_json

Optional boolean. When a daemon logs a JSON object as its message,
`message_json: true` decodes it and flattens it into fields the
[predicate gate](#gate--selections--condition--keywords) can test by their
dotted paths, the way a `json` rule works, while the syslog envelope stays
reachable under reserved keys (`syslog.daemon`, `syslog.host`, ...). With it
on, `message_regexp` becomes optional, the gate being the matcher. See
[`App::Baphomet::Rules::Syslog`](https://metacpan.org/pod/App::Baphomet::Rules::Syslog).

### correlation... offense and address on different lines

Some daemons log the offense and the offender's address separately, tied by a
key like a connection or queue id... pre-4.4 mongod logs
`[conn7] Failed to authenticate` with no address and later
`[conn7] end connection 192.0.2.35:53276`. syslog and raw rules handle this
with `capture_regexp` entries, which harvest context rather than being
offenses, and keyed `message_regexp` entries:

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

A keyed offense resolves through the stored captures of a capture line with
the same key, whichever order the two arrive in... `defer` says how long a
offense may wait for its address, `ttl` how long harvested context lives.
Both directions work, so sendmail's address-first queue id pairs and
mongodb's offense-first conn id pairs are the same machinery. State is per
watcher and in memory only. Test these with the `messages:` array form (see
[tests](#tests)); `raw/mongodb-auth-legacy` and the No such user pair in
`syslog/sendmail-reject` are shipped examples.

A `key` may also be a array of components, and on the syslog type a
component may name a reserved envelope field... `syslog.daemon`,
`syslog.host`, or `syslog.pid`... in place of a capture. So a daemon whose
lines share nothing but the logging process itself, the fail2ban F-MLFID
shape, correlates by its session with no key in the message at all:

```yaml
capture_regexp:
  - regexp: '^Connection from %%%%SRC%%%% port \d+'
    key: [ syslog.host, syslog.daemon, syslog.pid ]
    ttl: 120
message_regexp:
  - regexp: '^Too many authentication failures'
    key: [ syslog.host, syslog.daemon, syslog.pid ]
    defer: 60
ban_var:
  - SRC
```

Every component must resolve for a key to hold... a keyed offense any of
whose components is missing (a daemon logging with no pid, say) is judged a
plain unkeyed offense, and a capture line harvests nothing. `syslog.pid`
alone scopes to one process life; include `syslog.host` when several hosts
share the log. The raw type has no envelope, so envelope components are a
load error there.

### stages... ordered sequences with in one rule

Correlation merges data across lines but knows no order and counts
nothing. A **staged rule** matches a *sequence*... ordered stages, each a
`message_regexp` list with an optional hit `count` (default 1), a `within`
bound in seconds on the gap since the previous hit, and a `skip` bound on
the log lines allowed between hits. The final stage completing is the
offense, its data the captures of every hit merged, later stages
authoritative. `stages` replaces `message_regexp`/`capture_regexp`
entirely... a staged rule's stages are its whole matcher, with
`ignore_regexp` still vetoing lines ahead of them.

The brute-force-that-worked shape... failures, then a success, the
compromised-credential alarm one typo never trips:

```yaml
stages:
  - message_regexp:
      - '^Failed (?:password|publickey) for .* from %%%%SRC%%%%'
    count: 5
    within: 300
  - message_regexp:
      - '^Accepted \w+ for .* from %%%%SRC%%%%'
    within: 60
per: [ SRC ]
detection_var: [ SRC ]
```

`per` names the key the sequence state lives under... captures, and on
the syslog type the `syslog.host`/`syslog.daemon`/`syslog.pid` envelope
fields, so a single counted stage keyed
`per: [ syslog.host, syslog.daemon, syslog.pid ]` counts repetition
*with in one daemon session*, a far sharper signal than per-IP counting
across the whole window. Every `per` component must resolve on a hit or
the line joins nothing.

The mechanics worth knowing... a hit landing past its stage's `within` or
`skip` kills the sequence (the line may then head a fresh one); a line
matching the *first* stage never tramples a sequence already in flight
for its key, so failures past the count do not reset a
waiting-for-success rule; intermediate hits do not consume the line, so
the plain rules beside a staged one still count what it watches. State is
per watcher, memory only, bounded, and swept... a restart forgets a
half-built sequence. The found's EVE event carries a `stages` array of
every hit (stage index, epoch, line) beside the usual fields, the `raw`
being the final line.

With out `per` the state is one slot per followed file... pure adjacency.
That is only sound for serialized logs, a single-worker daemon or a
one-connection-at-a-time service... any multi-client daemon interleaves
sessions and adjacency would stitch one client's stage to another's, so
prefer `per` wherever a key exists and say so loudly in a keyless rule's
header.

Sequences prove themselves through the `messages:` test form, whose line
order also drives `skip`. A `within` bound is time and can not be
exercised from embedded tests... prove the order and counts there, and
the gap behavior in a `.t` against the rule object (see
`t/rule-stages.t`).

See
[`App::Baphomet::Rules::Syslog`](https://metacpan.org/pod/App::Baphomet::Rules::Syslog)
for the full reference.

## raw rules

Rules of the `raw` type work on lines from the `raw` parser, the no-op escape
hatch where the whole line is the message. A raw rule is a syslog rule with
out the daemons gate... the same `message_regexp` with the same
[tokens](#message_regexp), the same `ignore_regexp`, the same `ban_var`,
the same
[correlation](#correlation-offense-and-address-on-different-lines), and
the same [staging](#stages-ordered-sequences-with-in-one-rule), though
with no envelope a raw `per` keys on captures only. Tests default to the
`raw` parser.

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

The missing daemon gate has a real cost... **every regexp runs against every
line** of the log. Anchor with `^` and lead each regexp with the log's own
timestamp shape, which restores most of the gate's cheap rejection, and keep
raw watchers on single purpose app logs rather than busy shared ones.

## http rules

Rules of the `http` type work on lines parsed by the `http_access` parser
(common and combined access logs). There is nothing to extract... the client
is already the `host` field of the parsed line, so a http rule just decides
which lines are offenses, and what gets banned is always `host` (unless a
[`detection_var`](#detection_var) overrides it).

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
protocol, status, bytes, referer, user_agent, and format. The
[predicate gate](#gate--selections--condition--keywords) works over them too,
ahead of the matches. Gates-only rules (every 401, say) are legal... a rule
with neither gates nor matches is a error. Tests default to the `http_access`
parser. See
[`App::Baphomet::Rules::HTTP`](https://metacpan.org/pod/App::Baphomet::Rules::HTTP)
for the full reference.

## http_error rules

Rules of the `http_error` type work on lines parsed by the `apache_error` or
`nginx_error` parsers. As with http rules, the offender is already the
`client` field of the parsed line and is what gets banned, and lines with no
client (startup notices) are never offenses. As with syslog rules, the
matching is `message_regexp`/`ignore_regexp` against the message free text...
for apache that is what follows the `[client ip]` and the optional
`AHnnnnn:` code, and for nginx the trailing `, client: ..., server: ...`
pairs are peeled into fields first, so the regexps stay clean of them. These
are plain Perl regexps... the `%%%%TOKEN%%%%` shortcuts are a syslog/raw
feature, not used here, but named captures in a winning regexp merge into
`data`.

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

The [predicate gate](#gate--selections--condition--keywords) is available,
ANDed ahead of the message match. See
[`App::Baphomet::Rules::HTTPError`](https://metacpan.org/pod/App::Baphomet::Rules::HTTPError)
for the full reference.

## json rules

Rules of the `json` type work on lines parsed by the `json` parser, which
flattens whatever the application logged into dotted field paths
(`attr.remote`, `request.client_ip`, `tags.0`). The rule says which fields
matter... ANDed `gate` entries pinning fields to value lists
(string-or-`//regexp//`), ORed first-match-wins `match` entries running
regexps ([tokens](#message_regexp) included) against named fields, and
vetoing `ignore` entries of the same shape. A rule needs at least a gate or a
match.

`ban_var` resolves against the found line's data, which is the flattened
fields merged with the winning match's captures... so it may name a token
capture like `SRC` when the address has to be dug out of a string like
`"remote":"192.0.2.5:54321"`, or a field path like `request.client_ip` when
the log hands the address over bare.

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

Tests default to the `json` parser, each message being one line of JSON. The
full [predicate gate](#gate--selections--condition--keywords) vocabulary,
`selections`/`condition` and `keywords` included, is at home here... json is
where the Sigma-style boolean model earns its keep. See
[`App::Baphomet::Rules::JSON`](https://metacpan.org/pod/App::Baphomet::Rules::JSON)
for the full reference.

### correlation on json... capture, key, defer

Structured logs split events too... mongod 4.4+ logs the auth failure and
the connection's address as separate JSON events sharing a `ctx` conn id,
the same shape its old text logs had. The json type carries the same
two-phase [correlation](#correlation-offense-and-address-on-different-lines)
as syslog and raw, keyed on fields instead of an envelope: `capture`
entries (their own `gate`/`match`, a `key`, a `ttl`) harvest context
without being offenses, and a rule-level `key`, with an optional `defer`,
makes the rule's own match resolve through it, whichever order the events
arrive in.

```yaml
gate:
  - field: c
    values: [ ACCESS ]
  - field: msg
    values: [ "Authentication failed" ]
key: [ ctx ]
defer: 60
capture:
  - gate:
      - field: msg
        values: [ "Connection ended" ]
    match:
      - field: attr.remote
        regexp: '^%%%%SRC%%%%:\d+$'
    key: [ ctx ]
    ttl: 120
ban_var:
  - SRC
```

A `key` is a field path or capture name, or an array of them compounding
into one key, every component required to resolve. An unresolved offense
with `defer` waits that many seconds for its capture; with out `defer` it
is not judged an offense at all. State is per watcher and in memory only,
as on the other types, and the `messages:` test form proves it. The
`syslog.*` namespace is reserved (it is the [message_json](#message_json)
envelope), so keying on it here is a load error.

## Writing one

Start from a real log line and work backwards...

```shell
# see how the line parses and whether the rule matches... --rules-dir looks
# in just that dir, handy for a rule tree being worked on in a checkout
baphomet test_line --rules-dir ./share/rules --rule syslog/myrule \
    'Jul 12 08:15:50 vixen42 mydaemon[123]: auth failure from 1.2.3.4'

# run a rule's own tests
baphomet check_rules --rules-dir ./share/rules syslog/myrule

# run every rule's tests... the override dir and the shipped rules both
baphomet check_rules
```

`test_line` loads the rule with its tests skipped, so a rule you are midway
through writing can still be poked at.

Things worth knowing...

- Anchor with `^` where you can... it keeps a regexp from matching inside
  quoted or logged-through content, like sshd logging a client supplied
  string.
- The fail2ban filters (`config/filter.d/` in its source) are a rich vein of
  patterns to translate. Drop their `<HOST>` style tags in favor of the
  tokens above and their `%(...)s` includes in favor of spelling things out.
- Every regexp should have at least one positive test, and lines that look
  temptingly close but must not match (successful logins above all) make the
  best negative tests.
- Rules load once at start. After editing one, restart baphomet or verify
  first with `check_rules`.
