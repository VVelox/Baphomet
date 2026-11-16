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
shipped rule of the same name... drop `syslog/sshd.yaml` there to replace
the shipped `syslog/sshd`, or add `syslog/mydaemon.yaml` for one that does
not ship. Anything else falls through to the shipped set, so a fresh install
needs nothing copied into place. See the [catalog](rules-catalog.md) for
what ships.

## Rule groups

A group is a named list of rules a watcher can pull in by reference, so a
large set need not be spelled out entry by entry. In a watcher's `rule` list,
an entry wrapped in percent signs is a group... `%json/suricata-all%` expands,
in place, to every rule the group names:

```toml
[kur.ids.eve]
log = "/var/log/suricata/eve.json"
parser = "json"
rule = [ "%json/suricata-all%", "json/caddy-botsearch" ]
```

Groups live and resolve exactly as rules do... a **site override dir**,
`groups_dir` from the config (`/usr/local/etc/baphomet/groups` by default),
searched ahead of the **shipped groups** under the dist share dir. A group
named `json/suricata-all` is the file `groups/json/suricata-all`, and a file
of that name in the override dir shadows the shipped one. Unlike a rule, a
group file carries no extension.

The file is newline delimited, one rule name per line... `#` comments and
blank lines are ignored, and surrounding whitespace is trimmed.

```
# every shipped Suricata classtype rule
json/suricata-attempted-admin
json/suricata-denial-of-service

json/suricata-exploit-kit
```

Expansion happens once, before any rule loads. The result keeps order and is
deduplicated to the first occurrence, so a rule named twice... by two groups,
or by a group and again explicitly... loads once, sits at its first position,
and can never count twice, whatever the [`overlap`](configuration.md). A
group that resolves to no file, a member not in `type/name` form, an empty
group, or a member of a type the watcher's parser can not feed all fail
loudly at start, never silently. Groups do not nest... a member is a rule,
not another `%group%`.

Groups pair naturally with per-rule
[config overrides](configuration.md#per-rule-config-overrides): pull the bulk
in with a group, then tune the handful of exceptions by name with a
`rule_config` table, no need to list the rest. A `rule_config` key may itself
be a `%group%`, applying to every rule it names, so a whole family can be put
in observe mode in one stanza and a single member excepted by name.

### Shipped groups

A group's members are all of one type, so it drops into a single-parser
watcher whole. What ships:

| group | for | holds |
| --- | --- | --- |
| `json/suricata-all` | a Suricata `eve.json` | every classtype rule |
| `json/suricata-bad` | " | all of them bar the noise and the too-generic... no `icmp-event`, `inappropriate-content`, generic protocol-command-decode, or `policy-violation` |
| `json/suricata-attack` | " | the high-confidence hostile set... malware plus active intrusion attempts and successes |
| `json/suricata-malware` | " | the critical "host is compromised" classtypes (C2, trojan, exploit kit, credential theft, coin mining) |
| `json/suricata-recon` | " | scanning and probing... noisier, suits `eve_only` observe mode |
| `syslog/mail` | a maillog | postfix, sendmail, dovecot, courier, cyrus, perdition, sieve, qmail, and the rest of the MTA/IMAP/POP auth rules |
| `syslog/messages` | the broad catch-all syslog | the eighteen daemons with no log file of their own... the panels and monitors (webmin, phpMyAdmin, Froxlor, monit, nrpe, haproxy), the file and directory services (samba, rsyncd, slapd), openvpn, postgresql, screensharingd, suhosin, and the daemons that refuse or rate-limit (strongswan, unbound, freeradius's unknown clients, scanlogd, xinetd). Their facilities scatter them across `messages`/`daemon`/`syslog`, so give it to each broad log you have... a rule whose daemon is absent costs one string compare. Deliberately excludes `pam-generic` and `drupal-auth`, whose `//.//` gate double-counts against the service rules, and `named-refused`, whose own header warns a refusal can be innocent |
| `syslog/ftp` | an FTP log | proftpd, pure-ftpd, vsftpd, wuftpd, gssftpd |
| `syslog/voip` | a VoIP log | asterisk, freeswitch, murmur |
| `syslog/ssh` | an auth log | the base `sshd` and `dropbear`... not the `sshd-*` tuning variants, which are alternative modes, not additive |
| `syslog/foreign-auth` | any log carrying a login service | the fourteen `*-foreign-auth` rules... any authentication event, failed or successful, from outside `country_codes{home}`, banning on the first one. Opt-in twice over (list it, and name your home countries) and **listed ahead** of the per-service rules it shadows. See [the country gate](rule-gates/country.md) |
| `syslog/linux-audit` | a forwarded auditd stream (audisp-syslog) | the auditd auth-failure and login-failure-anomaly ban rules, plus a detection-only sweep for the shapes a compromise leaves in the audit trail: account management, SELinux AVC and AppArmor denials, promiscuous NICs, MAC/audit tampering, fault-signal crashes, forbidden execs, kernel module loads, linker-preload writes, execs from writable dirs, and paths named to hide. Not `syslog/linux-apparmor-denied`, which reads the kernel ring buffer, not this stream |
| `http_error/apache` | an Apache error log | the `apache-*` error-log rules |
| `http_error/nginx` | an Nginx error log | the `nginx-*` error-log rules |
| `http/scanners` | an HTTP access log | bad bots, panel sweeps, the fake-Googlebot check, PHP url-fopen abuse, protected-area probes |

## Anatomy of a rule

Every rule, whatever its type, is a YAML hash of two sorts of key.

`rule_gates` is everything the rule matches with. It is a list of gates, each
entry a hash of one key, the gate type, over what that gate is told. A line
goes down the list in the order it is written, and between them the gates do
three things:

1. **Match** ... decide which lines are offenses. Which gates a rule can
   match with depends on its type, covered under
   [how the types differ](#how-the-types-differ) and each type's own section
   below.
2. **Name the offender** ... who or what the offense counts against, with
   [`ban_var`](rule-gates/ban_var.md) or [`detection_var`](rule-gates/detection_var.md).
3. **Refine** ... the [gates](#refining-a-match-the-gates) that judge a match
   after the fact, by marks, geography, blocklists, time of day, or reverse
   DNS, and the ones that brand the offender. These are shared by every type.

The rest of the keys are about the rule and not the line:

1. **Counting** ... how hits accumulate and when a ban fires, with
   [`max_score`/`find_time`/`ban_time`/`weight`](#max_score--find_time--ban_time--weight),
   [`distinct`](#distinct-counting-how-many-not-how-often) when the offense is a
   count of different things rather than of hits, and [`eve_only`](#eve_only).
2. **Describing and proving itself** ... [triage metadata](#triage-metadata)
   for EVE, and its own [tests](#tests).

Here is a whole syslog rule. Only the `daemons` and `message_regexp` gates are
the syslog type's own:

```yaml
---
msg: "[SSHD] invalid user"     # about the rule... triage metadata
severity: high
classtype: brute-force
rule_gates:                    # what it matches with, in the order it runs
  - daemons:                   # syslog's matcher... a daemon gate,
      - sshd                   #   then the regexps below
      - sshd-session
  - message_regexp:
      - '^[iI](?:llegal|nvalid) user .*? from %%%%SRC%%%%'
  - ban_var:                   # who to count and ban
      - SRC
tests:                         # about the rule... proven every load
  positive:
    - message: "Jul 12 08:15:50 mail01 sshd-session[66891]: Invalid user moth3r from 216.137.179.214 port 34640"
      found: 1
      data:
        SRC: "216.137.179.214"
  negative:
    - message: "Jul 12 08:25:49 mail01 sshd-session[36748]: Accepted publickey for neti from 127.0.0.1 port 21680 ssh2: ED25519 SHA256:hjUfLIEAIR3ueytAg+XlbiVHmCQSQ6MCEdo2xYbyJ48"
      found: 0
      undefed: ["SRC"]
```

A key that is a gate is refused at the top level, and a gate is refused by a
rule of a type that does not have what it reads, both when the rule loads.
Every rule has to have a `ban_var` or a `detection_var`, and something that
makes an offense of a line or judges one. A type may be named more than once
where that means something... two `gate` entries are ANDed, and each `mark`,
`unmark`, `track`, `tracked`, and `not_tracked` is an entry of its own.

### The order it runs in

A rule's gates are of two phases, going by what they read, and the phase
decides the order before the list does.

- line :: Reads the line. Asked once per line. It may turn the line away
  outright, lay fields down, make an offense, or refuse one. `daemons`,
  `message_regexp`, `gate`, `track`, and `extract` are of it.
- offense :: Reads an offense the line made. Asked once per offense. It may
  veto the offense, name its offenders, drop some of them, or brand them.
  `country`, `ban_var`, and `mark` are of it.

**Every line gate is asked before any offense gate.** Within a phase the
gates go in the order written. Across phases, they don't. A `country` written
above the `message_regexp` is still asked after it, because the offense it
judges does not exist until the matcher makes one. The first gate to turn a
line away or veto an offense ends the walk, sparing the lookups of every gate
after it.

That walk is the middle of a longer passage. This is all of it, for one line
and one rule.

```
   a line arrives on a watched log
   │
   ├─ the watcher's parser splits it up
   │  └─▶ the line does not parse. It is counted and dropped.
   │
   ├─ the rule index picks the candidates
   │  It holds which rules a line could possibly match, keyed on the
   │  `daemons` gates leading a syslog rule's list and on the most
   │  selectively pinned `gate` field of a json one.
   │  └─▶ a rule the index does not name is never asked.
   │
   ▼
   The candidates are tried in the watcher's config order.

   ├──[ 1  THE LINE ]  the line gates, in the order written
   │  └─▶ one turns the line away, or none makes an offense.
   │      The rule stops.
   │
   ├──[ 2  THE OFFENSE ]  the offense gates, in the order written
   │  Settled along the way, the first time anything asks who the
   │  offenders are:
   │    ban_not_internal  drops a candidate that is one of your hosts
   │    usedns            drops, resolves, or keeps a hostname
   │  └─▶ a veto, or no candidate survives. The rule did not fire.
   │
   ├──[ 3  COUNTING ]
   │  ├─ mark_only / track_only stop here, leaving the line unconsumed
   │  ├─ an offender in `ignore_ips` is not counted, except into the
   │  │  shadow buckets under `observe_ignored`
   │  ├─ max_score, find_time, ban_time, and weight resolve from the
   │  │  per-rule table, the rule file (under
   │  │  `allow_per_rule_thresholds`), the watcher, the kur, then the
   │  │  global config
   │  ├─ observe mode, a detection rule, and `overlap: shadow` count into
   │  │  the shadow buckets; a rule overriding max_score or find_time
   │  │  gets a bucket of its own
   │  ├─ the hit is deposited: weight added, or a value added to a
   │  │  `distinct` set; anything older than find_time is dropped first
   │  └─ with ban_subnet_v4 or ban_subnet_v6 set, the offender's network
   │     takes the same deposit
   │
   ├──[ 4  THE VERDICT ]
   │  ├─ short of max_score: `found`, `noted` in observe mode, or
   │  │  `sighting` from a detection rule
   │  └─ at max_score: `sighted`, `alert`, or `banish`. A ban goes to the
   │     Ereshkigal manager for ban_time seconds, queued and retried every
   │     ten seconds if it is unreachable, and the bucket is cleared. A
   │     subnet that crossed on the same hit is banished as a whole CIDR.
   │
   ├──[ 5  CONSUMPTION ]  a rule that fired consumes the line
   │  ├─ overlap: first, the default. No later rule is tried.
   │  ├─ overlap: shadow. Later rules run, and any that fires is demoted.
   │  └─ overlap: all. Every later rule that fires judges for real.
   │
   ▼
   the next line
```

**A veto is not a quiet pass.** A rule turned away anywhere in phase 2 or 3
did not fire. It counts nothing, writes no EVE event, and does not consume the
line, so the line carries on to the rules listed after it. This is what lets a
legitimate Googlebot cleared by `reverse_dns` go on to match a benign rule.

**Within a phase, the order written is the order run.** Written some other
way, a rule runs some other way:

- A gate that turns the line away stops every gate below it and none above
  it. An `ignore_regexp` below a `capture_regexp` lets the context be stored
  on a line the rule was told to ignore.
- A line gate that judges reads what stands when it is asked. Above the
  matcher it judges the line's fields, and a line it refuses is not matched at
  all. Below the matcher it judges the captures. On a syslog or raw rule the
  line has no fields until a gate such as `message_json` or `mungers` lays
  some down, so a `gate`, `keywords`, or `condition` above that judges
  nothing and lets every line by.
- A `capture_regexp` or `capture` goes above the matcher and the gates that
  refuse lines. Below them, a capture line they turn away ends the walk
  before the capture is asked.
- A json `key` goes below the `gate` that judges its offense. Above it, an
  offense the gate would refuse is parked anyway, and counts when its
  capture completes it.
- `message_json` and `mungers` go above the gates that read their fields.
- `track` goes below the `tracked` and `not_tracked` that read its record.
  Above them, `not_tracked` could never hold and a `where` would judge what
  this line just wrote.
- `tracked` goes above the line gates that read what its `into` lifts. The
  offense gates always see it.
- A gate keyed by the offender goes below the `ban_var` that names one.
- `mark` and `unmark` go below the gates that are to be able to stop them. A
  `mark` above a `country` gate brands the offender the `country` gate then
  spares.
- `daemons`, `status`, `method`, `level`, `module`, `ignore_regexp`, and
  `ignore` cost least leading the list. They read nothing but the parsed line,
  so a line one of them turns away there has had nothing made for it.

## Naming the offender

Every rule names who or what an offense counts against, with one of two
gates, and never both.

- [`ban_var`](rule-gates/ban_var.md) :: The captures or fields whose value
  is the offender, counted and, at the threshold, banished. Usually `SRC`.
- [`detection_var`](rule-gates/detection_var.md) :: The captures or fields
  to count by, for a rule that only sights and banishes nobody.

A banning rule may also spare your own hosts with
[`ban_not_internal`](rule-gates/ban_not_internal.md), which drops any
candidate on the `internal` list. Where a name is a hostname rather than an
address, [usedns](usedns.md) decides what becomes of it.

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
separate counters. With every weight 1 the score is just the hit count.
`weight`, like the thresholds, is honored only under
`allow_per_rule_thresholds`.

```yaml
# one heavy hit is enough, hold the door eternally
weight: 10
max_score: 10
ban_time: 0
```

These are the numbers a rule *file* carries, the same everywhere it is used.
To tune a named rule from the config instead, differently per kur or watcher
and with no file touched, use a watcher or kur `rule_config` table... it beats
these and, unlike them, needs no `allow_per_rule_thresholds`. See
[configuration](configuration.md#per-rule-config-overrides).

### distinct... counting how many, not how often

Optional, on every rule type. Some offenses are not a matter of *how often* a
thing happened but of *how many different* things it happened to. Ten failures
against one account is someone who forgot their password; ten failures against
ten different accounts from the one source is credential stuffing, and a plain
counter cannot tell the two apart... both are ten hits.

`distinct` swaps the sum for a set. Instead of each match depositing its
`weight` into a running score, the bucket becomes the **set of distinct values**
of a named field, and the score is that set's size. The threshold is unchanged:
the rule fires when the set holds `max_score` values, and a value is forgotten
once `find_time` has passed since it was last seen.

| key | what |
| --- | --- |
| `of` | Required. The field whose distinct values are counted... a capture on syslog/raw, a flattened path on json, a parsed field on http/http_error. |
| `by` | Optional. The field the sets are keyed by. Absent, they are keyed by the offender. |

Because the score is a cardinality, `weight` has no part in it... a match either
brings a new value to the set or it does not.

**Keyed by the offender** ... "how many different X from one source". The set
belongs to the address, and crossing banishes it and clears the set, just as a
counter would:

```yaml
# ten accounts tried from one source... credential stuffing, not a typo
distinct:
  of: USER
max_score: 10
find_time: 600
rule_gates:
  - ban_var:
      - SRC
```

**Keyed by something else** ... "how many different X against one Y", where Y is
not the thing to punish. Naming `by` decouples the counting from the banishing:

```yaml
# one account hit from five different sources... a distributed spray, which
# per-source counting can never see, each source alone staying under threshold
distinct:
  of: SRC
  by: USER
max_score: 5
find_time: 3600
rule_gates:
  - ban_var:
      - SRC
```

The set here is keyed by the account, so nothing is ever keyed by an address and
the account is never what gets banished. The offender that *tips the account
over* is banished instead, and the set is deliberately **not** cleared... so
every further source arriving against that same account is caught too, for as
long as the account stays over the threshold. Contrast the offender-keyed form,
which clears on crossing like an ordinary counter.

This is the shape [marks](#marks-cross-rule-state-keyed-by-anything) reach with
a `mark_only` brander and a `value_not` reader (the `syslog/sshd-mark-users` and
`syslog/sshd-spray` pair). `distinct` says it in one rule when the question is
purely "how many", where the marks pair earns its keep when the answer needs a
brand other rules can also read.

It is not only an auth-log key. On the http types the offender is the parsed
`client`/`host` and the path is already parsed, so the shipped `http/path-scan`
is little more than the few lines that matter... a client fetching thirty
different paths that do not exist is mapping your install, whatever it makes of
any one of them:

```yaml
# a scanner by breadth rather than by signature... no path list to keep current
distinct:
  of: path
max_score: 30
find_time: 600
rule_gates:
  - status:
      - 404
  - ban_var: [ host ]
```

That complements `http/botsearch`, which knows a list of paths worth alarming
at... this catches the scanner whose list you have never seen. Counting paths
is also what keeps it quiet with no ignore list: a browser 404ing on
favicon.ico, robots.txt and an apple-touch icon holds at three paths however
often it retries them. `path` drops the method, so a scanner alternating GET
and HEAD counts one path... the query string does survive it, so an
application that 404s with varying parameters counts each as its own, and
wants a higher score rather than a wider gate.

The shipped `syslog/sshd-stuffing` is the offender-keyed form worked through: the
same failures `syslog/sshd` reads, the account captured instead of stepped over,
and `distinct: {of: USER}` so the score is how many accounts a source has failed
against. It matches the same lines as `syslog/sshd`, so under the default
[`overlap`](configuration.md) of `first` whichever is listed earlier eats the
line and the other never counts... two rules counting different things off one
line want `overlap = "all"`.

Two practical notes. A result whose grouping key is missing or empty is skipped
rather than counted, since there is nothing to file it under. And each set is
bounded per key... expired values are pruned first and the oldest evicted after
that, so a source deliberately flooding distinct values cannot grow the galla
without limit.

`distinct` composes with the rest as you would expect: it rides the shadow
buckets for a [detection rule](rule-gates/detection_var.md) and surfaces as `sighted`, holds
back as an `alert` under [`eve_only`](#eve_only), and the sets survive a restart
on the state tablets, keyed exactly as they were counted.

### eve_line

Optional, on every rule type, true by default. False leaves the line a
match was found in out of the rule's EVE events... the `raw` line, the
`parsed` one, and the line of each stage of a staged rule. What the rule
found, and the rule's own fields, are still there.

It is for a rule that hashes what it found with a
[`digest`](rule-gates/digest.md) gate. Hashing the name
keeps it out of the tablets, but the line it was found in still has it,
and an event carries the line.

### eve_only

Optional, on every rule type, and also settable at the global, kur, and
watcher level (see [configuration](configuration.md)). Puts the rule in
**observe mode**: its matches are written to EVE but never count toward a
real ban. A would-be banish surfaces as an `alert` event and each match as
`noted` rather than `found`, so a new rule can be stood up and watched
before it is trusted to act... CrowdSec's simulation, on a rule. The rule's
own `eve_only` layers over the watcher-resolved one, so a deployment can be
set observe at any level and a trusted rule opt back in with
`eve_only: false`. The gates all still run; observe mode changes the
consequence, not the matching. Unlike the thresholds and `weight`, it is
honored whether or not `allow_per_rule_thresholds` is on.

Observe mode differs from a [detection rule](rule-gates/detection_var.md): observe mode is
a would-be ban held back and shown as an `alert`, still keyed to an offender
IP; a detection rule never bans at all and counts any subject, surfacing as
`sighting`/`sighted`. See [eve](eve.md) for the event shapes.

## Triage metadata

### msg

Optional, on every rule type. A short human-readable signature naming what
the rule detects, the Sagan/Suricata `msg` convention... a `[TAG]
description` line like `[SSHD] authentication failure` or `[SURICATA]
Attempted Administrator Privilege Gain`. It is written to every EVE event
the rule produces as the top-level `.msg` field (Suricata's
`alert.signature`, promoted... see [eve](eve.md)), so a SOC
analyst or a jq one-liner reads what tripped without decoding the raw line.
When a rule sets none, `.msg` falls back to the rule's name (`syslog/sshd`),
so it is always present. Inert to matching.

### severity / classtype / references / attack / rev

Optional triage metadata, on every rule type, all inert to matching and all
written to EVE beside `msg` when set (see [eve](eve.md)):

- `severity` — one of `info`/`low`/`medium`/`high`/`critical`. Emitted as
  `.severity`. When a rule sets none, the config's `default_severity`
  (global/kur/watcher, see [configuration](configuration.md)) fills in; absent
  that too, the field is omitted.
- `classtype` — the rule's class, the short Snort/Sagan/Suricata classtype slug
  (e.g. `brute-force`, `web-application-attack`, `trojan-activity`). Emitted as
  `.category`, in words rather than as the slug, the way Snort and Suricata keep
  the slug in the rule and the description in their `classification.config`...
  `misc-attack` reads downstream as `Misc Attack`. Free-form; the shipped
  suricata rules carry their Suricata class here, and a classtype Baphomet's
  table does not know becomes its slug title-cased.
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
stable positive integer hashed from the rule name. See [eve](eve.md).

### src_ip_var / dest_ip_var / src_port_var / dest_port_var / user_var

Optional, on every rule type, inert to matching. Each names the found var
holding one of the fields worth reading at a glance, whose value is lifted to
a top-level EVE field so a consumer gets it without digging through `found`
(see [eve](eve.md)):

- `src_ip_var` — the var promoted to `.src_ip`. Defaults to the found var
  literally named `src_ip`.
- `dest_ip_var` — the var promoted to `.dest_ip`. Defaults to `dest_ip`.
- `src_port_var` — the var promoted to `.src_port`. Defaults to `src_port`.
- `dest_port_var` — the var promoted to `.dest_port`. Defaults to `dest_port`.
- `user_var` — the var promoted to `.user`, the account the line was about.
  Defaults to `user`.

Point any of them at whatever a schema uses, `flow.src_ip` for a Suricata eve
line say, since `found` flattens nesting to dotted paths. All five are always
emitted, `null` when the named var is absent, so the fields can be leaned on.
This only shapes the EVE event; who gets banished is still
[`ban_var`](rule-gates/ban_var.md) / [`ban_not_internal`](rule-gates/ban_not_internal.md).

The defaults suit the JSON schemas and the http access parse, which name these
fields exactly so already. A regexp rule capturing them under its own names
has to say which is which, the way the shipped syslog rules pair a
`(?<USER>...)` capture with `user_var: USER`.

A [munger](#enriching-a-match-mungers) field is as good a target as a capture,
and often the only one there is. The shipped sshd rules promote their own `SRC`
capture as `.src_ip`, since it matches lines the munger does not read, but take
`.src_port` and `.user` from `ssh_src_port` / `ssh_user`, which no sshd regexp
holds. Where both sources exist, prefer whichever covers more of the rule's
lines... a var names one field, not a fallback chain, so a var pointed at the
thinner source reads as absent on every line the other would have covered.

A port is written as a number wherever it reads as one, so a native JSON
integer and a regexp capture's `"22"` land in the field as the one type... a
port stored as a string loses every range query over it. A var pointed at
something that is not a port is written as it is rather than dropped, so the
mistake surfaces.

## Tests

Every rule carries its own tests and they run at every load... a rule that
fails its own refuses to load, so `baphomet start` and `check_rules` are
the proof, not a hope. This section is both the reference and the writing
guide: [the shape](#the-shape) of a test entry, then how to write them for
[plain matchers](#writing-them-the-matcher-and-its-near-misses), for
[marks and gated rules](#proving-brands-and-gates), for
[order and time](#proving-order-and-time), and for
[lookup-gated rules](#proving-lookups). The working loop lives under
[writing one](#writing-one)... `test_line` to poke a draft,
`check_rules` to run the tests.

### The shape

Positive tests are lines the rule must match, negative tests are lines it
must not, and [injection](#injection-tests-who-picks-the-offender) tests are
forged lines it must still aim right on. Each is a hash...

| key | what |
| --- | --- |
| `message` | The full log line, as it would appear in the log. Required (or `messages`, below). |
| `parser` | The parser to parse it with. Defaults per type (`bsd_syslog` for syslog, `http_access` for http, and so on)... a stricter parser is better inside a rule's own tests, and one may be named per test. |
| `found` | Whether the rule should match, `1` or `0`. Defaults to 1 for positive and injection tests, 0 for negative. |
| `data` | For positive tests, capture names to the values they should have captured. **Required** on a injection test, where it is the assertion. |
| `undefed` | For negative tests, capture names that should not be defined. |
| `marks_before` | Brands seeded into the test's own throwaway mark store before the lines run, each `{name, key, value?, set?, ttl?, hosts?}`... `key` a string or, for a `vars` compound, a list joined as the store joins. What other rules would have branded, so a [mark](#marks-cross-rule-state-keyed-by-anything)-gated rule proves its gate from its own file. `ttl` defaults 3600, `set` to the clock base, and `hosts`, how many hosts set the brand, to 1. |
| `marks_expected` | Brands the store must hold (or, under `absent: 1`, lack) after the lines run, each `{name, key, value?, absent?}`... what proves a rule's own `mark`/`unmark` did what it claims. |
| `dns` | A fixture resolver for the [reverse_dns](rule-gates/reverse_dns.md) and [dnsbl](rule-gates/dnsbl.md) gates... `ptr` maps an address to its names, `forward` a name to its addresses, and `dnsbl` a zone to a map of address to what the zone answers, each answer a list, `nxdomain` (authoritative absence), or `servfail` (a failure). Anything unfixtured answers servfail, fail-closed as an unanswerable question is live. With the fixture present the gate runs exactly as in the galla, offender pass and all; without it the gate is skipped, as it always was. |
| `geo` | A fixture locator for the [country](rule-gates/country.md), [asn](rule-gates/asn.md), and [travel](rule-gates/travel.md) gates... `countries` maps an address to its ISO code, `asns` one to its AS number or a `{number, org}` hash, and `locations` one to a `[ latitude, longitude ]` pair or a `{lat, lon, radius}` hash (each `unknown` for one the database would not place), and `lists` and `asn_lists` name the sets a `%%%country_codes{name}%%%` and a `%%%asn_lists{name}%%%` token resolve against, standing in for the config. Anything unfixtured is unplaceable, fail-closed as it is live. Present, the gate runs as in the galla; absent, it is skipped. |
| `pressure` | A fixture for the [pressure](rule-gates/pressure.md) gate... the count of matched lines it reads, however far back it asks. Present, the gate runs as in the galla; absent, it is skipped. |
| `scores` | A fixture for the [scored](rule-gates/scored.md) gate... a map of address to what its live hits add up to, standing in for the galla's counts. Present, the gate runs as in the galla; absent, it is skipped. |
| `uptime` | A fixture for the [startup](rule-gates/startup.md) gate... how many seconds the galla has been up. Present, the gate runs as in the galla; absent, it is skipped. |
| `rules_hit` | A fixture for the [breadth](rule-gates/breadth.md) gate... a map of address to the rules that have hits against it, standing in for the galla's counts. Present, the gate runs as in the galla; absent, it is skipped. |
| `digest_key` | The key a [digest](rule-gates/digest.md) gate hashes under, standing in for the config's. Present, the gate runs as in the galla; absent, it is skipped. |
| `accounts` | A fixture for the [account](rule-gates/account.md) gate... the list of names that are accounts, or a hash of name to `{uid, shell, groups}`, every other name being nobody's. Present, the gate runs as in the galla; absent, it is skipped. |

A test may use `messages`, an array of lines fed through in order, instead of
a single `message`, with `found` the expected count across the sequence...
this is how [correlation](#syslog-rules) rules, whose offense and address
span lines, are tested. `data` then asserts against the last result found.
The whole `test_parser` key sets a rule-wide default
parser for its tests.

Each test entry runs the galla's own order per line... parse, then the
rule's gates in the order it wrote them, the mark ones against a throwaway
store... so `found` counts what would really have fired, a gate veto and
all. Time inside a test is a virtual clock, base `1000000000`,
threading through matching (correlation windows, staged `within`) and the
mark store alike. A `messages` entry may be a hash instead of a bare line
to steer and probe it mid-run:

| key | what |
| --- | --- |
| `message` | The line itself. Required in the hash form. |
| `advance` / `at` | Move the clock forward by seconds, or pin it absolutely, before the line runs... ttl expiry and sequence ordering become provable. |
| `found_after` | The cumulative `found` count expected once this line has run. |
| `marks_after` | A `marks_expected`-shaped assertion ran at this point rather than the end. |

An unknown key anywhere in a test entry is itself a failure, so a typo'd
assertion can not silently become one that never runs. One bound: a gate is
judged here only when the test has what it judges over. The mark gates
always do, the throwaway store being there for every entry. `reverse_dns`
and `dnsbl` do with a `dns` fixture, `country` and `asn` with a `geo` one,
and `account` with an `accounts` one, and each is skipped with out it.
`travel` does with the `locations` of a `geo` one and `pressure` with a
`pressure` one. `limit`, `after`, `sum`, `beacon`, `sample`, and
`concurrent` need none, their windows being their own, and every entry
starts with none open. `forgive` has no fixture, the
counts it takes hits back out of being the galla's, so it is proven
galla-side only. `namtar_list` and `active_time` have no fixture, their
lists and windows being config a rule file has none of, so those two stay
proven galla-side only (see each gate's page). `ban_not_internal` has none
either, your own hosts being config as well, so it drops nobody in a test.

### Injection tests... who picks the offender

A third section, `tests.injection`, holds lines carrying a **forged copy of the
field the rule aims by**, and asserts the rule still aims at the real one. It is
the same shape as a positive test with two differences: `found` defaults to 1 and
`data` is **required**, since naming the offender is the whole assertion.

The thing being defended against is that most of what a daemon logs beside the
address is chosen by whoever connected. An account name may hold spaces, commas,
quotes, or a `>`; a mail subject or a user agent holds anything at all. So a
pattern that reaches over such a field to find the address can be steered by it.
Log in to a FortiGate as `admin srcip=8.8.8.8` and a rule scanning for the first
`srcip=` bans 8.8.8.8 instead of you... an attacker choosing who gets banned,
which is a denial of service against whoever they name.

```yaml
tests:
  injection:
    # the account name carries a second "from <addr>" ahead of the real one
    - message: "Jul 12 08:15:50 mail01 sshd[2278]: Invalid user moth3r from 203.0.113.222 from 216.137.179.214 port 34640"
      data:
        SRC: "216.137.179.214"
```

**A rule of the risky shape is warned about.** When a pattern puts a lazy
unbounded wildcard between its head and its offender token and nothing anchors
the token, whichever candidate appears *first* is the one banned... so if the
line lets a client write ahead of the real field, the client chooses. The loader
spots that shape, and where the rule carries no `tests.injection` to answer it
says so, naming the pattern. Greedy is not asked about: it takes the *last*
candidate, and a forgery can only be planted ahead of what the daemon writes, so
the ordering is itself the defence.

It is a **warning and not a failure**, and the rule loads regardless. The shape
does not make a rule exploitable... that turns on what feeds the log, which no
reading of the pattern settles. The two `raw/palo-alto-*` rules are the same
shape with opposite answers: the auth failures write the account *before* the
address, so they are anchored, while the SSL-VPN and GlobalProtect events write
it *after*, where lazy is already correct and greedy would be the bug. Only a
test can carry that, so the warning points at a question rather than declaring a
defect.

If the shape is safe in your log, answering with the same test is still worth the
one entry... it records *why* it is safe, and stops a later tidy-up from quietly
reversing the reasoning. `check_rules` counts the warnings in its summary and
exits zero on them.

Three ways to answer the demand, all of them real fixes seen in the shipped set:

- **Anchor past the token** :: require the tail the daemon itself appends, so a
  forged copy can not satisfy it. `syslog/sshd` requires the `port`/`preauth`
  run, `syslog/dovecot` the `, lip=` that always trails the address,
  `raw/palo-alto-auth-bruteforce` the closing quote of the description field.
- **Go greedy** :: where the real field is written last, take the last
  candidate. The `raw/citrix-*` rules do this, their format being too irregular
  to decompose.
- **Stop scanning** :: read the line into fields with a
  [munger](#a-munger-as-the-matcher) and name one, so there is no wildcard to
  steer. The `raw/fortinet-*` and `raw/sonicwall-*` families do this.

One trap worth naming, because it looks like a fix and is not: tightening the
field run until the forged line stops matching *at all*. That trades a wrong ban
for no ban, so an attacker who plants the right bytes goes uncounted instead of
misaimed... quieter, and worse. `found` defaulting to 1 is what catches it; an
injection test insists the line still matches and merely aims right.

### Writing them... the matcher and its near-misses

Start every test from a real line... your own logs, the daemon's
documentation, or the corpus the rule was ported from, with a full
collector-shaped line including whatever syslog header the parser expects.
A line you invented to fit the regexp proves the regexp agrees with
itself, nothing more.

The discipline that makes a test suite worth carrying:

- **One positive per regexp, at least.** A rule with five `message_regexp`
  entries and one positive test has four regexps nothing proves. The
  shipped `syslog/sshd` carries a positive per pattern for exactly this
  reason.
- **Assert the captures, not just the match.** A positive without a
  `data:` block proves the line matched *somewhere*... `data: { SRC: ... }`
  proves the offender came out right, which is what the ban aims with. A
  regexp edit that still matches but grabs the wrong field is invisible to
  `found` and loud under `data`.
- **The best negatives are near-misses.** A blank line proves little.
  Lines that look temptingly close and must not match are what fence a
  regexp in: the *successful* login beside the failures, the same message
  from the wrong daemon, the `FAIL LOGIN` beside the `OK LOGIN`. Give
  negatives `undefed: ["SRC"]` so a half-match cannot leak a capture.
- **Prefer the strict parser.** `test_parser` (or a per-test `parser`)
  pinned to the strictest parser that fits keeps a test line honest about
  its header shape rather than sliding through a permissive fallback.

```yaml
tests:
  positive:
    - message: "Jul 12 08:15:50 mail01 sshd[2278]: Failed password for invalid user admin from 192.0.2.7 port 4711 ssh2"
      found: 1
      data:
        SRC: "192.0.2.7"
  negative:
    # the success right beside the failures... the classic near-miss
    - message: "Jul 12 08:25:49 mail01 sshd[36748]: Accepted publickey for neti from 192.0.2.7 port 21680 ssh2"
      found: 0
      undefed: ["SRC"]
    # right message, wrong daemon
    - message: "Jul 12 08:25:49 mail01 cron[1234]: Failed password for invalid user admin from 192.0.2.7 port 4711 ssh2"
      found: 0
      undefed: ["SRC"]
```

### Proving brands and gates

A rule that sets marks proves them with `marks_expected`... the brand, the
key it landed on, and any harvested value. This is what catches a regexp
edit that shifts which capture feeds the brand:

```yaml
# syslog/sshd-mark-users... brand the account with the source that hit it
tests:
  positive:
    - message: "Jul 12 08:15:50 mail01 sshd[66891]: Invalid user moth3r from 216.137.179.214 port 34640"
      found: 1
      marks_expected:
        - name: sshd-account-src
          key: moth3r
          value: "216.137.179.214"
```

A rule that *reads* marks needs its gate armed, and no sequence of its own
messages can do that... the brands come from other rules. `marks_before`
seeds them, and the discipline is to prove the gate **both ways**: the
seeded positive fires, and the same matching line unseeded is a negative.
Without that negative, a typo'd brand name in the gate passes every test
and silently never fires in the field... the exact failure this machinery
exists to end.

```yaml
# a reader... success from a source holding any standard brand
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Accepted \S+ for \S+ from %%%%SRC%%%%'
  - marked:
      names: [ brute_force, recon, exploit_attempt, honeypot ]
      var: SRC
  - detection_var: [ SRC ]
tests:
  positive:
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for root from 192.0.2.7 port 4711 ssh2"
      marks_before:
        - name: honeypot          # any listed brand... vary it across tests
          key: "192.0.2.7"
      found: 1
  negative:
    # the same line, no seed... the gate must veto
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for root from 192.0.2.7 port 4711 ssh2"
      found: 0
```

A gate naming no var keys on the offender, and is proved the same way...
seed the brand on the address the line would banish, and leave it off for
the negative.

Value compares prove both ways too, by seeding the stored value: the
shipped `syslog/sshd-spray` (gate `value_not: SRC`) seeds the account's
brand with a *different* source for its positive, and with the *same*
source for a negative... the second attacker fires, the established
source is spared. Note that a gate-vetoed line is not a match at all...
its result is dropped whole, so a gated negative asserts `found: 0`
without `undefed` (the captures existed, the gate discarded them). A
`mark_only` rule still counts its firings toward `found`... what it never
does is count toward a ban, and `marks_expected` is what proves its
branding.

Tracked records get the same treatment. `tracked_before` seeds one, each
entry a `name`, a `key` (a string, or a list for a compound key), the
`fields` the record holds, and an optional `ttl`. `tracked_expected`
asserts after the run, either that a record is live and holds the named
fields or, under `absent`, that there is none.

```yaml
tests:
  positive:
    - message: "Jan  2 04:00:00 mx1 postfix/local[222]: 1C36D185729: to=<victim@example.org>, status=bounced"
      tracked_before:
        - name: mail-queue
          key: 1C36D185729
          fields: { postfix_client_ip: "203.0.113.9", postfix_sasl_username: alice }
      data:
        postfix_client_ip: "203.0.113.9"   # lifted by into, never on this line
      tracked_expected:
        - name: mail-queue
          key: 1C36D185729
          fields: { postfix_status: bounced }
  negative:
    # the same line unseeded... a where over no history fails closed
    - message: "Jan  2 04:00:00 mx1 postfix/local[222]: 1C36D185729: to=<victim@example.org>, status=bounced"
      found: 0
```

The both-ways discipline is the same as for marks, and for the same reason.
Better still, where the rule file owns both halves, drop the seed and prove
it for real: a multiline `messages:` test walks the harvest line and the
reading line through one scope, so the record the gate reads is one the rule
actually built. `tracked_after` asserts mid-run beside `marks_after`.

### Proving order and time

The `messages` form feeds lines in order through one throwaway scope, and
the hash entry form steers the clock and asserts mid-run... which is what
correlation windows, staged `within` bounds, mark ttls, and `sequence`
ordering all need, none of them being provable against a wall clock.

```yaml
# a brand outlives its ttl... the clock advanced past it, the gate vetoes
tests:
  negative:
    - marks_before:
        - name: brute_force
          key: "192.0.2.9"
          ttl: 21600
      messages:
        - message: "Jul 12 14:25:49 mail01 sshd[2278]: Accepted password for root from 192.0.2.9 port 4711 ssh2"
          advance: 21601
      found: 0
```

A `sequence` gate orders by the brands' first-seen `set` times, so its
tests seed them explicitly... the shipped `json/suricata-escalation`
proves scanned-then-exploited fires and, with the same two seeds and the
`set:` times swapped, that exploited-then-scanned does not. `found_after`
and `marks_after` assert between lines... a staged rule proving its third
line is the one that fires says `found_after: 0` on the first two and
`found_after: 1` on the last, rather than only a final count.

### Proving lookups

A `reverse_dns`-gated rule carries `dns` fixtures... maps standing in for
the resolver, so the judgment runs cold exactly as it would live. The
shipped `http/fakegooglebot` is the worked example, one test per behavior
the gate exists for:

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

Cover the judgment's whole ladder the way that rule does: the confirmed
hit, the authoritative absence (`nxdomain`), the spoof that fails forward
confirmation, the legitimate name spared, and the outage. Anything
unfixtured answers servfail, so a fixture only needs the names the test
actually walks.

A `country`-gated rule carries `geo` fixtures the same way... a
`countries` map placing each address and a `lists` map standing in for
the config's `country_codes`, so an "outside the home countries" rule
proves its judgment cold. The shipped `syslog/sshd-foreign-login` and its
mail siblings are the worked example:

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Accepted \S+ for \S+ from %%%%SRC%%%%'
  - country:
      isnot:
        - "%%%country_codes{home}%%%"
      vars:
        - SRC
  - detection_var: [ SRC ]
tests:
  positive:
    # a login from abroad... the isnot gate lets it count
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for root from 203.0.113.9 port 4711 ssh2"
      geo:
        countries:
          "203.0.113.9": NL
        lists:
          home: [ US ]
      found: 1
  negative:
    # at home, spared... and an unplaceable address fails closed, so a
    # database gap misses rather than false-alarms
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for root from 192.0.2.66 port 4711 ssh2"
      geo:
        countries:
          "192.0.2.66": unknown
        lists:
          home: [ US ]
      found: 0
```

Prove both the home and the away, and the unplaceable... the last is the
one that catches a rule mistakenly written to fire on database gaps.

The other lookups are proved the same way. A `dnsbl` gate reads the `dnsbl`
map of the `dns` fixture, a zone to what it answers about each address. An
`asn` gate reads the `asns` and `asn_lists` of the `geo` fixture. An
`account` gate reads an `accounts` list.

```yaml
tests:
  positive:
    # on a blocklist, on a hosting network, and a name that is nobody's
    - message: "Jul 12 08:25:49 mail01 sshd[2278]: Failed password for oracle from 203.0.113.9 port 4711 ssh2"
      dns:
        dnsbl:
          bl.example.org:
            "203.0.113.9": [ "127.0.0.2" ]
      geo:
        asns:
          "203.0.113.9": { number: 64496, org: "Example Hosting" }
        asn_lists:
          hosting: [ 64496 ]
      accounts: [ neti ]
      found: 1
```

A fixture only stands in for what it names. A `dns` fixture with only a
`dnsbl` map leaves a `reverse_dns` gate skipped, and a `geo` fixture with
only `asns` leaves a `country` gate skipped, so a rule with both proves one
at a time.

A `travel` gate is placed by the `locations` of the `geo` fixture, and its
sightings are brands, so the test's own mark store holds them. A `messages`
test with an `advance` walks an account from one place to another, and
`marks_before` stands in for a sighting some earlier line left:

```yaml
tests:
  positive:
    # New York an hour after London
    - messages:
        - "Jul 12 08:25:49 mail01 sshd[2278]: Accepted password for neti from 198.51.100.5 port 4711 ssh2"
        - message: "Jul 12 09:25:49 mail01 sshd[2279]: Accepted password for neti from 203.0.113.9 port 4711 ssh2"
          advance: 3600
      geo:
        locations:
          "198.51.100.5": [ 51.5072, -0.1276 ]
          "203.0.113.9": { lat: 40.7128, lon: -74.0060, radius: 20 }
      found: 1
```

## Refining a match... the gates

After a rule matches, a set of optional gates can still drop the count. They
are the shared vocabulary layered over every type's matcher... a match that
passes the matcher but fails one of them is not an offense. An offender one
of them vetoes is neither counted nor branded... a `mark` written below it
skips that offender too, since a non-offense earns no brand. And a rule
whose gates veto every offender did not fire at all, so the line falls
through to the rules after it...
[a veto is not a quiet pass](#the-order-it-runs-in).

These gates are universal, but the ones a rule matches with are not... which
is the whole shape of the types. The full support matrix, a ✓ where a type
accepts a gate or key:

| gate or key | syslog | raw | http | http_error | json |
| --- | :---: | :---: | :---: | :---: | :---: |
| `daemons` | ✓ | — | — | — | — |
| `message_regexp` | ✓ | ✓ | — | ✓ | — |
| `ignore_regexp` | ✓ | ✓ | — | ✓ | — |
| `capture_regexp` / `capture`+`key` (correlation) | ✓ | ✓ | — | — | ✓ |
| `stages` (staged sequences) | ✓ | ✓ | — | — | — |
| `message_json` | ✓ | — | — | — | — |
| `status` / `method` | — | — | ✓ | — | — |
| `level` / `module` | — | — | — | ✓ | — |
| `match` / `ignore` | — | — | ✓ | — | ✓ |
| `ban_var` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ban_not_internal` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `detection_var` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `gate` / `condition` / `keywords` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `mark` / `unmark` / `mark_only` / `forgive` / `weigh` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `pressure` / `epoch` / `fresh` / `startup` / `extract` / `normalize` / `digest` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `marked` / `not_marked` / `sequence` / `country` / `asn` / `namtar_list` / `active_time` / `reverse_dns` / `dnsbl` / `account` / `limit` / `after` / `sum` / `beacon` / `sample` / `travel` / `novel` / `banished` / `address` / `network` / `forwarded` / `concurrent` / `breadth` / `scored` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `max_score` / `find_time` / `ban_time` / `weight` / `eve_only` / `eve_line` / `distinct` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `msg` / `severity` / `classtype` / `references` / `attack` / `rev` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `src_ip_var` / `dest_ip_var` / `src_port_var` / `dest_port_var` / `user_var` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `tests` / `test_parser` | ✓ | ✓ | ✓ | ✓ | ✓ |

Everything from `ban_var` down is universal... any rule whose ban target is an
IP can spare your own hosts. The one asymmetry among the universal rows is not
*whether* a gate runs but *what it can key on*: a gate naming a
`field`/`var`/`vars` resolves it against the matched line's data... regexp
captures on syslog, raw, and json, flattened dotted paths on json. The http
and http_error types expose no arbitrary captures, so on them a keyed gate
reaches the parsed fields, not a custom capture.

### gate / selections / condition / keywords

The predicate layer, a boolean refinement over a line's fields or captures,
ANDed with the type's own matching. Every type has it, in three forms:

- [`gate`](rule-gates/gate.md) :: A flat list of field tests, ANDed.
- [`keywords`](rule-gates/keywords.md) :: A string searched for across a
  line's fields.
- [`condition`](rule-gates/condition.md) :: Named `selections` folded into
  one boolean judgment.

What a `field` names depends on the type... a regexp capture (syslog/raw), a
flattened dotted path (json), a parsed access/error-log field (http,
http_error). Three names are reserved:

- `%%%ANY%%%` :: Fans the predicate over every field value and, on syslog
      and raw, the message.
- `%%%ANY:<prefix>%%%` :: Fans it over just the fields at or under `prefix`.
- `MESSAGE` :: On syslog and raw, the whole message.

### Every gate

Each gate has a page of its own under [rule-gates](rule-gates/), with what
it is told, where it goes, what it refuses, and how to prove it.

**Matching the line**, the line phase

- [`daemons`](rule-gates/daemons.md) :: Which daemons a syslog rule reads.
- [`status`](rule-gates/status.md) :: Which HTTP statuses a http rule reads.
- [`method`](rule-gates/method.md) :: Which HTTP methods a http rule reads.
- [`level`](rule-gates/level.md) :: Which log levels a http_error rule reads.
- [`module`](rule-gates/module.md) :: Which apache module logged it.
- [`message_regexp`](rule-gates/message_regexp.md) :: The offense, out of a
  line's message.
- [`match`](rule-gates/match.md) :: The offense, out of a line's fields.
- [`ignore_regexp`](rule-gates/ignore_regexp.md) :: A message that is never
  an offense.
- [`ignore`](rule-gates/ignore.md) :: A field that is never an offense.
- [`stages`](rule-gates/stages.md) :: An ordered sequence with in one rule.
- [`message_json`](rule-gates/message_json.md) :: A JSON message read into
  fields.
- [`mungers`](rule-gates/mungers.md) :: A line read into fields by
  Log-Munger.
- [`capture_regexp`](rule-gates/capture_regexp.md) :: The address, from a
  line that is not the offense.
- [`capture`](rule-gates/capture.md) :: The address, from a json record that
  is not the offense.
- [`key`](rule-gates/key.md) :: A json offense resolved through its context.

**Judging and reshaping the line**, the line phase

- [`gate`](rule-gates/gate.md) :: A flat list of field tests.
- [`keywords`](rule-gates/keywords.md) :: A string searched for across a
  line's fields.
- [`condition`](rule-gates/condition.md) :: Named selections folded into one
  judgment.
- [`extract`](rule-gates/extract.md) :: A capture out of any field.
- [`normalize`](rule-gates/normalize.md) :: The path a server would make of
  it.
- [`digest`](rule-gates/digest.md) :: A hash in place of a name.
- [`epoch`](rule-gates/epoch.md) :: A timestamp as seconds.
- [`fresh`](rule-gates/fresh.md) :: Old news.
- [`startup`](rule-gates/startup.md) :: Only just started.
- [`pressure`](rule-gates/pressure.md) :: A rule for when it is under
  attack.
- [`track`](rule-gates/track.md) :: Harvesting a line into a record.
- [`tracked`](rule-gates/tracked.md) :: Judging a line by the record of its
  transaction.
- [`not_tracked`](rule-gates/not_tracked.md) :: A line with no record of
  its transaction.

**Naming the offender**, the offense phase

- [`ban_var`](rule-gates/ban_var.md) :: Who the offense is counted against.
- [`detection_var`](rule-gates/detection_var.md) :: Counting by a thing,
  banishing nobody.
- [`ban_not_internal`](rule-gates/ban_not_internal.md) :: Sparing your own
  hosts.

**Brands**, the offense phase

- [`mark`](rule-gates/mark.md) :: Branding what an offense names.
- [`unmark`](rule-gates/unmark.md) :: Lifting a brand.
- [`marked`](rule-gates/marked.md) :: Only what already has a brand.
- [`not_marked`](rule-gates/not_marked.md) :: Sparing what already has a
  brand.
- [`sequence`](rule-gates/sequence.md) :: Brands set in order.
- [`forgive`](rule-gates/forgive.md) :: A login that worked clears the
  failures.

**What an address is**, the offense phase

- [`country`](rule-gates/country.md) :: Narrowing an offense by geography.
- [`asn`](rule-gates/asn.md) :: Narrowing an offense by network.
- [`network`](rule-gates/network.md) :: The network as a found var.
- [`address`](rule-gates/address.md) :: What kind of address it is.
- [`namtar_list`](rule-gates/namtar_list.md) :: Only the already-condemned.
- [`reverse_dns`](rule-gates/reverse_dns.md) :: The client is who its
  address says.
- [`dnsbl`](rule-gates/dnsbl.md) :: What a blocklist says of an address.
- [`forwarded`](rule-gates/forwarded.md) :: The client behind a proxy.
- [`banished`](rule-gates/banished.md) :: What an address has already been
  banished for.

**Counting and history**, the offense phase

- [`account`](rule-gates/account.md) :: A real account or a guess.
- [`active_time`](rule-gates/active_time.md) :: Only in, or out of, certain
  hours.
- [`limit`](rule-gates/limit.md) :: Only so many of a key.
- [`after`](rule-gates/after.md) :: Only once a key has been seen enough.
- [`sum`](rule-gates/sum.md) :: How much, not how often.
- [`beacon`](rule-gates/beacon.md) :: Like clockwork.
- [`sample`](rule-gates/sample.md) :: One in so many.
- [`concurrent`](rule-gates/concurrent.md) :: Too many at once.
- [`travel`](rule-gates/travel.md) :: Further than it could have gone.
- [`novel`](rule-gates/novel.md) :: A value a key has not had before.
- [`breadth`](rule-gates/breadth.md) :: Counted by many rules.
- [`scored`](rule-gates/scored.md) :: Counted for enough.
- [`weigh`](rule-gates/weigh.md) :: Worth more, or less.

**Every entry has to hold.** The first that does not ends the asking, so
among the gates of a phase the order written decides only what a veto
spares... put the gate cheapest to ask, or likeliest to veto, first, and one
that goes to DNS last. A type may be named more than once, which is how one
rule gates the country of both a captured address and the offender.

**What an offense gate keys on decides what it is asked of.** One naming a
`var` or `vars` reads a found value, resolved like `ban_var`, so JSON dotted
paths work. It is asked once for the whole result, needs no offender, and a
veto drops the result. One naming neither keys on the offender and is asked
once per candidate, filtering which of them count, like `ban_not_internal`,
so it has to be written below the `ban_var` that names them. `active_time`
is the exception... with no var it keys on the clock, so it is always asked
once for the result. `account`, `limit`, `after`, `sum`, `beacon`, `sample`,
`concurrent`, `travel`, `novel`, and `weigh` only ever key on a found
value, or on none, so they are asked once for the result too.

### What every gate is refused for

Each gate's own page lists what that gate refuses. These are refused of
every gate, and all of them die when the rule loads, except the last, which
dies when a galla binds the rule to a watcher.

- not a hash of one key :: A `rule_gates` entry has to be a hash whose one
  key is the gate type. An empty or missing list is refused too.
- an unknown type :: The key names no class under `App::Baphomet::Gate`.
- an unknown or ill-formed option :: A key the gate does not take, one it
  needs and lacks, a value of the wrong kind, or two options that exclude
  each other.
- the wrong rule type :: A gate that reads what only some types have, such
  as `daemons` or `status`, is refused on the others.
- the offender before it is named :: A gate keyed by the offender with no
  `ban_var` above it, or on a detection rule, which has no offender. `mark`
  and `unmark` are the exception, loading on a detection rule and branding
  nobody.
- naming the offender twice :: A second `ban_var` or `detection_var`, or
  one of each.
- a second of a single gate :: A type a rule can have only one of, named
  again.
- what the watcher lacks :: A gate needing something of its watcher, such
  as the GeoIP database for `country` or a named list or window, that the
  watcher does not have.
### marks... cross-rule state, keyed by anything

Correlation (below) ties lines together with in one rule. Marks tie rules
together... a mark is a named, expiring brand a rule leaves on a key that a
later rule, in the same or another watcher of that galla, can gate on. It is
how one rule remembers something for another, Sagan's xbits and flexbits. The
mark gates are legal on every rule type.

The key defaults to the offender IP, but any capture or field of the matched
line can be the key (`var`), or several joined into one compound key
(`vars`), and a mark can carry a value harvested from the line too
(`value_var`)... so a mark can remember not just "this IP" but "this
username", "this source on this account", and store "the address that used
it".

- [`mark`](rule-gates/mark.md) :: Sets a brand on match.
- [`unmark`](rule-gates/unmark.md) :: Lifts a brand on match.
- [`marked`](rule-gates/marked.md) :: Holds when a brand is set, and may ask
  how old it is, what it stores, and how many hosts set it.
- [`not_marked`](rule-gates/not_marked.md) :: Holds when a brand is not set.
- [`sequence`](rule-gates/sequence.md) :: Holds when brands were set in
  order.
- `mark_only` :: A key of the rule. When true the rule only brands and
  gates, never counting toward a ban, and does not consume the line, so
  matching falls through to the later rules.

#### How old a brand is, and who set it

A brand is as old as when it was first set, however often it has been set
since. A [`marked`](rule-gates/marked.md) can ask that age with
`older_than` and `newer_than`, and how many hosts of a fleet set the brand
with `hosts`.

A brand says who set it only as far as it has been told. Hosts share brands
over a [Redis tablet](tablets.md), each delta naming the host it came from,
so with out one there is only ever this host and `hosts: 2` never holds.
Who set a brand rides the tablet across a restart, and `baphomet marked`
shows the count. A test seeds it with a `hosts` count on a `marks_before`
entry, and the age with its `set`.

A rule whose mark gates veto, like a mark_only rule, does not consume the
line either, so a branding rule and the rule that reads it can both act on
the same line by falling through. What consuming costs the rules after it
is the watcher's [`overlap`](configuration.md) setting, phase 5 of
[the order it runs in](#the-order-it-runs-in).

The shipped `syslog/sshd-mark-users` and `syslog/sshd-spray` pair catch a
single account hit from more than one source... the distributed brute-force
signature per-IP counting can not see, since each source alone stays under
the threshold. The first rule brands each failed account with the source that
hit it:

```yaml
# syslog/sshd-mark-users, mark_only... brand USER with the SRC
mark_only: true
rule_gates:
  - mark:
      name: sshd-account-src
      ttl: 3600
      var: USER
      value_var: SRC
```

The second matches the same failures and fires only when the account is
already branded with a *different* source:

```yaml
# syslog/sshd-spray... a second source on a branded account
rule_gates:
  - marked:
      name: sshd-account-src
      var: USER
      value_not: SRC
max_score: 1
```

Order matters: list the reading rule (`sshd-spray`) before the branding one
(`sshd-mark-users`) in the watcher, so the gate sees the source that
established the account rather than the one the same line would re-brand it
with. Since `sshd-spray` carries `max_score: 1`, it only fires where the kur
sets `allow_per_rule_thresholds`.

A `vars` key brands a *pair* instead... `vars: [ SRC, USER ]` joins both
captures into one compound key, so "this source cleared this account" and
"this pair is still suspect" write and read the same brand:

```yaml
# brand the pair on a good login
mark_only: true
rule_gates:
  - mark:
      name: cleared
      ttl: 3600
      vars: [ SRC, USER ]
```

```yaml
# count only the pairs never cleared
rule_gates:
  - not_marked:
      name: cleared
      vars: [ SRC, USER ]
```

This is Sagan's `track ip_username`, with the `not_marked` its `isnotset`.
The joined key shows up in `baphomet marked` and on tablets as the captures
joined on the unit separator, `\u001f` in the JSON.

A rule's own embedded tests exercise the mark machinery against a
throwaway store... `marks_before` seeds the brands other rules would have
set, `marks_expected` asserts what this one branded, and the virtual clock
proves ttls and sequence ordering (see [tests](#tests)). Live marks are
galla state... visible with `baphomet marked`, surviving a restart via a
marks tablet. Scope is the galla, so marks cross watchers and rules but not
kurs. Each mark name is capped, and a mark keyed by the offender never
brands an address in `ignore_ips`.

#### The galla's own brands

Two brand names are the galla's. It brands every address it banishes under
`banished`, for as long as the ban is to last, and under `banishments`,
valued with when each of its last twenty bans was made, for ninety days.
The [`banished`](rule-gates/banished.md)
gate reads them. A rule may read them with `marked` as well, and should
not set either.

#### The standard brands

The shipped rules share a standard vocabulary of brands, Sagan's own bit
names kept name for name so a rule ported from its corpus lands already
wired into the same mesh:

| brand | ttl | earned by |
| --- | --- | --- |
| `brute_force` | 21600 | every shipped rule of classtype `brute-force`... sshd and its variants, the mail/FTP/VoIP auth rules, the panel and database logins |
| `recon` | 86400 | the scanning classes, classtypes `attempted-recon`, `network-scan`, and the successful-recon pair... scanlogd and portsentry through the fake Googlebot and the matching Suricata classes |
| `exploit_attempt` | 86400 | the exploit classes, classtypes `web-application-attack`, `attempted-admin`, `attempted-user`, and `shellcode-detect`... the bot searches, shellshock, suhosin, mod_security, and the matching Suricata classes |
| `honeypot` | 86400 | `raw/portsentry` and `json/cowrie`, a trap by nature... otherwise reserved for your own decoy rules |

The mapping is classtype-driven, so a site rule joins the mesh by carrying
the classtype's `mark` entry itself... the names are convention, not
machinery. Every setter brands var-less, keyed by each offender IP, on top
of whatever the rule already counts, so branding changes no rule's own
behavior.

Three shipped readers gate on the vocabulary, weighted heavy so that under
`allow_per_rule_thresholds` one hit from the already-branded is a verdict
(`weight: 10`, `max_score: 10`)... without that consent the weight is inert
and they count like any other rule, just under their own name:

| rule | fires on |
| --- | --- |
| `syslog/sshd-condemned` | a sshd auth failure from a source branded `brute_force`, wherever the brand was earned |
| `json/suricata-condemned` | any Suricata alert from a src branded `brute_force`, whatever the alert's own class |
| `json/suricata-escalation` | any Suricata alert from a src holding `recon` then `exploit_attempt` in that order... scanned, then exploited |

List a reader ahead of the rules it upgrades... when its gate vetoes the
line falls through to the normal rules untouched, and when it holds the
reader speaks instead, counting the same line into its own heavier bucket.
None ride the shipped groups, so they are opt-in by listing.

Beside those sit the breach readers, ported from Sagan's `*-correlated`
family with each product's four per-bit rules folded into one by the
any-of `names` gate... a *success* from a source holding any standard
brand, the likely credential compromise. Detection-only, since banning a
source that just got in is a policy call... each sights to EVE and
banishes nobody until its `detection_var` is flipped to `ban_var`:

| rule | fires on |
| --- | --- |
| `syslog/sshd-breach` | a successful ssh login from a branded source |
| `syslog/vsftpd-breach` | a successful vsftpd login from a branded source |
| `syslog/vsftpd-breach-upload` | a vsftpd upload by a branded source |
| `syslog/courier-breach` | a successful Courier IMAP/POP3 login from a branded source |
| `raw/cisco-asa-breach`, `raw/fortinet-breach`, `raw/citrix-breach` | a successful firewall/VPN/admin login from a branded source, per gear family |
| `raw/citrix-condemned` | a NetScaler AAA failure from a source branded recon/exploit/honeypot |

The shared vocabulary is what makes marks a mesh rather than pairwise
plumbing. The network gear families ([rules-catalog](rules-catalog.md))
brand the same names the Unix daemons do, the brand crosses watchers within
the galla, and it rides the mark bus of a Redis tablet across a fleet... so
a source that hammered the FortiGate VPN arrives at sshd already condemned,
and the mail host's brute-forcer lands at the web host the same way.

### tracked records... state that accumulates across lines

A mark holds one scalar per key. A tracked record holds a hash that
accumulates, which is what a daemon logging one transaction over several
lines needs.

Postfix is the clearest case. The client address arrives on the `smtpd`
line, the sender and recipient on `cleanup`, the delivery verdict on `local`
or `smtp` an hour later, and the only thing joining them is the queue id.
The line that finally says something worth banning on is rarely the line
that says who to ban.

    track_only: true
    rule_gates:
      - track:
          name: mail-queue
          key: postfix_queueid
          fields: [ postfix_client_ip, postfix_sasl_username ]
          ttl: 3600

That is the harvest rule. It watches the `smtpd` lines, files what they say
under the queue id, and does nothing else. And this is the rule that reads
it back:

    rule_gates:
      - tracked:
          name: mail-queue
          where:
            - { field: postfix_sasl_username, op: exists }
            - { field: postfix_client_ip, op: cidr, value: 10.0.0.0/8, negate: true }
          into: [ postfix_client_ip ]
      - track:
          name: mail-queue
          key: postfix_queueid
          fields: [ postfix_status ]
      - ban_var: [ postfix_client_ip ]

The bounce fires on the `local` line, and `ban_var` names an address that
only ever appeared on an `smtpd` line an hour earlier. That is what `into`
is for.

- [`track`](rule-gates/track.md) :: Harvests the line into a record, keyed
  by the joining id.
- [`tracked`](rule-gates/tracked.md) :: Judges the line by its record with
  a `where`, or lifts stored fields into the offense with an `into`.
- [`not_tracked`](rule-gates/not_tracked.md) :: Holds when there is no live
  record for the key.
- `track_only` :: `mark_only`'s sibling. The rule harvests, never counts,
  and does not consume the line.

A rule that reads a record also declares the `track` for it, the
declaration being what the read is a read of. One with nothing of its own
to add says so with `fields: []`, which still keeps the record alive on
every sighting.

The harvest runs whether or not the message regexps hit and whether or not
the gates that judge held, a record being a record of the transaction
rather than of offenses. Only a gate above it that turns the line away
outright stops it, as the `daemons` gate and `ignore` do: the one because a
postfix track has no business reading sshd lines, the other because
`ignore` is the operator saying this line is not evidence. With the `track`
written below the `tracked` that reads its record, the read precedes the
write, so a `where` judges the history rather than a record the
same line just wrote.

Records live per galla, cross watchers and rules but not kurs, survive a
restart, and are visible with `baphomet tracked`. They are deliberately not
fleet synced... a record republished per stage line on a busy MX is a
different order of traffic than a scalar brand. A record holds at most 64
fields, and the store keeps the same 10000-key bound the marks and the DNS
and geo caches share.

Prove one from the rule file the way brands are proved: `tracked_before`
seeds a record, `tracked_expected` asserts one, and a multiline `messages:`
test walks a harvest line and a reading line through one scope so the record
the gate reads is one the rule really built. See
[Proving brands and gates](#proving-brands-and-gates).

## Enriching a match... mungers

Where the [primitive fragments](rule-gates/message_regexp.md#primitive-fragments-building-blocks-not-captures)
borrow Log-Munger's regexp *pieces* to help write a pattern, a
**munger** borrows a whole Log-Munger decoder to *read* the line for you. A
rule names the mungers that apply to it in a `mungers` gate, written above
its `message_regexp` so they run over the line before it, and every field
they decode is laid into the offense... available to the gates below, the
marks, `ban_var`/`detection_var`, the promoted vars, and the EVE `found`
alike, no rule-format change.

```yaml
# a sshd rule that leans on Log-Munger's sshd decoder for the ssh_* fields
rule_gates:
  - daemons: [sshd]
  - mungers: [sshd]
  - message_regexp:
      - 'Failed password for (?:invalid user )?\S+ from %%%%SRC%%%% port'
  - ban_var: [SRC]
```

Each entry is a **leaf** munger... a
[Log-Munger](https://github.com/LilithSec/Log-Munger) rule file (`sshd`,
`postfix`, `http_access_logs`, ...) named without its `.yaml`. Log-Munger
resolves a file's own dependencies, so you name only the relevant decoder,
never `base`. A set builds one processor, memoized and shared by every rule
naming it, so a fleet of sshd rules pays the compile once.

The line is handed over as the fields the parser already split out... for a
syslog rule the message maps to Log-Munger's `MESSAGE`, the daemon to its
`PROGRAM` gate, the level to `PRIORITY`, the facility to `FACILITY`; a raw
rule has only its message to give. The munger's first matching rule decides,
and its captures come back as the enrichment.

Order is deliberate: written above the `message_regexp`, the munger runs
**first**, its fields laid down underneath, and the rule's own
`message_regexp` captures then overwrite any of the same name... the rule
choosing a different read than the munger's for that one field, on purpose.
Everything the munger decoded that the rule did not recapture rides along
untouched. The one exception is an offense deferred to wait for its capture
line: it is parked with only its regexp captures, so once completed it holds
the capture line's munger fields and not its own.

Mungers are supported on `syslog` and `raw` rules, including
[staged](rule-gates/stages.md) ones... a staged rule enriches the *completed
sequence* from its final, sequence-completing line (the same line whose
`raw` the event carries), so a `sshd-worked` alarm arrives with the
`Accepted` line's decoded fields beside the sequence's own captures. Like
the `country` gate's GeoIP, the dependency is optional but **not**
fail-soft: a rule that asks for enrichment it can not get is a
misconfiguration, so a missing Log::Munger or a munger file that will not
resolve is fatal... caught and named at galla load (an `err` to the log),
never silently skipped and never a surprise mid-line. A malformed `mungers`
gate is refused when the rule loads.

### A munger as the matcher

A munger need not only enrich. Because its decoded fields land in the same
field space the [predicate gate](#gate--selections--condition--keywords) reads,
a rule may carry `mungers` and **no `message_regexp` at all**, letting the
gate be the matcher and `ban_var` name a decoded field... the same concession
[`message_json`](rule-gates/message_json.md) has, and for the same reason. Such a rule must
still gate on something, or it would call every line it decodes an offense;
one with no `gate`, `condition`, or `keywords` is refused at load.

This is how the appliance families are written. A FortiGate or SonicWall line
is a flat `key=value` ledger, and the offender is a *named field* in it, so
there is nothing to scan for:

```yaml
# raw/fortinet-admin-auth... no regexp, the ledger read rather than scanned
rule_gates:
  - mungers:
      - fortinet
  - gate:
      - field: fg_logid
        op: re
        value: '^\d*32002$'
      - field: fg_type
        values: [ event ]
  - ban_var:
      - fg_offender_ip
```

The gain is not tidiness. These events log the attempted account name, and
that name is whatever the client typed at the login prompt. A rule that
scanned the line for the first `srcip=` took the one an attacker pasted into
their own username... logging in as `admin srcip=8.8.8.8` aimed the ban at
8.8.8.8. Quote-aware decomposition cannot be steered that way: `user=` is one
value and `srcip=` is another, so the offender stays the field the appliance
wrote. Each of those rules carries a positive test proving exactly that.

Because such a rule's matcher *is* its munger, losing the munger would not
merely lose fields... it would veto every line and never fire. The
fatal-on-unresolvable behavior above covers that, and the rule's own
[tests](#tests) exercise the real munger, so a missing or wrong decoder
fails at load rather than matching nothing in the field. The
`raw/fortinet-*` and `raw/sonicwall-*` rules accordingly need Log::Munger
installed *with* the `fortinet` and `sonicwall` rule files, not merely
present.

## How the types differ

Everything above is shared. What each type changes is the **matcher** ... how
a raw line becomes a match, and where the offender comes from.

| type | works on (parser) | how it decides an offense | offender |
| --- | --- | --- | --- |
| `syslog` | syslog lines (`bsd_syslog`/`syslog`/`ietf_syslog`/`json_syslog`/journal) | a `daemons` gate, then `message_regexp` over the message text | `ban_var` captures |
| `raw` | whole lines (`raw`) | `message_regexp` over the whole line, no daemon gate | `ban_var` captures |
| `http` | access logs (`http_access`) | `status`/`method` gates and `match` regexps over parsed fields | `ban_var` naming the parsed `host` |
| `http_error` | error logs (`apache_error`/`nginx_error`) | `level`/`module` gates, then `message_regexp` over the message | `ban_var` naming the parsed `client` |
| `json` | JSON logs (`json`) | `gate`/`match` over flattened dotted fields | `ban_var` naming a field or capture |

The axes underneath that table:

- **Text or structured.** syslog, raw, and http_error match Perl regexps
  against a line's free text; http and json match against fields the parser
  already broke out (`status`, `attr.remote`). The predicate
  [gate/selections/keywords](#gate--selections--condition--keywords) layer
  refines either kind, on every type.
- **Extracted or handed over.** syslog, raw, and json dig the offender out,
  their `ban_var` naming a token capture, a named group, or a field path. On
  http and http_error there is nothing to dig for... the parser already
  isolated the client, so their `ban_var` names the parsed `host` / `client`.
- **Tokens.** The `%%%%TOKEN%%%%` shortcuts (`SRC`, `HOST`, `ADDR`, ...)
  compile into address-matching named captures. They work in the
  `message_regexp` of syslog and raw, and in the `match` entries of json.
  http field matches and http_error `message_regexp` are plain Perl regexps,
  not tokened (http_error still merges a winning regexp's named captures into
  the data).
- **Correlation.** Offense-and-address-on-different-lines correlation is a
  syslog, raw, and json feature... `capture_regexp` and keyed
  `message_regexp` on the text types, a `capture` gate and a `key` gate
  keyed on fields for json. The http and http_error types have no
  need of it, every line already carrying its offender.
- **Staging.** In-rule ordered sequences... counted stages with time and
  line bounds (`stages`)... are a syslog and raw feature.
- **JSON in a syslog envelope.** `message_json` decodes a JSON message inside
  a syslog line into gateable fields, a syslog-only bridge to the json
  machinery.

The rest of this page is one section per type.

## syslog rules

A syslog rule matches the message portion of a parsed syslog line, after a
cheap daemon gate. Its own gates are:

- [`daemons`](rule-gates/daemons.md) :: Which daemons the rule reads. Every
  syslog rule has one, and leading the list it keeps the rule off every
  other daemon's lines.
- [`message_regexp`](rule-gates/message_regexp.md) :: The regexps tried
  against the message, with the `%%%%TOKEN%%%%` offender tokens and
  [primitive fragments](rule-gates/message_regexp.md#primitive-fragments-building-blocks-not-captures).
- [`ignore_regexp`](rule-gates/ignore_regexp.md) :: Regexps that veto a
  line, fail2ban's `ignoreregex`.
- [`message_json`](rule-gates/message_json.md) :: A JSON message decoded
  into dotted-path fields, the predicate gate then being the matcher.

### correlation... offense and address on different lines

Some daemons log the offense and the offender's address separately, tied by a
key like a connection or queue id... pre-4.4 mongod logs
`[conn7] Failed to authenticate` with no address and later
`[conn7] end connection 192.0.2.35:53276`. syslog and raw rules handle this
with `capture_regexp` entries, which harvest context rather than being
offenses, and keyed `message_regexp` entries:

```yaml
rule_gates:
  - capture_regexp:
      - regexp: '^\S+\s+\[conn(?<KEY>\d+)\] end connection %%%%SRC%%%%:\d+'
        key: KEY
        ttl: 600
  - message_regexp:
      - regexp: '^\S+\s+\[conn(?<KEY>\d+)\] Failed to authenticate '
        key: KEY
        defer: 600
  - ban_var:
      - SRC
```

A keyed offense resolves through the stored captures of a capture line with
the same key, whichever order the two arrive in... `defer` says how long a
offense may wait for its address, `ttl` how long harvested context lives.
Both directions work, so sendmail's address-first queue id pairs and
mongodb's offense-first conn id pairs are the same machinery. State is per
watcher, and the context tablet carries it across a restart. Test these with the `messages:` array form (see
[tests](#tests)); `raw/mongodb-auth-legacy` and the No such user pair in
`syslog/sendmail-reject` are shipped examples.

A `key` may also be a array of components, and on the syslog type a
component may name a reserved envelope field... `syslog.daemon`,
`syslog.host`, or `syslog.pid`... in place of a capture. So a daemon whose
lines share nothing but the logging process itself, the fail2ban F-MLFID
shape, correlates by its session with no key in the message at all:

```yaml
rule_gates:
  - capture_regexp:
      - regexp: '^Connection from %%%%SRC%%%% port \d+'
        key: [ syslog.host, syslog.daemon, syslog.pid ]
        ttl: 120
  - message_regexp:
      - regexp: '^Too many authentication failures'
        key: [ syslog.host, syslog.daemon, syslog.pid ]
        defer: 60
  - ban_var:
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
entirely... a staged rule's stages are its whole matcher, with an
`ignore_regexp` above them still vetoing lines. A true `message_json` is
refused beside them too. The gate is told a hash
of `stages`, the list of them, and an optional `per`.

The brute-force-that-worked shape... failures, then a success, the
compromised-credential alarm one typo never trips:

```yaml
rule_gates:
  - stages:
      per: [ SRC ]
      stages:
        - message_regexp:
            - '^Failed (?:password|publickey) for .* from %%%%SRC%%%%'
          count: 5
          within: 300
        - message_regexp:
            - '^Accepted \w+ for .* from %%%%SRC%%%%'
          within: 60
  - detection_var: [ SRC ]
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
order also drives `skip`. A `within` bound is proven the same way, an
`advance` or `at` on a `messages:` entry moving the virtual clock past it.

See [`App::Baphomet::Rule`](https://metacpan.org/pod/App::Baphomet::Rule)
and the class of each gate,
[`App::Baphomet::Gate::daemons`](https://metacpan.org/pod/App::Baphomet::Gate::daemons)
and the like, for the full reference.

## raw rules

Rules of the `raw` type work on lines from the `raw` parser, the no-op escape
hatch where the whole line is the message. A raw rule is a syslog rule with
out the daemons gate... the same `message_regexp` with the same
[tokens](rule-gates/message_regexp.md), the same `ignore_regexp`, the same `ban_var`,
the same
[correlation](#correlation-offense-and-address-on-different-lines), and
the same [staging](rule-gates/stages.md), though
with no envelope a raw `per` keys on captures only. Tests default to the
`raw` parser.

```yaml
---
rule_gates:
  - message_regexp:
      - '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} auth failure from %%%%SRC%%%%$'
  - ban_var:
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
which lines are offenses, and its `ban_var` names `host` (or a
[`detection_var`](rule-gates/detection_var.md) stands in its place).

```yaml
---
rule_gates:
  # status and method... optional, ANDed, same string-or-//regexp// convention
  - status:
      - 401
      - 403
      - //^5//
  - method:
      - GET
      - POST
  # ignores... a hit vetoes the line, each naming the field it runs against
  - ignore:
      - field: user_agent
        regexp: 'FriendlyAuditBot'
  # matches... same shape, ORed, first hit wins
  - match:
      - field: user_agent
        regexp: '(?i:masscan|zgrab|sqlmap)'
      - field: path
        regexp: '\.(?:env|git)(?:$|/)'
  # the offender... the client the parser already split out
  - ban_var: [ host ]
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
written above the `match`. A rule with no `match` (every 401, say) is legal...
one with neither a `match` nor a gate that judges is a error. Tests default to
the `http_access` parser. See
[`App::Baphomet::Rule`](https://metacpan.org/pod/App::Baphomet::Rule) and the
class of each gate,
[`App::Baphomet::Gate::match`](https://metacpan.org/pod/App::Baphomet::Gate::match)
and the like, for the full reference.

## http_error rules

Rules of the `http_error` type work on lines parsed by the `apache_error` or
`nginx_error` parsers. As with http rules, the offender is already a field of
the parsed line, the `client` its `ban_var` names, and lines with no client
(startup notices) are never offenses. As with syslog rules, the
matching is `message_regexp`/`ignore_regexp` against the message free text...
for apache that is what follows the `[client ip]` and the optional
`AHnnnnn:` code, and for nginx the trailing `, client: ..., server: ...`
pairs are peeled into fields first, so the regexps stay clean of them. These
are plain Perl regexps... the `%%%%TOKEN%%%%` shortcuts are a syslog/raw
feature, not used here, but named captures in a winning regexp merge into
`data`.

```yaml
---
test_parser: nginx_error # per rule test parser default... apache_error if unset
rule_gates:
  - level:               # optional gates, ANDed, string-or-//regexp//
      - error
  - module:              # apache 2.4 module... a module gate makes a rule 2.4 only
      - auth_basic
  - ignore_regexp:
      - 'from the health checker'
  - message_regexp:
      - '^user \S*: password mismatch'
  - ban_var: [ client ]
tests:
  positive:
    - message: '[Wed Jul 17 22:18:52 2013] [error] [client 127.0.0.1] user username: authentication failure for "/basic/file": Password Mismatch'
      found: 1
      data:
        client: "127.0.0.1"
```

The [predicate gate](#gate--selections--condition--keywords) is available,
written above the `message_regexp`, which every http_error rule has to have.
See [`App::Baphomet::Rule`](https://metacpan.org/pod/App::Baphomet::Rule) and
the class of each gate,
[`App::Baphomet::Gate::level`](https://metacpan.org/pod/App::Baphomet::Gate::level)
and the like, for the full reference.

## json rules

Rules of the `json` type work on lines parsed by the `json` parser, which
flattens whatever the application logged into dotted field paths
(`attr.remote`, `request.client_ip`, `tags.0`). The rule says which fields
matter... ANDed `gate` entries pinning fields to value lists
(string-or-`//regexp//`), ORed first-match-wins `match` entries running
regexps ([tokens](rule-gates/message_regexp.md) included) against named fields, and
vetoing `ignore` entries of the same shape. A rule needs at least a gate or a
match.

`ban_var` resolves against the found line's data, which is the flattened
fields merged with the winning match's captures... so it may name a token
capture like `SRC` when the address has to be dug out of a string like
`"remote":"192.0.2.5:54321"`, or a field path like `request.client_ip` when
the log hands the address over bare.

```yaml
---
rule_gates:
  - gate:
      - field: c
        values: [ ACCESS ]
      - field: msg
        values: [ "Authentication failed" ]
  - match:
      - field: attr.remote
        regexp: '^%%%%SRC%%%%:\d+$'
  - ban_var:
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
[`App::Baphomet::Rule`](https://metacpan.org/pod/App::Baphomet::Rule) and the
class of each gate,
[`App::Baphomet::Gate::match`](https://metacpan.org/pod/App::Baphomet::Gate::match)
and the like, for the full reference.

### correlation on json... capture, key, defer

Structured logs split events too... an offense on one record and the
address it came from on another, sharing an id. The json type carries the same
two-phase [correlation](#correlation-offense-and-address-on-different-lines)
as syslog and raw, keyed on fields instead of an envelope: `capture`
entries (their own `gate`/`match`, a `key`, a `ttl`) harvest context
without being offenses, and a `key` gate, with an optional `defer`, makes
the rule's own match resolve through it, whichever order the events arrive
in.

```yaml
rule_gates:
  - capture:
      - gate:
          - field: msg
            values: [ "Connection ended" ]
        match:
          - field: attr.remote
            regexp: '^%%%%SRC%%%%:\d+$'
        key: [ ctx ]
        ttl: 120
  - gate:
      - field: c
        values: [ ACCESS ]
      - field: msg
        values: [ "Authentication failed" ]
  - key: { key: [ ctx ], defer: 60 }
  - ban_var:
      - SRC
```

A `key` is a field path or capture name, or an array of them compounding
into one key, every component required to resolve. The gate is told the key
alone, or a hash of it and a `defer`. An unresolved offense with `defer`
waits that many seconds for its capture; with out `defer` it is not judged
an offense at all. State is per watcher and rides the context tablet across
a restart, as on the other types, and the `messages:` test form proves it. The `syslog.*` namespace is
reserved (it is the [message_json](rule-gates/message_json.md) envelope), so keying on it
here is a load error.

## Writing one

Start from a real log line and work backwards...

```shell
# see how the line parses and whether the rule matches... --file names the
# file outright, which is what you want on a rule being edited in a checkout
baphomet test_line --file ./share/rules/syslog/myrule.yaml \
    'Jul 12 08:15:50 mail01 mydaemon[123]: auth failure from 1.2.3.4'

# run one rule's own tests, again by path
baphomet check_rules --file ./share/rules/syslog/myrule.yaml

# with the file, the ranking, and the tests by section
baphomet check_rules -v --file ./share/rules/syslog/myrule.yaml

# the whole tree in isolation
baphomet check_rules --rules-dir ./share/rules

# run every rule's tests as the galla would resolve them... the override dir
# and the shipped rules both
baphomet check_rules
```

**Mind which copy you are checking.** With neither `--file` nor `--rules-dir`,
rules resolve exactly as at run time... the config's override dir, then the
shipped dir under `File::ShareDir`. In a source checkout that shipped dir is the
*installed* copy, so a bare `check_rules` in a tree you are editing may report a
clean pass having never read your edits, and an override dir shadowing them
hides them from both. Every run therefore ends by naming what it read:

```
254 rules checked, read from /usr/local/etc/baphomet/rules (135), \
    /usr/local/lib/perl5/site_perl/auto/share/dist/App-Baphomet/rules (119)
```

`test_line` answers the same question with a `rule_file` in its JSON. When it
matters which file gave an answer, name it with `--file` and nothing is
searched for.

`test_line` loads the rule with its tests skipped, so a rule you are midway
through writing can still be poked at.

The loop is: find a real offending line, poke it at the draft with
`test_line` until the match and captures come out right, then move that
very line into the rule's `tests:` with its `data:` assertions and let
`check_rules` carry it forever. Repeat per regexp, then add the
near-misses. The [tests](#tests) section is the full writing guide...
the matcher discipline, and the seeds, fixtures, and clock that prove
marks, gates, sequences, and lookups from the rule's own file.

Things worth knowing...

- Anchor with `^` where you can... it keeps a regexp from matching inside
  quoted or logged-through content, like sshd logging a client supplied
  string.
- The fail2ban filters (`config/filter.d/` in its source) are a rich vein of
  patterns to translate. Drop their `<HOST>` style tags in favor of the
  tokens above and their `%(...)s` includes in favor of spelling things out.
- Rules load once at start. After editing one, restart baphomet or verify
  first with `check_rules`.
