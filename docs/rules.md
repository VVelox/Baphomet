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
| `syslog/foreign-auth` | any log carrying a login service | the thirteen `*-foreign-auth` rules... any authentication event, failed or successful, from outside `country_codes{home}`, banning on the first one. Opt-in twice over (list it, and name your home countries) and **listed ahead** of the per-service rules it shadows. See [the country gate](#country-narrowing-an-offense-by-geography) |
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
   [`ban_var`](#ban_var) or [`detection_var`](#detection_var).
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

A rule runs in the order it is written. Each gate is one of two phases, going
by what it reads, and each phase is asked in the order of the list.

- line :: Reads the line. Asked once per line. It may turn the line away
  outright, lay fields down, make an offense, or refuse one. `daemons`,
  `message_regexp`, and `gate` are of it.
- offense :: Reads an offense the line made. Asked once per offense, once the
  line gates are done. It may veto the offense, name its offenders, drop some
  of them, or brand them. `country`, `ban_var`, and `mark` are of it.

Where a gate sits decides what it sees and what a veto there costs. A line the
`daemons` gate turns away cost nothing at all. One refused by a gate below the
matcher cost a regexp and left nothing behind it. One that reaches the
threshold has already been counted, and will be counted again by the next line
like it. This is the whole passage of one line through one rule, with the
gates in the order a rule usually writes them.

```
   a line arrives on a watched log
   │
   ├─ the watcher's parser splits it up
   │  A syslog parser yields the time, host, daemon, level, and message.
   │  The others yield the fields of an access log, an error log, or a
   │  JSON record.
   │  └─▶ the line does not parse. It is counted and dropped.
   │
   ├─ the rule index picks the candidates
   │  It holds which of the watcher's rules a line could possibly match,
   │  keyed on the `daemons` gates leading the lists of a syslog
   │  watcher's rules and on the most selectively pinned `gate` field
   │  for a json one.
   │  └─▶ a rule the index does not name is never asked.
   │
   ▼
   The candidates are tried in the watcher's config order. Everything
   below happens inside one of them.

   ├──[ 1  THE LINE ]  is this line an offense?
   │
   │  The gates of the line phase, each asked once, in the order the
   │  rule wrote them.
   │
   ├─ 1.0  pressure
   │       Reads nothing of the line. It lets the line by only while
   │       the watcher's rules are matching above a mark.
   │       └─▶ not above it. The rule stops. Leading the list, that
   │           cost next to nothing.
   │
   ├─ 1.0  epoch / fresh / startup
   │       An `epoch` makes seconds of a timestamp, the line's own or a
   │       field's, and a `fresh` below it turns away a line written too
   │       long before it was read. A `startup` turns away every line
   │       while the galla has only just started.
   │       └─▶ old news. The rule stops, and nothing is counted.
   │
   ├─ 1.0  extract / normalize / digest
   │       Wherever they are written, these act on what stands when
   │       they are asked... an offense when one has been made above
   │       them, the line's fields while there is none. An `extract`
   │       lifts named captures out of a field. A `normalize` lifts the
   │       path a server would make of a request. A `digest` puts a
   │       hash in place of a value, and every gate below it, and every
   │       gate of the offense phase, sees the hash.
   │
   ├─ 1.1  daemons / status / method / level / module
   │       A syslog rule checks the line's daemon. An http rule checks
   │       the status and method of the request. An http_error rule
   │       checks the level and module. The raw and json types have no
   │       such gate.
   │       └─▶ no match. The rule stops. Leading the list, it has read
   │           nothing and remembered nothing, which is what makes the
   │           index above safe.
   │
   ├─ 1.2  message_json                              syslog rules only
   │       The message is decoded as JSON and its fields are flattened
   │       into dotted paths that the gates below can read.
   │       └─▶ the message is not a JSON object. The rule stops.
   │
   ├─ 1.3  mungers                          syslog and raw rules only
   │       Log-Munger decodes the line and its fields are laid down for
   │       the gates below. They go underneath, so a capture of the same
   │       name at 1.6 or 1.7 wins over one of them.
   │
   ├─ 1.4  ignore_regexp / ignore
   │       └─▶ a hit. The rule stops. No gate below it is asked, so no
   │           context is stored, no deferred offense completes, and
   │           nothing is harvested at 1.9.
   │
   ├─ 1.5  stages                           syslog and raw rules only
   │       The line is tested against the stage its sequence is waiting
   │       on. A hit advances the sequence if that stage's `within` and
   │       `skip` bounds allow it, and kills the sequence if they do not.
   │       A line matching the first stage starts a fresh sequence unless
   │       one is already in flight for its key. Only the line completing
   │       the last stage is an offense, and it holds the captures of
   │       every stage before it. A staged rule has no 1.6 or 1.7.
   │
   ├─ 1.6  capture_regexp / capture
   │       A hit stores this line's captures under its correlation key,
   │       where a later offense can claim them. An offense already
   │       deferred against that key completes here and now.
   │
   ├─ 1.7  message_regexp / match, with key
   │       The entries are tried in order and the first to hit makes the
   │       offense. A keyed one needs its context. If the context holds
   │       that key, the stored captures merge with this line's into one
   │       offense. If it does not, the offense is deferred to wait for a
   │       capture line, or passed over. A rule with no such gate makes
   │       its offense of the line's fields, once every gate has let
   │       them by.
   │
   ├─ 1.8  tracked / not_tracked / keywords / gate / condition
   │       The gates that judge. Each reads what stands when it is
   │       asked... the offense, with its captures, munger fields, and
   │       JSON fields alike, or the line's fields while there is no
   │       offense yet. `tracked` goes first among them, so whatever its
   │       `into` lifts is readable by the rest.
   │       └─▶ one of them does not hold. The offense is refused, and the
   │           gates below are not asked, 1.9 aside.
   │
   ├─ 1.9  track
   │       Each record the rule declares takes this line's contribution.
   │       It does not care whether the regexps hit or whether 1.8 held,
   │       a record being a record of the transaction rather than of
   │       offenses... only a gate that turns the line away outright
   │       stops it. Below the `tracked` and `not_tracked` of 1.8, those
   │       judge the history rather than a record this line just wrote.
   │
   ▼
   An offense, holding every field the gates above put in it, and
   beside it any offense a capture line just completed.
   A rule that got no further than 1.9 harvested and stopped.

   ├──[ 2  THE OFFENSE ]  is it a real one, and whose is it?
   │
   │  The gates of the offense phase. Each offense goes down them once,
   │  in the order the rule wrote them.
   │
   ├─ 2.1  the gates naming a var
   │       Any of marked, not_marked, sequence, country, asn, address,
   │       namtar_list, reverse_dns, dnsbl, breadth, and scored told a
   │       `var` or `vars`, which read a field of the offense. Every
   │       account, limit, after, sum, beacon, sample, travel,
   │       concurrent, network, forwarded, and weigh is of these too,
   │       each only ever keyed by a field, and so is every active_time,
   │       as with no var it reads the clock and never an offender. A
   │       network and a forwarded only lift, and a weigh only weighs,
   │       and none of the three vetoes.
   │       └─▶ any one of them vetoes. The rule did not fire, and the
   │           gates below it are not asked. See "a veto is not a quiet
   │           pass" below.
   │
   ├─ 2.2  ban_var / detection_var
   │       The candidates are read out of the offense. A banning rule
   │       takes the value of each var `ban_var` names. A detection rule
   │       takes the value of each `detection_var` names instead and
   │       will banish nobody.
   │
   ├─ 2.3  ban_not_internal
   │       A candidate that is one of your own hosts is dropped. Your own
   │       hosts are the `internal` list, which defaults to `ignore_ips`.
   │
   ├─ 2.4  usedns
   │       Not a gate, but settled here, the first time anything asks
   │       who the offenders are. A candidate that is a hostname rather
   │       than an address is dropped under `no`, replaced by the
   │       addresses it resolves to under `resolve_seen`, or kept as a
   │       name under `resolve_ban`.
   │
   ├─ 2.5  the gates keyed by the offender
   │       The same types as 2.1, told no var. Each is asked once per
   │       candidate, and a candidate it does not hold for is dropped.
   │       One of these has to be below the `ban_var`, and a detection
   │       rule can not have one, both refused when the rule loads.
   │       └─▶ no candidate survives. The rule did not fire.
   │
   ├─ 2.6  mark / unmark / forgive
   │       Each offender is branded with the rule's `mark` gates and
   │       lifted from the ones its `unmark` gates name. An offender in
   │       `ignore_ips` is never branded. A `forgive` takes back the
   │       hits other rules have counted against each.
   │
   ▼
   The survivors. These are the offenders.

   ├──[ 3  COUNTING ]  what does the hit change?
   │
   ├─ 3.1  mark_only / track_only
   │       └─▶ either set. The rule stops here. It harvests and does
   │           nothing else, so the line is not consumed.
   │
   ├─ 3.2  ignore_ips
   │       └─▶ the offender is on the list. It is not counted. Observe
   │           mode with `observe_ignored` counts it into the shadow
   │           buckets anyway, so an operator can see what the list
   │           hides.
   │
   ├─ 3.3  the numbers are resolved
   │       `max_score`, `find_time`, `ban_time`, and `weight` are taken
   │       from the per-rule config table first, then the rule file
   │       (which speaks only under `allow_per_rule_thresholds`), then
   │       the watcher, then the kur, then the global config.
   │
   ├─ 3.4  the bucket is chosen
   │       Observe mode, a detection rule, and a rule demoted by
   │       `overlap: shadow` all count into the shadow buckets, which can
   │       neither cause nor delay a ban. Everything else counts into the
   │       real ones. A rule overriding `max_score` or `find_time` counts
   │       into a bucket of its own either way.
   │
   ├─ 3.5  the hit is deposited
   │       A plain rule adds its `weight` to the offender's score. A
   │       `distinct` rule adds the value of `of` to a set keyed by `by`,
   │       or by the offender when `by` is absent, and the score is the
   │       size of that set. Either way, anything last seen more than
   │       `find_time` ago is dropped before the score is read.
   │
   ├─ 3.6  the subnet tally
   │       With `ban_subnet_v4` or `ban_subnet_v6` set, the offender's
   │       network takes the same deposit in a bucket of its own.
   │
   ▼
   A score, and the max_score it is racing.

   ├──[ 4  THE VERDICT ]  does anyone get banished?
   │
   ├─ 4.1  the score is short of max_score
   │       One event goes to EVE and nothing else happens. It is `found`
   │       normally, `noted` in observe mode, and `sighting` from a
   │       detection rule.
   │
   ├─ 4.2  the score has reached max_score
   │       A detection rule writes `sighted` and stops. Observe mode
   │       writes `alert` and stops. Every other rule writes `banish` and
   │       the galla sends a ban command to the Ereshkigal manager for
   │       `ban_time` seconds. An unreachable Ereshkigal does not lose
   │       the ban: it is queued and retried every ten seconds. The
   │       offender's bucket is then cleared. A subnet that crossed on
   │       the same hit is banished as a whole CIDR.
   │
   ├──[ 5  CONSUMPTION ]  which rules see the line next?
   │
   │  A rule that fired and is not mark_only consumes the line. What
   │  that costs the rules after it is the watcher's `overlap`.
   │
   ├─ 5.1  overlap: first, the default
   │       No later rule is tried. The line is done.
   │
   ├─ 5.2  overlap: shadow
   │       Later rules still run, and any that fires is demoted. It
   │       counts into the shadow buckets and its events read `noted`.
   │
   ├─ 5.3  overlap: all
   │       Every later rule that fires judges for real.
   │
   ▼
   the next line
```

**A veto is not a quiet pass.** A rule turned away anywhere in phase 2 or 3
did not fire. It counts nothing, writes no EVE event, and does not consume the
line, so the line carries on to the rules listed after it. This is what lets a
legitimate Googlebot cleared by `reverse_dns` go on to match a benign rule.

**The order is yours, and it is read literally.** Written some other way, a
rule runs some other way:

- A gate that turns the line away stops every gate below it and none above
  it. An `ignore_regexp` below a `capture_regexp` lets the context be stored
  on a line the rule was told to ignore.
- A gate that judges reads what stands when it is asked. Above the matcher it
  judges the line's fields, and a line it refuses is not matched at all.
  Below the matcher it judges the captures.
- `message_json` and `mungers` go above the gates that read their fields.
- `track` goes below the `tracked` and `not_tracked` that read its record.
  Above them, `not_tracked` could never hold and a `where` would judge what
  this line just wrote.
- A gate keyed by the offender goes below the `ban_var` that names one.
- `mark` and `unmark` go below the gates that are to be able to stop them. A
  `mark` above a `country` gate brands the offender the `country` gate then
  spares.
- The gates of 1.1 and 1.4 cost least leading the list. They read nothing but
  the parsed line, so a line one of them turns away there has had nothing
  made for it.

## Naming the offender

### ban_var

The gate naming the captures or fields whose value is the offender, the
thing a hit is registered against and, at the threshold, banished. For each
name here that a matched line carries a value for, that value gets counted.
Usually just `SRC`. How the names resolve depends on the type... a regexp
capture on syslog/raw, a flattened field or capture on json, and a parsed
field on http and http_error, whose rules name `host` and `client` (see
[how the types differ](#how-the-types-differ)). A rule has a `ban_var` or a
`detection_var` gate, never both, and every type requires one of the two.

Naming several is ordinary... both ends of a flow, say. Each is counted in
its own bucket, each is judged by the per-offender gates on its own, and a
result whose every candidate is gated out did not fire at all. Two of them
naming the one address is one piece of evidence and counts once. Every event
the match raises names each var and what each is worth, under `subject_vars`
and `subject_vars_scores`, and a terminal event adds `subjects_crossed`, which
of them tipped over... see [eve](eve.md).

### detection_var

The parallel of `ban_var` for a **detection-only rule**. It names the
captures or fields to count by, under no obligation to be a address... a
username, a hostname, a URI, a service, or a IP when that is what you want.
The presence of `detection_var` (in place of `ban_var`) is what makes a rule
detection-only: it runs the whole match/count/threshold path like any other
rule, but never banishes. Each match writes a `sighting` to EVE, and a
subject crossing `max_score` within `find_time` writes a `sighted` whose
`subjects_crossed` names the var that did it, never touching Kur. Counting
rides the shadow buckets, so a detection rule
can never nudge a real ban over its threshold, and `ignore_ips` does not
apply. This is Sagan/Wazuh-style detection... alerting on a thing with no
address to banish, a policy tripwire, a config change, a service crash.

Because a detection rule writes only to EVE, loading one forces `eve_enable`
on (logged at start) so it is never a silent no-op. See [eve](eve.md) for the
event shapes.

A detection rule has no offender, so any of the gates
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear)
has to name the var it checks. One keyed by the offender would never be
asked, and is refused when the rule loads.

```yaml
# count by the offending username, banish nobody
rule_gates:
  - detection_var:
      - USER
```

### ban_not_internal

Some sources, Suricata's eve.json above all, log both ends of a flow, and
which one is the offender depends on where in the stream the alert fired. A
rule whose `ban_var` names both endpoints, with a `ban_not_internal` gate
below it, banishes only the ends that are not one of your own hosts:

```yaml
rule_gates:
  - ban_var:
      - src_ip
      - dest_ip
  - ban_not_internal: true
```

Your own hosts are the `internal` config field, which defaults to the
`ignore_ips` list. So an inbound attack bans the external src, an outbound
callout bans the external dest, a transit flow bans both, and a
host-to-host flow bans neither. A ignored IP is never banished regardless.

It works on every type, not just the multi-endpoint case: with a single
offender... a `ban_var` naming one var, as the `host` of an http rule or the
`client` of an http_error one is... it simply skips the ban when that
offender is one of your own. Set `internal` wider than `ignore_ips` (say all
of RFC 1918) to spare internal clients from a rule without globally ignoring
them. Anything whose ban target is an IP can carry it.

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
buckets for a [detection rule](#detection_var) and surfaces as `sighted`, holds
back as an `alert` under [`eve_only`](#eve_only), and the sets survive a restart
on the state tablets, keyed exactly as they were counted.

### eve_line

Optional, on every rule type, true by default. False leaves the line a
match was found in out of the rule's EVE events... the `raw` line, the
`parsed` one, and the line of each stage of a staged rule. What the rule
found, and the rule's own fields, are still there.

It is for a rule that hashes what it found with a
[`digest`](#digest-a-hash-in-place-of-a-name) gate. Hashing the name
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

Observe mode differs from a [detection rule](#detection_var): observe mode is
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
[`ban_var`](#ban_var) / [`ban_not_internal`](#ban_not_internal).

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
| `dns` | A fixture resolver for the [reverse_dns](#reverse_dns-the-client-is-who-its-address-says) and [dnsbl](#dnsbl-what-a-blocklist-says-of-an-address) gates... `ptr` maps an address to its names, `forward` a name to its addresses, and `dnsbl` a zone to a map of address to what the zone answers, each answer a list, `nxdomain` (authoritative absence), or `servfail` (a failure). Anything unfixtured answers servfail, fail-closed as an unanswerable question is live. With the fixture present the gate runs exactly as in the galla, offender pass and all; without it the gate is skipped, as it always was. |
| `geo` | A fixture locator for the [country](#country-narrowing-an-offense-by-geography), [asn](#asn-narrowing-an-offense-by-network), and [travel](#travel-further-than-it-could-have-gone) gates... `countries` maps an address to its ISO code, `asns` one to its AS number or a `{number, org}` hash, and `locations` one to a `[ latitude, longitude ]` pair or a `{lat, lon, radius}` hash (each `unknown` for one the database would not place), and `lists` and `asn_lists` name the sets a `%%%country_codes{name}%%%` and a `%%%asn_lists{name}%%%` token resolve against, standing in for the config. Anything unfixtured is unplaceable, fail-closed as it is live. Present, the gate runs as in the galla; absent, it is skipped. |
| `pressure` | A fixture for the [pressure](#pressure-a-rule-for-when-it-is-under-attack) gate... the count of matched lines it reads, however far back it asks. Present, the gate runs as in the galla; absent, it is skipped. |
| `scores` | A fixture for the [scored](#scored-counted-for-enough) gate... a map of address to what its live hits add up to, standing in for the galla's counts. Present, the gate runs as in the galla; absent, it is skipped. |
| `uptime` | A fixture for the [startup](#startup-only-just-started) gate... how many seconds the galla has been up. Present, the gate runs as in the galla; absent, it is skipped. |
| `rules_hit` | A fixture for the [breadth](#breadth-counted-by-many-rules) gate... a map of address to the rules that have hits against it, standing in for the galla's counts. Present, the gate runs as in the galla; absent, it is skipped. |
| `digest_key` | The key a [digest](#digest-a-hash-in-place-of-a-name) gate hashes under, standing in for the config's. Present, the gate runs as in the galla; absent, it is skipped. |
| `accounts` | A fixture for the [account](#account-a-real-account-or-a-guess) gate... the list of names that are accounts, or a hash of name to `{uid, shell, groups}`, every other name being nobody's. Present, the gate runs as in the galla; absent, it is skipped. |

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
`pressure` one. `limit` and `after` need none, their windows being their
own, and every entry starts with none open. `forgive` has no fixture, the
counts it takes hits back out of being the galla's, so it is proven
galla-side only. `namtar_list` and `active_time` have no fixture, their
lists and windows being config a rule file has none of, so those two stay
proven galla-side only (see each gate below). `ban_not_internal` has none
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
          fields: { postfix_client_ip: "203.0.113.9" }
      data:
        postfix_client_ip: "203.0.113.9"   # lifted by into, never on this line
      tracked_expected:
        - name: mail-queue
          key: 1C36D185729
          fields: { postfix_to: "victim@example.org" }
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
a flat [`gate`](#gate) list, the [`keywords`](#keywords) shorthand, and the
boolean [`selections` / `condition`](#selections--condition).

What a `field` names depends on the type... a regexp capture (syslog/raw), a
flattened dotted path (json), a parsed access/error-log field (http,
http_error). Three names are reserved:

- `%%%ANY%%%` :: Fans the predicate over every field value and, on syslog
      and raw, the message.
- `%%%ANY:<prefix>%%%` :: Fans it over just the fields at or under `prefix`.
- `MESSAGE` :: On syslog and raw, the whole message.

#### gate

Optional, a list of entries, ANDed. Each names a field and the values it
must have. A field the line does not carry never matches.

The legacy form is `{field, values: [ ... ]}`, where a values entry starting
and ending with `//` is a regexp and everything else is string equality:

```yaml
rule_gates:
  - gate:
      - field: event_type
        values: [ alert ]
      - field: alert.category
        values: [ "//Attack$//", "Misc activity" ]
```

The typed form is opt-in, detected by the presence of an `op`, `value`,
`all`, `negate`, `nocase`, `fieldref`, or `decode` key. A plain
`field`/`values` entry stays the legacy form above.

```yaml
rule_gates:
  - gate:
      - { field: event,     op: eq,       value: auth_fail }
      - { field: bytes_out, op: gt,       value: 1000000 }
      - { field: src,       op: cidr,     values: [ 10.0.0.0/8, 2001:db8::/32 ] }
      - { field: cmd,       op: contains, values: [ psexec, mimikatz ], all: false }
      - { field: user,      op: eq,       value: healthcheck, negate: true }
```

- `op` :: The operator.
    - default :: `eq`
    - `eq` / `contains` / `startswith` / `endswith` :: The string tests.
    - `re` :: A regexp, [tokens](#message_regexp) included.
    - `gt` / `lt` / `ge` / `le` :: Numeric. The field is read as a number,
          and one that is not a number is treated as missing.
    - `cidr` :: IPv4 or IPv6 membership.
    - `exists` :: The field is present, whatever its value... Sigma's
          `|exists`. It takes no value, and with `negate` it is the
          field-absent test.
- `value` / `values` :: One scalar or a non-empty list. The entry holds if
      any of them does, or all of them when `all` is true.
- `fieldref` :: Names another field to compare against instead of a literal,
      its value at match time being what is compared, Sigma's `|fieldref`. It
      stands in for `value`/`values`. `eq`, `contains`, `startswith`, and
      `endswith` take it, and so do `gt`, `lt`, `ge`, and `le`, for which
      the referenced field has to be a number.
- `times` :: Beside a `fieldref` under a numeric op, what the referenced
      number is multiplied by first, so one field is held to a share of
      another... `{ field: errors, op: gt, fieldref: requests, times: 0.9 }`
      is errors above nine in ten of requests.
    - default :: 1
- `measure` :: Beside a numeric op, what of the value is compared in place
      of the value... `length`, how many bytes long it is, `entropy`, how
      many bits of it a byte carries, 0 for one byte over and over up to 8,
      or `count`, how many times the regexp in `of` matches in it. A
      400-byte account name, or a random-looking host name, is rarely a
      person's: `{ field: user, measure: length, op: gt, value: 64 }`. It is
      taken after any `decode`. No value scores more entropy than the log2
      of its length, so twenty bytes of anything are 4.3 at the most, and a
      mark on a short field has to sit lower.
- `of` :: Beside a `measure` of `count`, the regexp counted, the
      [tokens](#message_regexp) included and folded under `nocase`. Three
      `../` in one path, or two SQL words in one query, is another thing
      from one: `{ field: query, measure: count, of: '(?i)\b(?:union|select)\b', op: ge, value: 2 }`.
- `all` :: Require every value to match rather than any.
    - default :: false
- `negate` :: Invert the entry.
- `nocase` :: Case-fold the compare.
    - default :: false
- `decode` :: A list of transforms run left to right over the field value
      before the operator, so an obfuscated payload is compared decoded.

`fieldref` is how a rule says two fields must agree, or with `negate` must
not... `{ field: auth_user, op: eq, fieldref: cert_user }`. Setting it beside
a `value` or `values` is an error, and a referenced field the line does not
carry is a non-match. It folds under `nocase` and its source decodes under
`decode` like any other compare.

A negated entry also holds when the field is absent, matching Sigma's
field-absent semantics.

Baphomet matches case-sensitively, so `nocase` is what gives Sigma's
default-insensitive matching, and a Sigma `|cased` field is just the
default. It applies to the string ops and to `re`, and is an error on the
numeric and cidr ops, where it means nothing.

The `decode` transforms are `base64`, `base64offset` (the three alignment
candidates), `utf16le` / `utf16be` / `utf16` (`wide` being an alias for
`utf16le`), `windash`, `url`, `lower`, and `upper`. A transform that can not
decode a value drops that candidate, so a bad decode simply does not match.
`decode: [ base64, utf16le ]` with `op: contains` is the PowerShell `-enc`
shape.

#### keywords

Optional, shorthand for a `contains` over the keyword field. A plain list
searches every field:

```yaml
rule_gates:
  - keywords: [ mimikatz, sekurlsa, "Invoke-Mimikatz" ]
```

The table form scopes it with `in`... a field path, a `%%%ANY:prefix%%%`
subtree, or `%%%ANY%%%`, which is the default... so nothing unrelated is
searched when the path is known:

```yaml
rule_gates:
  - keywords:
      in: process.command_line
      values: [ mimikatz ]
```

Keywords are ANDed with any `gate` or `condition`, and may stand alone as
the whole matcher.

#### selections / condition

Optional, the boolean form and an alternative to `gate`... a rule carries
one or the other. The `condition` gate is told a hash of the two.
`selections` is a table of named selections, each a list of gate entries,
legacy or typed, ANDed together. `condition` is a string composing the
selections with `and`, `or`, `not`, parens, and the quantifiers
`all of them`, `1 of them`, and `N of <prefix>_*`. That gives the OR, the
nesting, and the N-of-M a flat gate can not express, the Sigma detection
model.

```yaml
rule_gates:
  - condition:
      condition: "auth and admin and not trust"
      selections:
        auth:  [ { field: event, op: eq, value: authFailure } ]
        admin: [ { field: user,  op: eq, values: [ root, admin ] } ]
        trust: [ { field: src,   op: cidr, value: 10.0.0.0/8 } ]
```

A selection referenced but not defined, an unbalanced paren, or a stray
token is a load-time error, as is a `condition` gate with out either of
the two, or one beside a `gate`.

### rule_gates... what a match still has to clear

A match says a line looks like an offense. `rule_gates` is the whole list a
line goes down, and twenty-two of its gate types are what a match still has to
clear to count as one, each asking something the line can not answer for
itself... if an address is branded, what country or network it is in, if it
is on a list, what DNS says of it, if a name is a real account, what time
it is, how many like it came before. They are of the offense phase, and
legal on every rule type.

```yaml
rule_gates:
  - active_time: { isnot: [ business ] }
  - marked: { name: brute_force, var: SRC }
  - ban_var: [ SRC ]
  - country: { isnot: [ "%%%country_codes{home}%%%" ] }
  - reverse_dns: { matches: '\.example\.org$', negate: true }
```

Each entry is a hash of one key, the gate's type, over what that gate is
told. The twenty-two are...

- [`marked`](#marks-cross-rule-state-keyed-by-anything) :: The key has a
      brand.
- [`not_marked`](#marks-cross-rule-state-keyed-by-anything) :: The key has
      no such brand.
- [`sequence`](#sequence-marks-in-order) :: The key was branded in an order.
- [`country`](#country-narrowing-an-offense-by-geography) :: An address is
      in, or out of, a set of countries.
- [`asn`](#asn-narrowing-an-offense-by-network) :: An address is on, or
      off, a set of networks.
- [`namtar_list`](#namtar_list-only-the-already-condemned) :: A value is on
      a named list.
- [`active_time`](#active_time-only-in-or-out-of-certain-hours) :: The time
      is in, or out of, named windows.
- [`reverse_dns`](#reverse_dns-the-client-is-who-its-address-says) :: An
      address reverses to what it should.
- [`dnsbl`](#dnsbl-what-a-blocklist-says-of-an-address) :: An address is on
      a DNS blocklist.
- [`account`](#account-a-real-account-or-a-guess) :: A name is, or is not,
      an account of the host.
- [`limit`](#limit-only-so-many-of-a-key) :: Only so many offenses of a key
      are let by in a window.
- [`after`](#after-only-once-a-key-has-been-seen-enough) :: A key has been
      seen often enough in a window.
- [`sum`](#sum-how-much-not-how-often) :: A number has added up to enough
      for a key in a window.
- [`beacon`](#beacon-like-clockwork) :: A key's offenses come at even
      gaps.
- [`sample`](#sample-one-in-so-many) :: Only one offense in so many is
      let by.
- [`address`](#address-what-kind-of-address-it-is) :: An address is, or
      is not, of a kind the address space sets aside.
- [`concurrent`](#concurrent-too-many-at-once) :: A key is seen with too
      many values at once.
- [`breadth`](#breadth-counted-by-many-rules) :: An address has been
      counted by many rules.
- [`scored`](#scored-counted-for-enough) :: An address has been counted for
      enough, over every rule.
- [`travel`](#travel-further-than-it-could-have-gone) :: A key is seen
      further away than it could have gone.
- [`novel`](#novel-a-value-a-key-has-not-had-before) :: A key is seen with
      a value it has not had before.
- [`banished`](#banished-what-an-address-has-already-been-banished-for) ::
      An address is banished now, or has been so often of late.

**Every entry has to hold.** The first that does not ends the asking, so
among these gates the order written decides only what a veto spares... put
the gate cheapest to ask, or likeliest to veto, first, and one that goes to
DNS last. A type may be named more than once, which is how one rule gates
the country of both a captured address and the offender.

**What an entry keys on decides what it is asked of.** One naming a `var`
or `vars` reads a found value, resolved like `ban_var`, so JSON dotted paths
work. It is asked once for the whole result, needs no offender, and a veto
drops the result. One naming neither keys on the offender and is asked once
per candidate, filtering which of them count, like `ban_not_internal`, so
it has to be written below the `ban_var` that names them. `active_time` is
the exception... with no var it keys on the clock, so it is always asked
once for the result. `account`, `limit`, `after`, `sum`, `beacon`,
`sample`, `travel`, and `novel` only ever key on a found value, or on
none, so they are asked once for the result too.

**A rule that can not have a gate does not load.** An entry naming a type
there is none of, one telling a gate what it does not know, one keyed by
the offender with no `ban_var` above it, and one keyed by the offender on a
[detection rule](#detection_var), which has no offender for it to key on,
each die when the rule loads rather than leave it counting what its author
gated off.

### marks... cross-rule state, keyed by anything

Correlation (below) ties lines together with in one rule. Marks tie rules
together... a mark is a named, expiring brand a rule leaves on a key that a
later rule, in the same or another watcher of that galla, can gate on. It is
how one rule remembers something for another, Sagan's xbits and flexbits. The
mark gates are legal on every rule type, the two that read a brand being among
those [a match still has to clear](#rule_gates-what-a-match-still-has-to-clear).

The key defaults to the offender IP, but any capture or field of the matched
line can be the key (`var`), or several joined into one compound key
(`vars`), and a mark can carry a value harvested from the line too
(`value_var`)... so a mark can remember not just "this IP" but "this
username", "this source on this account", and store "the address that used
it".

| gate or key | what |
| --- | --- |
| `mark` | A gate, one entry per brand to set on match. Told `{name, ttl, var?, vars?, value_var?}`. `name` is the mark's name, `ttl` its life in seconds. Without `var`/`vars` the brand is keyed by each offender IP, with `var` by that capture, with `vars` by the named captures joined into one compound key. `value_var` names a capture to store on the brand. |
| `unmark` | A gate, one entry per brand to lift on match. Told `{name, var?, vars?}`. A successful login lifting a suspicion, say. |
| `marked` | A gate... the entry holds when the brand is set. Told `{name\|names, var?, vars?, value_is?, value_not?}`. `names` in place of `name` is a any-of... the entry holds when any listed brand is set. A var/vars-keyed entry is checked against the line's captures, a var-less one against each offender IP. `value_is`/`value_not` (at most one) name a capture the stored value must equal or differ from. `older_than`/`newer_than` and `hosts` ask [more of the brand](#how-old-a-brand-is-and-who-set-it). |
| `not_marked` | A gate, the inverse... the entry holds when the named brand is not set. Told `{name, var?, vars?, value_is?, value_not?}`, with the same keying and the same value compares... with one, a live brand only vetoes when the compare holds, so `value_is` spares a brand storing a *different* value and `value_not` one storing the *same*. A compare that can not be evaluated still vetoes. |
| `mark_only` | A key of the rule. When true the rule only brands and gates, never counting toward a ban, and does not consume the line, so matching falls through to the later rules. |

#### How old a brand is, and who set it

A `marked` may ask two things more of a brand than its being there.

```yaml
rule_gates:
  - marked: { name: logged-in, var: USER, newer_than: 300 }
  - ban_var: [ SRC ]
  - marked: { name: recon, hosts: 3 }
```

- `older_than` / `newer_than` :: Seconds the brand has to have been set for
      at least, or for less than. A brand is as old as when it was first
      set, however often it has been set since, so the first is "still at
      it a day after being branded" and the second "with in five minutes
      of the login". Both together are a span of ages.
- `hosts` :: How many hosts of a fleet have to have set the brand, this one
      among them when it has. A scan that touches each host once is under
      every count any one of them keeps, and is three hosts having seen the
      one address.

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
marks tablet, unlike correlation context. Scope is the galla, so marks
cross watchers and rules but not kurs. Each mark name is capped, and the
ignored are never branded.

#### sequence... marks in order

`marked` asks whether brands are set. `sequence` asks whether they were set
in order... a rule watching several stages, one `mark_only` rule branding
each, fires only when they happened in sequence. Legal on every rule type.

```yaml
rule_gates:
  - sequence:
      marks: [ recon, foothold, exfil ]
      var: HOST
```

The gate is told:

- `marks` :: Two or more mark names that must all be set for the key, in the
      listed order by when each first fired.
- `var` / `vars` :: Optional, at most one of them. The capture keying the
      correlation, or several joined into one compound key, as on a `mark`.
      Without either the key is the offender IP.

A stage that is missing, expired, or out of order fails the gate. The
ordering compares each brand's first-seen time, which a later re-branding
does not move, and two stages in the same instant count as in order. That
time survives a restart and rides the fleet mark sync bus, so a fleet-shared
sequence correlates stages seen on different machines. Unordered
correlation, all stages present in any order, is the plain `marked` gate
over the same brands.

#### The galla's own brands

Two brand names are the galla's. It brands every address it banishes under
`banished`, for as long as the ban is to last, and under `banishments`,
valued with when each of its last twenty bans was made, for ninety days.
The [`banished`](#banished-what-an-address-has-already-been-banished-for)
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

- `track` :: The gate that harvests, one entry per record this rule is
      party to. Each names the record (`name`), the found var holding the
      joining id (`key`, or a list of them for a compound key), optionally
      the found vars to contribute (`fields`, defaulting to everything
      found), optionally a `ttl` in seconds, default 3600, and optionally a
      `count`, a field of the record to keep a tally in, one more for each
      line the rule harvests into it.

- `tracked` :: The gate that reads, one entry per record. Each names a
      record and carries at least one of `where` (predicate entries, the
      ordinary gate vocabulary, judged against the **stored** record rather
      than the line) and `into` (stored fields lifted into this line's
      offense). It takes no key of its own, using the one the `track` beside
      it declared.

- `not_tracked` :: The inverse gate, naming a record and nothing else. It
      means "no live record for this key". A record that exists but does not
      match is already `tracked` with a negated `where`.

- `track_only` :: `mark_only`'s sibling. The rule harvests, never counts,
      and does not consume the line.

A `tracked` or `not_tracked` naming a record the rule declared no `track`
for will not load, the declaration being what the read is a read of. So a
rule that reads is always also a rule that harvests... one with nothing of
its own to add says so with `fields: []`, which still keeps the record
alive on every sighting. Nor will a `tracked` carrying neither `where` nor
`into` load, doing nothing being worth saying out loud.

Four states a read can find:

| the key | the record | `where` | what happens |
|---|---|---|---|
| does not resolve | — | — | no veto. A `NOQUEUE` reject carries no queue id and must sail through |
| resolves | none | present | veto, failing closed, as country and namtar_list do |
| resolves | none | absent | no veto. Nothing lifts, so a `ban_var` naming a lifted field finds nothing |
| resolves | exists | names a field no line ever gave | veto. A missing value fails every operator but `exists`, which makes `{ op: exists, negate: true }` the never-appeared test |

The harvest runs whether or not the message regexps hit and whether or not
the gates that judge held, a record being a record of the transaction
rather than of offenses. Only a gate above it that turns the line away
outright stops it, as the `daemons` gate and `ignore` do: the one because a
postfix track has no business reading sshd lines, the other because
`ignore` is the operator saying this line is not evidence. With the `track`
written below the `tracked` that reads its record, the read at 1.8 precedes
the write at 1.9, so a `where` judges the history rather than a record the
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

### country... narrowing an offense by geography

A `country` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
only lets a match count when the offender, or some captured address, is in
(or not in) a set of countries. It needs a GeoIP database, the `geoip_db`
config setting, read through the optional `IP::Geolocation::MMDB` module.

```yaml
rule_gates:
  - ban_var: [ SRC ]
  - country:
      isnot:                              # count only if NOT in these
        - "%%%country_codes{allowed}%%%"  # import a named list from the config
        - "MX"                            # literal 2-letter codes compose too
max_score: 1
```

`is` or `isnot`, never both. Each list entry is either a literal ISO 3166
2-letter code or the `%%%country_codes{name}%%%` token, which splices in a
named list from the config, layered per watcher... so a shipped rule stays
geography-neutral and the operator owns the policy. A bare string is taken as
a one-element list.

By default the gate checks the offender IP being counted. An optional `vars`
list checks the country of named found vars instead:

```yaml
rule_gates:
  - country:
      is: [ "%%%country_codes{yours}%%%" ]
      vars: [ dest_ip ]        # gate on the dest's country, still ban the src
  - ban_var: [ src_ip ]
```

- **No `vars`** ... offender-keyed. Written below the `ban_var` and checked
  per candidate, filtering which offenders count, like `ban_not_internal`.
- **`vars` given** ... data-keyed. Checked once per result against the named
  found vars (resolved like `ban_var`, so JSON dotted paths work); all must
  pass, and a veto drops the whole result.

A rule wanting both names the gate twice, an entry on the dest and an entry
on the offender.

#### into... the country as a found var

`into` lifts the code the gate looked up into a found var, for what is
below the gate and the counting to read. This is one account seen from two
countries inside an hour:

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
it, which is why it only sights. The same lift lets a
[`mark`](#marks-cross-rule-state-keyed-by-anything) store the code as its
`value_var` and a `marked` compare against it with `value_not`... a login
from a country the account did not last use.

- `into` needs exactly one entry in `vars`. An offense may have several
  offenders, each in a country of its own, and the var holds one value.
- With an `into`, `is` and `isnot` are both optional. A gate with neither
  judges nothing and vetoes nothing... an address that does not locate
  leaves the var unset, and `distinct`, `mark`, and `marked` each fail
  closed on an unset var for themselves.
- It never lifts over a value the offense already has.
- Only what is asked once there is an offense can read it... `distinct`,
  the mark gates, `namtar_list`, and the EVE event. `gate`, `condition`,
  `keywords`, and `track` are asked of the line, before any `country` gate
  is.

The gate always **fails closed**: a value that does not locate, or a missing
database, blocks the count rather than risking a wrong ban. A galla with
country-gated rules and no loadable database says so loudly at start.

Two shipped families use the gate, both importing `country_codes{home}` and
neither shipping the policy... each does nothing until you both list it in a
watcher and name your home countries in the config, and dies loudly if listed
without them. All of them prove their gate from their own tests with a
[`geo` fixture](#tests).

- **`syslog/sshd-foreign-login`** and its `dovecot`/`postfix-sasl` siblings...
  each matches a successful login and is **detection-only**, since a foreign
  login is a traveler or a takeover and the rule can not tell which.
- **`%syslog/foreign-auth%`**, thirteen rules... each matches its service's
  whole offense vocabulary *plus* that service's successful login, and
  **bans**, at `max_score: 1`. The blunt policy, for the drive-by that probes
  a few credentials and moves on faster than any per-service threshold can
  answer. It banishes on a login that worked, which is deliberate and which
  will banish a traveling admin mid-session, so read the group file before
  listing it. Run one family or the other per service, not both.

Order the ban family **ahead** of the per-service rules it shadows. A vetoed
gate does not consume the line (see
[the order it runs in](#the-order-it-runs-in)), so a domestic event falls
straight through and counts at the ordinary rule exactly as before, while
foreign traffic is peeled off the top.

Beyond these, a geography policy is yours to compose... any offense rule plus
a `country` gate and your own `country_codes` lists.

### namtar_list... only the already-condemned

A `namtar_list` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
only lets a match count when a value appears on a named
blocklist, the inverse of `ignore_ips`. The lists are named in the config's
`namtar_lists`, layered per watcher and reloaded on mtime change, so a rule
can count only what a feed you supply condemns. A list is either a **CIDR
list** matched by address containment, or a **string list** matched by exact
(optionally case-folded) equality... so the gate reaches beyond IPs to any
field a rule captures, a username, a URI, a user-agent. The flavor is set on
the list in the config, not here, so a rule stays a pure matcher.

```yaml
rule_gates:
  - namtar_list:
      lists: [ threatfeed, torexits ]   # SRC on ANY of these (union)
      var: SRC
  - namtar_list:
      list: bait_users                  # a string list of honeypot accounts
      var: USER                         # check the user, still ban the offender
max_score: 1
```

An entry names one or more lists (`lists`, or `list` for one) and,
optionally, the found var to check (resolved like `ban_var`, so JSON dotted
paths work); without a var it checks the offender IP. A value on **any** of
an entry's lists satisfies it (union), even across flavors, and of a rule's
entries **every** one must hold. Like the country gate, a var entry is
data-keyed and vets the whole result while a var-less one filters offenders.

The gate **fails closed**: an address on no list, or a list whose file is
unreadable or empty, blocks the count... an absent feed banishes nobody,
never everybody. `ignore_ips` still wins absolutely. There is no shipped
namtar rule, since which addresses are condemned is your policy.

### active_time... only in, or out of, certain hours

A `active_time` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
only lets a match count when the time falls in, or out of, named windows...
an admin login that is routine at midday and worth a ban at 03:00. The
windows are defined in the config's `active_time`, layered per watcher.

```yaml
rule_gates:
  - active_time:
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

A `reverse_dns` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
compares the PTR names of an address against a regexp
or against another found value, negatable... how a claim in the log is
checked against what DNS says about the client. The gate that finally
ports `apache-fakegooglebot` (shipped as `http/fakegooglebot`): a
user-agent claiming Googlebot whose client does not reverse into Google's
domains is a pretender.

It sits behind the galla's `enable_rdns` consent, on by default, and rides
the optional `Net::DNS` and `POE::Component::Client::DNS` modules (see
[install](install.md)).

```yaml
rule_gates:
  - ban_var: [ SRC ]
  - reverse_dns:
      matches: '\.google(?:bot)?\.com$'   # regexp over the PTR names
      negate: true                        # count when it does NOT hold
  - reverse_dns:
      var: SRC                            # gate a named found value instead
      matches_var: HELO                   # ... against another found value
      forward_confirm: false              # default true, see below
```

An entry names exactly one of
`matches` (a Perl regexp any PTR name must satisfy) or `matches_var`
(equality against another found value, case-folded, trailing dots
stripped). A `var` entry checks that found value's address once per result,
vetoing the whole result; a var-less entry checks each offender the
`ban_var` above it names, like `country`. `negate` inverts the comparison.

`into` lifts a PTR name of the address into a found var when the gate
holds, under the rules
[`country`'s `into`](#into-the-country-as-a-found-var) has... the name the
comparison hit on, or under `negate`, where it holds on hitting none, the
first that took part. It needs a `var`.

**Forward confirmation is on by default.** An attacker controls their own
PTR, so with out it a negated Google pattern is evaded by pointing your
PTR at `anything.googlebot.com`. A PTR name only participates when it
resolves back to the address it came from... a spoofed PTR is as good as
absent. `forward_confirm: false` is for cheap heuristics only.

**Absence is an answer; failure is not... by default, and per rule.** An
authoritative empty PTR set compares false... so `negate` counts the
client with no reverse DNS at all, which is most fake bots. A timeout or
SERVFAIL vetoes the count regardless of `negate`, so an outage can never
get the real Googlebot banished. Both verdicts are the entry's to override:

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
resolver, `enable_rdns` off (see [configuration](configuration.md)), a
non-address value, a missing `matches_var`.

Lookups happen per match, not per line, bounded by `rdns_timeout` and
cached... still, keep the gate behind a cheap matcher, never on a rule
that matches everything, and the last of its gates that judge so a cheaper
gate's veto spares the lookup. Unlike the config-side gates, a rule's embedded
tests exercise this one whole... a `dns` fixture in the test stands in
for the resolver, PTRs, forwards, absences, and outages alike (see
[tests](#tests)), which is how `http/fakegooglebot` proves its judgment
from its own file.

### asn... narrowing an offense by network

An `asn` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
only lets a match count when the offender, or some captured address, is on
(or off) a set of networks... the autonomous systems the internet is routed
by, each a number and the name of who runs it. It is `country` asking a
different question of the same address, and is written the same way. It
needs MaxMind's ASN database, the `geoip_asn_db` config setting, read
through the same optional `IP::Geolocation::MMDB` module.

```yaml
rule_gates:
  - ban_var: [ SRC ]
  - asn:
      isnot:                           # count only if NOT on these
        - "%%%asn_lists{office}%%%"    # import a named list from the config
        - AS64496                      # literal numbers compose too
max_score: 1
```

- `is` / `isnot` :: By number. Each entry is an AS number, bare or written
      `AS64496`, or a `%%%asn_lists{name}%%%` token.
- `org_is` / `org_isnot` :: By name. A regexp, or a list of them, matched
      against the name the database gives the network. Case-sensitive, so
      lead one with `(?i)` to fold it.
- `vars` :: The found vars holding the addresses to check, in place of the
      offender.
- `into` / `org_into` :: Lift the number and the name into found vars, under
      the rules [`country`'s `into`](#into-the-country-as-a-found-var) has.

At most one of the four that judge may be written, and a gate that lifts
needs none of them.

A number is the stable thing to list. The names are the database's own and
drift, so they are for the broad sweep, `org_is: '(?i)hosting|cloud|vps'`.

The gate **fails closed** like `country`... an address the database does
not place, or a missing database, blocks the count, and a network with no
name can not be cleared by `org_isnot`. It is proved from the rule file
with the `asns` and `asn_lists` of a [`geo` fixture](#proving-lookups).

### travel... further than it could have gone

A `travel` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
holds when a key is seen at an address too far from the one it was last
seen at for the time between the two. An account that logs in from one
continent and an hour later from another did not fly there. It needs
MaxMind's City database, the `geoip_city_db` config setting, read through
the same optional `IP::Geolocation::MMDB` module.

```yaml
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - travel: { name: last-login, by: USER, var: SRC, faster_than_kmh: 900 }
  - detection_var: [ SRC ]
```

- `name` :: The brand the sightings are kept in.
- `by` :: The found var, or a list of them, whose values joined are the
      key.
- `var` :: The found var holding the address.
- `faster_than_kmh` :: The speed it has to have taken more than.
- `min_km` :: The least distance worth asking the speed of, so two
      addresses in one city never trip it.
    - default :: 100
- `ttl` :: Seconds a sighting is kept.
    - default :: 2592000
- `km_into` / `kmh_into` :: Lift the distance and the speed into found vars,
      so the EVE event says how far and how fast.

Every offense that reaches the gate is a sighting, and takes the place of
the key's last one whether or not the gate held. So an intruder's login
fires once, and the owner's next one from home fires again... both true.
The distance is the great circle one less the accuracy radius the database
gives each place, so an address placed only roughly is not held to a
point.

**Feed it only what the owner of the key can do.** A failed login from
anywhere would move where the account was last seen, so the gate belongs
on a rule matching logins that worked, and below any gate that could veto
one, so a login the rule turned down is not kept as a sighting.

The sightings are [brands](#marks-cross-rule-state-keyed-by-anything) of
the gate's `name`, each valued `latitude longitude radius time`. They are
kept as any brand is... across the watchers of a galla, across a restart,
and across a fleet on a Redis tablet, so a login on one host and then
another is measured. `baphomet marked` shows them.

It does not hold on a first sighting, or on an address the database can
not place, which is not kept as a sighting either. Mobile and VPN addresses
place badly, so keep it on a `detection_var`, and put an
[`asn`](#asn-narrowing-an-offense-by-network) gate above it to spare the
carriers you know. It is proved from the rule file with the `locations` of
a [`geo` fixture](#proving-lookups).

### network... the network as a found var

A `network` gate lifts the network an address is in into a found var, and
does nothing else. It judges nothing and vetoes nothing. An attack that
comes from one address after another out of the one provider stays under
every count kept by address, and is one key once it is counted by network.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - network: { var: SRC, into: NET }
  - after: { by: NET, count: 30, seconds: 600 }
  - ban_var: [ SRC ]
max_score: 1
```

- `var` :: The found var holding the address.
- `into` :: The found var the network is lifted into, as a CIDR.
- `v4` :: The prefix length an IPv4 address is cut to.
    - default :: 24
- `v6` :: The prefix length an IPv6 address is cut to.
    - default :: 64

What can read it is what can read [`country`'s
`into`](#into-the-country-as-a-found-var)... `after`, `limit`, `sum`,
`distinct`, and the mark gates. A value that is not an address lifts
nothing, and each of those fails closed on an unset var for itself. This
only names the network. Banishing one is the config's
[subnet banning](configuration.md#subnet-banning).

### address... what kind of address it is

An `address` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
holds when an address is of one of the kinds the address space sets aside,
for `is`, or of none of them, for `isnot`. No list of yours has to name
them.

```yaml
rule_gates:
  - ban_var: [ SRC ]
  - address: { isnot: [ private, cgnat, loopback ] }
```

- `is` / `isnot` :: Exactly one. A kind, or a list of them.
- `var` :: The found var holding the address, in place of the offender.

The kinds...

- `private` :: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and
      `fc00::/7`.
- `loopback` :: `127.0.0.0/8` and `::1`.
- `link_local` :: `169.254.0.0/16` and `fe80::/10`.
- `cgnat` :: `100.64.0.0/10`, a carrier's shared space.
- `documentation` :: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
      and `2001:db8::/32`.
- `multicast` :: `224.0.0.0/4` and `ff00::/8`.
- `bogon` :: Any address no one on the internet can have... all of the
      above, and `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`,
      `240.0.0.0/4`, and `::`.

[`ban_not_internal`](#ban_not_internal) spares the hosts you listed as your
own. This knows the ones no list needs to name. A source from behind a
carrier's NAT is shared by every customer behind it, and banning it bans
them all. A bogon source in a firewall log is spoofed traffic, not an
attacker to banish. A value that is not an address fails closed whichever
way the gate asks.

### novel... a value a key has not had before

A `novel` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
holds when a key is seen with a value it has not been seen with before,
once the key has been seen often enough to have a before. An account that
has only ever logged in from one country and now logs in from another.

```yaml
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - country: { vars: [ SRC ], into: COUNTRY }
  - novel: { name: login-country, by: USER, of: COUNTRY }
  - detection_var: [ SRC ]
```

- `name` :: The brand the sightings are kept in.
- `by` :: The found var, or a list of them, whose values joined are the
      key.
- `of` :: The found var holding the value.
- `ttl` :: Seconds a value is remembered after it was last seen, after
      which it is new again.
    - default :: 2592000
- `after_seen` :: How many times a key has to have been seen before a
      value new to it holds.
    - default :: 3

A `not_marked` over the key and the value with a `mark` below it says
nearly the same, and holds on every account's very first login, all of a
new key's values being new. `after_seen` is what this adds... a key with no
history is learned from and not reported.

Every offense that reaches the gate is a sighting and is remembered,
whether or not the gate held. Like [`travel`](#travel-further-than-it-could-have-gone)
it keeps what it knows as brands of its `name`, one under the key valued
with how often the key has been seen and one under the key and each value,
so it survives a restart and is shared with a fleet. Feed it only what the
owner of the key can do. It is proved from the rule file with
`marks_before` and `marks_expected`.

### dnsbl... what a blocklist says of an address

A `dnsbl` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
asks one or more DNS blocklists about an address and holds when any of
them lists it... what a mail server does with `reject_rbl_client`, for any
rule.

```yaml
rule_gates:
  - ban_var: [ SRC ]
  - dnsbl:
      zones: [ bl.example.org, dnsbl.example.net ]
      codes: [ 127.0.0.2, 127.0.0.4 ]    # only these answers count
max_score: 1
```

- `zones` :: The zone to ask, or a list of them.
- `var` :: The found var holding the address to check, in place of the
      offender.
- `codes` :: The answers that count as a listing.
    - default :: any answer a zone lists with
- `negate` :: Hold when no zone lists the address.
- `on_servfail` :: What a failed lookup does when no zone lists the
      address, `pass` or `fail`.
    - default :: `fail`
- `zone_into` / `code_into` :: Lift the zone that listed the address, and
      the answer it gave, into found vars, so the EVE event says why. Either
      needs a `var`, and a gate holding on no listing lifts nothing.

**It tells a third party who you were talking to.** Every lookup hands the
address to whoever runs the zone, so the gate sits behind a consent of its
own, `enable_dnsbl`, off by default. With out it the gate fails closed,
loudly. An address on your `internal` list is never asked about. Most
public blocklists also meter or refuse queries that come by way of a large
shared resolver, so read a zone's terms before naming it.

**A zone that could not be asked clears nobody.** A listing in any zone
stands, whatever became of the others. With no listing, a timeout or
SERVFAIL settles the gate by `on_servfail`, `negate` or not. Two answers
are read as a failed lookup and never as a listing... one out of
`127.255.255.0/24`, which is how a zone says it refused the query, and one
that is not out of `127.0.0.0/8` at all, which is what a parked or hijacked
zone gives.

The lookups ride the machinery of
[`reverse_dns`](#reverse_dns-the-client-is-who-its-address-says)... the
same optional modules, `rdns_timeout`, a one minute cache, and under a
running galla the background engine, so a cold address fails its first
line and is answered for the next. Keep it the last of a rule's gates that
judge. It is proved from the rule file with the `dnsbl` map of a
[`dns` fixture](#proving-lookups).

### normalize... the path a server would make of it

A `normalize` gate lifts a copy of a request path, made the way a server
makes it before it looks for the file. A rule matching on the copy is not got
round by writing the one path another way... `/%77p-login.php`,
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

- `var` :: The found var holding the path.
- `into` :: The found var the copy is lifted into.
- `ops` :: The steps to do, a list of the names below.

The path is split from its query at the first `?` or `#` ahead of anything
else, as a server splits it, so a `%3f` is never taken for the start of a
query and `/../` in a query is never resolved. The steps run over the path
alone, and always in the order below whatever order `ops` names them in, as
a step done ahead of the one it depends on would leave standing what it was
for... `dot_segment` ahead of `url` would leave `%2e%2e` a segment.

- `url` :: Percent decoding, done again while it changes things, three
      times at the most. `%2577` is `%77` once and `w` twice, which is how a
      filter that decodes once is got past a backend that decodes twice.
- `overlong` :: The overlong UTF-8 forms of an ASCII byte, as `%c0%af` for
      `/`, and IIS's `%u002f` form, made the byte they stand for.
- `nul` :: Everything from a NUL on cut off, as a backend that reads a path
      as a C string does... `/x.php%00.jpg` is `/x.php`.
- `backslash` :: Each `\` made a `/`, as IIS takes it.
- `slashes` :: Each run of `/` made one.
- `params` :: The `;name=value` parameters of each segment cut off, as
      Tomcat's `/admin;x=1/` is `/admin/`.
- `dot_segment` :: The `.` and `..` segments resolved as a server resolves
      them. A `..` that would climb above `/` is dropped, so
      `/../../etc/passwd` is `/etc/passwd`.
- `dot_segment_below` :: The same, but a `..` that would climb above `/` is
      kept, so `/a/../../etc/passwd` is `/../etc/passwd` and a rule can see
      it tried to. Never beside `dot_segment`.
- `lower` :: Lower case, for a server that does not tell the cases apart.
- `query` :: The query left off. With out it the query is put back after
      the path as it was given.

`dot_segment_below` is for a rule about the climb its self:

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

A field a `normalize`, `extract`, or any other gate lifts with an `into` can
be named by the `match` and `ignore` of an http rule, which otherwise only
take the fields of the log format. It is never lifted over a value already
there.

### extract... a capture out of any field

An `extract` gate matches a regexp against a field and lifts its named
captures into found vars. `message_regexp` only ever reads the message, and
the `re` op of a `gate` tests a field and keeps nothing of it. This is how a
json or http rule takes the domain out of an address, or a part of a path
out of a request, to key or count on.

```yaml
rule_gates:
  - gate:
      - { field: event, value: login_failed }
  - extract: { var: user, regexp: '@(?<DOMAIN>[^@]+)$' }
  - after: { by: DOMAIN, count: 50, seconds: 600 }
  - ban_var: [ ip ]
```

- `var` :: The field to match against.
- `regexp` :: The regexp, with at least one named capture. The
      [tokens](#message_regexp) `message_regexp` takes work in it too.
- `on_miss` :: What a field it does not match does, `pass` or `fail`.
    - default :: `pass`

It reads what stands when it is asked. Above the matcher it lifts into the
line's fields, which the offense is then made of. Below, into the offense,
captures and all, so it can take apart what a `message_regexp` caught. A
capture is never lifted over a value already there.

### digest... a hash in place of a name

A `digest` gate puts a keyed hash of a found value in place of it. A rule
can still key and count on an account or an address of mail, while the
brands, the tracked records, the counts, and the tablets they are kept in
hold no plaintext. The one name always comes to the one hash under the one
key, so nothing that keys on it is the worse for it, and without the key
the hash is no way back to the name.

```yaml
user_var: USER
eve_line: false
rule_gates:
  - daemons: [ dovecot ]
  - message_regexp:
      - 'auth failed.*user=<(?<USER>[^>]+)>.*rip=%%%%SRC%%%%'
  - digest: { var: USER }
  - after: { by: USER, count: 20, seconds: 600 }
  - ban_var: [ SRC ]
```

- `var` :: The found var to hash.
- `into` :: The found var the hash goes into, the `var` left as it was.
      With out it the `var` is hashed where it is.

**Where it sits decides what sees the name.** The line-phase gates above it
see the value as it was. Those below it, and every gate of the offense
phase wherever it is written, see the hash. So an `account` or
`namtar_list` gate that reads the name needs the `digest` given an `into`,
to keep the name beside the hash, and a rule hashing in place what one of
them reads does not load. Nor does one hashing a var a `ban_var` names, a
ban having to be of the address itself.

**It does not keep the name out of the EVE log** on its own. An event
carries the line the match was found in, and that has the name in it. A
rule's [`eve_line`](#eve_line) of false leaves the line out. A `digest`
with an `into` leaves the name in the found data as well, and so in the
event's `found`... hash in place for the event to hold none of it.

The hash is the first 16 hex digits of an HMAC-SHA256 under the
`digest_key` of the [config](configuration.md). With none set, a rule with
the gate does not load, and the galla does not come up. Every galla of a
fleet needs the one key, for the brands they share to agree. A new key is a
new hash for every value, so what was kept under the old hashes is
forgotten... `novel` and `travel` see every account as new.
`baphomet digest <value>` gives the hash a value comes to, for finding a
name in what `baphomet marked` shows. A rule's tests give the key as a
`digest_key` fixture, and with none the gate is skipped.

### account... a real account or a guess

An `account` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
holds when a found name is, or is not, an account of the host. sshd says
`invalid user` for itself. Dovecot, postfix's SASL, and most web apps log a
failed login the same whether or not the name was real, and the difference
matters... a failure for a name that is nobody's is a guess, and one for a
real account may be its owner's typo.

```yaml
rule_gates:
  - account: { var: USER, exists: false }
  - ban_var: [ SRC ]
max_score: 1
```

- `var` :: The found var holding the name.
- `exists` :: `false` to hold on a name that is no account.
    - default :: `true`
- `shell` :: `nologin` to hold on an account that can not log in, its shell
      being `nologin` or `false`, or `login` to hold on one that can.
- `system` :: `true` to hold on an account the system has for itself, its
      uid being below `system_below`, or `false` to hold on one a person
      was given.
- `system_below` :: The uid the accounts of people start at.
    - default :: 1000
- `group` :: A group, or a list of them, the account has to be in one of.
- `near` :: Beside an `exists: false`, how many letters a name that is no
      account may be off from one that is, for the gate to hold on it.

Listed ahead of the service's ordinary rule, that banishes on the first
guess and lets every other failure fall through to be counted as before.

The last four ask more of an account that is there, and everything asked
has to be so. A login attempt for `www` or `daemon` is as sure a guess as
one for a name that does not exist, and `exists: false` does not see it,
the account being real:

```yaml
rule_gates:
  - account: { var: USER, shell: nologin }
  - ban_var: [ SRC ]
max_score: 1
```

`system: true` is the same idea by another test, for a host whose service
accounts have a real shell. Root's uid is below any mark, so it is one of
the system's... pair it with `shell: nologin` to leave root out. And
`group: wheel` on a rule with a harsher threshold makes a failure against an
administrator worth more than one against anyone else. A group holds its
own account, the one whose primary group it is, as well as the ones it
lists. An `exists: false` can not be written beside any of them, there
being nothing to ask of an account that is none.

`near` is the one thing that can be asked beside an `exists: false`.
`exists: false` treats the owner of `neti` typing `netti` the same as a
guess at `oracle`, and `near` tells them apart:

```yaml
rule_gates:
  - account: { var: USER, exists: false, near: 1 }    # a typo of a real one
  - ban_var: [ SRC ]
```

A letter added, dropped, or changed is one each, so two letters swapped are
two. The names are read out of the system's account database once and kept
five minutes, ten thousand at the most. In a rule's tests they are the names
of the `accounts` fixture.

The accounts are those of the host the galla runs on, asked of the
system's own account database, so LDAP and the like are seen when the host
is set up to see them. Over logs shipped in from another host the gate
means nothing. A name the offense lacks fails closed whichever way the gate
asks, and so does an account whose shell or uid is not known when that is
what is asked. Answers are cached for a minute, and a name no account could
have is never asked about. It is proved from the rule file with an
[`accounts` fixture](#proving-lookups), a list of names, or a hash of name
to `{uid, shell, groups}` when the gate asks more than whether there is
one.

### limit... only so many of a key

A `limit` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
lets the first few offenses of a key by and vetoes the rest until its
window runs out. It is for a detection or `eve_only` rule that sights more
than it needs to say, one noisy source filling the EVE log with the same
event.

```yaml
rule_gates:
  - detection_var: [ SRC ]
  - limit: { by: [ SRC, USER ], count: 3, seconds: 300 }
```

- `by` :: The found var, or a list of them, whose values joined are the
      key.
- `seconds` :: The length of a window, measured from the first offense it
      let by.
- `count` :: How many offenses of a key a window lets by.
    - default :: 1

A vetoed offense is vetoed as by any gate... it is not counted, and the
line goes on to the rules after this one. Where the gate sits decides what
it covers. A `mark` above it brands every offense, and one below it only
what was let by. On a banning rule it slows the count as well, what it
vetoes never reaching the threshold.

The windows are kept per watcher, bounded as the mark store is, and
forgotten at a restart. An offense lacking one of the `by` vars has nothing
to be held to and is let by. It needs no fixture to prove... a `messages`
test with an `advance` walks a window open and shut.

### after... only once a key has been seen enough

An `after` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
is `limit` the other way about... it vetoes the first offenses of a key
and holds from the `count`th with in `seconds` on. A rule's own count is
kept by its offender. This one is kept by anything, which is how a rule
says twenty failures against one account, whoever they came from.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for (?<USER>\S+) from %%%%SRC%%%%'
  - after: { by: USER, count: 20, seconds: 600 }
  - ban_var: [ SRC ]
max_score: 1
```

- `by` :: The found var, or a list of them, whose values joined are the
      key.
- `count` :: How many offenses of a key it takes. Two or more.
- `seconds` :: How long they have to land with in.

That banishes every source that goes on trying the account once it is
under a spread-out attack, each on its first try, where
[`distinct`](#distinct-counting-how-many-not-how-often) would count how
many sources there were. Listed ahead of the service's ordinary rule, the
line of a vetoed offense falls through to be counted as before.

The window slides. An offense holds when it and the `count` less one
before it all landed with in `seconds`, wherever a window might be said to
start. What is seen of a key is kept per watcher, bounded as the mark
store is, and forgotten at a restart. An offense lacking one of the `by`
vars has nothing to be counted under and is vetoed. Like `limit` it needs
no fixture to prove.

### sum... how much, not how often

A `sum` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
is `after` for a number... it adds a found var to a running total for a
key and holds while what the key has added up to with in `seconds` is above
a mark. The bytes sent to one client in an hour, say, off an access log.

```yaml
rule_gates:
  - status: [ 200, 206 ]
  - sum: { by: host, of: bytes, above: 1000000000, seconds: 3600 }
  - detection_var: [ host ]
```

- `by` :: The found var, or a list of them, whose values joined are the
      key.
- `of` :: The found var holding the number to add.
- `above` :: What the total has to be more than.
- `seconds` :: How far back it is added up over.

The total is kept in sixty spans of the `seconds`, so what falls out of it
does so a span at a time, and it may run up to one span long and never
short. It is kept per watcher, bounded as the mark store is, and forgotten
at a restart. An offense lacking one of the `by` vars, or whose `of` is not
a number of zero or more, adds nothing and is vetoed. Like `after` it needs
no fixture to prove.

### beacon... like clockwork

A `beacon` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
holds when the last `count` gaps between a key's offenses are all much the
same length. A host calling home every five minutes, or a slow brute force
on a timer, stays under every count, and is far too even to be a person.

```yaml
rule_gates:
  - beacon: { by: [ SRC, dest ], count: 10, jitter: 0.1 }
  - detection_var: [ SRC ]
```

- `by` :: The found var, or a list of them, whose values joined are the
      key.
- `count` :: How many gaps it takes, two or more.
- `jitter` :: How uneven the gaps may be, as a share of their average.
    - default :: 0.1
- `min_interval` :: The shortest average gap that can be a beacon, in
      seconds. Shorter is a burst.
    - default :: 10
- `max_interval` :: The longest gap that does not start the key over.
    - default :: 86400

How even is the gaps' standard deviation over their average. Gaps of 300,
302, and 298 seconds are well under one percent. Once regular, every even
offense after holds too, until an uneven one breaks it. What is seen of a key
is kept per watcher, bounded as the mark store is, and forgotten at a
restart. An offense lacking one of the `by` vars is vetoed. It needs no
fixture to prove... a `messages` test with an `advance` on each line walks a
rhythm.

### sample... one in so many

A `sample` gate lets the first offense by, then one in every `every` after
it, whatever its key, and vetoes the rest. It thins a whole detection rule
that sights more than anyone will read. A [`limit`](#limit-only-so-many-of-a-key)
holds each key to so many, so a flood from many keys gets through it, and
what `sample` lets by is a fair cut of all of it.

```yaml
rule_gates:
  - detection_var: [ SRC ]
  - sample: { every: 100 }
```

- `every` :: One offense in how many is let by, two or more.

The count is kept per watcher and starts over at a restart. A vetoed offense
is vetoed as by any gate, so the line goes on to the rules after this one.

### breadth... counted by many rules

A `breadth` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
holds when at least `rules` different rules have live hits against an
address, the rule it is of counted among them. A scanner that tries ssh,
ftp, and the web panel once each stays under every count a rule keeps, and
has been counted by three.

```yaml
max_score: 1
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - breadth: { rules: 3, seconds: 3600 }
```

- `rules` :: How many different rules it takes, two or more.
- `seconds` :: How far back a hit is read.
- `of` :: The rules whose hits are counted, in place of all of them. The
      rule the gate is of is counted whether or not it is named.
- `var` :: The found var holding the address, in place of the offender.

It reads the hits the galla is counting, the shared bucket and each rule's
own, observe mode's included. So a hit a ban already cleared, or one older
than its rule's `find_time`, is not there to read, and `seconds` past the
longest `find_time` reads no further back. The rule's own hit on this line
is counted, though it is not in the counts yet.

Listed ahead of the service's ordinary rules, it banishes the address on
the first hit of the third service, and lets every other line fall through
to be counted as before. A hit restored from a tablet written before the
counts said which rule made it is no rule's. It is proved from the rule file
with a [`rules_hit` fixture](#tests).

### scored... counted for enough

A `scored` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
holds when the hits the galla is counting against an address add up to more
than `above`, over every rule. [`breadth`](#breadth-counted-by-many-rules)
says how many rules have counted an address, and this how much they have
counted it for. A source sitting just under the thresholds of several rules
at once is nearer a ban than any one of them shows.

```yaml
max_score: 1
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - scored: { above: 8 }
```

- `above` :: What the hits have to add up to more than.
- `seconds` :: How far back a hit is read. With out it every live hit is.
- `var` :: The found var holding the address, in place of the offender.

It reads the weight of each live hit, the shared bucket and each rule's own,
observe mode's included, with any [`weigh`](#weigh-worth-more-or-less) in
it. A hit a ban already cleared, or one older than its rule's `find_time`,
is not there to read. The hit this line is about to be is not counted, as
its weight is not known until it is. It is proved from the rule file with a
[`scores` fixture](#tests).

### weigh... worth more, or less

A `weigh` gate multiplies the weight a hit is counted with, where every
other gate vetoes or lets by. A failure against an administrator's account
is worth more than one against anyone else's, and the rule counting them can
say so with out a second rule to do it in.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for (?<USER>\S+) from %%%%SRC%%%%'
  - weigh: { times: 3, when: [ { field: USER, op: eq, values: [ root, admin ] } ] }
  - ban_var: [ SRC ]
```

- `times` / `by` :: Exactly one. The number to multiply by, or the found
      var holding it. A var that is not a number above nothing leaves the
      weight as it was.
- `when` :: A list of entries as a [`gate`](#gate) takes, every one of
      which has to hold for it to multiply.

Several multiply one after another, and over the rule's own
[`weight`](#max_score--find_time--ban_time--weight). It vetoes nothing.

It is honored where the rule's own `weight` is... on a watcher with
`allow_per_rule_thresholds`, or when the operator's `rule_config` gives the
rule a `weight`. With out that consent every hit weighs 1, a `weigh` gate
included, so a shipped rule can not reshape the counting. A rule counting
[`distinct`](#distinct-counting-how-many-not-how-often) values has no
weights to multiply. The counts are the galla's, so a rule's embedded tests
run the gate but can not show what it weighed.

### forgive... a login that worked clears the failures

A `forgive` gate takes back the hits other rules have counted against an
address. With out one, someone who mistypes their password four times and
then gets in is one typo from a ban for the rest of the `find_time`. It
vetoes nothing, and sits with `mark` and `unmark` among the gates that act
on an offense that stood.

```yaml
mark_only: true
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - forgive: { rules: [ syslog/sshd ], same: USER }
```

- `rules` :: The rule whose hits are taken back, or a list of them, named
      as a watcher names them.
- `var` :: The found var holding the address to forgive, in place of the
      offender. A detection rule has no offender and needs it.
- `same` :: The found var holding the account the hits have to have been
      about.

**Name a `same`.** With out it one login that worked washes every guess
the address made at every other account, which is what a stuffing run
with one good password looks like. With it only the failures for that
account go. What a hit was about is the value of the
[`user_var`](#src_ip_var--dest_ip_var--src_port_var--dest_port_var--user_var)
of the rule that counted it, so the rule being forgiven has to name one...
a hit of a rule with none is about nobody, and a `same` leaves it.

Only the running counts are touched, the shared bucket and a rule's own
alike. A ban already made stands, as do the subnet counts and what a
`distinct` rule has seen. A rule named that no watcher of the galla lists
is said loudly at start, since a name spelled wrong would otherwise
forgive nothing and say nothing. What is taken back is counted in the
`forgiven` stat.

The counts are the galla's, so a rule's embedded tests can not prove a
`forgive`, and skip it.

### forwarded... the client behind a proxy

A `forwarded` gate names the real client of a request that came through
proxies, lifting its address into a found var for the `ban_var` below it.
Behind a load balancer every line has the balancer's address, and banning
that bans everyone. Taking the header at its word instead lets whoever sent
the request write in any address they like to have banished.

```yaml
rule_gates:
  - status: [ 401, 403 ]
  - forwarded: { var: xff, peer: host, trusted: [ 10.0.0.0/8 ], into: CLIENT }
  - ban_var: [ CLIENT ]
```

- `var` :: The found var holding the forwarding header.
- `peer` :: The found var holding the address the request came from.
- `trusted` :: A CIDR, or a list of them, of the proxies whose word is
      taken.
- `into` :: The found var the client's address is lifted into.
- `max_hops` :: The most hops read before it gives up.
    - default :: 10

The header is believed only as far as the proxies are trusted. A request
whose `peer` is not a trusted proxy is the peer's, and its header is
ignored. One whose peer is a trusted proxy is read from the right, each
address a hop nearer the client, and the first that is not a trusted proxy
is the client. Everything to the left of it was written by that client or
before it, and is never read... so a forged address put ahead of the real
one is never the one banished.

It reads a `X-Forwarded-For` list, addresses a comma apart, or a `Forwarded`
one, the `for=` of each hop. An address may have a port after it, or be an
IPv6 one in brackets. It lifts nothing when it can not say... a peer that is
no address, a hop that is not one, more hops than `max_hops`, or a chain of
nothing but trusted proxies... and the `ban_var` below it then names nobody.
It judges nothing and vetoes nothing.

The header has to be in the log to be read. An access log's common and
combined formats have none, so the server's log format has to be told to
write it, as a json log or a format of its own.

### concurrent... too many at once

A `concurrent` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
holds when a key has been seen with more than `more_than` different values
with in the last `seconds`, this offense's among them. One account logged in
from three addresses in the one ten minutes is an account shared, or one
that is not its owner's any more.

```yaml
rule_gates:
  - daemons: [ sshd, sshd-session ]
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - concurrent: { by: USER, of: SRC, more_than: 2, seconds: 600 }
  - detection_var: [ SRC ]
```

- `by` :: The found var, or a list of them, whose values joined are the
      key.
- `of` :: The found var whose different values are counted.
- `more_than` :: How many values a key may have at once and the gate not
      hold.
- `seconds` :: How long a value counts after it was last seen.

A value seen again stays one value. It says what
[`distinct`](#distinct-counting-how-many-not-how-often) says, as a gate
beside a rule's own counting where `distinct` is the rule's counting,
and a rule can have only one of those. What is seen is kept per watcher,
a thousand values a key at most, and forgotten at a restart. An offense
lacking one of the `by` vars or the `of` is vetoed.

### banished... what an address has already been banished for

A `banished` gate, one of those
[a match still has to clear](#rule_gates-what-a-match-still-has-to-clear),
holds on an address by what the galla has banished it for.

```yaml
# a ban that is not holding... a line from an address a minute into its ban
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - banished: { var: SRC, now: true, for: 60 }
  - detection_var: [ SRC ]
```

```yaml
# a shorter rope for one banished three times this month
max_score: 1
rule_gates:
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
  - banished: { times: 3, within: 2592000 }
```

- `var` :: The found var holding the address, in place of the offender.
- `now` :: `true` to hold on an address that is banished, `false` on one
      that is not.
- `for` :: Beside a true `now`, seconds it has to have been banished for. A
      line or two just after a ban are ones already on their way.
- `times` / `within` :: How many times it has to have been banished, and
      with in how many seconds back, 90 days at the most. Only together.

The first is a thing no count can say. A line from a banished address
means the ban is not holding... the wrong table, an IPv6 path round it, a
proxy in front of the daemon. List that rule ahead of the one that
banishes, as it only sights. The second, listed ahead of the service's
ordinary rule, banishes a repeat offender on the first hit.

It reads [the galla's own brands](#the-gallas-own-brands), so what it
knows is what any brand is... kept across a restart, and shared with a
fleet, where a ban made by one host is seen by the rest. It is the galla's
own account of it. A ban lifted by hand in the kur is not known of here,
and one whose length is the kur's to choose is taken as a day long. It is
proved from the rule file by seeding the two brands with `marks_before`.

### pressure... a rule for when it is under attack

A `pressure` gate lets a line by only while the watcher's rules are
matching above a mark. It is for a harsher copy of a rule, listed ahead of
the one it shadows, that only has its say during an attack.

```yaml
# syslog/sshd-siege, listed ahead of syslog/sshd
max_score: 2
rule_gates:
  - pressure: { above: 200, seconds: 60, hold: 300 }
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
```

- `above` :: How many matched lines it takes more than. Optional beside a
      `times`, where it is the least the count may be for the `times` to be
      asked.
- `seconds` :: How far back they are counted over.
- `times` / `baseline` :: How many times what is usual the count has to be
      more than, what is usual being what the `baseline` seconds before the
      `seconds` came to, evened out to as long. Only together.
- `hold` :: Seconds the gate goes on letting lines by after the count was
      last above the mark, so a lull between two waves does not shut it.
    - default :: 0
- `scope` :: What is counted over, `watcher` or `galla`.
    - default :: `watcher`

What is counted is the lines some banning rule named an offender on, each
once however many rules did. A rule that only sights or only brands is no
sign of an attack and is not counted. A line the harsher rule took is
counted like any other, so the gate letting lines by does not lower what
it reads and it does not flap. The count is kept in spans of ten seconds,
so it is exact to that and no finer, and is forgotten at a restart.

It is of the line phase and reads nothing of the line. Written first, it
turns a line away before anything else is done with it, so a family of
harsher rules costs next to nothing while there is no attack. The galla
logs a line each time one opens or shuts.

**It can be turned against you.** Whoever drives the count up makes the
harsher thresholds everyone's, so a real user's two typos during an attack
become a ban, and a password rotation day does the same with no attacker
at all. Run one as a detection rule first. It is proved from the rule file
with a [`pressure` fixture](#tests), which says what the gate reads.

A count for a mark wants setting for each host, a busy mail server and a
quiet bastion being nothing alike. `times` sets its self:

```yaml
  - pressure: { times: 5, above: 20, seconds: 60, baseline: 3600 }
```

That is five times the last hour's minute, and twenty at the least. Keep
the `above`... a host that matched one line in the hour is five times over
with a second, and with nothing matched in the baseline at all there is no
saying what is usual and the gate stays shut, which is where a galla is
for its first while after a restart.

### epoch... a timestamp as seconds

An `epoch` gate reads a timestamp and makes the seconds since the epoch of
it, for a gate below to read as a number. It judges nothing and turns no
line away. It is of the line phase.

```yaml
rule_gates:
  - epoch: { into: WHEN }                                    # the line's own
  - epoch: { var: started, format: '%Y-%m-%d %H:%M:%S' }     # a field, where it is
  - epoch: { var: time, into: WHEN, zone: utc }              # a field, into another
```

- `var` :: The field holding the timestamp. With out it the line's own is
      read, as the parser found it.
- `into` :: The field the seconds go into. With out it the `var` is
      converted where it is. The line's own timestamp is no field, so
      reading that needs one.
- `format` :: How the timestamp is written, a `strptime` format or one of
      the names below.
    - default :: `auto`
- `zone` :: The zone of a timestamp that names none... `local`, `utc`, or
      an offset as `+02:00`. It is also the zone the hour and the day are
      told in.
    - default :: `local`
- `hour_into` / `weekday_into` :: Lift the hour, 0 to 23, and the day of
      the week, 0 for Sunday to 6 for Saturday as `active_time` counts them,
      into found vars. Given either, reading the line's own timestamp needs
      no `into`.

The formats that are names...

- `auto` :: Whichever of the others reads it, then the ways the parsers
      write one... a syslog `Jul 12 08:15:50`, an access log
      `12/Jul/2026:08:15:50 -0500`, and the two error logs.
- `epoch` / `epoch_ms` / `epoch_us` :: Seconds, milliseconds, or
      microseconds since the epoch already.
- `iso8601` :: `2026-07-12T08:15:50`, a fraction of a second and a zone
      after it or not.

A timestamp with no year, as syslog's has none, is taken as this year's, or
as last year's when that would put it more than a day ahead of the line. One
that can not be read leaves the field as it was, unset when it is an
`into`, and what reads it judges that for itself.

With the hour lifted, [`novel`](#novel-a-value-a-key-has-not-had-before)
says a login at an hour the account never used, where `active_time` can only
say "outside office hours" for everyone at once:

```yaml
rule_gates:
  - daemons: [ sshd ]
  - epoch: { hour_into: HOUR, zone: '-05:00' }
  - message_regexp:
      - '^Accepted \S+ for (?<USER>\S+) from %%%%SRC%%%%'
  - novel: { name: login-hour, by: USER, of: HOUR, after_seen: 20 }
  - detection_var: [ SRC ]
```

It reads the line's fields, so it sees what is there when it is asked... a
json record's, an access log line's, what `mungers` and `message_json` laid
down above it. A capture of a `message_regexp` below it is not there yet.

### startup... only just started

A `startup` gate turns every line away while the galla has been up for less
than `grace` seconds. A galla that starts reads what was written to its
logs while it was down and counts all of it as happening now, so a minute of
failures from an hour ago reads as a burst.

```yaml
rule_gates:
  - startup: { grace: 120 }
  - daemons: [ sshd ]
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
```

- `grace` :: How many seconds after the galla starts lines are turned away.

[`fresh`](#fresh-old-news) does the same by the time a line says it was
written, which is the better wherever the lines carry a time that can be
read... it keeps the backlog out and counts the lines that are new, where
this keeps everything out for the grace. This is for the logs whose lines
carry no such time. A galla not started as a server, as one a test drives,
has nothing to wait out and lets every line by. It is proved from the rule
file with an [`uptime` fixture](#tests).

It reads nothing of the line, so leading the list it turns a line away
before anything else is done. On a syslog rule that puts it ahead of the
`daemons` gate the rule index reads, and the rule is then offered every
line of the log rather than its own daemon's... which costs only while the
gate turns them away, and then every line after.

### fresh... old news

A `fresh` gate turns a line away when the time it says it was written is
too long before it was read. A hit is counted when the line is read, so an
hour of backlog handed over at once, by a relay catching up or a log picked
up after an outage, reads as a burst happening now and can banish on events
long over. With this ahead of a rule's matcher, old news is not counted at
all.

```yaml
rule_gates:
  - daemons: [ sshd ]
  - epoch: { into: WHEN }
  - fresh: { var: WHEN, within: 300 }
  - message_regexp:
      - '^Failed password for \S+ from %%%%SRC%%%%'
  - ban_var: [ SRC ]
```

- `var` :: The field holding the time, in seconds since the epoch, which
      is what an `epoch` gate above it makes.
- `within` :: How many seconds old a line may be.
- `on_unparsed` :: What a line with no time to read does, `pass` or `fail`.
    - default :: `fail`

On a syslog rule write the two below the `daemons` gate, as above. The rule
index only reads a `daemons` gate that leads the list, and with an `epoch`
ahead of it the rule is offered every line of the log and not just its own
daemon's.

It turns the line away outright, so nothing below it is asked and nothing
is harvested. A line whose time is still to come, the clock that wrote it
running ahead, is fresh. A syslog timestamp names no zone, so a log shipped
in from a host in another needs the `epoch` above it told the `zone`, or
every line of it is hours old or hours ahead.

## Enriching a match... mungers

Where the [primitive fragments](#primitive-fragments-building-blocks-not-captures)
above borrow Log-Munger's regexp *pieces* to help write a pattern, a
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
untouched.

Mungers are supported on `syslog` and `raw` rules, including
[staged](#stages-ordered-sequences-with-in-one-rule) ones... a staged rule enriches the *completed
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
[`message_json`](#message_json) has, and for the same reason. Such a rule must
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
cheap daemon gate.

### daemons

Which daemons this rule processes, a gate every syslog rule has to have.
Leading the list, the daemon of a parsed line is checked against it first
and if it does not match, the regexps are never tried, which keeps rules
cheap on busy shared logs. Entries starting and ending with `//` are
regexps... `//^sshd//` is the regexp `^sshd`. Everything else is a plain
string equality check.

### message_regexp

The regexps tried, in order, against the message portion of a parsed line...
the part after `daemon[pid]: `, not the whole line. The first to match wins.
These are Perl regexps plus `%%%%TOKEN%%%%` tokens, of which there are two
kinds: the **offender tokens**, which capture, and the **primitive
fragments**, which do not.

The offender tokens each compile to a named capture group whose name is the
field:

| token | matches |
| --- | --- |
| `HOST` | a domain name, IPv4 address, or IPv6 address |
| `SUBNET` | a IPv4 or IPv6 subnet or address |
| `IP4` | a IPv4 address |
| `IP6` | a IPv6 address |
| `ADDR` | a IPv4 or IPv6 address |
| `DNS` | a domainname |
| `SRC` / `DEST` | a IPv4 or IPv6 address... meant to be used in combination, and when a regexp uses both, a match only regards as found if both matched |

An offender token may appear more than once in one regexp... whichever
occurrence matched is what comes out under the token name (a repeat is
numbered internally, since Perl forbids a duplicate capture name). The
captured value is what `ban_var` or `detection_var` names.

#### Primitive fragments... building blocks, not captures

The other `%%%%NAME%%%%` kind is a **primitive fragment**: a named regexp
building block (`INT`, `WORD`, `USERNAME`, `HOSTNAME`, `MONTH`,
`SYSLOGTIMESTAMP`, `TIMESTAMP_ISO8601`, `QUOTEDSTRING`, `GREEDYDATA`, and
~60 more) that expands to a bare, **non-capturing** `(?:...)` sub-pattern.
It contributes no field... it is there so a pattern can lean on a curated,
tested regexp for a timestamp or a username instead of hand-rolling it. The
library is [Log-Munger](https://github.com/LilithSec/Log-Munger)'s `base`
primitives, resolved through
[`App::Baphomet::Primitives`](https://metacpan.org/pod/App::Baphomet::Primitives)
the first time a rule reaches for a fragment, then cached under the galla's
tablet dir and re-resolved only when the Log-Munger version or its `base`
file changes. So the parse-and-template cost is paid once for the fleet,
and a deployment using only the offender tokens never loads Log-Munger at
all. The fragments are validated by Log-Munger's own tests, so they arrive
known-good.

Because a fragment captures nothing, wrap one in your own named capture
when you want its value as a field... the fragment writes the pattern, the
capture names the field:

```yaml
rule_gates:
  - message_regexp:
      # SYSLOGTIMESTAMP and INT are fragments (no field); SRC and the wrapped
      # USER are captures
      - '^%%%%SYSLOGTIMESTAMP%%%% \S+ myapp\[%%%%INT%%%%\]: login (?<USER>%%%%USERNAME%%%%) from %%%%SRC%%%%'
```

An offender token wins any name collision, and an unknown name in either
set is a load error. A fragment may repeat freely, having no capture name
to clash.

### ignore_regexp

Optional. Regexps that veto a line... written below the `daemons` gate and
above `message_regexp`, and if any matches the message, the line is not
regarded as found no matter what the message regexps would of said. The
fail2ban equivalent is `ignoreregex`. Tokens work here too.

```yaml
rule_gates:
  - ignore_regexp:
      - 'Registration from ''\S+'' failed for %%%%SRC%%%% - ACL rule'
```

### message_json

Optional, a gate told a boolean. When a daemon logs a JSON object as its
message, `message_json: true` decodes it and flattens it into fields the
[predicate gate](#gate--selections--condition--keywords) below it can test
by their dotted paths, the way a `json` rule works, while the syslog
envelope stays reachable under reserved keys (`syslog.daemon`,
`syslog.host`, ...). With it on, `message_regexp` becomes optional, the gate
being the matcher. See
[`App::Baphomet::Gate::message_json`](https://metacpan.org/pod/App::Baphomet::Gate::message_json).

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
watcher and in memory only. Test these with the `messages:` array form (see
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
`ignore_regexp` above them still vetoing lines. The gate is told a hash
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
order also drives `skip`. A `within` bound is time and can not be
exercised from embedded tests... prove the order and counts there, and
the gap behavior in a `.t` against the rule object (see
`t/rule-stages.t`).

See [`App::Baphomet::Rule`](https://metacpan.org/pod/App::Baphomet::Rule)
and the class of each gate,
[`App::Baphomet::Gate::daemons`](https://metacpan.org/pod/App::Baphomet::Gate::daemons)
and the like, for the full reference.

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
[`detection_var`](#detection_var) stands in its place).

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

Structured logs split events too... mongod 4.4+ logs the auth failure and
the connection's address as separate JSON events sharing a `ctx` conn id,
the same shape its old text logs had. The json type carries the same
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
an offense at all. State is per watcher and in memory only, as on the other
types, and the `messages:` test form proves it. The `syslog.*` namespace is
reserved (it is the [message_json](#message_json) envelope), so keying on it
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
