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
`perldoc App::Baphomet::Rules::HTTP` for the full reference.

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
`perldoc App::Baphomet::Rules::HTTPError` for the full reference.

## Banning the external end of a flow

Some sources, Suricata's eve.json above all, log both ends of a flow and
which one is the offender depends on where in the stream the alert fired.
A rule that lists both endpoints as ban_vars and sets `ban_not_internal`
consigns only the ends that are not one of your own hosts...

```yaml
ban_var:
  - src_ip
  - dest_ip
ban_not_internal: true
```

Your own hosts are the `internal` config field, which defaults to the
`ignore_ips` list. So an inbound attack bans the external src, an outbound
callout bans the external dest, a transit flow bans both, and a
host-to-host flow bans neither. A ignored IP is never consigned regardless,
so the consigned end is by extension not ignored either. Works on syslog,
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
See `perldoc App::Baphomet::Rules::JSON` for the full reference.

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
