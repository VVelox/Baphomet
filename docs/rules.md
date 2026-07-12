# Rules

Rules are YAML files under the rules dir, by default
`/usr/local/etc/baphomet/rules`. A rule name is its relative path with out
the `.yaml`, so the rule `syslog/sshd` is the file `syslog/sshd.yaml`. The
first path component is the rule type, and `syslog` is currently the only
type.

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
| `parser` | The parser to parse it with. Defaults to `bsd_syslog`. |
| `found` | Whether the rule should match, `1` or `0`. Defaults to 1 for positive and 0 for negative. |
| `data` | For positive tests, capture names to the values they should of captured. |
| `undefed` | For negative tests, capture names that should not be defined. |

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
