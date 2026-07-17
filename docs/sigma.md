# Coming from Sigma

Sigma is the generic detection format... a YAML signature language written
once and compiled to whatever SIEM backend runs it, Splunk, Elastic, or the
next one. Baphomet is not a SIEM, it is an accuser that counts an IP's
offenses and banishes the repeat ones to Kur. But its `json` rule type was
built on Sigma's detection model on purpose, so a Sigma rule over a log source
Baphomet can parse ports almost verbatim. The difference is where it runs:
Sigma is a query compiled against a data lake, here it is a matcher run live
on a log stream, and the verdict is a banishment, or a detection `sighting`,
not a dashboard alert.

## The concept map

| Sigma | here |
| --- | --- |
| `detection:` named selections | `selections`, each a list of predicates |
| `condition` | `condition`... `and`/`or`/`not`, `all of them`, `1 of them`, `N of <prefix>_*` |
| `field: value` | a `gate`/selection predicate over a flattened field |
| `\|contains` / `\|startswith` / `\|endswith` | `op: contains` / `startswith` / `endswith` |
| `\|re` | `op: re` (a tokened regexp) |
| `\|cidr` | `op: cidr` |
| `\|base64` / `\|base64offset` | `decode: [ base64 ]` / `[ base64offset ]` |
| `\|wide` / `\|utf16le` / `\|utf16be` | `decode: [ utf16le ]` / ... (`wide` an alias) |
| `\|windash` | `decode: [ windash ]` |
| `\|lt` / `\|lte` / `\|gt` / `\|gte` | `op: lt` / `le` / `gt` / `ge` |
| `\|cased` | the default (Baphomet matches case-sensitively); `nocase: true` is Sigma's default-insensitive |
| `\|fieldref` | `fieldref`, comparing to another field's live value |
| `\|exists: true` / `\|exists: false` | `op: exists` / `op: exists` with `negate` |
| `\|expand` | a `values` list, or a `namtar_list` gate (spliced at conversion) |
| `field: null` / absent | `negate` (a negated predicate holds when the field is absent) |
| `title` / `description` | `msg` |
| `level` | `severity` (informational→info, else 1:1) |
| `tags: attack.tXXXX` | `attack` |
| `id` / `references` | `references` |
| `logsource` (product/service) | the rule type, parser, and `daemons` |
| the query verdict | a `sighting` (detection rule) or a ban |

## The modifier surface, matched

The whole of Sigma's field-modifier vocabulary lands on the json rule's
predicate layer (see [rules](rules)):

- The string ops `contains`/`startswith`/`endswith`, the regexp `re`, the
  numeric `lt`/`le`/`gt`/`ge`, and `cidr` membership are all `op:` values.
- The transforms `base64`, `base64offset`, `utf16le`/`utf16be`/`wide`,
  `windash`, and `url` are a `decode:` chain, run left to right before the
  compare... `decode: [ base64, utf16le ]` with `op: contains` is the
  PowerShell `-enc` shape.
- `all` (every value must match), `negate` (invert, holding on an absent
  field, Sigma's field-absent semantics), `nocase` (case-fold the compare),
  `fieldref` (compare to another field), and `exists` (field presence) round
  it out.
- `expand` is the one that resolves at conversion rather than at match... a
  placeholder becomes a literal `values` list, or, for a config-managed set, a
  `namtar_list` gate.

So nothing in a Sigma rule's detection block goes untranslated. The
selections-and-condition boolean, the operators, the decode transforms, the
field-absent and field-present tests all have a home.

## What Sigma does that this does not

Honesty section... Sigma assumes a SIEM, and Baphomet is not one.

- **Log source coverage.** The public Sigma corpus is overwhelmingly
  Windows... Sysmon, the Security event log, `process_creation`,
  `registry_event`. Baphomet has no parser for those, so those rules have
  nowhere to land. The reachable slice is `product: linux` syslog services,
  the webserver categories, and generic JSON logs. The lever that widens this
  is more parsers, not the rule language.
- **Field names and pipelines.** A Sigma rule names source-specific fields
  (`Image`, `CommandLine`, `TargetUserName`). A ported json rule fires only if
  your log actually ships those field paths, and Sigma's processing pipelines,
  which remap fields per source, have no equivalent here yet... so you map
  names by hand or shape your ingest to match.
- **Correlation rules.** Sigma's newer correlation kind... `event_count`,
  `value_count`, `temporal`, `temporal_ordered`... maps in spirit onto the
  `distinct` counting, the [marks](rules), and `sequence`, but nothing stitches
  a correlation and its referenced base rules together automatically. You build
  the pieces by hand.
- **A data lake.** Sigma queries stored history; Baphomet matches a live
  stream and forgets, holding only its counting window. There is no backscan
  and no aggregation over stored events beyond that window.
- **Ready-made tests.** A Sigma rule ships no sample log lines, so a port
  arrives testless until you add positive and negative lines yourself... unlike
  the fail2ban corpus a fail2ban port draws on.

## Porting a rule

There is no converter command yet, so a Sigma rule ports by hand, and for a
supported log source the translation is mechanical.

1. **Check the logsource.** A `product: linux` service becomes a `syslog`
   rule with a `daemons` gate; a webserver category an `http` or `http_error`
   rule; a generic JSON log a `json` rule. A windows or sysmon source has no
   parser here, so stop... that rule is not portable.
2. **Selections become selections.** Each `detection` selection maps to a
   `selections` entry, and each `field: value` (with its modifiers) to a
   predicate per the concept map. A json rule's fields are the flattened dotted
   paths (`attr.remote`, `process.command_line`).
3. **The condition carries over** near-verbatim... `and`/`or`/`not`, the
   `all of them` / `1 of them` / `N of <prefix>_*` quantifiers.
4. **Carry the metadata.** `title`/`description` to `msg`, `level` to
   `severity`, `tags` to `attack`, `references` to `references`.
5. **Choose ban or detect.** A Sigma rule alerts, it does not firewall, so it
   is naturally a detection rule... `detection_var: [ SRC ]`, writing
   `sighting`/`sighted` to EVE and banishing nobody. Name a `ban_var` instead
   to turn the signature into a ban. This is the one real choice the port asks,
   the same as coming from [sagan](sagan).
6. **Add tests and verify.** Paste sample lines into a `tests:` block, then
   `baphomet test_line` pokes single lines at a draft and `baphomet
   check_rules` runs the embedded tests, refusing to load a rule that fails its
   own... the same guard `baphomet start` uses.

An automated `sigma2rule` converter is a future direction, but its ceiling is
log-source coverage, not the rule language, which already speaks Sigma. See
[rules](rules) to write one, [eve](eve) for the sighting the detection form
emits, and [rules-catalog](rules-catalog) for what already ships.
