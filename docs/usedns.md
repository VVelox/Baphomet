# Hostname offenders... usedns

Some daemons log a hostname where an offense wants an address... PAM's
rhost above all, whatever the client claimed, and mysqld when it resolves
clients itself. Ereshkigal banishes addresses, not names, so what becomes
of a hostname offender... a `ban_var` value that is not an IP... is the
`usedns` setting. This page is its own because the resolve modes are a
security decision with real teeth, and the reasoning belongs next to the
knobs.

## The knobs

| setting | default | what |
| --- | --- | --- |
| `usedns` | `no` | How a hostname offender is handled: `no`, `resolve_seen`, or `resolve_ban`. Layered watcher over kur over global, like the other counting settings. |
| `enable_dns` | `false` | The consent for DNS resolution. With out it, any `usedns` is treated as `no`, loudly. Resolution rides the optional `Net::DNS` module... set but unloadable, and `usedns` behaves as `no`, also loudly. Global only... consent is not delegated downward. |
| `usedns_timeout` | `2` | Seconds a DNS query may take before being given up on. Resolution is blocking, so this bounds how long a hostile name can stall the galla. |
| `usedns_max_addrs` | `4` | The most addresses a hostname may resolve to and still be acted on... more and the whole resolution is refused rather than trimmed, failing closed. |

## The modes

- **`no`** (the default) ... the hostname is dropped. The match still
  writes to EVE, so the sighting is not lost, but it counts and banishes
  nothing. The `hostname_dropped` stat counts what this discards.
- **`resolve_seen`** ... the hostname is resolved when seen and the
  offense buckets under its addresses, beside any direct hits from the
  same client... one attacker, one count, however the daemon spelled
  them. Resolution happens at match volume, so the cache and
  `usedns_timeout` are what stand between a hostile log and your
  resolver.
- **`resolve_ban`** ... the offense counts under the name itself, and
  resolution happens once, at the moment the threshold trips. The
  cheapest and quietest mode... one lookup per would-be ban, and the
  attacker's nameserver hears nothing until you have already decided to
  act.

## Why the default is no

**Read this part before turning a resolve mode on.** A logged hostname is
hostile input... PAM's rhost is whatever the attacker typed, and whoever
controls a name controls what it resolves to. Under a resolve mode an
attacker who can put a name into your log gets a say in what your
firewall bans... point a name at a victim's address, fail auth until the
threshold, and Baphomet would aim Kur at whomever they chose.

The fences:

- Resolved addresses that are in `ignore_ips` or `internal` are dropped
  absolutely, whatever the rule says... a name can never aim Kur at your
  own hosts, so keep `internal` honest.
- A name resolving to more than `usedns_max_addrs` addresses is refused
  whole rather than trimmed... a wide answer is a CDN or a deliberate
  spray, and the failure mode is always no ban, never a wrong one.
- Unresolvable names, timeouts, and refusals likewise banish nobody,
  logged and ticked (`dns_failures`, and `hostname_dropped` under `no`).
- A hostname is never queued for a ban retry... what a name means changes
  with whoever controls it.

## On the record

A banish that came through a name carries `hostname` beside `ip` in its
EVE event, so the chain of custody from name to address is on the record.
See [eve](eve). fail2ban's `raw` mode... hand the name over verbatim...
does not exist here, because the other side does not take names.

## The other direction... reverse_dns

The [`reverse_dns` rule gate](rules) is the other direction... PTR lookups
refining a match rather than resolving an offender... and rides its own
consent, `enable_rdns` (with its own `rdns_timeout`), on by default since
a gate can only veto a count, never aim one. The two are deliberately
separate switches. See [configuration](configuration) for those two
settings.
