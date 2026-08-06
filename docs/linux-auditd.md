# Linux auditd

The Linux kernel keeps its own ledger of who did what... logins, execs, file
touches, module loads, the audit subsystem's own subversion. `auditd` is the
daemon that collects it. This page is how you carry that ledger to a syslog
file a galla can tail, and how to tell the kernel to record the few things it
stays silent about by default, so the `%syslog/linux-audit%` rules have
something to read.

The rules and their group are named `linux-auditd-*` on purpose. Other
platforms carry their own audit machinery, with different records and different
field names... only the Linux one is described here. Anything else would want
its own rules and its own page.

For what each rule watches for, see [rules-catalog](rules-catalog.md). For the
mechanics of a rule, [rules](rules.md). For the alerts these detection rules raise,
[eve](eve.md).

## The shape of the stream

auditd does not speak syslog on its own. A plugin, **audisp-syslog**, takes each
audit record and writes it to syslog as one line. An audit *event* is several
records (a `SYSCALL`, then its `PATH`, `CWD`, `PROCTITLE`), and each becomes its
own syslog line... the `linux-auditd-*` rules are written to match a single
record apiece, so this splitting is fine and expected.

A forwarded line looks like this, the program field carrying the ident
`audisp-syslog`:

```
Nov 14 10:00:00 host audisp-syslog[1400]: type=ANOM_PROMISCUOUS msg=audit(1700000003.1:903): dev=eth0 prom=256 old_prom=0 auid=1000 uid=0 ses=3
```

The rules gate on the daemon idents `audisp-syslog`, `audispd` (the older name),
and a bare `audit`, so whichever your setup uses, the gate matches. Everything
after the ident... `type=... msg=audit(...): ...`... is what the rules and the
`auditd` [Log::Munger](rules.md#enriching-a-match-mungers) munger read.

## AppArmor hosts... the shorter road

If what you are actually after is AppArmor denials, read this before doing any
of the work below, because you may not need auditd at all.

An AppArmor denial is raised by the kernel, not by auditd, and where it goes
depends on whether anything is holding the audit socket. With auditd running it
leaves through audisp-syslog, wearing `type=AVC`, and
`linux-auditd-apparmor-denied` reads it off the forwarded file like every other
rule on this page. With no auditd installed... the stock state of a Debian or an
Ubuntu, where AppArmor is enforcing out of the box and auditd is not there at
all... the kernel prints it to its own ring buffer instead:

```
Nov 14 12:20:00 host kernel: [ 9134.220118] audit: type=1400 audit(1700000000.123:456): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/shadow" pid=1234 comm="foo" requested_mask="r" denied_mask="r" fsuid=0 ouid=0
```

That bracketed number is the printk uptime, and whether your host has it depends
on which reader wrote the file... see the wrinkle at the end of this section. The
rule matches with it or without it.

That is `syslog/linux-apparmor-denied`, gated on the `kernel` ident. It is not a
member of `%syslog/linux-audit%`, since it will never see a line on the
forwarded stream. Point a watcher at whatever file the kernel facility already
lands in (`/var/log/kern.log` on Debian and Ubuntu, `/var/log/messages`
elsewhere) and name it directly:

```toml
[kur.apparmor.kern]
log="/var/log/kern.log"
parser="syslog"
rule="syslog/linux-apparmor-denied"
```

No plugin, no audit rules, no restarting a daemon that refuses to stop. If you
want the rest of what this page offers, install auditd and carry on with Step 1;
the two rules coexist, and only one of them can fire on a given host, because
only one of the two roads is open at a time.

Verifying this road is its own thing, since `auditctl` and `ausearch` come with
auditd and a host on this road has neither. What it has instead:

```sh
aa-status                             # profiles loaded, and how many enforce
dmesg | grep -i 'apparmor="DENIED"'   # denials the kernel is raising now
tail -f /var/log/kern.log             # the same, as the galla will read them
```

`aa-status` reporting profiles in complain mode rather than enforce is the usual
reason a host that should be raising denials is silent... a complain-mode profile
writes `apparmor="ALLOWED"`, which this rule deliberately does not match. Then
poke a captured line at the rule directly:

```sh
baphomet test_line --rule syslog/linux-apparmor-denied \
  'Nov 14 12:20:00 host kernel: audit: type=1400 audit(1700000000.123:456): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/shadow" pid=1234 comm="foo" requested_mask="r" denied_mask="r" fsuid=0 ouid=0'
```

One wrinkle of the kernel road, worth knowing about but not worth doing anything
about: rsyslog's kernel reader keeps the printk uptime (`[ 1234.567890]`) at the
head of the message, while journald's kmsg reader strips it, so the same event
reaches two hosts in two shapes. Both the rule and Log-Munger's `kernel` decoder
step over the prefix rather than reading it, so the captures come out identical
either way and there is nothing to configure. The rule captures the profile
itself rather than leaning on the enrichment for it, so the match never depends
on the decoder having read the line the same way.

## Step 1 — install auditd and let it wake

Three things have to be true before any of the rest works: the kernel's audit
subsystem has to be on, `auditd` has to be installed and running, and the
`audisp-syslog` plugin binary has to exist on disk. The daemon is a host-level
thing... it claims the kernel's audit socket, one holder per host, and cannot be
run usefully inside a container. Watch the host, ship the host's file.

### Debian / Ubuntu

```sh
apt install auditd audispd-plugins
systemctl enable --now auditd
```

`auditd` carries the daemon and `augenrules`; `audispd-plugins` carries the
dispatcher plugins. Which of the two owns the syslog plugin has moved between
releases, so install both and confirm the binary actually landed:

```sh
ls -l /sbin/audisp-syslog && dpkg -S /sbin/audisp-syslog
```

Debian 12 and Ubuntu 22.04 onward ship audit 3.x, so the plugin config goes in
`/etc/audit/plugins.d/`; Ubuntu 20.04 and older Debian ship audit 2.x and use
`/etc/audisp/plugins.d/`.

Two Debian-family teeth to watch for:

- **rsyslog is no longer a given.** Recent Ubuntu images log to journald alone.
  Check with `systemctl status rsyslog` and `apt install rsyslog` if the unit is
  missing... Step 3 needs something that writes files.
- **AppArmor, not SELinux.** `linux-auditd-avc-denied` is written to the SELinux
  shape (`avc: denied { ... } for ... comm=`) and stays quiet here; the AppArmor
  shape is a k=v blob and belongs to `linux-auditd-apparmor-denied`, which is in
  the same group. Both ship, one fires per host. Same split in
  `linux-auditd-mac-tamper`, which reads SELinux's `enforcing=0` and AppArmor's
  profile removal as two separate regexps... see
  [AppArmor hosts](#apparmor-hosts-the-shorter-road) below, and note you may not
  need any of this page at all.

### RHEL / CentOS Stream / Rocky / AlmaLinux / Fedora

```sh
dnf install audit audispd-plugins     # yum, on EL7
systemctl enable --now auditd
```

`audit` is part of the base install on all of these and the daemon comes enabled
out of the box... the install line is for a stripped or minimal image. SELinux is
enforcing by default here, so the AVC rule earns its keep.

EL8, EL9, and Fedora are audit 3.x (`/etc/audit/plugins.d/`); EL7 is audit 2.8
(`/etc/audisp/plugins.d/`). The distro ships its own `/etc/audit/rules.d/audit.rules`...
leave it be and drop your file alongside it (Step 5). Fuller sample rulesets to
crib from sit in `/usr/share/audit/sample-rules/` (EL7: `/usr/share/doc/audit-*/`).

### SUSE / openSUSE

```sh
zypper install audit
systemctl enable --now auditd
```

The dispatcher plugins are packaged separately here, usually as
`audit-audispd-plugins`... `zypper search audisp` will say for your release.
SUSE defaults to AppArmor, so the AVC caveat from the Debian section applies.

### Arch

```sh
pacman -S audit
systemctl enable --now auditd
```

Arch builds the audit subsystem into the kernel but leaves it asleep: without
`audit=1` on the kernel command line the daemon starts onto a dead subsystem and
you will get nothing. See the kernel note below.

### Alpine, Gentoo, and other OpenRC systems

```sh
apk add audit rsyslog                 # emerge app-admin/audit, on Gentoo
rc-update add auditd default  && rc-service auditd start
rc-update add rsyslog default && rc-service rsyslog start
```

busybox syslog cannot route by program, which is what Step 3 asks of it... hence
rsyslog on Alpine. Gentoo with systemd takes the `systemctl enable --now auditd`
line instead.

### The kernel side, wherever you are

`audit=1` on the kernel command line brings the subsystem up at boot rather than
whenever auditd happens to start, so the early window is recorded instead of
lost. RHEL and its kin set it at install time; elsewhere add it to
`GRUB_CMDLINE_LINUX` in `/etc/default/grub`, regenerate
(`grub-mkconfig -o /boot/grub/grub.cfg`, or `grub2-mkconfig -o /boot/grub2/grub.cfg`
on the EL family), and reboot.

Then confirm the subsystem is awake and the daemon holds it:

```sh
auditctl -s
```

`enabled` of 0 means the subsystem is off; `pid` of 0 means nothing is
collecting, whatever the service manager claims. You want a nonzero pid and
`enabled 1` (or 2, if you have already gone immutable).

## Step 2 — forward auditd to syslog

Enable the syslog plugin. On audit 3.x it lives at
`/etc/audit/plugins.d/syslog.conf`; on audit 2.x, `/etc/audisp/plugins.d/syslog.conf`.

```ini
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_INFO
format = string
```

`args` is the syslog priority the records go out at (`LOG_INFO` is plenty).
Some builds accept a second word for the facility, e.g. `args = LOG_INFO LOG_LOCAL6`,
to route the stream onto a facility of its own; if yours does not, filter by the
`audisp-syslog` ident instead (next step), which always works.

Keep `format = string`. The `linux-auditd-*` rules match the raw
`type=/key=/name=` shape; the ENRICHED format merely appends resolved fields and
does not break them, but string is the tested path.

Restart the daemon. auditd refuses `systemctl stop`, so use the init wrapper:

```sh
service auditd restart
```

## Step 3 — land it in a file the galla can tail

Route the forwarded stream to a file of its own. With rsyslog, filtering on the
ident is the reliable way, whether or not you gave the plugin a private facility:

```
# /etc/rsyslog.d/30-audit-forward.conf
if $programname == 'audisp-syslog' then {
    action(type="omfile" file="/var/log/audit-forward.log")
    stop
}
```

```sh
systemctl restart rsyslog
```

If you routed the plugin onto `LOG_LOCAL6` instead, the equivalent is
`local6.*  /var/log/audit-forward.log`.

## Step 4 — point a watcher at it

A watcher tailing that file with the default `syslog` parser and the
`%syslog/linux-audit%` group, which expands to all fourteen `linux-auditd-*`
rules in place. Two of them ban (remote auth failures, the login-failure
anomaly); the rest are detection-only and raise sightings to
[EVE](eve.md) without banishing anyone.

```toml
[kur.audit]
max_score=5
ban_time=3600

[kur.audit.forward]
log="/var/log/audit-forward.log"
parser="syslog"
rule="%syslog/linux-audit%"
```

Prefer to run the whole set in observe mode first, so even the two banning rules
only alert while you watch the volume? Set `eve_only=true` on the kur or the
watcher. See [configuration](configuration.md) and [log-analysis](log-analysis.md).

## Which rules need which records

Most of the group reads records the kernel, PAM, or SELinux already emit with no
audit rules of your own... provided the emitting subsystem is active, which it is
by default on stock installs:

| rule | record it reads | emitted by |
| --- | --- | --- |
| `linux-auditd-auth-failed` | `USER_LOGIN`/`USER_AUTH`/`USER_ERR`/`CRED_ACQ` | PAM |
| `linux-auditd-anom-login-failures` | `ANOM_LOGIN_FAILURES` | PAM / faillock |
| `linux-auditd-user-mgmt` | `ADD_USER`/`DEL_USER`/`USER_MGMT`/... | shadow-utils |
| `linux-auditd-avc-denied` | `AVC` denied | SELinux |
| `linux-auditd-apparmor-denied` | `apparmor="DENIED"`, top-level or dbus-nested | AppArmor |
| `linux-auditd-mac-tamper` | `MAC_STATUS`/`MAC_CONFIG_CHANGE`, or `operation="profile_remove"` | kernel (setenforce) / apparmor_parser |
| `linux-auditd-promiscuous` | `ANOM_PROMISCUOUS` | kernel (NIC state) |
| `linux-auditd-abend` | `ANOM_ABEND` | kernel (fatal signal) |
| `linux-auditd-anom-exec` | `ANOM_EXEC` | kernel / policy tooling |
| `linux-auditd-audit-tamper` | `CONFIG_CHANGE`/`DAEMON_ABORT` | auditd itself |

The remaining four read `SYSCALL` and `PATH` records that only appear once you
have told the kernel to watch for them. Without the audit rules in the next step
these four sit silent... they are not wrong, they simply have nothing to match.

| rule | wants | supply it with |
| --- | --- | --- |
| `linux-auditd-kmod-load` | module syscalls, or a module watch key | the `modules` syscall rule below |
| `linux-auditd-preload-tamper` | a write to `ld.so.preload`/`ld.so.conf*`, or key `ldpreload` | the `ldpreload` watches below |
| `linux-auditd-exec-from-writable` | an exec whose binary is in `/tmp`,`/var/tmp`,`/dev/shm`, or key `susp_exec` | the `susp_exec` watches below |
| `linux-auditd-odd-path` | a `SYSCALL`/`PATH` naming an odd path | execve auditing below |

## Step 5 — the audit rules

Drop these in a file under `/etc/audit/rules.d/`, where `augenrules` gathers them
into the live ruleset. The keys (`modules`, `ldpreload`, `susp_exec`) are the
exact strings the rules match on, so keep them verbatim.

```
# /etc/audit/rules.d/baphomet.rules

## kernel module load / unload  ->  linux-auditd-kmod-load
## on x86_64 the rule already matches these by syscall number; the key makes
## the intent legible and lets the key branch fire too.
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -F key=modules
-a always,exit -F arch=b32 -S init_module -S finit_module -S delete_module -F key=modules

## dynamic-linker preload  ->  linux-auditd-preload-tamper
## a -p wa watch yields both a PATH record (the file) and a SYSCALL record
## carrying key=ldpreload (the program that touched it); the rule reads either.
-w /etc/ld.so.preload -p wa -k ldpreload
-w /etc/ld.so.conf     -p wa -k ldpreload
-w /etc/ld.so.conf.d/  -p wa -k ldpreload

## execution from a writable scratch directory  ->  linux-auditd-exec-from-writable
## perm=x on a directory watch fires on execs of anything beneath it; the
## SYSCALL's exe= lands under the writable path and carries key=susp_exec.
-a always,exit -F dir=/tmp     -F perm=x -F key=susp_exec
-a always,exit -F dir=/var/tmp -F perm=x -F key=susp_exec
-a always,exit -F dir=/dev/shm -F perm=x -F key=susp_exec

## every execve  ->  linux-auditd-odd-path (and richer context everywhere)
## THE HEAVY ONE. This logs a record for every program started on the host,
## which is what surfaces a binary hidden as a dotfile in a system dir, a '...'
## directory, or a filename audit had to hex-encode. High volume... enable it
## deliberately, or narrow it to the paths you actually care to watch.
-a always,exit -F arch=b64 -S execve -S execveat -F key=exec
-a always,exit -F arch=b32 -S execve -S execveat -F key=exec
```

Load them now, and confirm:

```sh
augenrules --load
auditctl -l | grep -E 'modules|ldpreload|susp_exec|exec'
```

A note on volume and drops. Auditing every execve is the loudest thing here; on a
busy host raise the kernel backlog so records are not lost under load, in a rules
file of its own or at the top of this one:

```
-b 8192
--backlog_wait_time 60000
```

And a note on syscall numbers. The `modules` rule is written per-architecture
(`b64`/`b32`) so it is portable; the `linux-auditd-kmod-load` rule's number-based
branch (`175`/`176`/`313`) is x86_64-specific, which is why the key branch above
is the belt to its suspenders on other arches.

## Verifying end to end

Confirm the rules are live and firing:

```sh
auditctl -l                     # the ruleset the kernel holds
ausearch -k ldpreload           # records tagged with a key you set
tail -f /var/log/audit-forward.log   # the forwarded syslog stream
```

Then poke a captured line straight at a rule, the same line the galla would see,
with out waiting for the real thing to happen:

```sh
baphomet test_line --rule syslog/linux-auditd-promiscuous \
  'Nov 14 10:00:00 host audisp-syslog[1400]: type=ANOM_PROMISCUOUS msg=audit(1700000003.1:903): dev=eth0 prom=256 old_prom=0 auid=1000 uid=0 ses=3'
```

`baphomet check_rules` runs every rule's own embedded tests; see [usage](usage.md).

## Caveats worth keeping

- **Immutability vs. tamper detection.** Setting `-e 2` at the end of your
  ruleset makes the audit config immutable until reboot... good hardening, but it
  also means the `remove_rule`/`audit_enabled=0` changes that
  `linux-auditd-audit-tamper` watches for can no longer happen while up. The
  `DAEMON_ABORT` half of that rule still fires. Choose knowingly.
- **Hex-encoded names.** audit encodes any filename with spaces or control
  characters as a bare, unquoted hex string (`name=2E2E2E20`). This is a
  hiding trick in its own right, and `linux-auditd-odd-path` treats such a bare
  name as suspicious by design... do not "fix" it by expecting quotes.
- **name_format.** If you set `name_format = hostname` (or `fqd`) in
  `auditd.conf` the daemon prefixes a `node=` field; it sits ahead of `type=` in
  the record and the rules, being anchored on `type=`, will not match. Leave
  `name_format = none` (the default) for a syslog-forwarded stream, or strip the
  prefix before the parser.
- **AppArmor complain mode is invisible.** A profile switched from enforce to
  complain arrives as `operation="profile_replace"`, which is exactly what an
  ordinary reload looks like... the record does not say which mode it landed in.
  `linux-auditd-mac-tamper` therefore matches only `profile_remove`, an unload,
  and lets the replace go. The blind spot is real and there is nothing in the
  record to close it with. What it does catch, note, includes every snap being
  removed, so on a snap-heavy host give that rule `eve_only` until you have
  watched the volume.
- **Not a file-integrity monitor.** These rules read the shapes a compromise
  leaves in the audit trail; they are not a substitute for a full FIM ruleset.
  The pre-existing `raw/selinux-ssh` rule covers the raw, SELinux-specific
  `audit.log` path and complements this forwarded stream.

## See also

- [rules-catalog](rules-catalog.md) ... every `linux-auditd-*` rule, and
  `linux-apparmor-denied`, one line each.
- [rules](rules.md) ... rule mechanics, tokens, groups, and the munger enrichment.
- [log-analysis](log-analysis.md) ... the detection half these rules live in.
- [eve](eve.md) ... the sightings and alerts they raise.
