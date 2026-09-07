# The Neti gate

Neti is the gatekeeper of Kur, and the manager socket has one too. This
page covers who may drive the manager... the socket perms baseline, the
ownership challenge over it, and the per command authorization over that.

Note this only covers the manager socker. Galla sockets are always owned by user running
baphomet with the perms 0600. It is expected that ONLY baphomet will be talking to those.

## The knobs

| setting           | default              | what                                                                                                                    |
|-------------------|----------------------|-------------------------------------------------------------------------------------------------------------------------|
| `socket_group`    | root's default group | Group ownership of the manager socket.                                                                                  |
| `socket_mode`     | `"0660"`             | Perms for the manager socket, an octal string, processed via oct.                                                       |
| `enable_auth`     | `false`              | Opens the Neti gate proper... the unix ownership auth challenge on the manager socket.                                  |
| `authed_users`    | `[]`                 | Users allowed past the Neti gate.                                                                                       |
| `authed_groups`   | `[]`                 | Groups whose members are allowed past the Neti gate.                                                                    |
| `auth_temp_dir`   | unset                | Dir for the ownership challenge cookie files, handed to the server module. Unset, that module chooses its own temp dir. |
| `[command_perms]` | off                  | Per command authorization layered over the baseline. See [below](#per-command-authorization).                           |

## The gate

By default the socket's group ownership and perms (`socket_group`,
`socket_mode`) are all that gate who may ask the manager its status or
stop it. Setting `enable_auth` opens the Neti gate proper... the
[POE::Component::Server::JSONUnix](https://metacpan.org/pod/POE::Component::Server::JSONUnix)
unix ownership challenge, where a caller proves who they are by owning a
cookie file, and only UID 0 or a user in `authed_users` or a
`authed_groups` is let through.

```toml
enable_auth   = true
authed_users  = [ "foo" ]
authed_groups = [ "wheel" ]
```

The `baphomet` CLI completes the challenge transparently, so nothing
changes in how you drive it beyond being one of the permitted. Group and
user membership is resolved per request, so changes apply without a
restart. This gates the manager socket only, and every CLI command rides
it, the manager reaching Ereshkigal on their behalf... the gate here
covers the whole control plane.

## Per command authorization

`authed_users` and `authed_groups` gate every command the same. To gate
them apart, `command_perms` lays per command rules over that baseline. It
is a table with an optional `default` verdict (`allow` or `deny`, the
default `deny`) and a `commands` table keyed by command name, or the
catch-all `%DEFAULT%` that stands in for the baseline. Each rule is
`"allow"`, `"deny"`, or a table of `users`, `groups`, `deny_users`, and
`deny_groups` arrays. An all-digit entry matches by UID or GID, everything
else by name. Explicit denials win over allowals. A command named here is
judged by its own rule alone; every command not named falls to the
baseline. UID 0 (root) is threaded into any rule that names allowed users
or groups, so root passes it as it passes the baseline.

The commands that may be named are `status`, `status_all`, `status_galla`,
`accused`, `marked`, `tracked`, `watching`, `banished`, and `stop`.

A example... the `lnms-f2b-extend` command an snmpd extend runs reaches the manager's
`banished` command for its tallies, so letting the `snmpd` user feed LibreNMS is a matter
of granting it just that one command, and nothing else... not `stop`, not the accused lists:

```toml
enable_auth   = true
socket_group  = "baphometAccess" # a group of users that will have access to the baphomet socket
authed_users  = [ "nanni" ]      # users allowed to run everything
authed_groups = [ "ops" ]        # groups allowed to run everything

[command_perms]
default = "deny"

# the snmpd user may run banished, which lnms-f2b-extend rides, and only that
[command_perms.commands.banished]
users = [ "snmpd" ] # remember to make sure snmpd is a member of baphometAccess

# stop in herits the top level and ea-nasir is turned away outright
[command_perms.commands.stop]
deny_users = [ "ea-nasir" ] # may be a member of ops, but fuck him being able to stop it
```

Here `snmpd` may run `banished` (and so `lnms-f2b-extend`) but falls to the
`deny` default for everything else; `nanni` and the `ops` group keep the
run of the baseline commands, while `stop` is narrowed to `nanni` alone.

The CLI side of the challenge, including driving it from your own code, is
covered in [usage](usage.md). Ereshkigal has the same gate on its own manager
socket... with its `enable_auth` on, the baphomet user needs granting over
there too, on the kurs it bans to.
