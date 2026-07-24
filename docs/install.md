# Install

Baphomet needs a running
[Ereshkigal](https://github.com/LilithSec/Ereshkigal) for the bans to go
anywhere... install and configure that first, and note the kur names you
configure there, as Baphomet's config targets them.

## Dependencies

| CPAN module | FreeBSD pkg | Debian pkg |
| --- | --- | --- |
| App::Cmd | p5-App-Cmd | libapp-cmd-perl |
| Error::Helper | p5-Error-Helper | (cpanm) |
| JSON::MaybeXS | p5-JSON-MaybeXS | libjson-maybexs-perl |
| Net::Server (Net::Server::Daemonize) | p5-Net-Server | libnet-server-perl |
| POE | p5-POE | libpoe-perl |
| POE::Component::Server::JSONUnix | (cpanm) | (cpanm) |
| Regexp::IPv4 | (cpanm) | (cpanm) |
| Regexp::IPv6 | p5-Regexp-IPv6 | libregexp-ipv6-perl |
| TOML::Tiny | (cpanm) | libtoml-tiny-perl |
| YAML::XS | p5-YAML-LibYAML | libyaml-libyaml-perl |
| Ereshkigal (for Ereshkigal::Client) | (cpanm) | (cpanm) |

Package names are current as of writing. Anything marked `(cpanm)` —
or missing from your release — installs cleanly from CPAN via
[cpanminus](https://metacpan.org/pod/App::cpanminus).

## From source

Dependencies are declared in Makefile.PL, so from a checkout or an
unpacked release tarball...

```shell
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

This installs the `baphomet` and `galla` bins, the modules, and the shipped
rules... the rules go into the dist's [`File::ShareDir`](https://metacpan.org/pod/File::ShareDir)
share dir and are found there at run time, so nothing needs copying into
place. The config is not installed by make, so put it in place...

```shell
mkdir -p /usr/local/etc/baphomet
$EDITOR /usr/local/etc/baphomet/config.toml
```

To override a shipped rule or add your own, drop the YAML under
`/usr/local/etc/baphomet/rules` (the `rules_dir`, searched ahead of the
shipped rules); a fresh install needs nothing there. See
[rules.md](rules.md#where-rules-live).

Then check the rules and start it up...

```shell
baphomet check_rules
baphomet start
baphomet status
```

## Running at boot

### FreeBSD

```shell
cp rc/freebsd/baphomet /usr/local/etc/rc.d/
chmod +x /usr/local/etc/rc.d/baphomet
sysrc baphomet_enable=YES
service baphomet start
```

### systemd

```shell
cp rc/systemd/baphomet.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now baphomet
```

On systems where `/var/run` is a tmpfs, `/var/run/baphomet` is created
automatically at startup — but if you point `run_base_dir` somewhere
deeper, make sure the parents exist at boot (a `RuntimeDirectory=` line
or a tmpfiles.d entry does it on systemd). Note that unix socket paths
are limited to roughly 104 characters on the BSDs, so keep
`run_base_dir` short.
