# Install

Baphomet needs a running
[Ereshkigal](https://github.com/LilithSec/Ereshkigal) for the bans to go
anywhere... install and configure that first, and note the kur names you
configure there, as Baphomet's config targets them.

## Dependencies

Perl 5.40 or newer, plus the modules below. `File::ShareDir::Install` is
wanted at configure time only, by Makefile.PL itself...

| CPAN module                          | FreeBSD pkg              | Debian pkg                    |
|--------------------------------------|--------------------------|-------------------------------|
| App::Cmd                             | p5-App-Cmd               | libapp-cmd-perl               |
| Error::Helper                        | p5-Error-Helper          | (cpanm)                       |
| File::ShareDir                       | p5-File-ShareDir         | libfile-sharedir-perl         |
| File::ShareDir::Install              | p5-File-ShareDir-Install | libfile-sharedir-install-perl |
| JSON::MaybeXS                        | p5-JSON-MaybeXS          | libjson-maybexs-perl          |
| Log::Munger                          | (cpanm)                  | (cpanm)                       |
| Net::Patricia                        | p5-Net-Patricia          | libnet-patricia-perl          |
| Net::Server (Net::Server::Daemonize) | p5-Net-Server            | libnet-server-perl            |
| Path::Tiny                           | p5-Path-Tiny             | libpath-tiny-perl             |
| POE                                  | p5-POE                   | libpoe-perl                   |
| POE::Component::Server::JSONUnix     | (cpanm)                  | (cpanm)                       |
| Ref::Util                            | p5-Ref-Util              | libref-util-perl              |
| Regexp::IPv4                         | (cpanm)                  | (cpanm)                       |
| Regexp::IPv6                         | p5-Regexp-IPv6           | libregexp-ipv6-perl           |
| Text::CSV_XS                         | p5-Text-CSV_XS           | libtext-csv-xs-perl           |
| TOML::Tiny                           | (cpanm)                  | libtoml-tiny-perl             |
| YAML::XS                             | p5-YAML-LibYAML          | libyaml-libyaml-perl          |
| Ereshkigal (for Ereshkigal::Client)  | (cpanm)                  | (cpanm)                       |

A few more are optional, wanted only if the pieces they serve are in use...

| CPAN module                 | FreeBSD pkg                 | Debian pkg                       |
|-----------------------------|-----------------------------|----------------------------------|
| IP::Geolocation::MMDB       | (cpanm)                     | libip-geolocation-mmdb-perl      |
| Net::DNS                    | p5-Net-DNS                  | libnet-dns-perl                  |
| POE::Component::Client::DNS | p5-POE-Component-Client-DNS | libpoe-component-client-dns-perl |
| Redis::Fast                 | p5-Redis-Fast               | libredis-fast-perl               |

`IP::Geolocation::MMDB` reads the `geoip_db` for rules with a `country`
gate, the `geoip_asn_db` for ones with an `asn` gate, and the
`geoip_city_db` for ones with a `travel` gate (see
[configuration.md](configuration.md)). `Net::DNS` and
`POE::Component::Client::DNS` together back `usedns` and the `reverse_dns`
and `dnsbl` gates (see [usedns.md](usedns.md)). `Redis::Fast` backs the
`redis` tablet backend (see [tablets.md](tablets.md)). None are needed
otherwise.

Two more are wanted only by the test suite...

| CPAN module                     | FreeBSD pkg | Debian pkg               |
|---------------------------------|-------------|--------------------------|
| Net::EmptyPort (from Test::TCP) | (cpanm)     | libtest-tcp-perl         |
| Test::RedisServer               | (cpanm)     | libtest-redisserver-perl |

Package names are current as of writing. Anything marked `(cpanm)`, or
missing from your release, installs cleanly from CPAN via
[cpanminus](https://metacpan.org/pod/App::cpanminus).

## From source

Dependencies are declared in Makefile.PL, so from a checkout or an
unpacked release tarball...

```shell
# Makefile.PL itself needs this one before it can say what else is wanted
cpanm File::ShareDir::Install
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

The live Redis tests spin up a throwaway `redis-server` through
`Test::RedisServer` and `Net::EmptyPort`, or use the server named by
`BAPHOMET_TEST_REDIS`, and skip when neither is available.

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

Then check the rules and loose the galla...

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
automatically at startup... but if you point `run_base_dir` somewhere
deeper, make sure the parents exist at boot (a `RuntimeDirectory=` line
or a tmpfiles.d entry does it on systemd). Unix socket paths are limited
to roughly 104 characters on the BSDs, so keep `run_base_dir` short.
