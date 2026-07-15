# Baphomet

In Sumerian myth the galla are the demons of Kur, the underworld. They
answer to no bribe and accept no gift... they exist to seize the condemned
and drag them below, where Ereshkigal rules.

In the world above, Baphomet is a log watcher in the same family as
fail2ban, and the accuser half of a pair whose punisher half is
[Ereshkigal](https://github.com/LilithSec/Ereshkigal). A `baphomet` manager
daemon spawns one `galla` worker per kur configured. Each galla follows the
log files of its kur, parses the lines, reads them against its rules like
omen tablets, and counts the offenses of each IP. An IP that racks up
`max_retrys` offenses with in `find_time` seconds is seized and banished
to Kur... a ban request sent to the Ereshkigal manager socket, targeted at
the kur of the same name over there, a real kur or a fan_out gate relaying
to several. Ereshkigal does the actual firewalling. Baphomet never touches
the firewall itself.

Watching sshd looks like this in `/usr/local/etc/baphomet/config.toml`...

```toml
# the base kur config for sshd
[kur.sshd]
max_retrys=5
ban_time=300
# read authlog
# the key for the hash under sshd is just a freeform name
[kur.sshd.authlog]
log=/var/log/auth.log
parser=bsd_syslog
rule=syslog/sshd
```

...and running it looks like this...

```shell
# loose the galla
baphomet start

# see what they are up to
baphomet status --all

# the IPs being counted toward a banishment, and who Kur already holds
baphomet accused
baphomet banished

# the banishment history... when, which kur, which IP, by which rule
baphomet ledger --since 7d

# verify the rules pass their own embedded tests
baphomet check_rules

# poke a single log line at a rule while writing one
baphomet test_line --rule syslog/sshd 'Jul 12 08:15:50 vixen42 sshd[1]: Invalid user foo from 1.2.3.4'
```

Rules are YAML files carrying their own positive and negative tests, which
are ran at load time... a rule that fails its own tests refuses to load.
See [docs/rules.md](docs/rules.md) for writing them.

## Install

Requires a running [Ereshkigal](https://github.com/LilithSec/Ereshkigal)
for the bans to go anywhere.

### From source

Dependencies are declared in Makefile.PL, so with
[cpanminus](https://metacpan.org/pod/App::cpanminus)...

```shell
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

Then copy the shipped rules into place...

```shell
mkdir -p /usr/local/etc/baphomet
cp -R rules /usr/local/etc/baphomet/
```

### FreeBSD

```shell
pkg install p5-App-Cmd p5-Error-Helper p5-JSON-MaybeXS p5-Net-Server \
    p5-POE p5-YAML-LibYAML p5-Regexp-IPv6 p5-App-cpanminus
cpanm TOML::Tiny Regexp::IPv4 POE::Component::Server::JSONUnix \
    Ereshkigal App::Baphomet
```

Startup script for running at boot [rc/freebsd/baphomet](rc/freebsd/baphomet).

### Debian

```shell
apt-get install libapp-cmd-perl libjson-maybexs-perl libnet-server-perl \
    libpoe-perl libtoml-tiny-perl libyaml-libyaml-perl libregexp-ipv6-perl \
    cpanminus
cpanm Error::Helper Regexp::IPv4 POE::Component::Server::JSONUnix \
    Ereshkigal App::Baphomet
```

Startup script for running at boot
[rc/systemd/baphomet.service](rc/systemd/baphomet.service).

## License

GNU General Public License, version 2 or (at your option) any later
version... see [COPYING](COPYING). The shipped rules are derived from the
filters of [fail2ban](https://github.com/fail2ban/fail2ban), which is under
the same license.

## Documentation

To continue your journey go to [docs/index.md](docs/index.md).

Also...

- `perldoc App::Baphomet`
- `perldoc App::Baphomet::Galla`
- `perldoc App::Baphomet::Rules::Syslog`
