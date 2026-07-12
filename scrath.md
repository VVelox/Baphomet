use POE::Component::Server::JSONUnix JSON::MaybeXS  YAML::XS App::Cmd POE::Wheel::FollowTail Regexp::IPv4 Regexp::IPv6

read /home/kitsune/github/Ereshkigal

use App::Baphomet as the module name

App::Baphomet::Rules implements the rules parser/handler
App::Baphomet::Rules::Syslog implements the handler for syslog rules

Baphomet reads logs and forwards failed IPs to Ereshkigal

wire baphotmet in with summerian/Mesopotamian dieties similar to Ereshkigal when it comes to writing out README.md and the docs/ dir

the config file is /usr/local/etc/baphomet/config.toml 

/usr/local/etc/baphomet/rules/ contains matching rules

.kur under the config file contains kurs that will be used

```
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

parser types should be...

ietf_syslog for RFC 5424 syslog
bsd_syslog for RFC 3164 syslog
json for json files
raw for raw

So for the example above it would look for `syslog/sshd.yaml` under the rules directory.

```
---
deamons:
  - sshd
  - sshd-session
message_regexp:
  - perl regexp pseodo code to fill out based on fail2ban
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd-session[66891]: Invalid user moth3r from 216.137.179.214 port 34640"
	  found: 1
      data:
        SRC: "216.137.179.214"
  negative:
    - message:"Jul 12 08:25:49 vixen42 sshd-session[36748]: Accepted publickey for kitsune from 127.0.0.1 port 21680 ssh2: ED25519 SHA256:hjUfLIEAIR3ueytAg+XlbiVHmCQSQ6MCEdo2xYbyJ48"
	  found: 0
      undefed: ["SRC"]
```

read /home/kitsune/github/fail2ban/config/filter.d for a idea of rexexp stuff to match ... that will need converted to perl and simplified

for now we will skip implement raw and json parser types and focus on syslog...

the syslog parser should extract the following... time, hostname, daemon, level, pid, facility, severity, and message...

facility and severity will not always be available

daemons in the rule file will specify which daemon types that rule processes... if it does not match further checking can be skipped ... entries starting/ending with // should be treated as regexp otherwise it is just a string equlity

tests in the rules file contains positive and negative tests for verifying the rules work

ban_var is the named regexp matches to used for bans

message_regexp contains the various tests to match against the message line ... items matching %%%%SRC%%%% for example should replace that chunk of the test with a named regexp that implements matching IPv4/IPv6 strings ...

- HOST :: Matches a domain name, IPv4 address, or IPv6 address.
- SUBNET ::Matches a IPv6 or IPv4 subnet or address.
- IP4 ::Matches a IPv4 address.
- IP6 ::Matches a IPv6 address.
- ADDR ::Matches a IPv4 or IPv6 address.
- DNS ::Matches a domainname.
- SRC / DEST :: These two are meant to be used in combination and only regard as being found if matched together. It will match either a IPv4 or IPv6 address.
