#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp            qw( tempdir );
use File::Path            qw( make_path );
use App::Baphomet::Rules  ();
use App::Baphomet::Parser ();

my $rules_dir = tempdir( CLEANUP => 1 );
make_path( $rules_dir . '/syslog' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $rules_dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

sub parsed_line {
	my ( $daemon, $message ) = @_;
	return App::Baphomet::Parser::parse( 'bsd_syslog',
		'Jul 12 08:15:50 vixen42 ' . $daemon . '[123]: ' . $message );
}

#
# basic rule, tokens, daemon gate
#

write_rule( 'syslog/basic', <<'EOR' );
---
daemons:
  - sshd
  - //^foo//
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
  - 'addr %%%%ADDR%%%% host %%%%HOST%%%% dns %%%%DNS%%%%'
  - 'subnet %%%%SUBNET%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
  negative:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: good thing from 1.2.3.4"
      found: 0
      undefed: ["SRC"]
EOR

my $rules = App::Baphomet::Rules->new( rules_dir => $rules_dir, shipped => 0 );
my $rule  = $rules->load('syslog/basic');
ok( defined($rule), 'basic rule loaded' );

is( $rules->load('syslog/basic'), $rule, 'cache returns the same object' );

my $found = $rule->check( parsed_line( 'sshd', 'bad thing from 1.2.3.4' ) );
ok( defined($found), 'IPv4 SRC matched' );
is( $found->{data}{SRC}, '1.2.3.4', 'IPv4 SRC captured' );
is( $found->{regexp},    0,         'matching regexp reported' );
is( ( $rule->ban_var )[0], 'SRC', 'ban_var' );

$found = $rule->check( parsed_line( 'sshd', 'bad thing from 2001:db8::1' ) );
ok( defined($found), 'IPv6 SRC matched' );
is( $found->{data}{SRC}, '2001:db8::1', 'IPv6 SRC captured' );

# daemon gate
ok( !defined( $rule->check( parsed_line( 'nginx', 'bad thing from 1.2.3.4' ) ) ), 'daemon gate blocks nginx' );
ok( defined( $rule->check( parsed_line( 'foobar', 'bad thing from 1.2.3.4' ) ) ), 'daemon gate regexp allows foobar' );
ok( !defined( $rule->check( parsed_line( 'barfoo', 'bad thing from 1.2.3.4' ) ) ),
	'daemon gate regexp is anchored as written' );

# other tokens
$found = $rule->check( parsed_line( 'sshd', 'addr 1.2.3.4 host example.com dns example.org' ) );
ok( defined($found), 'ADDR/HOST/DNS matched' );
is( $found->{data}{ADDR}, '1.2.3.4',     'ADDR captured' );
is( $found->{data}{HOST}, 'example.com', 'HOST captured a domain' );
is( $found->{data}{DNS},  'example.org', 'DNS captured' );

$found = $rule->check( parsed_line( 'sshd', 'subnet 10.0.0.0/8' ) );
ok( defined($found), 'SUBNET matched' );
is( $found->{data}{SUBNET}, '10.0.0.0/8', 'SUBNET captured with the mask' );

# an impossible prefix is not part of the subnet
$found = $rule->check( parsed_line( 'sshd', 'subnet 10.0.0.0/999' ) );
ok( defined($found), 'SUBNET with a out of range prefix still matches the address' );
is( $found->{data}{SUBNET}, '10.0.0.0', 'but the impossible prefix is not captured' );

# a DNS name may not end on a hyphen
$found = $rule->check( parsed_line( 'sshd', 'addr 1.2.3.4 host b.example.net dns example.org-' ) );
ok( defined($found), 'DNS beside a trailing hyphen still matched' );
is( $found->{data}{DNS}, 'example.org', 'the trailing hyphen is not captured' );

# no match
ok( !defined( $rule->check( parsed_line( 'sshd', 'nothing of note' ) ) ), 'non-matching message not found' );

#
# SRC/DEST pairing
#

write_rule( 'syslog/paired', <<'EOR' );
---
daemons:
  - routerd
message_regexp:
  - 'flow from %%%%SRC%%%%(?: to %%%%DEST%%%%)?'
ban_var:
  - SRC
EOR

my $paired = $rules->load('syslog/paired');
$found = $paired->check( parsed_line( 'routerd', 'flow from 1.2.3.4 to 5.6.7.8' ) );
ok( defined($found), 'SRC+DEST together found' );
is( $found->{data}{SRC},  '1.2.3.4', 'SRC captured' );
is( $found->{data}{DEST}, '5.6.7.8', 'DEST captured' );
ok( !defined( $paired->check( parsed_line( 'routerd', 'flow from 1.2.3.4' ) ) ),
	'SRC with out DEST not regarded as found' );

#
# duplicate token folding
#

write_rule( 'syslog/dup', <<'EOR' );
---
daemons:
  - dupd
message_regexp:
  - 'either a=%%%%SRC%%%% or b=%%%%SRC%%%%'
ban_var:
  - SRC
EOR

my $dup = $rules->load('syslog/dup');
$found = $dup->check( parsed_line( 'dupd', 'either a=1.2.3.4 or b=5.6.7.8' ) );
ok( defined($found), 'duplicate token rule matched' );
is( $found->{data}{SRC}, '1.2.3.4', 'first occurrence folded under the token name' );
ok( !defined( $found->{data}{SRC_2} ), 'numbered occurrence removed after folding' );

#
# ignore_regexp
#

write_rule( 'syslog/ignore', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ignore_regexp:
  - 'from %%%%SRC%%%% whom we like'
  - 'probably fine'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
  negative:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4 whom we like"
      found: 0
      undefed: ["SRC"]
EOR

my $ignore = $rules->load('syslog/ignore');
ok( defined( $ignore->check( parsed_line( 'sshd', 'bad thing from 1.2.3.4' ) ) ), 'non-ignored line found' );
ok( !defined( $ignore->check( parsed_line( 'sshd', 'bad thing from 1.2.3.4 whom we like' ) ) ),
	'ignore_regexp with a token vetoes the line' );
ok( !defined( $ignore->check( parsed_line( 'sshd', 'bad thing from 1.2.3.4 probably fine' ) ) ),
	'plain ignore_regexp vetoes the line' );

write_rule( 'syslog/badignore', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ignore_regexp:
  - '((('
ban_var:
  - SRC
EOR

ok( !eval { $rules->load('syslog/badignore'); 1 }, 'uncompilable ignore_regexp refuses to load' );

#
# load failures
#

write_rule( 'syslog/failing', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: something else entirely"
      found: 1
      data:
        SRC: "1.2.3.4"
EOR

ok( !eval { $rules->load('syslog/failing'); 1 }, 'rule failing its own tests refuses to load' );
like( $@, qr/failed/, 'failure error mentions the failing' );

my $failing = $rules->load( 'syslog/failing', skip_tests => 1 );
ok( defined($failing), 'skip_tests loads it anyway' );
my $results = $failing->run_tests;
is( $results->{fail}, 1, 'run_tests reports the failure' );

# the cache must not hand the untested copy to a caller wanting the tests
ok( !eval { $rules->load('syslog/failing'); 1 }, 'a cached skip_tests load does not bypass the tests' );

# a typo'd tests section must not mean zero tests and a clean load
write_rule( 'syslog/typotests', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  postive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4"
      found: 1
EOR
ok( !eval { $rules->load('syslog/typotests'); 1 }, 'a misspelled tests section refuses to load' );
like( $@, qr/unknown tests section/, 'and names the unknown section' );

write_rule( 'syslog/badtoken', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%LAMASHTU%%%%'
ban_var:
  - LAMASHTU
EOR

ok( !eval { $rules->load('syslog/badtoken'); 1 }, 'unknown token refuses to load' );
like( $@, qr/unknown token/, 'unknown token error mentions the token' );

write_rule( 'syslog/badregexp', <<'EOR' );
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from ((('
ban_var:
  - SRC
EOR

ok( !eval { $rules->load('syslog/badregexp'); 1 }, 'uncompilable regexp refuses to load' );

ok( !eval { $rules->load('nope/nope'); 1 },        'unknown type refuses to load' );
ok( !eval { $rules->load('syslog/missing'); 1 },   'missing file refuses to load' );
ok( !eval { $rules->load('../../etc/passwd'); 1 }, 'traversal-ish name refuses to load' );
ok( !eval { $rules->load('flat'); 1 },             'typeless name refuses to load' );

ok( App::Baphomet::Rules::known_type('syslog'), 'syslog is a known type' );
ok( !App::Baphomet::Rules::known_type('nope'),  'nope is not a known type' );
ok( $rules->known_type('syslog'),               'known_type works as a method too' );

done_testing;
