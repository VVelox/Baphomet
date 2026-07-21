#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();
use App::Baphomet::Rules ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/raw' );
make_path( $dir . '/run' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $dir . '/rules/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

# a negated regexp gate... the fakegooglebot shape, count only when no
# confirmed PTR name is the crawler's
write_rule( 'raw/fake', <<'EOR' );
---
message_regexp:
  - '^probe from %%%%SRC%%%%$'
reverse_dns:
  - matches: '\.crawler\.example$'
    negate: true
ban_var:
  - SRC
tests:
  positive:
    - message: "probe from 192.0.2.10"
      found: 1
      data:
        SRC: "192.0.2.10"
EOR

# the outcome knobs, one variant each
write_rule( 'raw/sfcompare', <<'EOR' );
---
message_regexp:
  - '^probe from %%%%SRC%%%%$'
reverse_dns:
  - matches: '\.crawler\.example$'
    negate: true
    on_servfail: compare
ban_var:
  - SRC
tests:
  positive:
    - message: "probe from 192.0.2.10"
      found: 1
EOR

write_rule( 'raw/sfpass', <<'EOR' );
---
message_regexp:
  - '^probe from %%%%SRC%%%%$'
reverse_dns:
  - matches: '\.crawler\.example$'
    on_servfail: pass
ban_var:
  - SRC
tests:
  positive:
    - message: "probe from 192.0.2.10"
      found: 1
EOR

write_rule( 'raw/nxpass', <<'EOR' );
---
message_regexp:
  - '^probe from %%%%SRC%%%%$'
reverse_dns:
  - matches: '\.crawler\.example$'
    on_nxdomain: pass
ban_var:
  - SRC
tests:
  positive:
    - message: "probe from 192.0.2.10"
      found: 1
EOR

write_rule( 'raw/nxfail', <<'EOR' );
---
message_regexp:
  - '^probe from %%%%SRC%%%%$'
reverse_dns:
  - matches: '\.crawler\.example$'
    negate: true
    on_nxdomain: fail
ban_var:
  - SRC
tests:
  positive:
    - message: "probe from 192.0.2.10"
      found: 1
EOR

# the matches_var form... the PTR must equal what the client claimed
write_rule( 'raw/claim', <<'EOR' );
---
message_regexp:
  - '^hello (?<CLAIM>\S+) from %%%%SRC%%%%$'
reverse_dns:
  - var: SRC
    matches_var: CLAIM
ban_var:
  - SRC
tests:
  positive:
    - message: "hello some.example from 192.0.2.14"
      found: 1
      data:
        SRC: "192.0.2.14"
EOR

open( my $fh, '>', $dir . '/log' ) || die($!);
print $fh '';
close($fh);

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
max_score = 10
find_time = 600

[kur.app]
ban_time = 300

[kur.app.fake]
log = "$dir/log"
parser = "raw"
rule = "raw/fake"

[kur.app.claim]
log = "$dir/log"
parser = "raw"
rule = "raw/claim"

[kur.app.sfcompare]
log = "$dir/log"
parser = "raw"
rule = "raw/sfcompare"

[kur.app.sfpass]
log = "$dir/log"
parser = "raw"
rule = "raw/sfpass"

[kur.app.nxpass]
log = "$dir/log"
parser = "raw"
rule = "raw/nxpass"

[kur.app.nxfail]
log = "$dir/log"
parser = "raw"
rule = "raw/nxfail"
EOC
close($fh);

my $galla = App::Baphomet::Galla->new( 'config' => $dir . '/config.toml', 'name' => 'app' );
ok( defined($galla),   'new worked' );
ok( !$galla->{perror}, 'no perror' ) || diag( $galla->{errorString} );
is( $galla->{enable_rdns}, 1, 'enable_rdns defaults on' );

# the mock lookups, injected through the closure seams so nothing here
# touches real DNS... arrayref (possibly empty, authoritative absence) or
# undef (failure), the tri-state the gate leans on
my %reverse_calls;
$galla->{dns_reverse} = sub {
	my ($address) = @_;
	$reverse_calls{$address}++;
	my %ptr = (
		'192.0.2.10' => ['bot.crawler.example'],
		'192.0.2.11' => [],
		'192.0.2.13' => ['spoof.crawler.example'],
		'192.0.2.14' => ['some.example'],
		'192.0.2.15' => ['lost.crawler.example'],
		'192.0.2.17' => [],
		'192.0.2.18' => [],
	);
	if ( !exists( $ptr{$address} ) ) {
		return undef;
	}
	return $ptr{$address};
}; ## end sub
$galla->{dns_forward} = sub {
	my ($hostname) = @_;
	my %fwd = (
		'bot.crawler.example'   => ['192.0.2.10'],
		'spoof.crawler.example' => ['198.51.100.9'],
		'some.example'          => ['192.0.2.14'],
	);
	return $fwd{$hostname};
};

#
# the negated regexp gate
#

$galla->_handle_line( 'fake', 'probe from 192.0.2.10' );
ok( !defined( $galla->{counters}{'192.0.2.10'} ), 'the real crawler passed the negated gate uncounted' );

$galla->_handle_line( 'fake', 'probe from 192.0.2.11' );
is( scalar( @{ $galla->{counters}{'192.0.2.11'} } ), 1, 'no PTR at all is authoritative absence... counted' );

$galla->_handle_line( 'fake', 'probe from 192.0.2.12' );
ok( !defined( $galla->{counters}{'192.0.2.12'} ), 'a lookup failure vetoes even a negated gate... not counted' );

$galla->_handle_line( 'fake', 'probe from 192.0.2.13' );
is( scalar( @{ $galla->{counters}{'192.0.2.13'} } ), 1, 'a spoofed PTR failed forward confirmation and so counted' );

# the cache answers repeats
$galla->_handle_line( 'fake', 'probe from 192.0.2.11' );
is( $reverse_calls{'192.0.2.11'},                    1, 'the resolver was asked once, the cache answered after' );
is( scalar( @{ $galla->{counters}{'192.0.2.11'} } ), 2, 'and the cached answer still counted' );

#
# the matches_var form
#

$galla->_handle_line( 'claim', 'hello some.example from 192.0.2.14' );
is( scalar( @{ $galla->{counters}{'192.0.2.14'} } ), 1, 'the PTR equalling the claim counted' );

$galla->_handle_line( 'claim', 'hello other.example from 192.0.2.14' );
is( scalar( @{ $galla->{counters}{'192.0.2.14'} } ), 1, 'the PTR differing from the claim did not' );

#
# the outcome knobs... pass and fail are terminal, negate never touches
# them, compare proceeds over whatever names there are
#

# on_servfail compare + negate... an unknown is treated as no names, so
# the negated gate counts it, the opt-in fail2ban stance
$galla->_handle_line( 'sfcompare', 'probe from 192.0.2.12' );
is( scalar( @{ $galla->{counters}{'192.0.2.12'} } ), 1, 'on_servfail compare let the negated gate count a failure' );
# and a forward-confirm failure under compare leaves the name unconfirmed
$galla->_handle_line( 'sfcompare', 'probe from 192.0.2.15' );
is( scalar( @{ $galla->{counters}{'192.0.2.15'} } ),
	1, 'a forward failure under compare left the name unconfirmed and counted' );

# on_servfail pass on a positive gate... the failure satisfies outright
$galla->_handle_line( 'sfpass', 'probe from 192.0.2.16' );
is( scalar( @{ $galla->{counters}{'192.0.2.16'} } ), 1, 'on_servfail pass satisfied a positive gate outright' );

# on_nxdomain pass on a positive gate... in my domain, or no PTR at all
$galla->_handle_line( 'nxpass', 'probe from 192.0.2.17' );
is( scalar( @{ $galla->{counters}{'192.0.2.17'} } ), 1, 'on_nxdomain pass let a PTR-less client through' );

# on_nxdomain fail beats negate... terminal verdicts are never inverted
$galla->_handle_line( 'nxfail', 'probe from 192.0.2.18' );
ok( !defined( $galla->{counters}{'192.0.2.18'} ), 'on_nxdomain fail vetoed despite the negate' );

#
# with enable_rdns off the gate fails closed
#

open( $fh, '>', $dir . '/config2.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache2"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
enable_rdns = false

[kur.quiet]
[kur.quiet.fake]
log = "$dir/log"
parser = "raw"
rule = "raw/fake"
EOC
close($fh);

my $quiet = App::Baphomet::Galla->new( 'config' => $dir . '/config2.toml', 'name' => 'quiet' );
ok( defined($quiet), 'new worked with enable_rdns off' );
$quiet->{dns_reverse} = $galla->{dns_reverse};
$quiet->{dns_forward} = $galla->{dns_forward};
$quiet->_handle_line( 'fake', 'probe from 192.0.2.11' );
ok( !defined( $quiet->{counters}{'192.0.2.11'} ), 'the gate fails closed with out the consent' );

#
# invalid defs
#

my $rules = App::Baphomet::Rules->new( rules_dir => $dir . '/rules' );

write_rule( 'raw/bothcompare',
	"---\nmessage_regexp:\n  - 'x'\nreverse_dns:\n  - matches: 'y'\n    matches_var: Z\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/bothcompare'); 1 }, 'both matches and matches_var refuses to load' );

write_rule( 'raw/nocompare', "---\nmessage_regexp:\n  - 'x'\nreverse_dns:\n  - negate: true\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/nocompare'); 1 }, 'neither matches nor matches_var refuses to load' );

write_rule( 'raw/badkey',
	"---\nmessage_regexp:\n  - 'x'\nreverse_dns:\n  - matches: 'y'\n    derp: 1\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/badkey'); 1 }, 'a unknown entry key refuses to load' );

write_rule( 'raw/badregexp', "---\nmessage_regexp:\n  - 'x'\nreverse_dns:\n  - matches: '('\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/badregexp'); 1 }, 'a matches that does not compile refuses to load' );

write_rule( 'raw/badknob',
	"---\nmessage_regexp:\n  - 'x'\nreverse_dns:\n  - matches: 'y'\n    on_servfail: derp\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/badknob'); 1 }, 'a unknown outcome knob value refuses to load' );

done_testing;
