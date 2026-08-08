#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use App::Baphomet::Config qw( compile_ignore_ips ip_ignored );

my $compiled = compile_ignore_ips( [ '127.0.0.0/8', '192.168.0.0/16', '203.0.113.7', '2001:db8::/32', '::1' ], 't' );
ok( defined($compiled), 'list compiled' );

ok( ip_ignored( $compiled, '127.0.0.1' ),         'v4 CIDR /8 match' );
ok( ip_ignored( $compiled, '127.255.255.255' ),   'v4 CIDR /8 edge match' );
ok( ip_ignored( $compiled, '192.168.44.9' ),      'v4 CIDR /16 match' );
ok( !ip_ignored( $compiled, '192.169.0.1' ),      'v4 just outside the /16' );
ok( ip_ignored( $compiled, '203.0.113.7' ),       'bare v4 match' );
ok( !ip_ignored( $compiled, '203.0.113.8' ),      'bare v4 non-match' );
ok( ip_ignored( $compiled, '2001:db8::dead' ),    'v6 CIDR match' );
ok( !ip_ignored( $compiled, '2001:db9::1' ),      'v6 just outside' );
ok( ip_ignored( $compiled, '::1' ),               'bare v6 match' );
ok( ip_ignored( $compiled, '::ffff:127.0.0.1' ),  'v4 mapped v6 checked as its v4 self' );
ok( !ip_ignored( $compiled, 'some.host.example' ), 'a hostname is never ignored' );
ok( !ip_ignored( $compiled, undef ),               'undef is never ignored' );

# a non-octet-boundary prefix
my $odd = compile_ignore_ips( ['10.0.0.0/12'], 't' );
ok( ip_ignored( $odd, '10.15.255.255' ), 'inside a /12' );
ok( !ip_ignored( $odd, '10.16.0.0' ),    'just outside a /12' );

# empty list ignores no one
is( ip_ignored( compile_ignore_ips( [], 't' ), '127.0.0.1' ), 0, 'empty list ignores no one' );

# the byte and bit split each network is compared under is cut at compile
# rather than per test, so every prefix shape is walked here... the boundary
# ones, where there is no partial byte to mask, and each bit of a partial one
foreach my $bit ( 1 .. 8 ) {
	# /25 through /32, walking the partial byte a bit at a time... $inside is
	# the first address of the top block that prefix cuts out of the octet
	my $prefix = 24 + $bit;
	my $inside = 256 - ( 2**( 8 - $bit ) );
	my $list   = compile_ignore_ips( [ '198.51.100.' . $inside . '/' . $prefix ], 't' );
	ok( ip_ignored( $list,  '198.51.100.' . $inside ),         'the network address itself matches a /' . $prefix );
	ok( ip_ignored( $list,  '198.51.100.255' ),                'and so does the top of its block, a /' . $prefix );
	ok( !ip_ignored( $list, '198.51.100.' . ( $inside - 1 ) ), 'the address below it does not, a /' . $prefix );
} ## end foreach my $bit ( 1 .. 8 )

# a whole-byte prefix has no partial byte at all, the branch the precompute
# leaves out entirely
foreach my $prefix ( 8, 16, 24, 32 ) {
	my $list = compile_ignore_ips( [ '198.51.100.0/' . $prefix ], 't' );
	ok( ip_ignored( $list, '198.51.100.0' ), 'the network address matches a /' . $prefix );
}
ok( !ip_ignored( compile_ignore_ips( ['198.51.100.0/32'], 't' ), '198.51.100.1' ), 'a /32 is exactly one address' );

# a /0 pins nothing, so every address of the family is in it and none of the
# other is... the degenerate end of the same arithmetic
my $everything = compile_ignore_ips( [ '0.0.0.0/0', '::/0' ], 't' );
ok( ip_ignored( $everything,  '198.51.100.7' ),      'a v4 /0 holds every v4 address' );
ok( ip_ignored( $everything,  '2001:db8::1' ),       'a v6 /0 holds every v6 address' );
ok( !ip_ignored( $everything, 'some.host.example' ), 'and a /0 still does not hold a hostname' );

# the families never cross... a v6 network must not answer for a v4 address
my $v6_only = compile_ignore_ips( ['2001:db8::/32'], 't' );
ok( !ip_ignored( $v6_only, '32.1.13.184' ), 'a v6 network does not match a v4 address of the same bytes' );
my $v4_only = compile_ignore_ips( ['10.0.0.0/8'], 't' );
ok( !ip_ignored( $v4_only, '2001:db8::1' ),     'and a v4 network does not match a v6 address' );
ok( ip_ignored( $v4_only,  '::ffff:10.1.2.3' ), 'though a v4 mapped v6 is matched as the v4 it is' );

# a non-boundary v6 prefix, the partial byte in the other family
my $v6_odd = compile_ignore_ips( ['2001:db8:8000::/33'], 't' );
ok( ip_ignored( $v6_odd,  '2001:db8:ffff::1' ), 'inside a v6 /33' );
ok( !ip_ignored( $v6_odd, '2001:db8:7fff::1' ), 'just outside a v6 /33' );

# unusable entries die
ok( !eval { compile_ignore_ips( ['not-an-ip'], 't' );      1 }, 'a hostname entry dies' );
ok( !eval { compile_ignore_ips( ['10.0.0.0/33'], 't' );    1 }, 'a overlong v4 prefix dies' );
ok( !eval { compile_ignore_ips( ['2001:db8::/129'], 't' ); 1 }, 'a overlong v6 prefix dies' );
ok( !eval { compile_ignore_ips( [''], 't' );               1 }, 'a empty entry dies' );
ok( !eval { compile_ignore_ips( 'nope', 't' );             1 }, 'a non-array dies' );

done_testing;
