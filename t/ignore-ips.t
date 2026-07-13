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

# unusable entries die
ok( !eval { compile_ignore_ips( ['not-an-ip'], 't' );      1 }, 'a hostname entry dies' );
ok( !eval { compile_ignore_ips( ['10.0.0.0/33'], 't' );    1 }, 'a overlong v4 prefix dies' );
ok( !eval { compile_ignore_ips( ['2001:db8::/129'], 't' ); 1 }, 'a overlong v6 prefix dies' );
ok( !eval { compile_ignore_ips( [''], 't' );               1 }, 'a empty entry dies' );
ok( !eval { compile_ignore_ips( 'nope', 't' );             1 }, 'a non-array dies' );

done_testing;
