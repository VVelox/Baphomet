#!perl
# direct unit tests for App::Baphomet::Gate::network, the network gate...
# what it lifts, and that it never vetoes
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::network ();

sub network_gate {
	my (%args) = @_;

	return App::Baphomet::Gate::network->new(
		'type'  => 'network',
		'args'  => { 'var' => 'SRC', 'into' => 'NET', %args },
		'where' => 'the gate'
	);
}

# what the gate lifts for a address, or undef when it lifts nothing
sub lifted {
	my ( $gate, $address ) = @_;

	my %data = ( 'SRC' => $address );
	is( $gate->holds( \%data ), 1, 'it holds whatever ' . ( $address // 'no address' ) . ' is' );
	return $data{NET};
}

my $gate = network_gate();
is( $gate->pass,            'result', 'it is asked once of the offense' );
is( $gate->reads_offenders, 0,        'and reads no offender, so it may sit above the ban_var' );
is_deeply( [ $gate->needs ], [], 'it needs nothing of the context' );

is( lifted( $gate, '203.0.113.77' ),         '203.0.113.0/24',  'a IPv4 address is cut to its /24' );
is( lifted( $gate, '2001:db8:1:2:3:4:5:6' ), '2001:db8:1:2::/64', 'a IPv6 one to its /64' );
is( lifted( $gate, '::ffff:203.0.113.77' ),  '203.0.113.0/24',  'a IPv4 mapped IPv6 one is cut as the IPv4 it is' );
is( lifted( $gate, 'crawl.example.org' ),    undef,             'a value that is no address lifts nothing' );
is( lifted( $gate, undef ),                  undef,             'nor does no value' );

my $wide = network_gate( 'v4' => 16, 'v6' => 48 );
is( lifted( $wide, '203.0.113.77' ),         '203.0.0.0/16',     'v4 says how a IPv4 address is cut' );
is( lifted( $wide, '2001:db8:1:2:3:4:5:6' ), '2001:db8:1::/48',  'and v6 a IPv6 one' );

my %held = ( 'SRC' => '203.0.113.77', 'NET' => 'from the line' );
$gate->holds( \%held );
is( $held{NET}, 'from the line', 'a value the offense already has is not lifted over' );

my %refused = (
	'no into'           => [ { 'var'  => 'SRC' }, qr/^the gate lacks a into/ ],
	'no var'            => [ { 'into' => 'NET' }, qr/^the gate lacks a var/ ],
	'a v4 past 32'      => [ { 'var'  => 'SRC', 'into' => 'NET', 'v4' => 33 },  qr/^the gate has a v4 that is not a prefix length of 1 to 32/ ],
	'a v6 of nothing'   => [ { 'var'  => 'SRC', 'into' => 'NET', 'v6' => 0 },   qr/^the gate has a v6 that is not a prefix length of 1 to 128/ ],
);
foreach my $description ( sort( keys(%refused) ) ) {
	my ( $args, $message ) = @{ $refused{$description} };
	my $error
		= eval { App::Baphomet::Gate::network->new( 'type' => 'network', 'args' => $args, 'where' => 'the gate' ); 1 }
		? ''
		: $@;
	like( $error, $message, $description . ' is refused' );
}

done_testing();
