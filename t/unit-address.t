#!perl
# direct unit tests for App::Baphomet::Gate::address, the address gate...
# which kind each address is, and the two ways of asking
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::address ();

sub address_gate {
	my (%args) = @_;

	return App::Baphomet::Gate::address->new( 'type' => 'address', 'args' => \%args, 'where' => 'the gate' );
}

# the addresses of each kind, and some of none
my %of_kind = (
	'private'       => [ '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', 'fd00::1' ],
	'loopback'      => [ '127.0.0.1', '127.255.0.9', '::1' ],
	'link_local'    => [ '169.254.10.10', 'fe80::1' ],
	'cgnat'         => [ '100.64.0.1', '100.127.255.255' ],
	'documentation' => [ '192.0.2.7', '198.51.100.5', '203.0.113.9', '2001:db8::1' ],
	'multicast'     => [ '224.0.0.1', '239.255.255.255', 'ff02::1' ],
);
my @public = ( '8.8.8.8', '172.32.0.1', '100.128.0.1', '2606:4700::1111', '1.1.1.1' );

foreach my $kind ( sort( keys(%of_kind) ) ) {
	my $gate = address_gate( 'is' => $kind );
	foreach my $address ( @{ $of_kind{$kind} } ) {
		is( $gate->holds( {}, $address ), 1, $address . ' is ' . $kind );
	}
	foreach my $address (@public) {
		is( $gate->holds( {}, $address ), 0, $address . ' is not ' . $kind );
	}
}

my $bogon = address_gate( 'is' => 'bogon' );
foreach my $address ( ( map { @{$_} } values(%of_kind) ), '0.1.2.3', '192.0.0.8', '198.18.0.1', '240.0.0.1', '255.255.255.255', '::' ) {
	is( $bogon->holds( {}, $address ), 1, $address . ' is a bogon' );
}
foreach my $address (@public) {
	is( $bogon->holds( {}, $address ), 0, $address . ' is no bogon' );
}

is( address_gate( 'is' => 'private' )->holds( {}, '::ffff:10.0.0.1' ), 1, 'a IPv4 mapped IPv6 address is the kind of the IPv4 it is' );

#
# isnot, several kinds, a var, and what is no address
#

my $routable = address_gate( 'isnot' => [ 'private', 'cgnat', 'loopback' ] );
is( $routable->holds( {}, '8.8.8.8' ),    1, 'isnot holds on a address of none of the kinds' );
is( $routable->holds( {}, '100.64.0.9' ), 0, 'and fails on one of any of them' );
is( $routable->holds( {}, '127.0.0.1' ),  0, 'any' );
is( $routable->pass, 'offender', 'with no var it is asked of each offender' );

my $by_var = address_gate( 'is' => 'documentation', 'var' => 'SRC' );
is( $by_var->pass, 'result', 'with a var it is asked once of the offense' );
is( $by_var->holds( { 'SRC' => '192.0.2.7' }, '8.8.8.8' ), 1, 'and checks the var, not the offender' );

foreach my $no_address ( 'crawl.example.org', '', undef, '10.0.0.0/8' ) {
	is( address_gate( 'is'    => 'bogon' )->holds( {}, $no_address ), 0, 'a value that is no address fails is' );
	is( address_gate( 'isnot' => 'bogon' )->holds( {}, $no_address ), 0, 'and isnot' );
}

my %refused = (
	'neither is nor isnot' => [ { 'var' => 'SRC' },                    qr/^the gate has neither is nor isnot/ ],
	'both'                 => [ { 'is'  => 'bogon', 'isnot' => 'private' }, qr/^the gate has both is and isnot/ ],
	'a kind there is none of' => [ { 'is' => 'reserved' }, qr/^the gate has a is that is not one of bogon, cgnat, documentation/ ],
);
foreach my $description ( sort( keys(%refused) ) ) {
	my ( $args, $message ) = @{ $refused{$description} };
	my $error = eval { address_gate( %{$args} ); 1 } ? '' : $@;
	like( $error, $message, $description . ' is refused' );
}

done_testing();
