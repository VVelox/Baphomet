#!perl
# direct unit tests for App::Baphomet::Gate::dnsbl, the dnsbl gate... a
# fixture map stands in for the blocklists, so what counts as a listing, what
# as a zone that could not be asked, and the name a zone is asked by are
# pinned with out a resolver
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::dnsbl qw( dnsbl_query_name );

# what each zone answers about each address... a array ref, or undef for a
# lookup that failed. a address a zone has no entry for is on no list
my %zones;
my @asked;

# a dnsbl gate told what a rule entry would tell it, bound over the zones
# above and the passed extra context
sub dnsbl_gate {
	my ( $args, %context ) = @_;

	my $gate  = App::Baphomet::Gate::dnsbl->new( 'type' => 'dnsbl', 'args' => $args, 'where' => 'the gate' );
	my $asker = sub {
		my ( $zone, $address ) = @_;
		push( @asked, $zone );
		return exists( $zones{$zone}{$address} ) ? $zones{$zone}{$address} : [];
	};
	return $gate->bound( { 'dnsbl' => sub { return $asker; }, %context }, 'the rule "x"' );
}

#
# the name a zone is asked by
#

is( dnsbl_query_name( '192.0.2.7', 'bl.example.org' ), '7.2.0.192.bl.example.org', 'a IPv4 address has its octets reversed' );
is(
	dnsbl_query_name( '2001:db8::1', 'bl.example.org' ),
	'1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.bl.example.org',
	'a IPv6 address has its 32 nibbles reversed'
);
is( dnsbl_query_name( 'crawl.example.org', 'bl.example.org' ), undef, 'a value that is no address has no name' );

#
# compile
#

my $compiled = App::Baphomet::Gate::dnsbl->new( 'type' => 'dnsbl', 'args' => { 'zones' => 'bl.example.org' }, 'where' => 'the gate' );
is_deeply( $compiled->{zones}, ['bl.example.org'], 'a lone zone is a list of one' );
is( $compiled->{on_servfail}, 'fail',     'a failed lookup fails the gate unless told otherwise' );
is( $compiled->pass,          'offender', 'with no var it is asked of each offender' );
is_deeply( [ $compiled->needs ], ['dnsbl'],    'it needs the asker' );
is_deeply( [ $compiled->wants ], ['internal'], 'and uses internal when it is there' );

#
# listed, not listed, and the answers that are neither
#

%zones = (
	'bl.example.org' => {
		'203.0.113.9'  => ['127.0.0.2'],
		'203.0.113.10' => ['127.0.0.4'],
		'203.0.113.11' => undef,
		'203.0.113.12' => ['127.255.255.254'],
		'203.0.113.13' => ['192.0.2.1'],
		'2001:db8::9'  => ['127.0.0.2'],
	},
	'bl2.example.org' => { '203.0.113.11' => ['127.0.0.3'], '203.0.113.20' => undef },
);

my $one_zone = dnsbl_gate( { 'zones' => 'bl.example.org' } );
is( $one_zone->holds( {}, '203.0.113.9' ),  1, 'a address a zone lists holds' );
is( $one_zone->holds( {}, '2001:db8::9' ),  1, 'a IPv6 one the same' );
is( $one_zone->holds( {}, '198.51.100.5' ), 0, 'a address on no list does not' );
is( $one_zone->holds( {}, '203.0.113.11' ), 0, 'a lookup that failed fails closed' );
is( $one_zone->holds( {}, '203.0.113.12' ), 0, 'a refusal out of 127.255.255.0/24 is a failed lookup, not a listing' );
is( $one_zone->holds( {}, '203.0.113.13' ), 0, 'a answer out of no blocklist range is a failed lookup too' );
is( $one_zone->holds( {}, 'crawl.example.org' ), 0, 'a value that is no address fails closed' );
is( $one_zone->holds( {}, undef ),               0, 'as does no value' );

my $by_var = dnsbl_gate( { 'zones' => 'bl.example.org', 'var' => 'PEER' } );
is( $by_var->pass, 'result', 'with a var it is asked once of the offense' );
is( $by_var->holds( { 'PEER' => '203.0.113.9' }, '198.51.100.5' ), 1, 'and checks the var, not the offender' );
is( $by_var->holds( {}, '203.0.113.9' ),                          0, 'a var the offense lacks fails closed' );

my $coded = dnsbl_gate( { 'zones' => 'bl.example.org', 'codes' => [ '127.0.0.2', '127.0.0.3' ] } );
is( $coded->holds( {}, '203.0.113.9' ),  1, 'a answer among the codes is a listing' );
is( $coded->holds( {}, '203.0.113.10' ), 0, 'a answer that is not among them is none' );

#
# several zones
#

my $two_zones = dnsbl_gate( { 'zones' => [ 'bl.example.org', 'bl2.example.org' ] } );
@asked = ();
is( $two_zones->holds( {}, '203.0.113.9' ), 1, 'any zone listing the address holds' );
is_deeply( \@asked, ['bl.example.org'], 'and the zones after the one that listed it are not asked' );
is( $two_zones->holds( {}, '203.0.113.11' ), 1, 'a listing stands though another zone could not be asked' );
is( $two_zones->holds( {}, '203.0.113.20' ), 0, 'with no listing a zone that could not be asked fails the gate' );

#
# negate and on_servfail
#

my $clean = dnsbl_gate( { 'zones' => [ 'bl.example.org', 'bl2.example.org' ], 'negate' => 1 } );
is( $clean->holds( {}, '198.51.100.5' ), 1, 'negate holds on a address no zone lists' );
is( $clean->holds( {}, '203.0.113.9' ),  0, 'and fails on a listed one' );
is( $clean->holds( {}, '203.0.113.20' ), 0, 'a zone that could not be asked clears nobody, negate or not' );
is( $clean->holds( {}, '203.0.113.11' ), 0, 'and a listing is a listing though another zone failed' );

my $lenient = dnsbl_gate( { 'zones' => 'bl.example.org', 'on_servfail' => 'pass' } );
is( $lenient->holds( {}, '203.0.113.11' ), 1, 'on_servfail pass lets a failed lookup by' );
is( $lenient->holds( {}, '198.51.100.5' ), 0, 'and changes nothing for a zone that answered' );

#
# the operator's own, and nothing to ask with
#

my $guarded = dnsbl_gate( { 'zones' => 'bl.example.org' }, 'internal' => sub { return $_[0] eq '203.0.113.9'; } );
@asked = ();
is( $guarded->holds( {}, '203.0.113.9' ), 0, 'one of the operator\'s own is taken as on no list' );
is_deeply( \@asked, [], 'and no zone is told of it' );
is( $guarded->holds( {}, '203.0.113.10' ), 1, 'a address that is not one of them is asked about as ever' );

my $unbound = App::Baphomet::Gate::dnsbl->new( 'type' => 'dnsbl', 'args' => { 'zones' => 'bl.example.org', 'negate' => 1 }, 'where' => 'the gate' );
my $silent  = $unbound->bound( { 'dnsbl' => sub { return undef; } }, 'the rule "x"' );
is( $silent->holds( {}, '198.51.100.5' ), 0, 'with nothing to ask with it fails closed, negate or not' );

#
# zone_into and code_into... the listing lifted for what is below the gate
#

my $lifting = dnsbl_gate(
	{ 'zones' => [ 'bl2.example.org', 'bl.example.org' ], 'var' => 'PEER', 'zone_into' => 'ZONE', 'code_into' => 'CODE' } );
my %data = ( 'PEER' => '203.0.113.10' );
is( $lifting->holds( \%data ), 1, 'a gate that lifts holds as it would with out' );
is_deeply(
	\%data,
	{ 'PEER' => '203.0.113.10', 'ZONE' => 'bl.example.org', 'CODE' => '127.0.0.4' },
	'the zone that listed the address and the answer it gave are lifted'
);

%data = ( 'PEER' => '198.51.100.5' );
is( $lifting->holds( \%data ), 0, 'a address on no list' );
is_deeply( \%data, { 'PEER' => '198.51.100.5' }, 'lifts nothing' );

my $coded_lift = dnsbl_gate(
	{ 'zones' => 'bl2.example.org', 'var' => 'PEER', 'codes' => '127.0.0.3', 'code_into' => 'CODE' } );
%zones = ( %zones, 'bl2.example.org' => { '203.0.113.11' => [ '127.0.0.9', '127.0.0.3' ] } );
%data  = ( 'PEER' => '203.0.113.11' );
$coded_lift->holds( \%data );
is( $data{CODE}, '127.0.0.3', 'with codes the answer lifted is the one that counted' );

%data = ( 'PEER' => '203.0.113.11', 'CODE' => 'from the line' );
$coded_lift->holds( \%data );
is( $data{CODE}, 'from the line', 'a value the offense already has is not lifted over' );

my $clean_lift = dnsbl_gate( { 'zones' => 'bl.example.org', 'var' => 'PEER', 'negate' => 1, 'zone_into' => 'ZONE' } );
%data = ( 'PEER' => '198.51.100.5' );
is( $clean_lift->holds( \%data ), 1, 'under negate it holds on no listing' );
ok( !exists( $data{ZONE} ), 'and there is no listing to lift' );
%data = ( 'PEER' => '203.0.113.9' );
is( $clean_lift->holds( \%data ), 0, 'and a listing it vetoes on' );
ok( !exists( $data{ZONE} ), 'is not lifted either' );

foreach my $lift ( 'zone_into', 'code_into' ) {
	ok(
		!eval {
			App::Baphomet::Gate::dnsbl->new(
				'type'  => 'dnsbl',
				'args'  => { 'zones' => 'bl.example.org', $lift => 'X' },
				'where' => 'the gate'
			);
			1;
		},
		'a ' . $lift . ' with no var is refused'
	);
	like( $@, qr/^the gate has a zone_into or code_into, which needs a var to lift the listing of/, 'and says why' );
}

done_testing();
