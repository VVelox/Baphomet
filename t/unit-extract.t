#!perl
# direct unit tests for App::Baphomet::Gate::extract and
# App::Baphomet::Gate::forwarded... what each lifts, and from where
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::extract   ();
use App::Baphomet::Gate::forwarded ();

sub extract_gate {
	my (%args) = @_;

	return App::Baphomet::Gate::extract->new(
		'type'  => 'extract',
		'args'  => { 'var' => 'user', 'regexp' => '@(?<DOMAIN>[^@]+)$', %args },
		'where' => 'the gate'
	);
}

my $gate = extract_gate();
is( $gate->phase, 'line', 'it is of the line phase' );

# with no offense yet, the line's fields... shared ones copied first
my %shared  = ( 'user' => 'neti@mail.example.org' );
my %passage = ( 'parsed' => {}, 'rule' => {}, 'fields' => \%shared, 'fields_owned' => 0 );
is( $gate->ask( \%passage ), 1, 'it lets the line by' );
is( $passage{fields}{DOMAIN}, 'mail.example.org', 'and lifts the capture into the line\'s fields' );
ok( !exists( $shared{DOMAIN} ), 'a field space every rule on the line shares is copied, not written to' );

# with offenses standing, into each of them
my %own   = ( 'data' => { 'user' => 'neti@mail.example.org' } );
my %later = ( 'data' => { 'user' => 'root@example.net', 'DOMAIN' => 'from the line' } );
%passage = ( 'parsed' => {}, 'rule' => {}, 'own' => \%own, 'results' => [ \%own, \%later ], 'fields' => { 'user' => 'x@y' } );
$gate->ask( \%passage );
is( $own{data}{DOMAIN},   'mail.example.org', 'with a offense made it lifts into the offense' );
is( $later{data}{DOMAIN}, 'from the line',    'and never over a value one already has' );
ok( !exists( $passage{fields}{DOMAIN} ), 'and not into the fields' );

my $several = extract_gate( 'var' => 'request', 'regexp' => '^/(?<TENANT>[^/]+)/(?<SECTION>[^/?]+)' );
%passage = ( 'parsed' => {}, 'rule' => {}, 'fields' => { 'request' => '/acme/admin?x=1' }, 'fields_owned' => 1 );
$several->ask( \%passage );
is_deeply( [ @{ $passage{fields} }{ 'TENANT', 'SECTION' } ], [ 'acme', 'admin' ], 'every named capture is lifted' );

# a miss, and on_miss
%passage = ( 'parsed' => {}, 'rule' => {}, 'fields' => { 'user' => 'neti' }, 'fields_owned' => 1 );
is( $gate->ask( \%passage ), 1, 'a field it does not match lets the line by' );
ok( !exists( $passage{fields}{DOMAIN} ), 'and lifts nothing' );
my $strict = extract_gate( 'on_miss' => 'fail' );
is( $strict->ask( { 'parsed' => {}, 'rule' => {}, 'fields' => { 'user' => 'neti' } } ), 0, 'on_miss fail turns it away' );
is( $strict->ask( { 'parsed' => {}, 'rule' => {}, 'fields' => {} } ),                   0, 'as it does a field that is not there' );
is( $strict->ask( { 'parsed' => {}, 'rule' => {}, 'fields' => { 'user' => 'a@b' } } ),  1, 'and lets by one it matches' );

my $tokened = extract_gate( 'var' => 'note', 'regexp' => 'from %%%%SRC%%%%' );
%passage = ( 'parsed' => {}, 'rule' => {}, 'fields' => { 'note' => 'relayed from 192.0.2.7' }, 'fields_owned' => 1 );
$tokened->ask( \%passage );
is( $passage{fields}{SRC}, '192.0.2.7', 'the tokens of message_regexp work in it' );
ok( !eval { extract_gate( 'regexp' => 'from %%%%PEER%%%%' ); 1 }, 'and a token there is none of is refused' );

foreach my $bad ( [ { 'regexp' => '(' }, qr/^the gate regexp/ ], [ { 'regexp' => '@[^@]+$' }, qr/^the gate has a regexp with no named capture/ ] ) {
	ok( !eval { extract_gate( %{ $bad->[0] } ); 1 }, 'a regexp of ' . $bad->[0]{regexp} . ' is refused' );
	like( $@, $bad->[1], 'and says why' );
}

#
# forwarded
#

sub forwarded_gate {
	my (%args) = @_;

	return App::Baphomet::Gate::forwarded->new(
		'type'  => 'forwarded',
		'args'  => { 'var' => 'xff', 'peer' => 'host', 'trusted' => [ '10.0.0.0/8', '2001:db8:ffff::/48' ], 'into' => 'CLIENT', %args },
		'where' => 'the gate'
	);
}

# what the gate lifts for a request from the passed peer with the passed
# header, or undef when it lifts nothing
sub client {
	my ( $gate, $peer, $header ) = @_;

	my %data = ( 'host' => $peer, defined($header) ? ( 'xff' => $header ) : () );
	is( $gate->holds( \%data ), 1, 'it holds whatever it finds' );
	return $data{CLIENT};
}

my $proxied = forwarded_gate();
is( $proxied->pass,            'result', 'it is asked once of the offense' );
is( $proxied->reads_offenders, 0,        'and reads no offender, so it sits above the ban_var' );

is( client( $proxied, '203.0.113.9', '198.51.100.7' ), '203.0.113.9', 'a request not from a trusted proxy is its peer\'s, the header ignored' );
is( client( $proxied, '10.0.0.5', '198.51.100.7' ),    '198.51.100.7', 'one from a trusted proxy is the header\'s' );
is( client( $proxied, '10.0.0.5', '198.51.100.7, 10.0.0.9' ), '198.51.100.7', 'the trusted hops on the right are walked past' );
is( client( $proxied, '10.0.0.5', '192.0.2.66, 198.51.100.7, 10.0.0.9' ),
	'198.51.100.7', 'and the first untrusted one is the client, a forged one to its left never read' );
is( client( $proxied, '10.0.0.5', '198.51.100.7:4711' ), '198.51.100.7', 'a port after a address is taken off' );
is( client( $proxied, '10.0.0.5', '[2001:db8::7]:4711, 2001:db8:ffff::1' ), '2001:db8::7', 'as are a IPv6 one\'s brackets' );
is( client( $proxied, '10.0.0.5', 'for=192.0.2.60;proto=http;by=203.0.113.43, for="[2001:db8:cafe::17]:4711"' ),
	'2001:db8:cafe::17', 'a Forwarded header is read by its for= of each hop' );
is( client( $proxied, '10.0.0.5:8080', '198.51.100.7' ), '198.51.100.7', 'a peer written with a port is still a peer' );

is( client( $proxied, '10.0.0.5', '10.0.0.1, 10.0.0.9' ), undef, 'a chain of nothing but trusted proxies names no client' );
is( client( $proxied, '10.0.0.5', 'unknown, 10.0.0.9' ),  undef, 'a hop that is no address stops it' );
is( client( $proxied, '10.0.0.5', undef ),                undef, 'a request from a proxy with no header names no one' );
is( client( $proxied, 'proxy.example.org', '198.51.100.7' ), undef, 'nor one whose peer is no address' );
is( client( forwarded_gate( 'max_hops' => 2 ), '10.0.0.5', '198.51.100.7, 10.0.0.1, 10.0.0.2' ), undef, 'more hops than max_hops names no one' );

my %held = ( 'host' => '203.0.113.9', 'CLIENT' => 'from the line' );
$proxied->holds( \%held );
is( $held{CLIENT}, 'from the line', 'a value the offense already has is not lifted over' );

ok( !eval { forwarded_gate( 'trusted' => ['the proxies'] ); 1 }, 'a trusted entry that is no CIDR is refused' );
ok( !eval { App::Baphomet::Gate::forwarded->new( 'type' => 'forwarded', 'args' => { 'var' => 'xff', 'trusted' => '10.0.0.0/8', 'into' => 'C' }, 'where' => 'the gate' ); 1 },
	'one with no peer is refused' );
like( $@, qr/^the gate lacks a peer/, 'and says so' );

done_testing();
