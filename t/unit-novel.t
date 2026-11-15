#!perl
# direct unit tests for App::Baphomet::Gate::novel and
# App::Baphomet::Gate::banished, both read out of the mark store
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::novel    ();
use App::Baphomet::Gate::banished ();

my %store;

sub bound_over_store {
	my ( $class, $type, $args ) = @_;

	my $gate = $class->new( 'type' => $type, 'args' => $args, 'where' => 'the gate' );
	return $gate->bound( { 'marks' => sub { return \%store; } }, 'the rule "x"' );
}

#
# novel
#

sub novel_gate {
	my (%args) = @_;

	return bound_over_store( 'App::Baphomet::Gate::novel', 'novel', { 'name' => 'login-country', 'by' => 'USER', 'of' => 'COUNTRY', %args } );
}

sub login {
	my ( $user, $country ) = @_;

	return { 'USER' => $user, 'COUNTRY' => $country };
}

my $novel = novel_gate();
is( $novel->pass,            'result', 'it is asked once of the offense' );
is( $novel->reads_offenders, 0,        'and reads no offender, so a detection rule may have one' );
is( $novel->{after_seen},    3,        'a key has to have been seen three times unless told otherwise' );
is( $novel->{ttl},           2592000,  'and a value is remembered thirty days' );

%store = ();
is_deeply( [ map { $novel->holds( login( 'neti', 'US' ), undef, 1000 + $_ ) } 0 .. 2 ], [ 0, 0, 0 ], 'a new key\'s first value is new and does not hold' );
is( $store{'login-country'}{neti}{value}, 3, 'how often the key has been seen is kept under the key' );
ok( exists( $store{'login-country'}{"neti\x1fUS"} ), 'and each value under the key and the value' );

is( $novel->holds( login( 'neti', 'US' ), undef, 1010 ), 0, 'a value the key has had does not hold' );
is( $novel->holds( login( 'neti', 'NL' ), undef, 1020 ), 1, 'one it has not had, the key seen often enough, does' );
is( $novel->holds( login( 'neti', 'NL' ), undef, 1030 ), 0, 'and is then one it has had' );

is( $novel->holds( login( 'namtar', 'NL' ), undef, 1040 ), 0, 'another key has a history of its own, and none yet' );
%store = ();
$novel->holds( login( 'neti', 'US' ), undef, 1000 );
$novel->holds( login( 'neti', 'US' ), undef, 1001 );
is( $novel->holds( login( 'neti', 'NL' ), undef, 1002 ), 0, 'a value new to a key seen only twice does not hold' );
is( $novel->holds( login( 'neti', 'DE' ), undef, 1003 ), 1, 'the next new one, the key now seen three times, does' );

# a value forgotten is new again
%store = ();
my $short = novel_gate( 'ttl' => 100, 'after_seen' => 1 );
$short->holds( login( 'neti', 'US' ), undef, 1000 );
$short->holds( login( 'neti', 'NL' ), undef, 1050 );
is( $short->holds( login( 'neti', 'US' ), undef, 1099 ), 0, 'a value seen with in the ttl is known' );
is( $short->holds( login( 'neti', 'NL' ), undef, 1140 ), 0, 'and being seen again keeps it so' );
is( $short->holds( login( 'neti', 'US' ), undef, 1199 ), 1, 'one last seen a ttl ago is new again' );

%store = ();
is( $novel->holds( { 'USER'    => 'neti' }, undef, 1000 ), 0, 'a offense lacking the value does not hold' );
is( $novel->holds( { 'COUNTRY' => 'US' },   undef, 1000 ), 0, 'nor one lacking the key' );
is_deeply( \%store, {}, 'and neither is a sighting' );

%store = ();
my $pair = novel_gate( 'by' => [ 'USER', 'REALM' ], 'after_seen' => 1 );
$pair->holds( { 'USER' => 'neti', 'REALM' => 'mail', 'COUNTRY' => 'US' }, undef, 1000 );
is_deeply( [ sort( keys( %{ $store{'login-country'} } ) ) ], [ "neti\x1fmail", "neti\x1fmail\x1fUS" ], 'a by of two vars is one key of both' );

#
# banished
#

sub banished_gate {
	my (%args) = @_;

	return bound_over_store( 'App::Baphomet::Gate::banished', 'banished', \%args );
}

my $address = '203.0.113.9';
%store = (
	'banished'    => { $address => { 'expires' => 5000, 'set' => 1000 } },
	'banishments' => { $address => { 'expires' => 9_000_000, 'set' => 1000, 'value' => '100 400 1000' } },
);

my $leak = banished_gate( 'now' => 1 );
is( $leak->pass, 'offender', 'with no var it is asked of each offender' );
is( $leak->holds( {}, $address,       2000 ), 1, 'now holds on a address that is banished' );
is( $leak->holds( {}, '198.51.100.5', 2000 ), 0, 'and not on one that is not' );
is( $leak->holds( {}, $address,       5000 ), 0, 'nor on one whose ban has run out' );
is( $leak->holds( {}, undef,          2000 ), 0, 'nor on no address' );

my $free = banished_gate( 'now' => 0 );
is( $free->holds( {}, $address,       2000 ), 0, 'now false fails on a address that is banished' );
is( $free->holds( {}, '198.51.100.5', 2000 ), 1, 'and holds on one that is not' );

my $settled = banished_gate( 'var' => 'SRC', 'now' => 1, 'for' => 60 );
is( $settled->pass, 'result', 'with a var it is asked once of the offense' );
is( $settled->holds( { 'SRC' => $address }, undef, 1059 ), 0, 'a ban a second short of the for does not hold' );
is( $settled->holds( { 'SRC' => $address }, undef, 1060 ), 1, 'one as old as it does' );
delete( $store{banished}{$address}{set} );
is( $settled->holds( { 'SRC' => $address }, undef, 2000 ), 0, 'a ban with no saying when it was made fails a for' );

my $repeat = banished_gate( 'times' => 3, 'within' => 1000 );
is( $repeat->holds( {}, $address,       1050 ), 1, 'three bans with in the seconds hold for times of three' );
is( $repeat->holds( {}, $address,       1100 ), 0, 'the first of them a second past the seconds, they do not' );
is( $repeat->holds( {}, '198.51.100.5', 1050 ), 0, 'nor does a address never banished' );
is( banished_gate( 'times' => 2, 'within' => 1000 )->holds( {}, $address, 1100 ), 1, 'the two still with in them do for times of two' );

my $both = banished_gate( 'now' => 0, 'times' => 2, 'within' => 90000 );
is( $both->holds( {}, $address, 6000 ), 1, 'not banished now but twice of late is both, and holds' );
is( $both->holds( {}, $address, 2000 ), 0, 'banished now, it does not' );

my %refused = (
	'nothing asked'           => [ {}, qr/^the gate has neither now nor times/ ],
	'a times with no within'  => [ { 'times'  => 3 },    qr/^the gate has a times with out a within/ ],
	'a within with no times'  => [ { 'now' => 1, 'within' => 60 },   qr/^the gate has a times with out a within/ ],
	'a for with no now'       => [ { 'times' => 3, 'within' => 60, 'for' => 5 }, qr/^the gate has a for with out a now that is true/ ],
	'a for beside a now false' => [ { 'now' => 0, 'for' => 5 }, qr/^the gate has a for with out a now that is true/ ],
	'a within past 90 days'   => [ { 'times' => 3, 'within' => 7776001 }, qr/^the gate has a within that is not a positive int of seconds, 7776000 at the most/ ],
);
foreach my $description ( sort( keys(%refused) ) ) {
	my ( $args, $message ) = @{ $refused{$description} };
	my $error
		= eval { App::Baphomet::Gate::banished->new( 'type' => 'banished', 'args' => $args, 'where' => 'the gate' ); 1 }
		? ''
		: $@;
	like( $error, $message, $description . ' is refused' );
}

done_testing();
