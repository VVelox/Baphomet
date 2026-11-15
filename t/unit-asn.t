#!perl
# direct unit tests for App::Baphomet::Gate::asn, the asn gate... a fixture
# map stands in for the ASN database, so the fail-closed rules, the token
# resolution, and the lifts are pinned with out one
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::asn ();

# a asn gate told what a rule entry would tell it, and bound over a locator
# of the passed address to network map and the passed named lists
sub asn_gate {
	my ( $args, $networks, $lists ) = @_;

	my $gate = App::Baphomet::Gate::asn->new( 'type' => 'asn', 'args' => $args, 'where' => 'the gate' );
	return $gate->bound( { 'asn_locator' => sub { return $networks->{ $_[0] }; }, 'asn_lists' => $lists },
		'the rule "x"' );
}

my %networks = (
	'203.0.113.9'  => { 'number' => 64496, 'org' => 'Example Hosting' },
	'198.51.100.5' => { 'number' => 64500, 'org' => 'Example Telecom' },
	'192.0.2.77'   => { 'number' => 64511, 'org' => undef },
);

#
# compile... the mode, lone values as lists, and the pass
#

my $compiled = App::Baphomet::Gate::asn->new(
	'type'  => 'asn',
	'args'  => { 'isnot' => 'AS64496', 'vars' => 'src' },
	'where' => 'the gate'
);
is( $compiled->{mode}, 'isnot', 'the mode is the key that was written' );
is_deeply( $compiled->{entries}, ['AS64496'], 'a lone entry is a list of one' );
is_deeply( $compiled->{vars},    ['src'],     'and so is a lone var' );
is( $compiled->pass, 'result', 'a gate naming vars is of the result pass' );
is_deeply( [ $compiled->needs ], ['asn_locator'], 'it needs the asn locator' );

my $offender_keyed = App::Baphomet::Gate::asn->new( 'type' => 'asn', 'args' => { 'is' => 64496 }, 'where' => 'the gate' );
is( $offender_keyed->pass, 'offender', 'a gate naming no vars is of the offender pass' );

my %refused = (
	'two modes at once'           => [ { 'is'     => 64496, 'org_is' => 'x' }, qr/^the gate has both is and org_is/ ],
	'nothing to do'               => [ { 'vars'   => 'src' },                  qr/^the gate has none of is, isnot/ ],
	'a regexp that will not compile' => [ { 'org_is' => '(' }, qr/^the gate has a org_is that does not compile\.\.\. / ],
	'a lift with no var'          => [ { 'into'   => 'ASN' },                  qr/needs exactly one var/ ],
	'a lift with two vars'        => [ { 'org_into' => 'ORG', 'vars' => [ 'a', 'b' ] }, qr/needs exactly one var/ ],
	'a entry that is no number'   => [ { 'is'     => 'AS-SET' },               qr/^the gate has a is that is not a AS number/ ],
);
foreach my $description ( sort( keys(%refused) ) ) {
	my ( $args, $message ) = @{ $refused{$description} };
	my $error = eval { App::Baphomet::Gate::asn->new( 'type' => 'asn', 'args' => $args, 'where' => 'the gate' ); 1 }
		? ''
		: $@;
	like( $error, $message, $description . ' is refused' );
}

#
# bound... numbers however they were written, and the imports
#

my $listed = asn_gate( { 'is' => [ 'as64496', '%%%asn_lists{carriers}%%%' ] }, \%networks, { 'carriers' => [64500] } );
is_deeply( $listed->{numbers}, { 64496 => 1, 64500 => 1 }, 'a AS prefix comes off and a import is spliced in' );

my $unbound = App::Baphomet::Gate::asn->new(
	'type'  => 'asn',
	'args'  => { 'is' => '%%%asn_lists{nowhere}%%%' },
	'where' => 'the gate'
);
ok( !eval { $unbound->bound( { 'asn_locator' => sub { }, 'asn_lists' => {} }, 'the rule "x"' ); 1 },
	'a import of a list the context lacks dies at binding' );
like( $@, qr/^the rule "x" imports asn_lists\{nowhere\}, which is not a defined list for it/, 'and says which' );

#
# holds by number
#

is( $listed->holds( {}, '203.0.113.9' ),  1, 'is holds on a listed number' );
is( $listed->holds( {}, '198.51.100.5' ), 1, 'and on one a import listed' );
is( $listed->holds( {}, '192.0.2.77' ),   0, 'is fails on a number that is not listed' );
is( $listed->holds( {}, '192.0.2.1' ),    0, 'is fails closed on a address the locator can not place' );
is( $listed->holds( {}, undef ),          0, 'and on no address at all' );

my $unlisted = asn_gate( { 'isnot' => 64496 }, \%networks, {} );
is( $unlisted->holds( {}, '203.0.113.9' ),  0, 'isnot fails on a listed number' );
is( $unlisted->holds( {}, '198.51.100.5' ), 1, 'isnot holds on one that is not' );
is( $unlisted->holds( {}, '192.0.2.1' ),    0, 'isnot fails closed on a address the locator can not place' );

my $by_var = asn_gate( { 'is' => 64496, 'vars' => [ 'src', 'dest' ] }, \%networks, {} );
is( $by_var->holds( { 'src' => '203.0.113.9', 'dest' => '203.0.113.9' } ),  1, 'every var has to pass, and here both do' );
is( $by_var->holds( { 'src' => '203.0.113.9', 'dest' => '198.51.100.5' } ), 0, 'one var failing fails the gate' );
is( $by_var->holds( { 'src' => '203.0.113.9' } ),                           0, 'a var the data lacks fails closed' );

#
# holds by name
#

my $hosting = asn_gate( { 'org_is' => [ '(?i)hosting', '(?i)cloud' ] }, \%networks, {} );
is( $hosting->holds( {}, '203.0.113.9' ),  1, 'org_is holds on a name one of its regexps matches' );
is( $hosting->holds( {}, '198.51.100.5' ), 0, 'and fails on a name none of them match' );
is( $hosting->holds( {}, '192.0.2.77' ),   0, 'a network with no name fails closed' );

my $not_hosting = asn_gate( { 'org_isnot' => '(?i)hosting' }, \%networks, {} );
is( $not_hosting->holds( {}, '203.0.113.9' ),  0, 'org_isnot fails on a name its regexp matches' );
is( $not_hosting->holds( {}, '198.51.100.5' ), 1, 'and holds on one it does not' );
is( $not_hosting->holds( {}, '192.0.2.77' ),   0, 'a network with no name fails closed for org_isnot too' );

#
# the lifts
#

my $lifting = asn_gate( { 'vars' => 'src', 'into' => 'ASN', 'org_into' => 'ORG' }, \%networks, {} );
my %data    = ( 'src' => '203.0.113.9' );
is( $lifting->holds( \%data ), 1, 'a gate that only lifts holds' );
is_deeply( \%data, { 'src' => '203.0.113.9', 'ASN' => 64496, 'ORG' => 'Example Hosting' }, 'the number and the name are lifted' );

%data = ( 'src' => '192.0.2.77' );
$lifting->holds( \%data );
is_deeply( \%data, { 'src' => '192.0.2.77', 'ASN' => 64511 }, 'a network with no name lifts its number alone' );

%data = ( 'src' => '192.0.2.1' );
is( $lifting->holds( \%data ), 1, 'a gate that only lifts vetoes nothing on a address it can not place' );
is_deeply( \%data, { 'src' => '192.0.2.1' }, 'and lifts nothing' );

%data = ( 'src' => '203.0.113.9', 'ASN' => 'from the line' );
$lifting->holds( \%data );
is( $data{ASN}, 'from the line', 'a value the offense already has is not lifted over' );

my $judging_lift = asn_gate( { 'isnot' => 64496, 'vars' => 'src', 'into' => 'ASN' }, \%networks, {} );
%data = ( 'src' => '203.0.113.9' );
is( $judging_lift->holds( \%data ), 0, 'a gate that judges and lifts still vetoes' );
ok( !exists( $data{ASN} ), 'and a vetoed offense is lifted nothing' );
%data = ( 'src' => '198.51.100.5' );
is( $judging_lift->holds( \%data ), 1, 'and it lifts into what it holds for' );
is( $data{ASN}, 64500, 'the number of the address it judged' );

done_testing();
