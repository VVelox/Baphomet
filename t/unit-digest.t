#!perl
# direct unit tests for App::Baphomet::Gate::digest and
# App::Baphomet::Gate::concurrent
use 5.006;
use strict;
use warnings;
use Test::More;

use Digest::SHA qw( hmac_sha256_hex );
use App::Baphomet::Gate::digest     qw( digest_of );
use App::Baphomet::Gate::concurrent ();

my $key = 'a key of sixteen bytes or more';

is( digest_of( 'neti', $key ), substr( hmac_sha256_hex( 'neti', $key ), 0, 16 ), 'a hash is the first 16 hex digits of the HMAC-SHA256' );
is( digest_of( 'neti', $key ), digest_of( 'neti', $key ), 'the one value always comes to the one hash' );
isnt( digest_of( 'neti', $key ), digest_of( 'neti', $key . '!' ), 'and a other key to a other one' );
like( digest_of( 'neti', $key ), qr/^[0-9a-f]{16}$/, 'of sixteen hex digits' );

sub digest_gate {
	my (%args) = @_;

	my $gate = App::Baphomet::Gate::digest->new( 'type' => 'digest', 'args' => { 'var' => 'USER', %args }, 'where' => 'the gate' );
	return $gate->bound( { 'digest_key' => $key }, 'the rule "x"' );
}

my $gate = digest_gate();
is( $gate->phase, 'line', 'it is of the line phase' );
is_deeply( [ $gate->needs ], ['digest_key'], 'it needs the key' );

my %shared  = ( 'USER' => 'neti' );
my %passage = ( 'parsed' => {}, 'rule' => {}, 'fields' => \%shared, 'fields_owned' => 0 );
is( $gate->ask( \%passage ), 1, 'it lets the line by' );
is( $passage{fields}{USER}, digest_of( 'neti', $key ), 'with no into the value is hashed where it is' );
is( $shared{USER}, 'neti', 'and a field space every rule shares is copied, not written to' );

my %own = ( 'data' => { 'USER' => 'neti', 'SRC' => '203.0.113.9' } );
%passage = ( 'parsed' => {}, 'rule' => {}, 'own' => \%own, 'results' => [ \%own ] );
digest_gate( 'into' => 'USER_ID' )->ask( \%passage );
is( $own{data}{USER_ID}, digest_of( 'neti', $key ), 'with a offense made it hashes into the offense, into the into' );
is( $own{data}{USER},    'neti',                    'and leaves the var as it was' );

%passage = ( 'parsed' => {}, 'rule' => {}, 'fields' => { 'SRC' => '203.0.113.9' }, 'fields_owned' => 1 );
$gate->ask( \%passage );
ok( !exists( $passage{fields}{USER} ), 'a value that is not there is not made up' );

#
# what it will not load beside
#

sub refusal {
	my (@gates) = @_;

	my @compiled = map {
		my ( $type, $args ) = %{$_};
		my $class = 'App::Baphomet::Gate::' . $type;
		eval 'require ' . $class or die($@);
		$class->new( 'type' => $type, 'args' => $args, 'where' => 'The ' . $type . ' gate' );
	} @gates;
	foreach my $compiled (@compiled) {
		if ( $compiled->can('settle') ) {
			if ( !eval { $compiled->settle( \@compiled ); 1 } ) {
				return $@ =~ s/ at \S+ line \d+\.\n\z//r;
			}
		}
	}
	return undef;
} ## end sub refusal

is( refusal( { 'digest' => { 'var' => 'SRC' } }, { 'ban_var' => ['SRC'] } ),
	'The digest gate hashes SRC, which a ban_var names, and a ban has to be of the address itself', 'hashing what a ban_var names is refused' );
is( refusal( { 'digest' => { 'var' => 'USER', 'into' => 'SRC' } }, { 'ban_var' => ['SRC'] } ),
	'The digest gate hashes SRC, which a ban_var names, and a ban has to be of the address itself', 'as is hashing into it' );
is( refusal( { 'digest' => { 'var' => 'USER' } }, { 'account' => { 'var' => 'USER', 'exists' => 0 } } ),
	'The digest gate hashes USER where it is, and the account gate that reads it would only ever see the hash... give it a into',
	'hashing in place what a account gate reads is refused' );
is( refusal( { 'digest' => { 'var' => 'USER' } }, { 'namtar_list' => { 'list' => 'bait', 'var' => 'USER' } } ),
	'The digest gate hashes USER where it is, and the namtar_list gate that reads it would only ever see the hash... give it a into',
	'as is what a namtar_list reads' );
is( refusal( { 'digest' => { 'var' => 'USER', 'into' => 'USER_ID' } }, { 'account' => { 'var' => 'USER', 'exists' => 0 } } ),
	undef, 'with a into the account gate reads the name, and it loads' );
is( refusal( { 'digest' => { 'var' => 'USER' } }, { 'detection_var' => ['USER'] } ), undef, 'a detection_var may name a hash' );

#
# concurrent
#

sub concurrent_gate {
	return App::Baphomet::Gate::concurrent->new(
		'type'  => 'concurrent',
		'args'  => { 'by' => 'USER', 'of' => 'SRC', 'more_than' => 2, 'seconds' => 600 },
		'where' => 'the gate'
	);
}

sub seen {
	my ( $gate, $user, $source, $now, $scope ) = @_;

	return $gate->ask( { 'data' => { 'USER' => $user, 'SRC' => $source }, 'now' => $now, 'scope' => $scope // 'auth' } );
}

my $concurrent = concurrent_gate();
is( $concurrent->reads_offenders, 0, 'concurrent does not read the offenders' );
is( seen( $concurrent, 'neti', '198.51.100.1', 1000 ), 0, 'one address' );
is( seen( $concurrent, 'neti', '198.51.100.2', 1010 ), 0, 'two' );
is( seen( $concurrent, 'neti', '198.51.100.1', 1020 ), 0, 'the first again is still two' );
is( seen( $concurrent, 'neti', '198.51.100.3', 1030 ), 1, 'a third with in the ten minutes is more than two' );
is( seen( $concurrent, 'namtar', '198.51.100.4', 1030 ), 0, 'another account has its own' );
is( seen( $concurrent, 'neti', '198.51.100.3', 1030, 'mail' ), 0, 'and they are kept apart by watcher' );
is( seen( $concurrent, 'neti', '198.51.100.4', 1611 ), 1, 'ten minutes after the second was last seen, the first and third still count' );
is( seen( $concurrent, 'neti', '198.51.100.4', 1631 ), 0, 'ten minutes after the last of them, only the one seen since does' );
is( seen( $concurrent, 'neti', '198.51.100.5', 1632 ), 0, 'so a second is two' );
is( seen( $concurrent, 'neti', '198.51.100.6', 1633 ), 1, 'and a third is three again' );
is( $concurrent->ask( { 'data' => { 'USER' => 'neti' }, 'now' => 1700, 'scope' => 'auth' } ), 0, 'a offense lacking the of is vetoed' );

my $flood = App::Baphomet::Gate::concurrent->new(
	'type'  => 'concurrent',
	'args'  => { 'by' => 'USER', 'of' => 'SRC', 'more_than' => 2, 'seconds' => 86400 },
	'where' => 'the gate'
);
seen( $flood, 'neti', '10.0.' . int( $_ / 256 ) . '.' . ( $_ % 256 ), 2000 + $_ ) foreach 1 .. 1200;
is( scalar( keys( %{ $flood->{windows}{auth}{neti}{values} } ) ), 1000, 'a key holds a thousand values at the most' );

$concurrent->sweep_state( 1633 + 599 );
ok( exists( $concurrent->{windows}{auth}{neti} ), 'a sweep before the seconds are up leaves the key' );
$concurrent->sweep_state( 1633 + 600 );
ok( !exists( $concurrent->{windows}{auth}{neti} ), 'and one after drops it' );

done_testing();
