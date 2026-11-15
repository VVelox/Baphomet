#!perl
# direct unit tests for App::Baphomet::Gate::account, the account gate... a
# fixture set stands in for the host's accounts
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::account ();

my %accounts = ( 'neti' => 1, 'root' => 1 );

# a account gate told what a rule entry would tell it, bound over the set
sub account_gate {
	my ($args) = @_;

	my $gate = App::Baphomet::Gate::account->new( 'type' => 'account', 'args' => $args, 'where' => 'the gate' );
	return $gate->bound( { 'accounts' => sub { return $accounts{ $_[0] }; } }, 'the rule "x"' );
}

my $compiled = App::Baphomet::Gate::account->new( 'type' => 'account', 'args' => { 'var' => 'USER' }, 'where' => 'the gate' );
is( $compiled->{exists}, 1,        'it holds on a real account unless told otherwise' );
is( $compiled->pass,     'result', 'it is of the result pass' );
is_deeply( [ $compiled->needs ], ['accounts'], 'it needs the accounts' );

ok( !eval { App::Baphomet::Gate::account->new( 'type' => 'account', 'args' => {}, 'where' => 'the gate' ); 1 },
	'one with no var is refused' );
like( $@, qr/^the gate lacks a var/, 'and says so' );

my $real = account_gate( { 'var' => 'USER', 'exists' => 1 } );
is( $real->holds( { 'USER' => 'neti' } ),   1, 'exists holds on a account' );
is( $real->holds( { 'USER' => 'oracle' } ), 0, 'and fails on a name that is nobody\'s' );
is( $real->holds( {} ),                     0, 'a name the offense lacks fails closed' );
is( $real->holds( { 'USER' => '' } ),       0, 'as does a empty one' );

# false however the loader spells it
foreach my $false ( 0, '', '0' ) {
	my $guess = account_gate( { 'var' => 'USER', 'exists' => $false } );
	is( $guess->holds( { 'USER' => 'oracle' } ), 1, 'exists false holds on a name that is nobody\'s' );
	is( $guess->holds( { 'USER' => 'neti' } ),   0, 'and fails on a account' );
	is( $guess->holds( {} ),                     0, 'a name the offense lacks still fails closed' );
}

done_testing();
