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

#
# what more may be asked of a account... over what is known of each
#

my %known = (
	'neti'   => { 'uid' => 1001, 'gid' => 1001, 'shell' => '/bin/sh' },
	'root'   => { 'uid' => 0,    'gid' => 0,    'shell' => '/bin/csh' },
	'www'    => { 'uid' => 80,   'gid' => 80,   'shell' => '/usr/sbin/nologin' },
	'backup' => { 'uid' => 990,  'gid' => 990,  'shell' => '/bin/false' },
	'ghost'  => { 'uid' => 1002, 'gid' => 1002, 'shell' => '' },
	'vague'  => {},
);
my %groups = (
	'wheel'    => { 'gid' => 0,  'members' => { 'neti' => 1 } },
	'operator' => { 'gid' => 5,  'members' => {} },
	'www'      => { 'gid' => 80, 'members' => {} },
);

# a account gate over what is known above
sub known_gate {
	my ($args) = @_;

	my $gate
		= App::Baphomet::Gate::account->new( 'type' => 'account', 'args' => { 'var' => 'USER', %{$args} }, 'where' => 'the gate' );
	return $gate->bound(
		{ 'accounts' => sub { return $known{ $_[0] }; }, 'groups' => sub { return $groups{ $_[0] }; } },
		'the rule "x"' );
}

# which of the names the gate holds on
sub held {
	my ($gate) = @_;

	return [ grep { $gate->holds( { 'USER' => $_ } ) } ( sort( keys(%known) ), 'oracle' ) ];
}

is_deeply( held( known_gate( {} ) ), [ sort( keys(%known) ) ], 'asked nothing more, it holds on every account and on no other name' );

is_deeply( held( known_gate( { 'shell' => 'nologin' } ) ),
	[ 'backup', 'www' ], 'shell nologin holds on a account whose shell is nologin or false' );
is_deeply( held( known_gate( { 'shell' => 'login' } ) ),
	[ 'ghost', 'neti', 'root' ], 'shell login holds on the rest, no shell at all being the system\'s default' );

is_deeply( held( known_gate( { 'system' => 1 } ) ), [ 'backup', 'root', 'www' ], 'system holds on a uid below a thousand, root\'s among them' );
is_deeply( held( known_gate( { 'system' => 0 } ) ), [ 'ghost', 'neti' ], 'system false holds on the accounts of people' );
is_deeply( held( known_gate( { 'system' => 1, 'system_below' => 500 } ) ),
	[ 'root', 'www' ], 'system_below moves where the accounts of people start' );

is_deeply( held( known_gate( { 'group' => 'wheel' } ) ),
	[ 'neti', 'root' ], 'group holds on a account the group lists and on one whose own group it is' );
is_deeply( held( known_gate( { 'group' => [ 'operator', 'www' ] } ) ), ['www'], 'any one of several groups will do' );
is_deeply( held( known_gate( { 'group' => 'nosuchgroup' } ) ), [], 'a group there is none of holds on nobody' );

is_deeply( held( known_gate( { 'shell' => 'login', 'system' => 1, 'group' => 'wheel' } ) ),
	['root'], 'everything asked has to be so' );

# vague is a account of which nothing is known, and so is one a context only
# says exists
is( known_gate( { 'shell'  => 'login' } )->holds( { 'USER' => 'vague' } ), 0, 'a shell that is not known fails closed' );
is( known_gate( { 'system' => 0 } )->holds( { 'USER' => 'vague' } ),       0, 'as does a uid that is not known' );
is( account_gate( { 'var' => 'USER', 'shell' => 'nologin' } )->holds( { 'USER' => 'neti' } ),
	0, 'and a answer that only says there is a account' );

my $with_group = App::Baphomet::Gate::account->new(
	'type'  => 'account',
	'args'  => { 'var' => 'USER', 'group' => 'wheel' },
	'where' => 'the gate'
);
is_deeply( [ $with_group->needs ], [ 'accounts', 'groups' ], 'a gate told a group needs the groups too' );
is_deeply( $with_group->{groups}, ['wheel'], 'and a lone group is a list of one' );

foreach my $asked ( [ 'shell', 'nologin' ], [ 'system', 1 ], [ 'group', 'wheel' ] ) {
	ok(
		!eval {
			App::Baphomet::Gate::account->new(
				'type'  => 'account',
				'args'  => { 'var' => 'USER', 'exists' => 0, @{$asked} },
				'where' => 'the gate'
			);
			1;
		},
		'a exists of false beside a ' . $asked->[0] . ' is refused'
	);
	like( $@, qr/^the gate has a exists of false and a $asked->[0], and nothing can be asked of a account that is none/, 'and says why' );
} ## end foreach my $asked ( [ 'shell', 'nologin' ], [ 'system'...])
ok(
	!eval {
		App::Baphomet::Gate::account->new(
			'type'  => 'account',
			'args'  => { 'var' => 'USER', 'shell' => 'bash' },
			'where' => 'the gate'
		);
		1;
	},
	'a shell that is neither is refused'
);
like( $@, qr/^the gate has a shell that is not one of nologin or login/, 'and says so' );

done_testing();
