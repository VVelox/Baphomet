#!perl
# direct unit tests for what a marked gate may ask of a brand beyond its
# being there... how old it is and how many hosts set it... and for the
# brand remembering who did
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::marked ();
use App::Baphomet::Marks qw( mark_set mark_hosts );

my %store;

# a marked gate told what a rule entry would tell it, bound over the store
sub marked_gate {
	my (%args) = @_;

	my $gate = App::Baphomet::Gate::marked->new(
		'type'  => 'marked',
		'args'  => { 'name' => 'seen', 'var' => 'USER', %args },
		'where' => 'the gate'
	);
	return $gate->bound( { 'marks' => sub { return \%store; } }, 'the rule "x"' );
}

my %neti = ( 'USER' => 'neti' );

#
# how old a brand is
#

%store = ( 'seen' => { 'neti' => { 'expires' => 9000, 'set' => 1000 } } );
my $fresh = marked_gate( 'newer_than' => 300 );
is( $fresh->holds( \%neti, undef, 1000 ), 1, 'a brand set this second is newer than five minutes' );
is( $fresh->holds( \%neti, undef, 1299 ), 1, 'as is one a second short of them' );
is( $fresh->holds( \%neti, undef, 1300 ), 0, 'and one exactly five minutes old is not' );

my $stale = marked_gate( 'older_than' => 300 );
is( $stale->holds( \%neti, undef, 1299 ), 0, 'a brand a second short of five minutes is not older than them' );
is( $stale->holds( \%neti, undef, 1300 ), 1, 'one exactly five minutes old is' );

my $between = marked_gate( 'older_than' => 60, 'newer_than' => 300 );
is_deeply( [ map { $between->holds( \%neti, undef, 1000 + $_ ) } ( 59, 60, 299, 300 ) ],
	[ 0, 1, 1, 0 ], 'the two together are a span of ages' );

# set again, a brand is as old as when it was first set
mark_set( \%store, 'seen', 'neti', undef, 8000, 1200 );
is( $store{seen}{neti}{set}, 1000, 'setting a live brand again leaves when it was first set' );
is( $fresh->holds( \%neti, undef, 1300 ), 0, 'so it is no newer for it' );

%store = ( 'seen' => { 'neti' => { 'expires' => 9000 } } );
is( $fresh->holds( \%neti, undef, 1000 ), 0, 'a brand with no saying when it was set fails a newer_than' );
is( $stale->holds( \%neti, undef, 1000 ), 0, 'and a older_than' );
is( marked_gate()->holds( \%neti, undef, 1000 ), 1, 'while a gate asking neither holds on it as ever' );

# any of several names
%store = ( 'old' => { 'neti' => { 'expires' => 9000, 'set' => 100 } }, 'new' => { 'neti' => { 'expires' => 9000, 'set' => 990 } } );
my $any_fresh = App::Baphomet::Gate::marked->new(
	'type'  => 'marked',
	'args'  => { 'names' => [ 'old', 'new' ], 'var' => 'USER', 'newer_than' => 60 },
	'where' => 'the gate'
)->bound( { 'marks' => sub { return \%store; } }, 'the rule "x"' );
is( $any_fresh->holds( \%neti, undef, 1000 ), 1, 'with several names one brand young enough will do' );

#
# how many hosts set it
#

is( mark_hosts( { 'expires' => 9000 } ), 0, 'a brand that says nothing of who set it was set by nobody known' );
is( mark_hosts( { 'here'    => 1 } ),    1, 'one set here was set by one host' );
is( mark_hosts( { 'here' => 1, 'hosts' => { 'mail01' => 1, 'web01' => 1 } } ), 3, 'and each other host that set it is one more' );

%store = ();
mark_set( \%store, 'seen', 'neti', undef, 600, 1000 );
ok( $store{seen}{neti}{here}, 'a brand set through mark_set is set here' );
$store{seen}{neti}{hosts} = { 'mail01' => 1 };
mark_set( \%store, 'seen', 'neti', undef, 600, 1100 );
is_deeply( $store{seen}{neti}{hosts}, { 'mail01' => 1 }, 'setting a live brand again keeps the hosts that set it' );
mark_set( \%store, 'seen', 'neti', undef, 600, 5000 );
ok( !exists( $store{seen}{neti}{hosts} ), 'a brand that had run out is set afresh, by this host alone' );

%store = ( 'seen' => { 'neti' => { 'expires' => 9000, 'set' => 1000, 'here' => 1, 'hosts' => { 'mail01' => 1, 'web01' => 1 } } } );
is( marked_gate( 'hosts' => 3 )->holds( \%neti, undef, 1000 ), 1, 'a brand three hosts set holds for hosts of three' );
is( marked_gate( 'hosts' => 4 )->holds( \%neti, undef, 1000 ), 0, 'and not for four' );
is( marked_gate( 'hosts' => 1 )->holds( \%neti, undef, 1000 ), 1, 'nor is more than was asked for any bar' );
delete( $store{seen}{neti}{here} );
is( marked_gate( 'hosts' => 3 )->holds( \%neti, undef, 1000 ), 0, 'this host counts only when it set the brand itself' );

#
# the shapes
#

foreach my $bad ( [ 'hosts', 0 ], [ 'older_than', 0 ], [ 'newer_than', 'soon' ] ) {
	ok(
		!eval {
			App::Baphomet::Gate::marked->new(
				'type'  => 'marked',
				'args'  => { 'name' => 'seen', @{$bad} },
				'where' => 'the gate'
			);
			1;
		},
		'a ' . $bad->[0] . ' of ' . $bad->[1] . ' is refused'
	);
} ## end foreach my $bad ( [ 'hosts', 0 ], [ 'older_than', 0...])

done_testing();
