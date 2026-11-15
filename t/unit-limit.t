#!perl
# direct unit tests for App::Baphomet::Gate::limit, the limit gate... the
# windows, what they are kept by, and when they run out
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::limit ();

sub limit_gate {
	my ($args) = @_;

	return App::Baphomet::Gate::limit->new( 'type' => 'limit', 'args' => $args, 'where' => 'the gate' );
}

# asks the gate of a offense of the passed data at the passed time, on the
# watcher "auth" unless a scope is passed
sub let_by {
	my ( $gate, $data, $now, $scope ) = @_;

	return $gate->ask( { 'data' => $data, 'now' => $now, 'scope' => $scope // 'auth' } );
}

my $compiled = limit_gate( { 'by' => 'SRC', 'seconds' => 60 } );
is_deeply( $compiled->{by}, ['SRC'], 'a lone by is a list of one' );
is( $compiled->{count},          1, 'a window lets one by unless told otherwise' );
is( $compiled->reads_offenders,  0, 'it does not read the offenders, so it may sit above the ban_var' );

foreach my $bad ( { 'seconds' => 60 }, { 'by' => 'SRC' }, { 'by' => 'SRC', 'seconds' => 0 }, { 'by' => [], 'seconds' => 60 } ) {
	ok( !eval { limit_gate($bad); 1 }, 'a entry of ' . join( ', ', map { $_ } sort( keys( %{$bad} ) ) ) . ' is refused' );
}

#
# one a window
#

my %first  = ( 'SRC' => '203.0.113.9' );
my %second = ( 'SRC' => '203.0.113.10' );
my $one    = limit_gate( { 'by' => 'SRC', 'seconds' => 60 } );
is( let_by( $one, \%first,  1000 ), 1, 'the first offense of a key is let by' );
is( let_by( $one, \%first,  1001 ), 0, 'the next is vetoed' );
is( let_by( $one, \%first,  1059 ), 0, 'as is one at the very end of the window' );
is( let_by( $one, \%second, 1001 ), 1, 'another key has a window of its own' );
is( let_by( $one, \%first,  1060 ), 1, 'the window run out, the key is let by again' );
is( let_by( $one, \%first,  1100 ), 0, 'and that opened a new window, measured from its first offense' );
is( let_by( $one, \%first,  1120 ), 1, 'which runs out in its turn' );

is( let_by( $one, \%second, 1001, 'messages' ), 1, 'the windows are kept apart by watcher' );
is( let_by( $one, {},       1001 ),             1, 'a offense lacking the by var is let by' );
is( let_by( $one, {},       1001 ),             1, 'however many of them there are' );

#
# several a window, and a compound key
#

my $three = limit_gate( { 'by' => [ 'SRC', 'USER' ], 'seconds' => 300, 'count' => 3 } );
my %neti  = ( 'SRC' => '203.0.113.9', 'USER' => 'neti' );
is_deeply( [ map { let_by( $three, \%neti, 2000 + $_ ) } 0 .. 4 ], [ 1, 1, 1, 0, 0 ], 'a count of three lets three by' );
is( let_by( $three, { 'SRC' => '203.0.113.9', 'USER' => 'namtar' }, 2004 ), 1, 'a key differing in one part is another key' );
is( let_by( $three, { 'SRC' => '203.0.113.9' }, 2004 ), 1, 'and one lacking a part is no key at all' );

#
# the sweep
#

$three->sweep_state(2299);
is( let_by( $three, \%neti, 2299 ), 0, 'a sweep before a window has run out leaves it' );
$three->sweep_state(2300);
is_deeply(
	[ keys( %{ $three->{windows}{auth} } ) ],
	["203.0.113.9\x1fnamtar"],
	'a sweep drops the window that has run out and leaves the one opened after it'
);
$three->sweep_state(2304);
is_deeply( $three->{windows}, {}, 'a sweep once every window has run out leaves none, nor a empty scope' );

done_testing();
