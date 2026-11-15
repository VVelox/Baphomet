#!perl
# direct unit tests for App::Baphomet::Gate::breadth and
# App::Baphomet::Gate::weigh
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::breadth ();
use App::Baphomet::Gate::weigh   ();

# the rules with live hits against each address, and what was asked for
my %hit = (
	'203.0.113.9'  => [ 'syslog/sshd', 'syslog/vsftpd' ],
	'203.0.113.10' => ['syslog/vsftpd'],
);
my @asked;

sub breadth_gate {
	my (%args) = @_;

	my $gate = App::Baphomet::Gate::breadth->new(
		'type'  => 'breadth',
		'args'  => { 'rules' => 3, 'seconds' => 3600, %args },
		'where' => 'the gate',
		'rule'  => { 'name' => 'http/scan' },
	);
	return $gate->bound( { 'rules_hit' => sub { push( @asked, [@_] ); return $hit{ $_[0] } // []; } }, 'the rule "x"' );
}

my $gate = breadth_gate();
is( $gate->{rule_name}, 'http/scan', 'it keeps the name of the rule it is of' );
is( $gate->pass, 'offender', 'with no var it is asked of each offender' );
is_deeply( [ $gate->needs ], ['rules_hit'], 'it needs the galla\'s hits' );

is( $gate->holds( {}, '203.0.113.9', 10_000 ), 1, 'two other rules and its own are three' );
is_deeply( $asked[-1], [ '203.0.113.9', 6400 ], 'the hits are read back the seconds from the line' );
is( $gate->holds( {}, '203.0.113.10', 10_000 ), 0, 'one other and its own are two' );
is( $gate->holds( {}, '198.51.100.5', 10_000 ), 0, 'none and its own is one' );
is( $gate->holds( {}, undef, 10_000 ), 0, 'no address holds on nothing' );

%hit = ( '203.0.113.9' => [ 'http/scan', 'syslog/sshd' ] );
is( $gate->holds( {}, '203.0.113.9', 10_000 ), 0, 'its own rule among the hits is counted once' );

%hit = ( '203.0.113.9' => [ 'syslog/sshd', 'syslog/vsftpd', 'syslog/dovecot' ] );
my $only = breadth_gate( 'of' => [ 'syslog/sshd', 'syslog/dovecot' ] );
is( $only->holds( {}, '203.0.113.9', 10_000 ), 1, 'with of, the rules it names and its own' );
is( breadth_gate( 'of' => 'syslog/sshd' )->holds( {}, '203.0.113.9', 10_000 ), 0, 'and no others' );

my $by_var = breadth_gate( 'var' => 'PEER', 'rules' => 2 );
is( $by_var->pass, 'result', 'with a var it is asked once of the offense' );
is( $by_var->holds( { 'PEER' => '203.0.113.9' }, '198.51.100.5', 10_000 ), 1, 'and checks the var, not the offender' );

foreach my $bad ( [ { 'rules' => 1 }, qr/^the gate has a rules that is not a int of two or more/ ], [ { 'of' => 'sshd' }, qr/^the gate has a of that is not a rule name/ ] ) {
	ok( !eval { App::Baphomet::Gate::breadth->new( 'type' => 'breadth', 'args' => { 'rules' => 3, 'seconds' => 60, %{ $bad->[0] } }, 'where' => 'the gate' ); 1 },
		'a entry of ' . join( ', ', %{ $bad->[0] } ) . ' is refused' );
	like( $@, $bad->[1], 'and says why' );
}

#
# weigh
#

sub weigh_gate {
	return App::Baphomet::Gate::weigh->new( 'type' => 'weigh', 'args' => {@_}, 'where' => 'the gate' );
}

sub weighed {
	my ( $data, @gates ) = @_;

	my %offense = ( 'data' => $data );
	foreach my $gate (@gates) {
		is( $gate->ask( \%offense ), 1, 'it vetoes nothing' );
	}
	return $offense{weight_times};
}

is( weighed( {}, weigh_gate( 'times' => 3 ) ), 3, 'times multiplies the weight' );
my $admins = weigh_gate( 'times' => 3, 'when' => [ { 'field' => 'USER', 'op' => 'eq', 'values' => [ 'root', 'admin' ] } ] );
is( weighed( { 'USER' => 'root' }, $admins ), 3,     'with a when that holds' );
is( weighed( { 'USER' => 'neti' }, $admins ), undef, 'and not with one that does not' );
is( weighed( { 'score' => '2.5' }, weigh_gate( 'by' => 'score' ) ), 2.5, 'by multiplies by the number in a var' );
foreach my $not_a_weight ( undef, 'high', '0', '-2' ) {
	is( weighed( { 'score' => $not_a_weight }, weigh_gate( 'by' => 'score' ) ), undef, 'and a var that is no number above nothing leaves it as it was' );
}
is( weighed( { 'USER' => 'root' }, $admins, weigh_gate( 'times' => 2 ) ), 6, 'several multiply one after another' );
is( weigh_gate( 'times' => 2 )->reads_offenders, 0, 'it reads no offender, so it may sit anywhere' );

foreach my $bad ( [ {}, qr/^the gate has neither times nor by/ ], [ { 'times' => 2, 'by' => 'score' }, qr/^the gate has both times and by/ ],
	[ { 'times' => 0 }, qr/^the gate has a times that is not a positive number/ ], [ { 'times' => 2, 'when' => 'root' }, qr/^the gate when/ ] )
{
	ok( !eval { weigh_gate( %{ $bad->[0] } ); 1 }, 'a weigh of ' . ( join( ', ', %{ $bad->[0] } ) || 'nothing' ) . ' is refused' );
	like( $@, $bad->[1], 'and says why' );
}

done_testing();
