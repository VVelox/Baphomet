#!perl
# direct unit tests for App::Baphomet::Gate::forgive, the forgive gate... a
# recorder stands in for the galla's counts, so who is forgiven, for which
# rules, and about which account is pinned with out one
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::forgive ();

my @forgiven;

# a forgive gate told what a rule entry would tell it, bound over the
# recorder
sub forgive_gate {
	my ($args) = @_;

	my $gate = App::Baphomet::Gate::forgive->new( 'type' => 'forgive', 'args' => $args, 'where' => 'the gate' );
	return $gate->bound( { 'forgive' => sub { push( @forgiven, [@_] ); return 1; } }, 'the rule "x"' );
}

my $compiled
	= App::Baphomet::Gate::forgive->new( 'type' => 'forgive', 'args' => { 'rules' => 'syslog/sshd' }, 'where' => 'the gate' );
is_deeply( $compiled->{rules}, { 'syslog/sshd' => 1 }, 'a lone rule is a set of one' );
is( $compiled->pass,            'offender', 'with no var it is asked of the offenders' );
is( $compiled->reads_offenders, 1,          'so it has to sit below a ban_var' );
is_deeply( [ $compiled->needs ], ['forgive'], 'it needs the forgiving' );

my $by_var = App::Baphomet::Gate::forgive->new(
	'type'  => 'forgive',
	'args'  => { 'rules' => ['syslog/sshd'], 'var' => 'SRC' },
	'where' => 'the gate'
);
is( $by_var->reads_offenders, 0, 'with a var it reads no offender, so a detection rule may have one' );

my %refused = (
	'no rules'               => [ {}, qr/^the gate lacks a rules/ ],
	'a rule that is no name' => [ { 'rules' => 'sshd' },            qr/^the gate has a rules that is not a rule name/ ],
	'a group for a rule'     => [ { 'rules' => '%syslog/sshd%' },   qr/^the gate has a rules that is not a rule name/ ],
	'a name with a newline'  => [ { 'rules' => "syslog/sshd\n" },   qr/^the gate has a rules that is not a rule name/ ],
	'a unknown key'          => [ { 'rules' => 'syslog/sshd', 'by' => 'USER' }, qr/^the gate has the unknown key "by"/ ],
);
foreach my $description ( sort( keys(%refused) ) ) {
	my ( $args, $message ) = @{ $refused{$description} };
	my $error
		= eval { App::Baphomet::Gate::forgive->new( 'type' => 'forgive', 'args' => $args, 'where' => 'the gate' ); 1 }
		? ''
		: $@;
	like( $error, $message, $description . ' is refused' );
}

#
# who is forgiven
#

my $offenders = forgive_gate( { 'rules' => [ 'syslog/sshd', 'syslog/sshd-ddos' ] } );
my %both      = ( 'syslog/sshd' => 1, 'syslog/sshd-ddos' => 1 );
is( $offenders->ask( { 'data' => {}, 'offenders' => [ '203.0.113.9', '203.0.113.10' ] } ), 1, 'it vetoes nothing' );
is_deeply(
	\@forgiven,
	[ [ '203.0.113.9', \%both, undef ], [ '203.0.113.10', \%both, undef ] ],
	'each offender is forgiven the hits of the rules, whoever they were about'
);

@forgiven = ();
is( $offenders->ask( { 'data' => {}, 'offenders' => [] } ), 1, 'a offense with no offender vetoes nothing either' );
is_deeply( \@forgiven, [], 'and forgives nobody' );

my $named = forgive_gate( { 'rules' => 'syslog/sshd', 'var' => 'PEER' } );
$named->ask( { 'data' => { 'PEER' => '198.51.100.5' }, 'offenders' => ['203.0.113.9'] } );
is_deeply( \@forgiven, [ [ '198.51.100.5', { 'syslog/sshd' => 1 }, undef ] ], 'with a var the address in it is forgiven, not the offender' );

@forgiven = ();
$named->ask( { 'data' => {}, 'offenders' => ['203.0.113.9'] } );
is_deeply( \@forgiven, [], 'and a offense lacking the var forgives nobody' );

#
# the same account
#

my $same = forgive_gate( { 'rules' => 'syslog/sshd', 'same' => 'USER' } );
$same->ask( { 'data' => { 'USER' => 'neti' }, 'offenders' => ['203.0.113.9'] } );
is_deeply( \@forgiven, [ [ '203.0.113.9', { 'syslog/sshd' => 1 }, 'neti' ] ], 'with a same only the hits about that account are asked to be taken back' );

@forgiven = ();
is( $same->ask( { 'data' => {}, 'offenders' => ['203.0.113.9'] } ), 1, 'a offense lacking the account vetoes nothing' );
$same->ask( { 'data' => { 'USER' => '' }, 'offenders' => ['203.0.113.9'] } );
is_deeply( \@forgiven, [], 'and forgives nothing, a account that can not be named not being the same as any' );

done_testing();
