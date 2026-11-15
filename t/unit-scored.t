#!perl
# direct unit tests for App::Baphomet::Gate::scored and
# App::Baphomet::Gate::startup
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::scored  ();
use App::Baphomet::Gate::startup ();

my %scores = ( '203.0.113.9' => 8, '203.0.113.10' => 9 );
my @asked;

sub scored_gate {
	my (%args) = @_;

	my $gate = App::Baphomet::Gate::scored->new( 'type' => 'scored', 'args' => { 'above' => 8, %args }, 'where' => 'the gate' );
	return $gate->bound( { 'score_of' => sub { push( @asked, [@_] ); return $scores{ $_[0] } // 0; } }, 'the rule "x"' );
}

my $gate = scored_gate();
is( $gate->pass, 'offender', 'with no var it is asked of each offender' );
is_deeply( [ $gate->needs ], ['score_of'], 'it needs the galla\'s scores' );
is( $gate->holds( {}, '203.0.113.10', 5000 ), 1, 'a address counted for more than the mark holds' );
is_deeply( $asked[-1], [ '203.0.113.10', 0 ], 'every live hit is read with no seconds' );
is( $gate->holds( {}, '203.0.113.9',  5000 ), 0, 'one counted for the mark exactly does not' );
is( $gate->holds( {}, '198.51.100.5', 5000 ), 0, 'nor one never counted' );
is( $gate->holds( {}, undef,          5000 ), 0, 'nor no address' );

scored_gate( 'seconds' => 600 )->holds( {}, '203.0.113.10', 5000 );
is_deeply( $asked[-1], [ '203.0.113.10', 4400 ], 'and only those newer than the seconds with them' );

my $by_var = scored_gate( 'var' => 'PEER', 'above' => 2.5 );
is( $by_var->pass, 'result', 'with a var it is asked once of the offense' );
is( $by_var->holds( { 'PEER' => '203.0.113.9' }, '198.51.100.5', 5000 ), 1, 'and reads the var, not the offender' );

foreach my $bad ( {}, { 'above' => 0 }, { 'above' => 8, 'seconds' => 0 } ) {
	ok( !eval { App::Baphomet::Gate::scored->new( 'type' => 'scored', 'args' => $bad, 'where' => 'the gate' ); 1 },
		'a scored of ' . ( join( ', ', %{$bad} ) || 'nothing' ) . ' is refused' );
}

#
# startup
#

my $uptime;

sub startup_gate {
	my $gate = App::Baphomet::Gate::startup->new( 'type' => 'startup', 'args' => { 'grace' => 120 }, 'where' => 'the gate' );
	return $gate->bound( { 'uptime' => sub { return $uptime; } }, 'the rule "x"' );
}

my $startup = startup_gate();
is( $startup->phase, 'line', 'startup is of the line phase' );
is( $startup->early, 1,      'and may be asked before anything is made of the line' );
$uptime = 0;
is( $startup->ask( { 'parsed' => {} } ), 0, 'a galla just up turns the line away' );
$uptime = 119;
is( $startup->ask( { 'parsed' => {} } ), 0, 'as does one a second short of the grace' );
$uptime = 120;
is( $startup->ask( { 'parsed' => {} } ), 1, 'one up as long as the grace lets it by' );
$uptime = undef;
is( $startup->ask( { 'parsed' => {} } ), 1, 'and so does one not started as a server' );
ok( !eval { App::Baphomet::Gate::startup->new( 'type' => 'startup', 'args' => { 'grace' => 0 }, 'where' => 'the gate' ); 1 }, 'a grace of nothing is refused' );

done_testing();
