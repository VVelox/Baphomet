#!perl
# direct unit tests for App::Baphomet::Gate::reverse_dns, the reverse_dns
# gate... a mock resolver pair stands in for the cached lookups, so the whole
# (outcome x knob x negate) decision tree is walked with out a galla or a
# live nameserver
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Gate::reverse_dns qw( rdns_addr_eq );

# a resolver over fixture maps... a arrayref of names/addresses, the empty
# arrayref for authoritative absence (nxdomain), or undef for a failure
# (servfail)... the tri-state the gate leans on
sub resolver {
	my ( $ptr, $fwd ) = @_;
	return {
		'reverse' => sub { return $ptr->{ $_[0] }; },
		'forward' => sub { return $fwd->{ $_[0] }; },
	};
}

# a reverse_dns gate told what a rule entry would tell it, and bound over
# the passed resolver, or over none to ask when it is undef
sub rdns_gate {
	my ( $args, $resolver ) = @_;

	my $gate = App::Baphomet::Gate::reverse_dns->new( 'type' => 'reverse_dns', 'args' => $args, 'where' => 'the gate' );
	return $gate->bound( { 'resolver' => sub { return $resolver; } }, 'the rule "x"' );
}

#
# rdns_addr_eq... packed compare within a family, spellings and case can
# not dodge it
#

ok( rdns_addr_eq( '1.2.3.4',     '1.2.3.4' ),         'identical v4 addresses are equal' );
ok( !rdns_addr_eq( '1.2.3.4',    '1.2.3.5' ),         'differing v4 are not' );
ok( rdns_addr_eq( '2001:db8::1', '2001:DB8:0:0::1' ), 'v6 equal by packed value across spellings' );
ok( !rdns_addr_eq( '1.2.3.4',    '::1' ),             'no common family is not equal' );

#
# compile... the defaults, the pass, and a matches that does not compile
#

my $compiled = App::Baphomet::Gate::reverse_dns->new(
	'type'  => 'reverse_dns',
	'args'  => { 'matches' => '\.crawler\.example$' },
	'where' => 'the gate'
);
is( $compiled->{negate},          0,          'negate is off unless asked for' );
is( $compiled->{forward_confirm}, 1,          'forward confirmation is on unless refused' );
is( $compiled->{on_nxdomain},     'compare',  'on_nxdomain is compare by default' );
is( $compiled->{on_servfail},     'fail',     'on_servfail is fail by default' );
is( $compiled->pass,              'offender', 'a gate naming no var is of the offender pass' );
is_deeply( [ $compiled->needs ], ['resolver'], 'it needs the resolver' );

ok(
	!eval {
		App::Baphomet::Gate::reverse_dns->new(
			'type'  => 'reverse_dns',
			'args'  => { 'matches' => '(' },
			'where' => 'the gate'
		);
		1;
	},
	'a matches that is not a regexp dies'
);
like( $@, qr/^the gate matches does not compile/, 'and the die leads with the where it was passed' );

#
# holds... fail closed with no resolver or on a non-address
#

my %crawler = ( 'matches' => '\.crawler\.example$' );
my $confirm = resolver( { '1.2.3.4' => ['bot.crawler.example'] }, { 'bot.crawler.example' => ['1.2.3.4'] } );

ok( !rdns_gate( \%crawler, undef )->holds( {}, '1.2.3.4' ),      'no resolver to ask fails closed' );
ok( !rdns_gate( \%crawler, $confirm )->holds( {}, 'not-an-ip' ), 'a non-address value fails closed' );

#
# the confirmed match, and negate flipping it
#

ok( rdns_gate( \%crawler, $confirm )->holds( {}, '1.2.3.4' ), 'a confirmed PTR matching the regexp counts' );
ok(
	!rdns_gate( { %crawler, 'negate' => 1 }, $confirm )->holds( {}, '1.2.3.4' ),
	'negate flips a match to a veto... the real crawler spared'
);

#
# authoritative absence (nxdomain)... data, so negate counts it
#

my $none = resolver( { '1.2.3.4' => [] }, {} );
ok( !rdns_gate( \%crawler, $none )->holds( {}, '1.2.3.4' ), 'no PTR at all does not match the regexp' );
ok(
	rdns_gate( { %crawler, 'negate' => 1 }, $none )->holds( {}, '1.2.3.4' ),
	'and negated, no PTR counts... the pretender with no reverse DNS'
);
ok( rdns_gate( { %crawler, 'on_nxdomain' => 'pass' }, $none )->holds( {}, '1.2.3.4' ),
	'on_nxdomain pass is terminal, satisfying outright' );
ok( !rdns_gate( { %crawler, 'on_nxdomain' => 'fail', 'negate' => 1 }, $none )->holds( {}, '1.2.3.4' ),
	'on_nxdomain fail is terminal, never inverted by negate' );

#
# a lookup failure (servfail)... never data, so negate can not count it
#

my $down = resolver( {}, {} );    # unfixtured PTR answers undef -> servfail
ok(
	!rdns_gate( { %crawler, 'negate' => 1 }, $down )->holds( {}, '1.2.3.4' ),
	'a servfail vetoes even a negated gate... a outage never counts anyone'
);
ok( rdns_gate( { %crawler, 'on_servfail' => 'pass' }, $down )->holds( {}, '1.2.3.4' ), 'on_servfail pass is terminal' );
ok(
	rdns_gate( { %crawler, 'on_servfail' => 'compare', 'negate' => 1 }, $down )->holds( {}, '1.2.3.4' ),
	'on_servfail compare treats the failure as no names, so negated it counts... the opt-in stance'
);

#
# forward confirmation... a PTR that does not resolve back is as good as
# absent
#

my $spoof = resolver( { '1.2.3.4' => ['bot.crawler.example'] }, { 'bot.crawler.example' => ['9.9.9.9'] } );
ok( !rdns_gate( \%crawler, $spoof )->holds( {}, '1.2.3.4' ),
	'a PTR that forward-resolves elsewhere fails confirmation, so no match' );
ok( rdns_gate( { %crawler, 'negate' => 1 }, $spoof )->holds( {}, '1.2.3.4' ),
	'and negated, the spoof counts like the pretender it is' );
# confirmation refused takes the PTR at its word
ok(
	rdns_gate( { %crawler, 'forward_confirm' => 0 }, $spoof )->holds( {}, '1.2.3.4' ),
	'with forward_confirm off the spoofed PTR is trusted and matches'
);
# a forward lookup that itself servfails, under compare, leaves the name unconfirmed
my $fwddown = resolver( { '1.2.3.4' => ['bot.crawler.example'] }, {} );
ok(
	!rdns_gate( { %crawler, 'on_servfail' => 'compare' }, $fwddown )->holds( {}, '1.2.3.4' ),
	'a forward servfail under compare leaves the name unconfirmed, so no match'
);
ok( !rdns_gate( \%crawler, $fwddown )->holds( {}, '1.2.3.4' ), 'and under the default it fails the gate outright' );

#
# the matches_var form... the PTR must equal the named capture
#

my $mailish = resolver( { '1.2.3.4' => ['mail.example'] }, { 'mail.example' => ['1.2.3.4'] } );
my $claimed = rdns_gate( { 'matches_var' => 'claim' }, $mailish );
ok(
	$claimed->holds( { 'claim' => 'mail.example' }, '1.2.3.4' ),
	'matches_var holds when the confirmed PTR equals the claim'
);
ok( !$claimed->holds( { 'claim' => 'other.example' }, '1.2.3.4' ), 'and fails when it differs' );
ok( !$claimed->holds( {},                             '1.2.3.4' ), 'a missing matches_var capture fails closed' );
# case and a trailing dot on the PTR do not dodge the compare
my $dotted = resolver( { '1.2.3.4' => ['Mail.Example.'] }, { 'Mail.Example.' => ['1.2.3.4'] } );
ok( rdns_gate( { 'matches_var' => 'claim' }, $dotted )->holds( { 'claim' => 'mail.example' }, '1.2.3.4' ),
	'the compare folds case and a trailing dot' );

#
# a gate naming a var reads the found data, with no offender
#

my $var_gate = rdns_gate( { %crawler, 'var' => 'src', 'negate' => 1 }, $none );
is( $var_gate->pass, 'result', 'a gate naming a var is of the result pass' );
ok( $var_gate->holds( { 'src' => '1.2.3.4' }, undef ),
	'the address is the value of its var... no crawler PTR, negated, counts' );
ok( !$var_gate->holds( {}, undef ), 'and a var the result lacks fails closed' );

#
# into... a PTR name lifted for what is below the gate to read
#

my $lift_resolver = resolver(
	{
		'192.0.2.10' => [ 'other.example.net', 'crawl.bot.example.org' ],
		'192.0.2.11' => ['plain.example.net'],
		'192.0.2.12' => [],
	},
	{
		'other.example.net'     => ['192.0.2.10'],
		'crawl.bot.example.org' => ['192.0.2.10'],
		'plain.example.net'     => ['192.0.2.11'],
	}
);
my $lifting = rdns_gate( { 'var' => 'src', 'matches' => '\.bot\.example\.org$', 'into' => 'PTR' }, $lift_resolver );
my %lift_data = ( 'src' => '192.0.2.10' );
ok( $lifting->holds( \%lift_data, undef ), 'a gate that lifts holds as it would with out' );
is( $lift_data{PTR}, 'crawl.bot.example.org', 'and the name the comparison hit on is lifted, not merely the first' );

%lift_data = ( 'src' => '192.0.2.11' );
ok( !$lifting->holds( \%lift_data, undef ), 'a gate that does not hold' );
ok( !exists( $lift_data{PTR} ), 'lifts nothing' );

my $lifting_negated
	= rdns_gate( { 'var' => 'src', 'matches' => '\.bot\.example\.org$', 'negate' => 1, 'into' => 'PTR' }, $lift_resolver );
%lift_data = ( 'src' => '192.0.2.11' );
ok( $lifting_negated->holds( \%lift_data, undef ), 'under negate it holds on hitting no name' );
is( $lift_data{PTR}, 'plain.example.net', 'and lifts the first name that took part' );
%lift_data = ( 'src' => '192.0.2.12' );
ok( $lifting_negated->holds( \%lift_data, undef ), 'a address with no name holds under negate' );
ok( !exists( $lift_data{PTR} ), 'and has none to lift' );

%lift_data = ( 'src' => '192.0.2.10', 'PTR' => 'from the line' );
$lifting->holds( \%lift_data, undef );
is( $lift_data{PTR}, 'from the line', 'a value the offense already has is not lifted over' );

ok(
	!eval {
		App::Baphomet::Gate::reverse_dns->new(
			'type'  => 'reverse_dns',
			'args'  => { 'matches' => 'x', 'into' => 'PTR' },
			'where' => 'the gate'
		);
		1;
	},
	'a into with no var is refused'
);
like( $@, qr/^the gate has a into, which needs a var to lift the name of/, 'and says why' );

done_testing;
