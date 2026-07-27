#!perl
# direct unit tests for App::Baphomet::RDNS, the reverse_dns gate's pure
# judgment... a mock resolver pair stands in for the cached lookups, so
# the whole (outcome x knob x negate) decision tree is walked without a
# galla or a live nameserver
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::RDNS qw( rdns_gate_pass rdns_entry_pass rdns_addr_eq );

# a resolver over fixture maps... an arrayref of names/addresses, the empty
# arrayref for authoritative absence (nxdomain), or undef for a failure
# (servfail)... the tri-state the gate leans on
sub resolver {
	my ( $ptr, $fwd ) = @_;
	return {
		'reverse' => sub { return $ptr->{ $_[0] }; },
		'forward' => sub { return $fwd->{ $_[0] }; },
	};
}

#
# rdns_addr_eq... packed compare within a family, spellings and case can
# not dodge it
#

ok( rdns_addr_eq( '1.2.3.4',         '1.2.3.4' ),         'identical v4 addresses are equal' );
ok( !rdns_addr_eq( '1.2.3.4',        '1.2.3.5' ),         'differing v4 are not' );
ok( rdns_addr_eq( '2001:db8::1',     '2001:DB8:0:0::1' ), 'v6 equal by packed value across spellings' );
ok( !rdns_addr_eq( '1.2.3.4',        '::1' ),             'no common family is not equal' );

#
# rdns_entry_pass... fail closed with no resolver or on a non-address
#

my $confirm = resolver( { '1.2.3.4' => ['bot.crawler.example'] }, { 'bot.crawler.example' => ['1.2.3.4'] } );
my $entry = { 'regexp' => qr/\.crawler\.example$/, 'negate' => 0, 'forward_confirm' => 1,
	'on_nxdomain' => 'compare', 'on_servfail' => 'fail' };

ok( !rdns_entry_pass( undef, $entry, '1.2.3.4', {} ), 'a undef resolver fails closed' );
ok( !rdns_entry_pass( $confirm, $entry, 'not-an-ip', {} ), 'a non-address value fails closed' );

#
# the confirmed match, and negate flipping it
#

ok( rdns_entry_pass( $confirm, $entry, '1.2.3.4', {} ), 'a confirmed PTR matching the regexp counts' );
ok(
	!rdns_entry_pass(
		$confirm, { %{$entry}, 'negate' => 1 },
		'1.2.3.4', {}
	),
	'negate flips a match to a veto... the real crawler spared'
);

#
# authoritative absence (nxdomain)... data, so negate counts it
#

my $none = resolver( { '1.2.3.4' => [] }, {} );
ok( !rdns_entry_pass( $none, $entry, '1.2.3.4', {} ), 'no PTR at all does not match the regexp' );
ok(
	rdns_entry_pass(
		$none, { %{$entry}, 'negate' => 1 },
		'1.2.3.4', {}
	),
	'and negated, no PTR counts... the pretender with no reverse DNS'
);
ok( rdns_entry_pass( $none, { %{$entry}, 'on_nxdomain' => 'pass' }, '1.2.3.4', {} ),
	'on_nxdomain pass is terminal, satisfying outright' );
ok( !rdns_entry_pass( $none, { %{$entry}, 'on_nxdomain' => 'fail', 'negate' => 1 }, '1.2.3.4', {} ),
	'on_nxdomain fail is terminal, never inverted by negate' );

#
# a lookup failure (servfail)... never data, so negate can not count it
#

my $down = resolver( {}, {} );    # unfixtured PTR answers undef -> servfail
ok( !rdns_entry_pass( $down, { %{$entry}, 'negate' => 1 }, '1.2.3.4', {} ),
	'a servfail vetoes even a negated gate... an outage never counts anyone' );
ok( rdns_entry_pass( $down, { %{$entry}, 'on_servfail' => 'pass' }, '1.2.3.4', {} ),
	'on_servfail pass is terminal' );
ok( rdns_entry_pass( $down, { %{$entry}, 'on_servfail' => 'compare', 'negate' => 1 }, '1.2.3.4', {} ),
	'on_servfail compare treats the failure as no names, so negated it counts... the opt-in stance' );

#
# forward confirmation... a PTR that does not resolve back is as good as
# absent
#

my $spoof = resolver( { '1.2.3.4' => ['bot.crawler.example'] }, { 'bot.crawler.example' => ['9.9.9.9'] } );
ok( !rdns_entry_pass( $spoof, $entry, '1.2.3.4', {} ),
	'a PTR that forward-resolves elsewhere fails confirmation, so no match' );
ok(
	rdns_entry_pass(
		$spoof, { %{$entry}, 'negate' => 1 },
		'1.2.3.4', {}
	),
	'and negated, the spoof counts like the pretender it is'
);
# confirmation refused takes the PTR at its word
ok( rdns_entry_pass( $spoof, { %{$entry}, 'forward_confirm' => 0 }, '1.2.3.4', {} ),
	'with forward_confirm off the spoofed PTR is trusted and matches' );
# a forward lookup that itself servfails, under compare, leaves the name unconfirmed
my $fwddown = resolver( { '1.2.3.4' => ['bot.crawler.example'] }, {} );
ok( !rdns_entry_pass( $fwddown, $entry, '1.2.3.4', {} ),
	'a forward servfail under compare leaves the name unconfirmed, so no match' );

#
# the matches_var form... the PTR must equal the named capture
#

my $mv = { 'matches_var' => 'claim', 'negate' => 0, 'forward_confirm' => 1,
	'on_nxdomain' => 'compare', 'on_servfail' => 'fail' };
my $mailish = resolver( { '1.2.3.4' => ['mail.example'] }, { 'mail.example' => ['1.2.3.4'] } );
ok( rdns_entry_pass( $mailish, $mv, '1.2.3.4', { 'claim' => 'mail.example' } ),
	'matches_var holds when the confirmed PTR equals the claim' );
ok( !rdns_entry_pass( $mailish, $mv, '1.2.3.4', { 'claim' => 'other.example' } ),
	'and fails when it differs' );
ok( !rdns_entry_pass( $mailish, $mv, '1.2.3.4', {} ),
	'a missing matches_var capture fails closed' );
# case and a trailing dot on the PTR do not dodge the compare
my $dotted = resolver( { '1.2.3.4' => ['Mail.Example.'] }, { 'Mail.Example.' => ['1.2.3.4'] } );
ok( rdns_entry_pass( $dotted, $mv, '1.2.3.4', { 'claim' => 'mail.example' } ),
	'the compare folds case and a trailing dot' );

#
# rdns_gate_pass... the two-mode dispatch over the entries
#

# a var entry runs the data pass (ip undef), skipped in the offender pass.
# the core wants the compiled regexp the galla builds from matches at load
my $vgate = [ { 'var' => 'src', 'regexp' => qr/\.crawler\.example$/, 'negate' => 1, 'forward_confirm' => 1,
		'on_nxdomain' => 'compare', 'on_servfail' => 'fail' } ];
ok( rdns_gate_pass( $none, $vgate, { 'src' => '1.2.3.4' }, undef ),
	'a var entry, data pass... no crawler PTR, negated, counts' );
ok( rdns_gate_pass( $none, $vgate, { 'src' => '1.2.3.4' }, '1.2.3.4' ),
	'the same var entry is skipped in the offender pass, holding vacuously' );

# a var-less entry runs the offender pass, skipped in the data pass
my $ogate = [ { 'regexp' => qr/\.crawler\.example$/, 'negate' => 1, 'forward_confirm' => 1,
		'on_nxdomain' => 'compare', 'on_servfail' => 'fail' } ];
ok( rdns_gate_pass( $confirm, $ogate, {}, undef ), 'a var-less entry is skipped in the data pass' );
ok( !rdns_gate_pass( $confirm, $ogate, {}, '1.2.3.4' ),
	'and runs in the offender pass... the confirmed crawler is vetoed by the negate' );

# a undef gate always passes
ok( rdns_gate_pass( undef, undef, {}, '1.2.3.4' ), 'a undef gate passes' );

done_testing;
