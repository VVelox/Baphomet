#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );
use JSON::MaybeXS ();

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();
use App::Baphomet::Rules::JSON ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

#
# rule def validation of the mark keys
#

my $base = {
	gate    => [ { field => 'event', values => ['fail'] } ],
	ban_var => ['ip'],
};

my %bad = (
	'a mark entry without a name' => { mark => [ { ttl => 60 } ] },
	'a mark entry without a ttl'  => { mark => [ { name => 'x' } ] },
	'a mark entry with a unknown key' => { mark => [ { name => 'x', ttl => 60, nope => 1 } ] },
	'a mark that is not an array'     => { mark => { name => 'x', ttl => 60 } },
	'a marked with both value_is and value_not' =>
		{ marked => [ { name => 'x', value_is => 'ip', value_not => 'ip' } ] },
	'a marked entry with a bad name' => { marked => [ { name => 'bad name' } ] },
	'a unmark with an empty var'     => { unmark => [ { name => 'x', var => '' } ] },
);
foreach my $desc ( sort( keys(%bad) ) ) {
	eval { App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base}, %{ $bad{$desc} } } ); };
	ok( $@, $desc . ' refuses to load' );
}

# a good mark def loads and the accessors report it
my $rule = App::Baphomet::Rules::JSON->new(
	name => 'json/x',
	def  => {
		%{$base},
		mark   => [ { name => 'acct', ttl => 60, var => 'user', value_var => 'ip' } ],
		unmark => [ { name => 'acct', var => 'user' } ],
		marked => [ { name => 'acct', var => 'user', value_not => 'ip' } ],
		mark_only => 1,
	}
);
is( $rule->mark_only,               1,      'mark_only reported' );
is( $rule->marks->[0]{name},        'acct', 'marks accessor' );
is( $rule->unmarks->[0]{var},       'user', 'unmarks accessor' );
is( $rule->mark_gates->{marked}[0]{value_not}, 'ip', 'mark_gates accessor' );

#
# galla behavior
#

my %rules = (
	'mark' => "mark_only: true\nmark:\n  - name: acct\n    ttl: 3600\n    var: user\n    value_var: ip\n",
	'spray' =>
		"marked:\n  - name: acct\n    var: user\n    value_not: ip\nmax_retrys: 1\n",
	'count'     => '',
	'markgood'  => "gate2: login\nmark_only: true\nmark:\n  - name: known\n    ttl: 3600\n",
	'blockbad'  => "not_marked:\n  - name: known\nmax_retrys: 1\n",
	'mark2'     => "gate2: bad\nmark_only: true\nmark:\n  - name: flag\n    ttl: 3600\n",
	'clear'     => "gate2: good\nmark_only: true\nunmark:\n  - name: flag\n",
	'ipmark'    => "gate2: hit\nmark_only: true\nmark:\n  - name: seen\n    ttl: 3600\n",
);
foreach my $name ( keys(%rules) ) {
	my $body  = $rules{$name};
	my $event = 'fail';
	if ( $body =~ s/^gate2: (\w+)\n// ) {
		$event = $1;
	}
	open( my $fh, '>', $dir . '/rules/json/' . $name . '.yaml' ) || die($!);
	print $fh "---\ngate:\n  - field: event\n    values: [ " . $event . " ]\nban_var:\n  - ip\n" . $body;
	close($fh);
}

open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
ignore_ips = [ "127.0.0.0/8" ]

[kur.marks]
max_retrys = 5
allow_per_rule_thresholds = true

[kur.marks.spray]
log = "$dir/l1"
parser = "json"
rule = [ "json/spray", "json/mark", "json/count" ]

[kur.marks.guard]
log = "$dir/l2"
parser = "json"
rule = [ "json/markgood", "json/blockbad" ]

[kur.marks.session]
log = "$dir/l3"
parser = "json"
rule = [ "json/mark2", "json/clear" ]

[kur.marks.iptest]
log = "$dir/l4"
parser = "json"
rule = [ "json/ipmark" ]
EOC
close($cfg);

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}

my $json = JSON::MaybeXS->new( 'canonical' => 1 );

sub feed {
	my ( $galla, $watcher, %fields ) = @_;
	$galla->_handle_line( $watcher, $json->encode( \%fields ), $dir . '/l' );
	return;
}

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'marks' );

#
# the spray pipeline... mark_only falls through, a different source on the
# same account is caught, the same source is not
#

@sent = ();
feed( $galla, 'spray', event => 'fail', user => 'admin', ip => '1.1.1.1' );
is_deeply( \@sent, [], 'first sight of an account does not ban' );
is( $galla->{marks}{acct}{admin}{value}, '1.1.1.1', 'the mark_only rule branded the account through the gate rule' );
is( scalar( @{ $galla->{counters}{'1.1.1.1'} } ), 1, 'and fell through to the counting rule' );

@sent = ();
feed( $galla, 'spray', event => 'fail', user => 'admin', ip => '2.2.2.2' );
is_deeply( \@sent, ['2.2.2.2'], 'a second source on the same account is banished at once' );
is( $galla->{marks}{acct}{admin}{value}, '1.1.1.1', 'the spray ban consumed the line, so the brand was not overwritten' );

@sent = ();
feed( $galla, 'spray', event => 'fail', user => 'admin', ip => '1.1.1.1' );
is_deeply( \@sent, [], 'the established source on its own account is not caught' );

#
# not_marked gate keyed by the offender IP
#

@sent = ();
feed( $galla, 'guard', event => 'login', ip => '5.5.5.5' );
ok( defined( $galla->{marks}{known}{'5.5.5.5'} ), 'a var-less mark brands the offender IP' );
feed( $galla, 'guard', event => 'fail', ip => '5.5.5.5' );
is_deeply( \@sent, [], 'a known IP passes the not_marked gate without counting' );
feed( $galla, 'guard', event => 'fail', ip => '6.6.6.6' );
is_deeply( \@sent, ['6.6.6.6'], 'an unmarked IP trips the not_marked gate and is banished' );

#
# unmark lifts a brand
#

feed( $galla, 'session', event => 'bad', ip => '7.7.7.7' );
ok( defined( $galla->{marks}{flag}{'7.7.7.7'} ), 'the mark is set' );
feed( $galla, 'session', event => 'good', ip => '7.7.7.7' );
ok( !defined( $galla->{marks}{flag} ), 'unmark lifted it, and the emptied name was dropped' );

#
# the ignored are never branded
#

feed( $galla, 'iptest', event => 'hit', ip => '127.0.0.1' );
ok( !defined( $galla->{marks}{seen} ), 'an ignore_ips offender is not branded' );
feed( $galla, 'iptest', event => 'hit', ip => '8.8.8.8' );
ok( defined( $galla->{marks}{seen}{'8.8.8.8'} ), 'a normal offender is' );

#
# the sweeper expires marks whose ttl has run out
#

$galla->{marks}{seen}{'8.8.8.8'}{expires} = time - 1;
$galla->_sweep;
ok( !defined( $galla->{marks}{seen} ), 'the sweeper drops an expired mark and its emptied name' );

#
# the marked command dumps the live store, name then key
#

feed( $galla, 'iptest', event => 'hit', ip => '9.9.9.9' );
my $dump = $galla->_cmd_marked;
is( $dump->{name}, 'marks', 'marked reports the galla name' );
ok( defined( $dump->{marks}{seen}{'9.9.9.9'}{expires} ), 'marked dumps a var-less brand with its expiry' );
is( $dump->{marks}{acct}{admin}{value}, '1.1.1.1', 'marked dumps a var-keyed brand with its value' );
# an expired brand is left out of the dump even before the sweeper runs
$galla->{marks}{seen}{'9.9.9.9'}{expires} = time - 1;
$dump = $galla->_cmd_marked;
ok( !defined( $dump->{marks}{seen} ), 'marked hides an expired brand' );

#
# the marks tablet round-trips, pruning the expired
#

$galla->{marks}{ride}{keepme}   = { 'expires' => time + 3600, 'value' => 'v' };
$galla->{marks}{ride}{dropme}   = { 'expires' => time - 1 };
$galla->checkpoint;

my $reborn = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'marks' );
is( $reborn->{marks}{ride}{keepme}{value}, 'v', 'a live mark rides the tablet, value and all' );
ok( !defined( $reborn->{marks}{ride}{dropme} ), 'an expired mark is pruned on restore' );
is( $reborn->{marks}{acct}{admin}{value}, '1.1.1.1', 'a var-keyed mark rides too' );

done_testing;
