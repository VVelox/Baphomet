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
use App::Baphomet::Config qw( kur_split resolve_namtar_lists );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

#
# config layer... resolve, validate, and the kur_split hash-setting
#

my $resolved = resolve_namtar_lists(
	{ namtar_lists => { bad => '/g/bad', tor => [ '/g/t1', '/g/t2' ] } },
	{ namtar_lists => { bad => [ '/k/bad1', '/k/bad2' ] } },
	{ namtar_lists => { tor => '/w/tor' } }
);
is_deeply( $resolved->{bad}, [ '/k/bad1', '/k/bad2' ], 'kur overrides a same-named list' );
is_deeply( $resolved->{tor}, ['/w/tor'], 'watcher overrides and a scalar normalizes to a array' );

is( App::Baphomet::Config::_namtar_lists_error( { x => '/p' },        'w' ), undef, 'a path passes' );
is( App::Baphomet::Config::_namtar_lists_error( { x => [ '/a', '/b' ] }, 'w' ), undef, 'a array of paths passes' );
like( App::Baphomet::Config::_namtar_lists_error( { x => [] }, 'w' ), qr/empty array/, 'a empty array fails' );
like( App::Baphomet::Config::_namtar_lists_error( { x => [''] }, 'w' ), qr/non-empty path/, 'a empty path fails' );

my ( $settings, $watchers ) = kur_split( { namtar_lists => { a => '/p' }, w => { log => 'x' } } );
ok( defined( $settings->{namtar_lists} ),  'kur_split keeps namtar_lists a setting' );
ok( !defined( $watchers->{namtar_lists} ), '...and not a watcher' );

#
# rule def validation of the namtar_list gate
#

my $base = {
	gate    => [ { field => 'event', values => ['fail'] } ],
	ban_var => ['ip'],
};
my %bad = (
	'not an array'          => { namtar_list => { list => 'bad' } },
	'a entry without lists' => { namtar_list => [ { var => 'ip' } ] },
	'both list and lists'   => { namtar_list => [ { list => 'bad', lists => ['tor'] } ] },
	'a bad list name'       => { namtar_list => [ { list => 'bad name' } ] },
	'a unknown key'         => { namtar_list => [ { list => 'bad', nope => 1 } ] },
	'an empty var'          => { namtar_list => [ { list => 'bad', var => '' } ] },
);
foreach my $desc ( sort( keys(%bad) ) ) {
	eval { App::Baphomet::Rules::JSON->new( name => 'json/x', def => { %{$base}, %{ $bad{$desc} } } ); };
	ok( $@, 'a namtar_list gate with ' . $desc . ' refuses to load' );
}

# a good gate loads and the accessor normalizes list/lists and the var
my $rule = App::Baphomet::Rules::JSON->new(
	name => 'json/x',
	def  => { %{$base}, namtar_list => [ { list => 'bad', var => 'peer' }, { lists => [ 'tor', 'vpn' ] } ] }
);
is_deeply( $rule->namtar_list->[0]{lists}, ['bad'],        'a scalar list normalizes to a array' );
is( $rule->namtar_list->[0]{var}, 'peer', 'the var is carried' );
is_deeply( $rule->namtar_list->[1]{lists}, [ 'tor', 'vpn' ], 'a lists array is kept' );

#
# galla behavior over real CIDR files
#

open( my $fh, '>', $dir . '/bad.cidr' ) || die($!);
print $fh "10.0.0.0/8\n192.0.2.5\n";
close($fh);
open( $fh, '>', $dir . '/tor.cidr' ) || die($!);
print $fh "# tor exit nodes\n203.0.113.0/24\n";
close($fh);
open( $fh, '>', $dir . '/override-bad.cidr' ) || die($!);
print $fh "198.51.100.0/24\n";
close($fh);
# note: $dir/missing.cidr is deliberately never created

my %rules = (
	'block'       => "namtar_list:\n  - list: bad\nmax_retrys: 1\n",
	'block-union' => "namtar_list:\n  - lists: [ bad, tor ]\nmax_retrys: 1\n",
	'guard'       => "namtar_list:\n  - list: bad\n    var: peer\nmax_retrys: 1\n",
	'empty'       => "namtar_list:\n  - list: missing\nmax_retrys: 1\n",
);
my %ban_var = ( 'guard' => 'src_ip' );
foreach my $name ( keys(%rules) ) {
	open( my $rf, '>', $dir . '/rules/json/' . $name . '.yaml' ) || die($!);
	my $bv = defined( $ban_var{$name} ) ? $ban_var{$name} : 'ip';
	print $rf "---\ngate:\n  - field: event\n    values: [ fail ]\nban_var:\n  - " . $bv . "\n" . $rules{$name};
	close($rf);
}

open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"

[namtar_lists]
bad = "$dir/bad.cidr"
tor = "$dir/tor.cidr"
missing = "$dir/missing.cidr"

[kur.nam]
max_retrys = 5
allow_per_rule_thresholds = true

[kur.nam.blockw]
log = "$dir/l1"
parser = "json"
rule = [ "json/block" ]

[kur.nam.unionw]
log = "$dir/l2"
parser = "json"
rule = [ "json/block-union" ]

[kur.nam.guardw]
log = "$dir/l3"
parser = "json"
rule = [ "json/guard" ]

[kur.nam.emptyw]
log = "$dir/l4"
parser = "json"
rule = [ "json/empty" ]

[kur.nam.overridew]
log = "$dir/l5"
parser = "json"
rule = [ "json/block" ]

[kur.nam.overridew.namtar_lists]
bad = "$dir/override-bad.cidr"
EOC
close($cfg);

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
	*App::Baphomet::Galla::log_drek  = sub { return; };    # hush the empty-file warning
}

my $json = JSON::MaybeXS->new( 'canonical' => 1 );

sub feed {
	my ( $galla, $watcher, %fields ) = @_;
	$galla->_handle_line( $watcher, $json->encode( \%fields ), $dir . '/l' );
	return;
}

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'nam' );

# offender-keyed, one list
@sent = ();
feed( $galla, 'blockw', event => 'fail', ip => '10.1.2.3' );
is_deeply( \@sent, ['10.1.2.3'], 'an offender inside a listed CIDR is banished' );
feed( $galla, 'blockw', event => 'fail', ip => '192.0.2.5' );
is_deeply( \@sent, [ '10.1.2.3', '192.0.2.5' ], 'an offender matching a listed address is banished' );
@sent = ();
feed( $galla, 'blockw', event => 'fail', ip => '8.8.8.8' );
is_deeply( \@sent, [], 'an offender on no list fails closed' );

# multiple lists in one entry are unioned
@sent = ();
feed( $galla, 'unionw', event => 'fail', ip => '203.0.113.9' );
is_deeply( \@sent, ['203.0.113.9'], 'a offender on the second of two unioned lists is banished' );
@sent = ();
feed( $galla, 'unionw', event => 'fail', ip => '10.5.5.5' );
is_deeply( \@sent, ['10.5.5.5'], 'and one on the first list too' );

# var gate... check the peer, ban the src
@sent = ();
feed( $galla, 'guardw', event => 'fail', peer => '10.9.9.9', src_ip => '8.8.8.8' );
is_deeply( \@sent, ['8.8.8.8'], 'a var gate bans the src when the checked peer is listed' );
@sent = ();
feed( $galla, 'guardw', event => 'fail', peer => '8.8.8.8', src_ip => '1.2.3.4' );
is_deeply( \@sent, [], 'a var gate vetoes the whole result when the peer is not listed' );

# a watcher that overrides the list resolves against different files
@sent = ();
feed( $galla, 'overridew', event => 'fail', ip => '10.1.2.3' );
is_deeply( \@sent, [], 'an override watcher spares an offender its overridden list does not hold' );
feed( $galla, 'overridew', event => 'fail', ip => '198.51.100.7' );
is_deeply( \@sent, ['198.51.100.7'], 'and banishes one the overridden list does hold' );

# a missing file loaded empty, so its gate matches nobody
is_deeply( $galla->{namtar_files}{ $dir . '/missing.cidr' }{set}, [], 'a missing feed loads as a empty set' );
@sent = ();
feed( $galla, 'emptyw', event => 'fail', ip => '10.1.2.3' );
is_deeply( \@sent, [], 'a gate over a missing feed fails closed' );

#
# a feed reloads on mtime change... the missing file appears, the sweeper
# picks it up, and its gate starts matching
#

open( $fh, '>', $dir . '/missing.cidr' ) || die($!);
print $fh "172.16.0.0/12\n";
close($fh);
$galla->_sweep;
@sent = ();
feed( $galla, 'emptyw', event => 'fail', ip => '172.16.5.5' );
is_deeply( \@sent, ['172.16.5.5'], 'the sweeper picks up a feed that appeared' );

# an existing feed gaining an entry, with a bumped mtime so the sweep sees it
my $cached = $galla->{namtar_files}{ $dir . '/bad.cidr' }{mtime};
open( $fh, '>', $dir . '/bad.cidr' ) || die($!);
print $fh "10.0.0.0/8\n192.0.2.5\n8.8.8.8\n";
close($fh);
utime( $cached + 5, $cached + 5, $dir . '/bad.cidr' );
$galla->_sweep;
@sent = ();
feed( $galla, 'blockw', event => 'fail', ip => '8.8.8.8' );
is_deeply( \@sent, ['8.8.8.8'], 'a reloaded feed matches its new entry' );

#
# a reference to a list the watcher does not define is fatal at bind
#

my $ref_rule = App::Baphomet::Rules::JSON->new(
	name => 'json/z',
	def  => { %{$base}, namtar_list => [ { list => 'nope' } ] }
);
eval { $galla->_resolve_namtar_gate( $ref_rule, { bad => ['/x'] }, 'where' ); };
like( $@, qr/nope.*not a defined list/, 'referencing a undefined namtar list dies' );
my $ok = $galla->_resolve_namtar_gate( $ref_rule, { nope => [ '/a', '/b' ] }, 'where' );
is_deeply( $ok->[0]{paths}, [ '/a', '/b' ], 'a defined reference resolves to its file paths' );

done_testing;
