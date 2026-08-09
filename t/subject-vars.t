#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp    qw( tempdir );
use File::Path    qw( make_path );
use JSON::MaybeXS qw( decode_json );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/raw', $dir . '/run' );

# a rule naming both ends of a flow... the offense is a list, and the event
# has to say so rather than promoting one end and misdescribing the other
open( my $fh, '>', $dir . '/rules/raw/pair.yaml' ) || die($!);
print $fh <<'EOR';
---
message_regexp:
  - '^flow %%%%SRC%%%% -> %%%%DEST%%%%$'
ban_var:
  - SRC
  - DEST
tests:
  positive:
    - message: "flow 192.0.2.5 -> 198.51.100.9"
      found: 1
      data:
        SRC: "192.0.2.5"
        DEST: "198.51.100.9"
EOR
close($fh);

open( $fh, '>', $dir . '/log' ) || die($!);
close($fh);

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
eve_log = "$dir/eve/eve.json"
eve_enable = true
max_score = 10
find_time = 600
ignore_ips = [ "203.0.113.0/24" ]

[kur.app]
ban_time = 300

[kur.app.w]
log = "$dir/log"
parser = "raw"
rule = "raw/pair"
EOC
close($fh);

sub read_events {
	my $path = $dir . '/eve/eve.json';
	return () if !-f $path;
	open( my $efh, '<', $path ) || die($!);
	my @lines = <$efh>;
	close($efh);
	return map { decode_json($_) } @lines;
}

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}

my $galla = App::Baphomet::Galla->new( 'config' => $dir . '/config.toml', 'name' => 'app' );
ok( !$galla->{perror}, 'galla built' ) || diag( $galla->{errorString} );

#
# two vars, two offenders... each counted in its own bucket and each named on
# the record beside what it is worth
#

$galla->_handle_line( 'w', 'flow 192.0.2.5 -> 198.51.100.9' );
is( scalar( @{ $galla->{counters}{'192.0.2.5'}    || [] } ), 1, 'the SRC offender counted' );
is( scalar( @{ $galla->{counters}{'198.51.100.9'} || [] } ), 1, 'and the DEST offender apart from it' );

my @events = read_events();
is_deeply(
	$events[-1]{subject_vars},
	{ 'SRC' => '192.0.2.5', 'DEST' => '198.51.100.9' },
	'both vars are on the record, under the names the rule gave them'
);
is_deeply( $events[-1]{subject_vars_scores}, { 'SRC' => 1, 'DEST' => 1 }, 'each with its own score' );
ok( !exists( $events[-1]{ip} ),               'and no promoted scalar beside them' );
ok( !exists( $events[-1]{subjects_crossed} ), 'and nothing crossed, so nothing says it did' );

#
# one line is one piece of evidence about a address... two vars naming the same
# one walk it a single step toward the threshold, and both then read the one
# bucket
#

$galla->_handle_line( 'w', 'flow 10.10.10.10 -> 10.10.10.10' );
is( scalar( @{ $galla->{counters}{'10.10.10.10'} || [] } ), 1, 'the same address in two vars counted once' );

@events = read_events();
is_deeply( $events[-1]{subject_vars}, { 'SRC' => '10.10.10.10', 'DEST' => '10.10.10.10' }, 'both vars named it' );
is_deeply( $events[-1]{subject_vars_scores}, { 'SRC' => 1, 'DEST' => 1 }, 'and both report the one score' );

#
# a var in ignore_ips is named but never counted, which is the whole of what a
# missing score entry means. before this the event promoted the ignored address
# to .ip and the other one's tally to .score, and the two described different
# offenders
#

$galla->_handle_line( 'w', 'flow 203.0.113.7 -> 198.51.100.50' );
@events = read_events();
is_deeply(
	$events[-1]{subject_vars},
	{ 'SRC' => '203.0.113.7', 'DEST' => '198.51.100.50' },
	'the ignored offender is still named'
);
is_deeply( $events[-1]{subject_vars_scores}, { 'DEST' => 1 }, 'but carries no score, never having been counted' );
ok( !defined( $galla->{counters}{'203.0.113.7'} ), 'and never reached a bucket' );

#
# the crossing... one determination, one banish, naming who it lands on
#

foreach ( 1 .. 9 ) {
	$galla->_handle_line( 'w', 'flow 192.0.2.5 -> 198.51.100.9' );
}

my ($banish) = grep { $_->{event_type} eq 'banish' } read_events();
ok( defined($banish), 'the tenth hit crossed and banished' );
is_deeply( $banish->{banishing}, ['192.0.2.5'], 'the banish names who it lands on' );
is( $banish->{subject_vars}{SRC}, '192.0.2.5', 'and which var named them' );

# the crossing is held until the whole line has been counted, so the banish
# carries every var's score and not just the crossing one's... DEST is at 10
# beside SRC because both ends counted on all ten lines
is_deeply(
	$banish->{subject_vars_scores},
	{ 'SRC' => 10, 'DEST' => 10 },
	'the banish carries the whole score map, the vars after the crossing one included'
);

# both ends are at 10 against a max_score of 10, so both crossed... which is
# the point of naming them rather than leaving the reader to compare each
# score against the threshold and guess
is_deeply(
	$banish->{subjects_crossed},
	{ 'SRC' => 10, 'DEST' => 10 },
	'and names which vars crossed, against the number they had to reach'
);

done_testing;
