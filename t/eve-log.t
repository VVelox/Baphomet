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
make_path( $dir . '/rules/syslog', $dir . '/rules/json', $dir . '/run', $dir . '/cache' );

open( my $fh, '>', $dir . '/rules/syslog/sshd.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
EOR
close($fh);

open( $fh, '>', $dir . '/rules/json/app.yaml' ) || die($!);
print $fh <<'EOR';
---
gate:
  - field: event
    values: [ authfail ]
match:
  - field: src
    regexp: '^%%%%SRC%%%%$'
ban_var:
  - SRC
EOR
close($fh);

sub write_config {
	my ($enable) = @_;
	open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
	print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"
eve_log = "$dir/eve/eve.json"
eve_enable = $enable
max_retrys = 3
find_time = 600

[kur.sshd]
ban_time = 300

[kur.sshd.authlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"

[kur.sshd.appjson]
log = "$dir/app.json"
parser = "json"
rule = "json/app"
EOC
	close($cfg);
	return;
} ## end sub write_config

sub read_events {
	my $path = $dir . '/eve/eve.json';
	return () if !-f $path;
	open( my $efh, '<', $path ) || die($!);
	my @lines = <$efh>;
	close($efh);
	return map { decode_json($_) } @lines;
}

# capture banishments so nothing tries to reach Ereshkigal
my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}

#
# disabled... default path set but nothing written
#

write_config('false');
my $off = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );
is( $off->{eve_log},    $dir . '/eve/eve.json', 'eve_log has its default even when off' );
is( $off->{eve_enable}, 0,                      'eve_enable off' );
$off->_handle_line( 'authlog', 'Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 5.5.5.5', $dir . '/log' );
ok( !-f $dir . '/eve/eve.json', 'nothing written while disabled' );

#
# enabled
#

write_config('true');
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );
is( $galla->{eve_enable}, 1, 'eve_enable on' );
ok( -d $dir . '/eve', 'the eve dir was created' );

# three bad lines... three found events and one banish at the threshold
foreach ( 1 .. 3 ) {
	$galla->_handle_line( 'authlog', 'Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 9.9.9.9', $dir . '/log' );
}

my @events = read_events();
my @found  = grep { $_->{event_type} eq 'found' } @events;
my @banish = grep { $_->{event_type} eq 'banish' } @events;
is( scalar(@found),   3, 'three found events' );
is( scalar(@banish), 1, 'one banish event' );

my $f = $found[0];
is( $f->{eve_type},   'baphomet', 'eve_type is baphomet' );
is( $f->{event_type}, 'found',    'event_type found' );
is( $f->{kur},        'sshd',     'kur' );
ok( defined( $f->{hostname} ), 'hostname present' );
like( $f->{timestamp}, qr/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/, 'ISO8601 timestamp' );
is( $f->{path}, $dir . '/log', 'path is the source file' );
is( $f->{raw},  'Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 9.9.9.9', 'raw line' );
is( $f->{found}{SRC}, '9.9.9.9', 'found carries the check data' );
is( $f->{parsed}{daemon}, 'sshd', 'parsed carries the parser output' );
is( $f->{count}, 1, 'count on the first found is 1' );
is( $found[2]{count}, 3, 'count on the third found is 3' );

# rule info present but without the tests
is( $f->{rule}{name}, 'syslog/sshd', 'rule name' );
ok( defined( $f->{rule}{def}{message_regexp} ), 'rule def present' );
ok( !exists( $f->{rule}{def}{tests} ),          'rule tests stripped for space' );

# the banish event
my $c = $banish[0];
is( $c->{event_type}, 'banish', 'banish event_type' );
is( $c->{ip},         '9.9.9.9', 'banish ip' );
is( $c->{ban_time},   300,       'banish ban_time' );
is( $c->{count},      3,         'banish count' );
is( $c->{found}{SRC}, '9.9.9.9', 'banish carries the triggering found' );

#
# a JSON watcher... parsed holds the parsed JSON
#

$galla->_handle_line( 'appjson', '{"event":"authfail","src":"2.2.2.2","user":"root"}', $dir . '/app.json' );
@events = read_events();
my ($json_found) = grep { $_->{event_type} eq 'found' && $_->{found}{SRC} && $_->{found}{SRC} eq '2.2.2.2' } @events;
ok( defined($json_found), 'json watcher produced a found event' );
is( $json_found->{parsed}{event}, 'authfail', 'parsed holds the flattened JSON fields' );
is( $json_found->{parsed}{src},   '2.2.2.2',  'including the source field' );

done_testing;
