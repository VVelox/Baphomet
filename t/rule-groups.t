#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla  ();
use App::Baphomet::Rules  ();
use App::Baphomet::Config qw( check_kur_def );

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/json', $dir . '/rules/syslog', $dir . '/groups/json', $dir . '/run', $dir . '/cache' );

# minimal json gate rules, one per named "which"
foreach my $name (qw( a b c extra )) {
	open( my $rfh, '>', $dir . '/rules/json/' . $name . '.yaml' ) || die($!);
	print $rfh "---\ngate:\n  - field: which\n    values: [ " . $name . " ]\nban_var:\n  - src_ip\n";
	close($rfh);
}

# a syslog rule, for the type/parser pairing check... it must load cleanly
# (its own tests pass) so the pairing check, which only fires on a loaded
# rule, is what is under test
open( my $sfh, '>', $dir . '/rules/syslog/s.yaml' ) || die($!);
print $sfh <<'EOR';
---
daemons:
  - foo
message_regexp:
  - 'bar from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 host foo[1]: bar from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
EOR
close($sfh);

# a group with a comment, a blank line, a whitespace-only line, and a member
# padded with leading and trailing whitespace
open( my $gfh, '>', $dir . '/groups/json/mygroup' ) || die($!);
print $gfh "# the group of a, b, and c\n";
print $gfh "json/a\n";
print $gfh "\n";
print $gfh "   \n";
print $gfh "  json/b  \n";
print $gfh "  # an indented comment\n";
print $gfh "json/c\n";
close($gfh);

# a group whose only lines are comments and blanks... no members
open( my $efh, '>', $dir . '/groups/json/empty' ) || die($!);
print $efh "# nothing here\n\n";
close($efh);

# a group with a malformed member
open( my $bfh, '>', $dir . '/groups/json/bad' ) || die($!);
print $bfh "json/a\nnotarule\n";
close($bfh);

# a group mixing a json rule and a syslog rule, for the pairing check
open( my $mfh, '>', $dir . '/groups/json/mixed' ) || die($!);
print $mfh "json/a\nsyslog/s\n";
close($mfh);

#
# the Rules object group methods, in isolation... shipped off so only the
# temp dirs are in play
#

my $rules = App::Baphomet::Rules->new(
	rules_dir  => $dir . '/rules',
	groups_dir => $dir . '/groups',
	shipped    => 0,
);

is( $rules->group_path('json/mygroup'), $dir . '/groups/json/mygroup', 'group_path finds a group file' );
is( $rules->group_path('json/nope'),    undef,                         'group_path is undef for a missing group' );

is_deeply(
	[ $rules->group_members('json/mygroup') ],
	[ 'json/a', 'json/b', 'json/c' ],
	'group_members drops comments and blanks, trims whitespace, keeps order'
);

# expand_rules... bare rules pass through, %group% expands, dedup keeps the
# first occurrence, order preserved
is_deeply(
	[ $rules->expand_rules( 'json/extra', '%json/mygroup%', 'json/a' ) ],
	[ 'json/extra', 'json/a', 'json/b', 'json/c' ],
	'expand_rules expands a group and dedups a later repeat'
);
is_deeply(
	[ $rules->expand_rules('json/sshd') ],
	['json/sshd'],
	'expand_rules passes a bare rule through untouched'
);

# the deaths
eval { $rules->group_members('json/missing'); };
like( $@, qr/does not exist under any of the groups dirs/, 'a missing group dies' );
eval { $rules->group_members('json/empty'); };
like( $@, qr/has no members/, 'a group with no members dies' );
eval { $rules->group_members('json/bad'); };
like( $@, qr/invalid rule "notarule"/, 'a group with a malformed member dies' );
eval { $rules->group_members('badname'); };
like( $@, qr/is not in the form "type\/name"/, 'a group name without a slash dies' );

#
# check_kur_def... a %group% entry is vetted for token syntax only
#

my %base_watcher = ( log => $dir . '/eve.json', parser => 'json' );
eval { check_kur_def( 'ids', { max_score => 3, eve => { %base_watcher, rule => ['%json/mygroup%'] } } ); };
is( $@, '', 'a %group% rule entry validates' );

# it validates even for a group that does not exist... membership is checked
# when the galla expands it, not here
eval { check_kur_def( 'ids', { max_score => 3, eve => { %base_watcher, rule => ['%json/absent%'] } } ); };
is( $@, '', 'a %group% entry validates without the group file existing' );

eval { check_kur_def( 'ids', { max_score => 3, eve => { %base_watcher, rule => ['%badname%'] } } ); };
like( $@, qr/invalid rule group/, 'a %group% token without a slash is rejected' );

#
# the galla... a watcher pulls its rules in through a group and they fire
#

sub write_config {
	my ($rule_list) = @_;
	open( my $cfg, '>', $dir . '/config.toml' ) || die($!);
	print $cfg <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
groups_dir = "$dir/groups"
ereshkigal_socket = "$dir/nonexistent.sock"
max_score = 2

[kur.ids.eve]
log = "$dir/eve.json"
parser = "json"
rule = $rule_list
EOC
	close($cfg);
	return;
} ## end sub write_config

my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub { push( @sent, $_[1] ); return; };
}

sub feed {
	my ( $galla, $which, $ip ) = @_;
	$galla->_handle_line( 'eve', '{"which":"' . $which . '","src_ip":"' . $ip . '"}', $dir . '/eve.json' );
	return;
}

write_config('[ "%json/mygroup%", "json/extra" ]');
my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' );
ok( !$galla->{perror}, 'a watcher with a group builds without error' );
is_deeply(
	$galla->{watchers}{eve}{rules},
	[ 'json/a', 'json/b', 'json/c', 'json/extra' ],
	'the group expanded in place, deduped, ahead of the explicit rule'
);

# a rule pulled in through the group actually fires
@sent = ();
feed( $galla, 'b', '203.0.113.1' );
feed( $galla, 'b', '203.0.113.1' );
is_deeply( \@sent, ['203.0.113.1'], 'a group member fires and bans at the watcher max_score' );

#
# a group member of a type the parser can not feed is caught, loudly... a
# rules-load error is fatal, so the galla refuses to build
#

write_config('[ "%json/mixed%" ]');
eval { App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'ids' ); };
like(
	$@,
	qr/parser "json" does not produce/,
	'a json watcher pulling a syslog rule in through a group fails to build, naming the parser'
);

done_testing;
