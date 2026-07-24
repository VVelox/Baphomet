#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp            qw( tempdir );
use File::Path            qw( make_path );
use App::Baphomet::Config qw( check_kur_def );
use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();

my $rules_dir = tempdir( CLEANUP => 1 );
make_path( $rules_dir . '/raw' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $rules_dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

write_rule( 'raw/appfail', <<'EOR' );
---
message_regexp:
  - '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} auth failure from %%%%SRC%%%%$'
  - '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} flow from %%%%SRC%%%%(?: to %%%%DEST%%%%)?$'
ignore_regexp:
  - 'from %%%%SRC%%%% whom we like'
ban_var:
  - SRC
tests:
  positive:
    - message: "2026-07-12 08:15:50 auth failure from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
  negative:
    - message: "2026-07-12 08:15:51 auth success from 1.2.3.4"
      found: 0
      undefed: ["SRC"]
EOR

my $rules = App::Baphomet::Rules->new( rules_dir => $rules_dir, shipped => 0 );
my $rule  = $rules->load('raw/appfail');
ok( defined($rule), 'raw rule loaded' );
is( ( $rule->ban_var )[0], 'SRC', 'ban_var' );

sub raw_line {
	my ($line) = @_;
	return App::Baphomet::Parser::parse( 'raw', $line );
}

my $found = $rule->check( raw_line('2026-07-12 08:15:50 auth failure from 1.2.3.4') );
ok( defined($found), 'match found' );
is( $found->{data}{SRC}, '1.2.3.4', 'SRC captured' );
is( $found->{regexp},    0,         'first regexp hit' );

# the shared machinery carries over... tokens, SRC/DEST pairing, ignores
$found = $rule->check( raw_line('2026-07-12 08:15:50 flow from 1.2.3.4 to 5.6.7.8') );
ok( defined($found), 'SRC+DEST together found' );
is( $found->{data}{DEST}, '5.6.7.8', 'DEST captured' );
ok( !defined( $rule->check( raw_line('2026-07-12 08:15:50 flow from 1.2.3.4') ) ),
	'SRC with out DEST not regarded as found' );
ok( !defined( $rule->check( raw_line('2026-07-12 08:15:50 auth failure from 1.2.3.4 whom we like') ) ),
	'ignore_regexp vetoes' );
ok( !defined( $rule->check( raw_line('nothing of note') ) ), 'non-matching line not found' );

# no daemon gate to worry about, but shape still checked
ok( !defined( $rule->check(undef) ),  'undef refused' );
ok( !defined( $rule->check( {} ) ),   'messageless hash refused' );

#
# invalid defs
#

write_rule( 'raw/nobanvar', "---\nmessage_regexp:\n  - 'foo'\n" );
ok( !eval { $rules->load('raw/nobanvar'); 1 }, 'missing ban_var refuses to load' );

write_rule( 'raw/daemons', "---\ndaemons:\n  - sshd\nmessage_regexp:\n  - 'foo'\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/daemons'); 1 }, 'a daemons key on a raw rule refuses to load' );

write_rule( 'raw/badtoken', "---\nmessage_regexp:\n  - '%%%%LAMASHTU%%%%'\nban_var:\n  - SRC\n" );
ok( !eval { $rules->load('raw/badtoken'); 1 }, 'unknown token refuses to load' );

#
# pairing
#

ok( App::Baphomet::Rules::type_accepts_parser( 'raw', 'raw' ),     'raw takes raw' );
ok( !App::Baphomet::Rules::type_accepts_parser( 'raw', 'syslog' ), 'raw refuses syslog' );
ok( !App::Baphomet::Rules::type_accepts_parser( 'syslog', 'raw' ), 'syslog refuses raw' );

my $good_def = { 'applog' => { 'log' => '/var/log/app.log', 'parser' => 'raw', 'rule' => 'raw/appfail' } };
ok( eval { check_kur_def( 'app', $good_def ); 1 }, 'raw rule with the raw parser checks out' ) || diag($@);

my $bad_def = { 'applog' => { 'log' => '/var/log/app.log', 'rule' => 'raw/appfail' } };
ok( !eval { check_kur_def( 'app', $bad_def ); 1 }, 'raw rule with the default syslog parser refuses' );

done_testing;
