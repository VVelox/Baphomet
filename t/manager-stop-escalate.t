#!perl
# the stop path's aliveness accounting... a clean stop must not be held a
# grace period by the stop_escalate alarm, so the last reaped child drops
# it, and a straggler is TERMed then KILLed rather than TERMed and waited
# on forever. the handlers are driven directly with a recording kernel...
# no forked gallas, no running POE loop, just the slots the handlers read
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

use App::Baphomet ();
use POE::Session;

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run' );

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

my $group = getgrgid( ( split( /\s+/, $) ) )[0] );
open( my $config_fh, '>', $dir . '/config.toml' ) || die($!);
print $config_fh <<"EOC";
run_base_dir = "$dir/run"
rules_dir = "$dir/rules"
socket_group = "$group"

[kur.one]
ban_time = 300

[kur.one.authlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"

[kur.two]
ban_time = 300

[kur.two.authlog]
log = "$dir/log2"
parser = "bsd_syslog"
rule = "syslog/sshd"
EOC
close($config_fh);

my $baphomet = App::Baphomet->new( 'config' => $dir . '/config.toml' );
ok( defined($baphomet), 'manager built' );

# a kernel that only remembers what was asked of it
{

	package Mock::Kernel;

	sub new { return bless( { 'calls' => [] }, $_[0] ); }

	sub calls { return $_[0]{calls}; }

	sub reset_calls { $_[0]{calls} = []; return; }

	sub alarm_remove_all { push( @{ $_[0]{calls} }, ['alarm_remove_all'] ); return; }

	sub delay {
		my ( $self, @args ) = @_;
		push( @{ $self->{calls} }, [ 'delay', @args ] );
		return;
	}

	sub delay_set {
		my ( $self, @args ) = @_;
		push( @{ $self->{calls} }, [ 'delay_set', @args ] );
		return;
	}
}

# a wheel that only remembers being signaled
{

	package Mock::Wheel;

	sub new { return bless( { 'signals' => [] }, $_[0] ); }

	sub kill { push( @{ $_[0]{signals} }, $_[1] ); return; }

	sub signals { return $_[0]{signals}; }

	sub ID { return 42; }
}

my $kernel = Mock::Kernel->new;

sub poe_args {
	my (%slot) = @_;
	my @args;
	$args[OBJECT] = $baphomet;
	$args[KERNEL] = $kernel;
	$args[ARG0]   = $slot{arg0} if exists( $slot{arg0} );
	$args[ARG1]   = $slot{arg1} if exists( $slot{arg1} );
	$args[ARG2]   = $slot{arg2} if exists( $slot{arg2} );
	return @args;
}

#
# reaping during shutdown... the last child drops every pending alarm, an
# earlier one leaves the escalate armed
#

$baphomet->{shutting_down} = 1;
$baphomet->{pid_to_galla}  = { 111 => 'one', 222 => 'two' };
$baphomet->{gallas}{one}{pid}   = 111;
$baphomet->{gallas}{one}{wheel} = Mock::Wheel->new;
$baphomet->{gallas}{two}{pid}   = 222;
$baphomet->{gallas}{two}{wheel} = Mock::Wheel->new;

App::Baphomet::_poe_galla_reaped( poe_args( arg1 => 111, arg2 => 0 ) );
is_deeply( $kernel->calls, [], 'a reap with a sibling still running leaves the escalate alarm be' );

App::Baphomet::_poe_galla_reaped( poe_args( arg1 => 222, arg2 => 0 ) );
is_deeply( $kernel->calls, [ ['alarm_remove_all'] ], 'the last reap drops the pending alarms' );

# and never a restart while shutting down
ok( !grep( { $_->[0] eq 'delay_set' } @{ $kernel->calls } ), 'no restart was scheduled during shutdown' );

#
# the escalation ladder... TERM re-arms for KILL, KILL ends it, and with
# nothing left running neither signals nor re-arms
#

$kernel->reset_calls;
my $wheel = Mock::Wheel->new;
$baphomet->{gallas}{one}{pid}   = 111;
$baphomet->{gallas}{one}{wheel} = $wheel;

App::Baphomet::_poe_stop_escalate( poe_args( arg0 => 'TERM' ) );
is_deeply( $wheel->signals, ['TERM'], 'the first grace period ends in TERM' );
is_deeply(
	$kernel->calls,
	[ [ 'delay', 'stop_escalate', $baphomet->{timeout}, 'KILL' ] ],
	'and re-arms one more grace, for KILL'
);

$kernel->reset_calls;
App::Baphomet::_poe_stop_escalate( poe_args( arg0 => 'KILL' ) );
is_deeply( $wheel->signals, [ 'TERM', 'KILL' ], 'the second ends in KILL' );
is_deeply( $kernel->calls, [], 'and nothing re-arms past the unrefusable' );

$kernel->reset_calls;
$baphomet->{gallas}{one}{pid}   = undef;
$baphomet->{gallas}{one}{wheel} = undef;
App::Baphomet::_poe_stop_escalate( poe_args( arg0 => 'TERM' ) );
is_deeply( $kernel->calls, [], 'nothing running... nothing signaled, nothing re-armed' );

done_testing;
