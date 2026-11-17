package App::Baphomet::App::Command::stop;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use App::Baphomet::App -command;
use App::Baphomet::Config ();
use JSON::MaybeXS         ();
use Path::Tiny            qw( path );
use Time::HiRes           qw( usleep );

=head1 NAME

App::Baphomet::App::Command::stop - Stop all the gallas and the manager.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet stop
    baphomet stop --no-wait
    baphomet stop --timeout 10

=head1 DESCRIPTION

Asks the Baphomet manager, over its socket, to stop all its gallas and
then itself, via the C<stop> command. The stop is asynchronous on the
manager's side, so by default this waits for the manager's PID to exit,
up to C<--timeout> seconds or else the config's C<timeout>, falling back
to 30 when the config can not be read. That keeps a restart from racing
the still-present PID file. C<--no-wait> returns as soon as the stop is
acknowledged.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, description, usage_desc,
opt_spec, validate_args, and execute.

=cut

# the subs below with out a comment block are App::Cmd::Command hooks the
# framework calls... abstract and description for the help, usage_desc and
# opt_spec for the usage line and option parsing, validate_args to vet the
# args ahead of execute, and execute for the work itself. their contract is
# App::Cmd's, so they are not documented one by one here

sub abstract { return 'stop all the gallas and the manager' }

sub description {
	return
		  'Stop all the gallas and then the manager. The stop is asynchronous '
		. 'on the manager side, so by default this waits for the manager process '
		. 'to actually exit before returning, up to the config timeout, so a '
		. 'restart does not race the still-present PID file. --no-wait returns as '
		. 'soon as the stop is acknowledged, --timeout sets the wait (0 to not wait).';
}

sub usage_desc { return '%c stop %o'; }

sub opt_spec {
	return (
		[ 'config=s',  'path of the config file', { default => '/usr/local/etc/baphomet/config.toml' } ],
		[ 'timeout=i', 'seconds to wait for the manager to exit, 0 to not wait' ],
		[ 'no-wait',   'return as soon as the stop is acknowledged, without waiting for exit' ],
	);
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} ) {
		$self->usage_error('stop does not take any args');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $result = $self->app->manager_call('stop');

	# the stop is asynchronous... the manager acknowledges, then shuts down a
	# beat later. wait for the process to actually die so a following start,
	# as in a restart, does not race the still-present PID file. best effort,
	# on the manager's returned PID
	if ( !$opt->no_wait && defined( $result->{pid} ) && $result->{pid} =~ /^[0-9]+$/ ) {
		my $timeout = defined( $opt->timeout ) ? $opt->timeout : _config_timeout( $opt->config );
		my $waited  = _wait_for_exit( $result->{pid}, $timeout );
		if ( !$waited ) {
			warn(     'the manager (PID '
					. $result->{pid}
					. ') was still alive after '
					. $timeout
					. 's... a immediate restart may race its PID file'
					. "\n" );
		}
	} ## end if ( !$opt->no_wait && defined( $result->{...}))

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	return;
} ## end sub execute

# the effective wait timeout... the config's socket timeout, or 30 seconds
# when the config can not be read, since stop is often run with out a
# config. a raw TOML read rather than load_config, as one integer does not
# warrant the full validation pass and a config broken in some other way
# should not break stopping
#
# args:
#   $config_path :: path of the TOML config, from --config
#
# returns:
#   the config's timeout in int seconds when it reads as a non-negative int,
#   else 30
#
# example:
#   my $timeout = _config_timeout('/usr/local/etc/baphomet/config.toml');
sub _config_timeout {
	my ($config_path) = @_;

	my $timeout;
	eval {
		my $raw = path($config_path)->slurp;
		require TOML::Tiny;
		$timeout = TOML::Tiny::from_toml($raw)->{timeout};
	};

	return ( defined($timeout) && $timeout =~ /^[0-9]+$/ ) ? $timeout : 30;
} ## end sub _config_timeout

# polls until the passed PID is gone or the timeout elapses, 100ms a poll,
# so stop can return only once the manager has truly exited. a timeout of 0
# does not wait, just checks once
#
# args:
#   $pid :: the manager's PID, a int
#   $timeout :: int seconds to wait at most
#
# returns:
#   true (1) if the PID is gone, false if it was still alive when the
#   timeout ran out
#
# example:
#   if ( !_wait_for_exit( 4242, 30 ) ) { warn("still alive\n"); }
sub _wait_for_exit {
	my ( $pid, $timeout ) = @_;

	my $polls = $timeout * 10;
	for ( my $i = 0; $i < $polls; $i++ ) {
		if ( !_pid_alive($pid) ) {
			return 1;
		}
		usleep(100_000);
	}

	return !_pid_alive($pid);
} ## end sub _wait_for_exit

# kill 0 tests liveness without signalling... a dead PID gives 0, but so
# does a live one owned by somebody else, with EPERM, and a non-root stop
# of a root-owned manager must not read that as it having died
#
# args:
#   $pid :: the PID to test, a int
#
# returns:
#   1 if the process exists, whoever owns it, else 0
#
# example:
#   my $alive = _pid_alive(4242);
sub _pid_alive {
	my ($pid) = @_;

	if ( kill( 0, $pid ) ) {
		return 1;
	}

	return $!{EPERM} ? 1 : 0;
}

1;
