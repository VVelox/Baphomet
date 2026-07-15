package App::Baphomet::App::Command::stop;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use App::Baphomet::Config qw( load_config );
use Ereshkigal::Client ();
use JSON::MaybeXS      ();
use Time::HiRes        qw( usleep );

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

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

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
		[ 'config=s', 'path of the config file', { default => '/usr/local/etc/baphomet/config.toml' } ],
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

	my $client = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );
	my $result = $client->call_ok('stop');

	# the stop is asynchronous... the manager acknowledges, then shuts down a
	# beat later. wait for the process to actually die so a following start,
	# as in a restart, does not race the still-present PID file. best effort,
	# on the manager's returned PID
	if ( !$opt->no_wait && defined( $result->{pid} ) && $result->{pid} =~ /^[0-9]+$/ ) {
		my $timeout = defined( $opt->timeout ) ? $opt->timeout : _config_timeout( $opt->config );
		my $waited  = _wait_for_exit( $result->{pid}, $timeout );
		if ( !$waited ) {
			warn( 'the manager (PID '
					. $result->{pid}
					. ') was still alive after '
					. $timeout
					. 's... a immediate restart may race its PID file' . "\n" );
		}
	} ## end if ( !$opt->no_wait && defined...)

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	return;
} ## end sub execute

# the effective wait timeout... the config's socket timeout, or 30 seconds
# when the config can not be read, since stop is often run with out a config
sub _config_timeout {
	my ($config_path) = @_;

	my $timeout;
	eval { $timeout = load_config($config_path)->{timeout}; };

	return ( defined($timeout) && $timeout =~ /^[0-9]+$/ ) ? $timeout : 30;
}

# polls until the passed PID is gone or the timeout elapses, 100ms a poll...
# returns true if it died, false on timeout. a timeout of 0 does not wait
sub _wait_for_exit {
	my ( $pid, $timeout ) = @_;

	my $polls = $timeout * 10;
	for ( my $i = 0; $i < $polls; $i++ ) {
		# kill 0 tests liveness without signalling... a dead PID gives 0
		if ( !kill( 0, $pid ) ) {
			return 1;
		}
		usleep(100_000);
	}

	return !kill( 0, $pid );
} ## end sub _wait_for_exit

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991, or (at your
  option) any later version, matching fail2ban, which parts of this
  project, most notably the shipped rules, are derived from.

=cut

1;
