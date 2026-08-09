package App::Baphomet::App::Command::start;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use App::Baphomet          ();
use App::Baphomet::Config  qw( pidfile_or_daemonize );
use App::Baphomet::LogDrek qw( log_drek );

=head1 NAME

App::Baphomet::App::Command::start - Start the manager and a galla for every configured kur.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet start
    baphomet start --foreground
    baphomet start --config /usr/local/etc/baphomet/config.toml

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'start the manager and a galla for every configured kur' }

sub description { return 'Start the manager, daemonizing unless told otherwise.'; }

sub usage_desc { return '%c start %o'; }

sub opt_spec {
	return (
		[ 'config=s',     'path of the config file', { default => '/usr/local/etc/baphomet/config.toml' } ],
		[ 'foreground|f', 'do not daemonize' ],
	);
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} ) {
		$self->usage_error('start does not take any args');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $baphomet = App::Baphomet->new( 'config' => $opt->config );

	pidfile_or_daemonize( $baphomet->pid_path, $opt->foreground );

	# daemonized, STDERR is gone, so a death in here would otherwise be
	# wholly silent... a start that leaves nothing behind but a stale PID
	# file. syslog is the only place left to say it, and the PID file is
	# cleared either way so the next start does not race a dead PID
	eval { $baphomet->start_server; };
	my $died = $@;

	unlink( $baphomet->pid_path ) if -e $baphomet->pid_path;

	if ($died) {
		log_drek( 'err', 'the manager failed to start... ' . $died );
		die($died);
	}

	return;
} ## end sub execute

1;
