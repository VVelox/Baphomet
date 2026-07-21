package App::Baphomet::App::Command::start;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use App::Baphomet         ();
use App::Baphomet::Config qw( pidfile_or_daemonize );

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

	$baphomet->start_server;

	unlink( $baphomet->pid_path ) if -e $baphomet->pid_path;

	return;
} ## end sub execute

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
