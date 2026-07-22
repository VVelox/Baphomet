package App::Baphomet::App;

use 5.006;
use strict;
use warnings;
use App::Cmd::Setup -app;
use POE::Component::Server::JSONUnix::BlockingClient ();

=head1 NAME

App::Baphomet::App - App::Cmd app for the baphomet bin.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::App;

    App::Baphomet::App->run;

=head1 DESCRIPTION

L<App::Cmd> app providing the C<baphomet> CLI. See the various
App::Baphomet::App::Command modules for the subcommands.

=head1 METHODS

=head2 global_opt_spec

Global options available to every subcommand.

    -s|--socket :: Path of the manager unix socket.
        Default :: /var/run/baphomet/socket

=cut

sub global_opt_spec {
	return ( [ 'socket|s=s', 'path of the manager unix socket', { default => '/var/run/baphomet/socket' } ], );
}

=head2 manager_call

Makes one blocking call to the baphomet manager over its socket and returns
the result, dieing on a connect, auth, or command failure. The manager
speaks the L<POE::Component::Server::JSONUnix> protocol, so every CLI query
rides that dist's own blocking client to the one manager socket rather than
reaching around it to Ereshkigal... the manager is the one that talks to
Ereshkigal. The socket is the global C<--socket>.

    my $result = $self->app->manager_call('status');
    my $result = $self->app->manager_call( 'banished', { 'name' => 'sshd' } );

=cut

sub manager_call {
	my ( $self, $command, $args ) = @_;

	my $client = POE::Component::Server::JSONUnix::BlockingClient->new( 'socket_path' => $self->global_options->{socket} );

	# the Neti dance, done transparently as the old client did... it answers
	# ok whether or not the manager gates, so it is always safe to ask
	my $auth = $client->authenticate;
	if ( ( $auth->{status} // '' ) ne 'ok' ) {
		die( 'authenticating to the manager failed... '
				. ( defined( $auth->{error} ) ? $auth->{error} : 'unknown error' )
				. "\n" );
	}

	my $response = $client->call( 'command' => $command, ( defined($args) ? ( 'args' => $args ) : () ) );
	if ( ( $response->{status} // '' ) ne 'ok' ) {
		die( 'the manager refused "'
				. $command . '"... '
				. ( defined( $response->{error} ) ? $response->{error} : 'unknown error' )
				. "\n" );
	}

	return $response->{result};
} ## end sub manager_call

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
