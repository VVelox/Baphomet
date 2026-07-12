package App::Baphomet::App;

use 5.006;
use strict;
use warnings;
use App::Cmd::Setup -app;

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
