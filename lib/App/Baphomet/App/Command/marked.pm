package App::Baphomet::App::Command::marked;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use App::Baphomet::App::FanoutCmd qw( fanout_validate_args fanout_execute );

=head1 NAME

App::Baphomet::App::Command::marked - Show the marks the gallas are holding.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet marked
    baphomet marked sshd
    baphomet marked --name sprayed-user

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'show the marks the gallas are holding' }

sub description {
	return
		  'Marks are the named, expiring brands rules leave on a key, an IP or a '
		. 'harvested capture like a username, so a later rule can gate on them. '
		. 'This shows the live marks, per mark name a hash of the branded keys with '
		. 'their expiries and any stored value. With no args, every galla is asked. '
		. 'With a galla name, just that one. With --name, only that mark is shown.';
}

sub usage_desc { return '%c marked %o [galla]'; }

sub opt_spec {
	return ( [ 'name=s', 'only show this mark name' ], );
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	return fanout_validate_args( $self, $args, 'marked' );
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	# --name pares each galla down to the one mark, dropping gallas not
	# holding it at all
	return fanout_execute( $self, $args, 'marked', $opt->name, 'marks' );
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
