package App::Baphomet::App::Command::tracked;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use App::Baphomet::App::FanoutCmd qw( fanout_validate_args fanout_execute );

=head1 NAME

App::Baphomet::App::Command::tracked - Show the tracked records the gallas are holding.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet tracked
    baphomet tracked mail
    baphomet tracked --name mail-queue

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'show the tracked records the gallas are holding' }

sub description {
	return
		  'A daemon that logs one transaction over several lines spreads the facts '
		. 'about it across all of them, joined only by a key it repeats... a postfix '
		. 'queue id, a session id. A tracked record is where those facts accumulate, '
		. 'so the line that finally says something worth banning on can reach what an '
		. 'earlier line said. This shows the live records, per track name a hash of '
		. 'keys with their expiries and the fields gathered so far. A compound key is '
		. 'handed back split into its components rather than joined. '
		. 'With no args, every galla is asked. '
		. 'With a galla name, just that one. With --name, only that track is shown.';
} ## end sub description

sub usage_desc { return '%c tracked %o [galla]'; }

sub opt_spec {
	return ( [ 'name=s', 'only show this track name' ], );
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	return fanout_validate_args( $self, $args, 'tracked' );
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	# --name pares each galla down to the one track, dropping gallas not
	# holding it at all
	return fanout_execute( $self, $args, 'tracked', $opt->name, 'tracked' );
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
