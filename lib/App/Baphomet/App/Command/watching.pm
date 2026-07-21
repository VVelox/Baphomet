package App::Baphomet::App::Command::watching;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use App::Baphomet::App::FanoutCmd qw( fanout_validate_args fanout_execute );

=head1 NAME

App::Baphomet::App::Command::watching - Show what each galla is watching.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet watching
    baphomet watching sshd

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'show what files and globs each galla is watching' }

sub description {
	return
		  'Per galla and per watcher, what it is set to watch and what it is watching now... '
		. 'for a file watcher the log specs, literal paths and globs alike, under globs, '
		. 'and the concrete files a spec has resolved to and is being followed now under following. '
		. 'For a journal watcher the journalctl matches under journal, with journal_running '
		. 'saying whether the journal is being followed. '
		. 'With no args, every galla is asked. With a galla name, just that one.';
}

sub usage_desc { return '%c watching %o [galla]'; }

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	return fanout_validate_args( $self, $args, 'watching' );
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	return fanout_execute( $self, $args, 'watching', undef, undef );
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
