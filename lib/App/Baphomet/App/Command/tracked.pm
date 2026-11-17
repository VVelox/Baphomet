package App::Baphomet::App::Command::tracked;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
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

=head1 DESCRIPTION

Asks the Baphomet manager, over its socket, for the live tracked records
via the C<tracked> command. A tracked record is where the facts a daemon
spreads over several lines of one transaction accumulate, joined by a
key it repeats such as a postfix queue id. Per track name it shows a
hash of keys with their expiries and the fields gathered so far, a
compound key handed back split into its components.

With no args every galla is asked, with a galla name just that one, and
C<--name> pares each galla down to that one track, dropping gallas not
holding it. The manager must be running.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, description, usage_desc,
opt_spec, validate_args, and execute.

=cut

# the subs below with out a comment block are App::Cmd::Command hooks the
# framework calls... abstract and description for the help, usage_desc and
# opt_spec for the usage line and option parsing, validate_args to vet the
# args ahead of execute, and execute for the work itself. their contract is
# App::Cmd's, so they are not documented one by one here

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

1;
