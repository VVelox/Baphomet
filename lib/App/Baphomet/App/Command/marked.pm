package App::Baphomet::App::Command::marked;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
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

=head1 DESCRIPTION

Asks the Baphomet manager, over its socket, for the live marks via the
C<marked> command. Marks are the named, expiring brands rules leave on a
key, a IP or a harvested capture such as a username, so a later rule can
gate on them. Per mark name it shows a hash of the branded keys with
their expiries and any stored value.

With no args every galla is asked, with a galla name just that one, and
C<--name> pares each galla down to that one mark, dropping gallas not
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

sub abstract { return 'show the marks the gallas are holding' }

sub description {
	return
		  'Marks are the named, expiring brands rules leave on a key, an IP or a '
		. 'harvested capture like a username, so a later rule can gate on them. '
		. 'This shows the live marks, per mark name a hash of the branded keys with '
		. 'their expiries and any stored value. A compound key, a vars mark, is its '
		. 'captures joined on the unit separator, shown in the JSON as \\u001f. '
		. 'With no args, every galla is asked. '
		. 'With a galla name, just that one. With --name, only that mark is shown.';
} ## end sub description

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

1;
