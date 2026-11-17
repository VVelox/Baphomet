package App::Baphomet::App::Command::watching;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
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

=head1 DESCRIPTION

Asks the Baphomet manager, over its socket, what each galla is watching
via the C<watching> command. Per galla and per watcher, a file watcher
shows its log specs, literal paths and globs alike, under C<globs> and
the concrete files they resolved to and are being followed under
C<following>. A journal watcher shows its journalctl matches under
C<journal>, with C<journal_running> saying whether it is being followed.

With no args every galla is asked, with a galla name just that one. The
manager must be running.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, description, usage_desc,
validate_args, and execute.

=cut

# the subs below with out a comment block are App::Cmd::Command hooks the
# framework calls... abstract and description for the help, usage_desc for
# the usage line, validate_args to vet the args ahead of execute, and
# execute for the work itself. their contract is App::Cmd's, so they are
# not documented one by one here

sub abstract { return 'show what each galla is watching' }

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

1;
