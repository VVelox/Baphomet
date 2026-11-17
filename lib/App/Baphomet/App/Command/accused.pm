package App::Baphomet::App::Command::accused;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use App::Baphomet::App -command;
use App::Baphomet::App::FanoutCmd qw( fanout_validate_args fanout_execute );

=head1 NAME

App::Baphomet::App::Command::accused - Show the IPs being counted but not yet banished.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet accused
    baphomet accused sshd
    baphomet accused --ip 1.2.3.4

=head1 DESCRIPTION

Asks the Baphomet manager, over its socket, for the accused via the
C<accused> command... the IPs piling up offenses but not yet banished to
Kur. Per IP it shows the live hit count, the weighted score that races
C<max_score>, and the epochs of the first and last hit, with a C<rules>
breakdown when a rule with its own thresholds is counting it.

With no args every galla is asked, with a galla name just that one, and
C<--ip> pares each galla down to that one IP, dropping gallas not
counting it. The manager must be running.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, description, usage_desc,
opt_spec, validate_args, and execute.

=cut

# the subs below with out a comment block are App::Cmd::Command hooks the
# framework calls... abstract and description for the help, usage_desc and
# opt_spec for the usage line and option parsing, validate_args to vet the
# args ahead of execute, and execute for the work itself. their contract is
# App::Cmd's, so they are not documented one by one here

sub abstract { return 'show the IPs being counted but not yet banished' }

sub description {
	return
		  'The accused are IPs accumulating offenses but not yet banished to Kur... '
		. 'per IP the live hit count, the weighted score racing max_score, and the '
		. 'epochs of the first and last hit, '
		. 'with a rules breakdown when a rule carrying its own thresholds is counting it. '
		. 'With no args, every galla is asked. With a galla name, just that one. '
		. 'With --ip, only that IP is shown, in whichever gallas are counting it.';
}

sub usage_desc { return '%c accused %o [galla]'; }

sub opt_spec {
	return ( [ 'ip=s', 'only show this IP' ], );
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	return fanout_validate_args( $self, $args, 'accused' );
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	# --ip pares each galla down to the one defendant, dropping gallas not
	# counting it at all
	return fanout_execute( $self, $args, 'accused', $opt->ip, 'accused' );
}

1;
