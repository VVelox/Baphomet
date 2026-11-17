package App::Baphomet::App::Command::status;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use App::Baphomet::App -command;
use JSON::MaybeXS ();

=head1 NAME

App::Baphomet::App::Command::status - Show status of the manager and gallas.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet status
    baphomet status --all
    baphomet status sshd

=head1 DESCRIPTION

Asks the Baphomet manager, over its socket, for its status. With no args
it is the manager's own status and the up or down state of each galla,
via the C<status> command. C<--all> adds each galla's full status block,
via C<status_all>, and a galla name shows the full status of just that
one, via C<status_galla>. The manager must be running.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, description, usage_desc,
opt_spec, validate_args, and execute.

=cut

# the subs below with out a comment block are App::Cmd::Command hooks the
# framework calls... abstract and description for the help, usage_desc and
# opt_spec for the usage line and option parsing, validate_args to vet the
# args ahead of execute, and execute for the work itself. their contract is
# App::Cmd's, so they are not documented one by one here

sub abstract { return 'show status of the manager and gallas' }

sub description {
	return
		  'With no args, shows manager status and the up/down state of each galla. '
		. 'With --all, includes each galla\'s full status block. '
		. 'With a galla name, shows the full status of that one galla.';
}

sub usage_desc { return '%c status %o [galla]'; }

sub opt_spec {
	return ( [ 'all', 'include the full status of every galla' ], );
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} > 1 ) {
		$self->usage_error('status takes at most one arg, a galla name');
	}
	if ( @{$args} && $opt->all ) {
		$self->usage_error('--all and a galla name may not be used together');
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $result;
	if ( @{$args} ) {
		$result = $self->app->manager_call( 'status_galla', { 'name' => $args->[0] } );
	} elsif ( $opt->all ) {
		$result = $self->app->manager_call('status_all');
	} else {
		$result = $self->app->manager_call('status');
	}

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	return;
} ## end sub execute

1;
