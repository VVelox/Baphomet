package App::Baphomet::App::Command::digest;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use App::Baphomet::App -command;
use JSON::MaybeXS ();

=head1 NAME

App::Baphomet::App::Command::digest - Show the hash a digest gate makes of a value.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet digest neti

=head1 DESCRIPTION

Asks the Baphomet manager, over its socket, for the hash a value comes to
under the config's C<digest_key> via the C<digest> command. A rule with a
digest gate keeps the hash of a name in place of the name, so this is how
an operator finds that name in what C<baphomet marked> or C<baphomet
tracked> shows.

The manager must be running, and the config must set a C<digest_key>.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, description, usage_desc,
opt_spec, validate_args, and execute.

=cut

# the subs below with out a comment block are App::Cmd::Command hooks the
# framework calls... abstract and description for the help, usage_desc and
# opt_spec for the usage line and option parsing, validate_args to vet the
# args ahead of execute, and execute for the work itself. their contract is
# App::Cmd's, so they are not documented one by one here

sub abstract { return 'show the hash a digest gate makes of a value' }

sub description {
	return
		  'Asks the Baphomet manager for the hash a value comes to under the '
		. 'digest_key of the config, as a rule\'s digest gate makes it, so a name '
		. 'can be found in the brands and tracked records the gallas hold.';
}

sub usage_desc { return '%c digest %o <value>'; }

sub opt_spec {
	return ();
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} != 1 ) {
		$self->usage_error('digest takes one arg, the value to hash');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $result = $self->app->manager_call( 'digest', { 'value' => $args->[0] } );
	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	return;
}

1;
