package App::Baphomet::App::Command::status;

use 5.006;
use strict;
use warnings;
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

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

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
