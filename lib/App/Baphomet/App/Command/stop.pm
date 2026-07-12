package App::Baphomet::App::Command::stop;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use Ereshkigal::Client ();
use JSON::MaybeXS      ();

=head1 NAME

App::Baphomet::App::Command::stop - Stop all the gallas and the manager.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet stop

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, validate_args, and execute.

=cut

sub abstract { return 'stop all the gallas and the manager' }

sub description { return 'Stop all the gallas and then the manager.'; }

sub usage_desc { return '%c stop'; }

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} ) {
		$self->usage_error('stop does not take any args');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $client = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );
	my $result = $client->call_ok('stop');

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
