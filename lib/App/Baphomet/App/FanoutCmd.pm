package App::Baphomet::App::FanoutCmd;

use 5.006;
use strict;
use warnings;
use Exporter qw( import );
use Ereshkigal::Client ();
use JSON::MaybeXS      ();

our @EXPORT_OK = qw( fanout_validate_args fanout_execute );

=pod

=head1 NAME

App::Baphomet::App::FanoutCmd - The shared body of the per-galla fan-out commands.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::App::FanoutCmd qw( fanout_validate_args fanout_execute );

    sub validate_args {
        my ( $self, $opt, $args ) = @_;
        return fanout_validate_args( $self, $args, 'accused' );
    }

    sub execute {
        my ( $self, $opt, $args ) = @_;
        return fanout_execute( $self, $args, 'accused', $opt->ip, 'accused' );
    }

=head1 DESCRIPTION

The accused and marked commands are the same shape... ask the manager,
which fans out to one galla or all, then optionally pare each galla's
answer down to one key of interest. This holds that shape once so the
commands carry only their own names and wording.

=head1 FUNCTIONS

=head2 fanout_validate_args

Dies via usage_error when more than the one optional galla-name arg was
passed. C<$command> names the command in the error.

    fanout_validate_args( $self, $args, $command );

=cut

sub fanout_validate_args {
	my ( $self, $args, $command ) = @_;

	if ( @{$args} > 1 ) {
		$self->usage_error( $command . ' takes at most one arg, a galla name' );
	}

	return;
}

=head2 fanout_execute

Calls the manager's C<$command>, passing the galla name when one was
argued. C<$pare_value>, when defined, pares each galla's C<$pare_key>
hash down to that one entry, dropping gallas not carrying it at all. The
result prints as pretty canonical JSON.

    fanout_execute( $self, $args, $command, $pare_value, $pare_key );

=cut

sub fanout_execute {
	my ( $self, $args, $command, $pare_value, $pare_key ) = @_;

	my $client = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );

	my $result;
	if ( @{$args} ) {
		$result = $client->call_ok( $command, { 'name' => $args->[0] } );
	} else {
		$result = $client->call_ok($command);
	}

	if ( defined($pare_value) && ref( $result->{gallas} ) eq 'HASH' ) {
		foreach my $galla ( keys( %{ $result->{gallas} } ) ) {
			my $held = $result->{gallas}{$galla}{$pare_key};
			if ( ref($held) ne 'HASH' || !defined( $held->{$pare_value} ) ) {
				delete( $result->{gallas}{$galla} );
				next;
			}
			$result->{gallas}{$galla}{$pare_key} = { $pare_value => $held->{$pare_value} };
		}
	} ## end if ( defined($pare_value) && ref( $result->...))

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	return;
} ## end sub fanout_execute

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
