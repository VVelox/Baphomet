package App::Baphomet::App::Command::banished;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use JSON::MaybeXS ();

=head1 NAME

App::Baphomet::App::Command::banished - Show who Kur holds, seen from the watcher's seat.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet banished
    baphomet banished sshd
    baphomet banished --ip 1.2.3.4

=head1 DESCRIPTION

Asks the Baphomet manager, over its socket, for who Kur holds via the
C<banished> command. The manager is the one that talks to Ereshkigal, the
source of truth for who Kur holds... it pares the banned lists to the kurs
this Baphomet feeds and merges in each galla's pending bans, banishments
spoken but not yet heard, marked C<pending>, so this command reaches only
the one manager socket rather than around it to Ereshkigal.

A kur this Baphomet targets that is a fan_out kur on the Ereshkigal side
has no ban list of it's own... the banishments land on it's members, so
such a kur is shown with it's member list and each member's holdings.

The recidive kur, when configured, is included alongside the watched kurs.

The manager must be running... with it down there is nothing to ask, and
the command errors rather than falling back to Ereshkigal.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'show who Kur holds for the kurs this Baphomet feeds' }

sub description {
	return
		  'Asks the Baphomet manager for the banned lists of the kurs this '
		. 'Baphomet feeds, expanding fan_out kurs to their members, and merging '
		. 'in each galla\'s pending bans. With a kur name, just that one. With '
		. '--ip, only the kurs holding that IP are shown.';
}

sub usage_desc { return '%c banished %o [kur]'; }

sub opt_spec {
	return ( [ 'ip=s', 'only show the kurs holding this IP' ], );
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} > 1 ) {
		$self->usage_error('banished takes at most one arg, a kur name');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	# the manager does the whole gathering now... the Ereshkigal ask, the
	# fan_out expansion, and the pending merge. this side just asks it, over
	# the one socket, and shapes the answer for the eye
	my $call_args = {};
	if ( @{$args} ) {
		$call_args->{name} = $args->[0];
	}

	my $result = $self->app->manager_call( 'banished', $call_args );

	if ( defined( $opt->ip ) ) {
		$result = _pare_to_ip( $result, $opt->ip );
	}

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	return;
} ## end sub execute

# pares the result down to the one IP... each kur reduced to whether it
# holds it, banned or pending, and kurs not holding it dropped entirely
sub _pare_to_ip {
	my ( $result, $ip ) = @_;

	my $pared = { 'ip' => $ip, 'kurs' => {} };
	if ( defined( $result->{pending_error} ) ) {
		$pared->{pending_error} = $result->{pending_error};
	}

	foreach my $kur ( keys( %{ $result->{kurs} } ) ) {
		my $entry = $result->{kurs}{$kur};
		my $found = {};

		if ( ref( $entry->{banned} ) eq 'ARRAY' && grep { $_ eq $ip } @{ $entry->{banned} } ) {
			$found->{banned} = 1;
			if ( ref( $entry->{expires} ) eq 'HASH' && defined( $entry->{expires}{$ip} ) ) {
				$found->{expires} = $entry->{expires}{$ip};
			}
		}

		if ( ref( $entry->{members} ) eq 'HASH' ) {
			foreach my $member ( keys( %{ $entry->{members} } ) ) {
				my $held = $entry->{members}{$member};
				if ( ref( $held->{banned} ) eq 'ARRAY' && grep { $_ eq $ip } @{ $held->{banned} } ) {
					$found->{members}{$member}{banned} = 1;
					if ( ref( $held->{expires} ) eq 'HASH' && defined( $held->{expires}{$ip} ) ) {
						$found->{members}{$member}{expires} = $held->{expires}{$ip};
					}
				}
			}
		} ## end if ( ref( $entry->{members} ) eq 'HASH' )

		if ( ref( $entry->{pending} ) eq 'ARRAY' && grep { $_ eq $ip } @{ $entry->{pending} } ) {
			$found->{pending} = 1;
		}

		if ( keys( %{$found} ) ) {
			$pared->{kurs}{$kur} = $found;
		}
	} ## end foreach my $kur ( keys( %{ $result->{kurs} } ) )

	return $pared;
} ## end sub _pare_to_ip

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
