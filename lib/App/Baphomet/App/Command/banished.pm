package App::Baphomet::App::Command::banished;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use App::Baphomet::Config qw( load_config );
use Ereshkigal::Client    ();
use JSON::MaybeXS         ();

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

Asks the Ereshkigal manager, the source of truth for who Kur holds, for
its banned lists via the C<banned> command, pares them down to the kurs
this Baphomet feeds, and merges in each galla's pending bans...
banishments spoken but not yet heard, marked C<pending>.

A kur this Baphomet targets that is a fan_out kur on the Ereshkigal side
has no ban list of it's own... the banishments land on it's members, so
such a kur is shown with it's member list and each member's holdings.

The recidive kur, when configured, is included alongside the watched kurs.

If the Baphomet manager is not running, the Ereshkigal side is still
shown, with C<pending_error> noting the pending bans could not be had.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'show who Kur holds for the kurs this Baphomet feeds' }

sub description {
	return
		  'Asks Ereshkigal for the banned lists of the kurs this Baphomet feeds, '
		. 'expanding fan_out kurs to their members, and merges in each galla\'s '
		. 'pending bans. With a kur name, just that one. With --ip, only the kurs '
		. 'holding that IP are shown.';
}

sub usage_desc { return '%c banished %o [kur]'; }

sub opt_spec {
	return (
		[ 'config=s', 'path of the config file', { default => '/usr/local/etc/baphomet/config.toml' } ],
		[ 'ip=s',     'only show the kurs holding this IP' ],
	);
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

	my $config = load_config( $opt->config );

	# the kurs this Baphomet feeds... the watched ones plus the recidive
	# kur, which banishments are escalated to
	my @kurs = sort( keys( %{ $config->{kur} } ) );
	if ( defined( $config->{recidive} ) && !grep { $_ eq $config->{recidive}{kur} } @kurs ) {
		push( @kurs, $config->{recidive}{kur} );
	}
	if ( @{$args} ) {
		if ( !grep { $_ eq $args->[0] } @kurs ) {
			$self->usage_error( 'the kur "' . $args->[0] . '" is not one this Baphomet feeds' );
		}
		@kurs = ( $args->[0] );
	}

	my $ereshkigal = Ereshkigal::Client->new(
		'socket'  => $config->{ereshkigal_socket},
		'timeout' => $config->{timeout},
	);
	my $banned = $ereshkigal->call_ok('banned');
	my $held   = ref( $banned->{kurs} ) eq 'HASH' ? $banned->{kurs} : {};

	my $result = { 'kurs' => {} };

	foreach my $kur (@kurs) {
		if ( defined( $held->{$kur} ) ) {
			$result->{kurs}{$kur} = {
				'banned'  => $held->{$kur}{banned},
				'expires' => $held->{$kur}{expires},
			};
			next;
		}

		# not among the real kurs... a fan_out kur has no list of it's own,
		# the banishments land on it's members
		my $kur_status;
		eval { $kur_status = $ereshkigal->call_ok( 'status_kur', { 'name' => $kur } ); };
		if ($@) {
			$result->{kurs}{$kur} = { 'error' => $@ };
			next;
		}
		if ( ref( $kur_status->{fan_out} ) eq 'ARRAY' ) {
			my $members = {};
			foreach my $member ( @{ $kur_status->{fan_out} } ) {
				$members->{$member}
					= defined( $held->{$member} )
					? { 'banned' => $held->{$member}{banned}, 'expires' => $held->{$member}{expires} }
					: { 'error'  => 'not among the banned lists' };
			}
			$result->{kurs}{$kur} = {
				'fan_out' => $kur_status->{fan_out},
				'members' => $members,
			};
		} else {
			$result->{kurs}{$kur} = { 'error' => 'no banned list... not running?' };
		}
	} ## end foreach my $kur (@kurs)

	# pending bans from the gallas... banishments spoken but not yet heard
	my $status_all;
	eval {
		my $manager = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );
		$status_all = $manager->call_ok('status_all');
	};
	if ($@) {
		$result->{pending_error} = $@;
	} else {
		foreach my $kur (@kurs) {
			my $galla = $status_all->{gallas}{$kur};
			if (   defined($galla)
				&& ref( $galla->{status} ) eq 'HASH'
				&& ref( $galla->{status}{pending_bans} ) eq 'ARRAY' )
			{
				$result->{kurs}{$kur}{pending} = $galla->{status}{pending_bans};
			}
		}
	} ## end else [ if ($@) ]

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
