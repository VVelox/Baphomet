package App::Baphomet::App::Command::banished;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util  qw( is_plain_arrayref is_plain_hashref );
use List::Util qw( any );
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
source of truth... it pares the banned lists to the kurs this Baphomet
feeds and merges in each galla's pending bans, banishments spoken but not
yet heard, marked C<pending>, so this command reaches only the one manager
socket rather than around it.

A kur this Baphomet targets that is a fan_out kur on the Ereshkigal side
has no ban list of its own... the banishments land on its members, so
such a kur is shown with its member list and each member's holdings.

The recidive kur, when configured, is included alongside the watched kurs.

The manager must be running... with it down there is nothing to ask, and
the command errors rather than falling back to Ereshkigal.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, description, usage_desc,
opt_spec, validate_args, and execute.

=cut

# the subs below with out a comment block are App::Cmd::Command hooks the
# framework calls... abstract and description for the help, usage_desc and
# opt_spec for the usage line and option parsing, validate_args to vet the
# args ahead of execute, and execute for the work itself. their contract is
# App::Cmd's, so they are not documented one by one here

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

# pares the manager's banished answer down to the one IP for --ip... each
# kur reduced to whether it holds it, banned outright, on a fan_out kur's
# members, or pending, and kurs not holding it at all dropped entirely
#
# args:
#   $result :: hashref, the manager's banished answer... kurs is a hash of
#       kur name to entry, each entry with banned (arrayref of IPs) and
#       expires (hashref of IP to epoch), or members (hashref of member kur
#       name to a hashref of the same banned/expires shape), plus pending
#       (arrayref of IPs not yet heard by Kur). pending_error is passed
#       through when present
#   $ip :: the IP string to pare to, compared as a exact string
#
# returns:
#   hashref... ip, the IP; kurs, a hash of kur name to a hashref of what was
#   found, banned => 1 and expires when held directly, members => { member
#   => { banned => 1, expires } } when held by members, pending => 1 when
#   pending; and pending_error when the answer had one. a kur holding none
#   of these is left out, so kurs may be empty
#
# example:
#   my $pared = _pare_to_ip( $result, '192.0.2.7' );
#   # { 'ip' => '192.0.2.7',
#   #   'kurs' => { 'sshd' => { 'banned' => 1, 'expires' => 1763300000 } } }
sub _pare_to_ip {
	my ( $result, $ip ) = @_;

	my $pared = { 'ip' => $ip, 'kurs' => {} };
	if ( defined( $result->{pending_error} ) ) {
		$pared->{pending_error} = $result->{pending_error};
	}

	foreach my ( $kur, $entry ) ( %{ $result->{kurs} } ) {
		my $found = {};

		if ( is_plain_arrayref( $entry->{banned} ) && any { $_ eq $ip } @{ $entry->{banned} } ) {
			$found->{banned} = 1;
			if ( is_plain_hashref( $entry->{expires} ) && defined( $entry->{expires}{$ip} ) ) {
				$found->{expires} = $entry->{expires}{$ip};
			}
		}

		if ( is_plain_hashref( $entry->{members} ) ) {
			foreach my ( $member, $held ) ( %{ $entry->{members} } ) {
				if ( is_plain_arrayref( $held->{banned} ) && any { $_ eq $ip } @{ $held->{banned} } ) {
					$found->{members}{$member}{banned} = 1;
					if ( is_plain_hashref( $held->{expires} ) && defined( $held->{expires}{$ip} ) ) {
						$found->{members}{$member}{expires} = $held->{expires}{$ip};
					}
				}
			}
		} ## end if ( is_plain_hashref( $entry->{members} ))

		if ( is_plain_arrayref( $entry->{pending} ) && any { $_ eq $ip } @{ $entry->{pending} } ) {
			$found->{pending} = 1;
		}

		if ( keys( %{$found} ) ) {
			$pared->{kurs}{$kur} = $found;
		}
	} ## end foreach my ( $kur, $entry ) ( %{ $result->{kurs...}})

	return $pared;
} ## end sub _pare_to_ip

1;
