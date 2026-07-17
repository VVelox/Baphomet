package App::Baphomet::App::Command::accused;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use Ereshkigal::Client ();
use JSON::MaybeXS      ();

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

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'show the IPs being counted but not yet banished' }

sub description {
	return
		  'The accused are IPs accumulating offenses but not yet banished to Kur... '
		. 'per IP the live hit count and the epochs of the first and last hit, '
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

	if ( @{$args} > 1 ) {
		$self->usage_error('accused takes at most one arg, a galla name');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $client = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );

	my $result;
	if ( @{$args} ) {
		$result = $client->call_ok( 'accused', { 'name' => $args->[0] } );
	} else {
		$result = $client->call_ok('accused');
	}

	# --ip pares each galla down to the one defendant, dropping gallas not
	# counting it at all
	if ( defined( $opt->ip ) && ref( $result->{gallas} ) eq 'HASH' ) {
		foreach my $galla ( keys( %{ $result->{gallas} } ) ) {
			my $accused = $result->{gallas}{$galla}{accused};
			if ( ref($accused) ne 'HASH' || !defined( $accused->{ $opt->ip } ) ) {
				delete( $result->{gallas}{$galla} );
				next;
			}
			$result->{gallas}{$galla}{accused} = { $opt->ip => $accused->{ $opt->ip } };
		}
	} ## end if ( defined( $opt->ip ) && ref( $result->...))

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
