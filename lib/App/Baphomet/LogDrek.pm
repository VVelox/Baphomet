package App::Baphomet::LogDrek;

use 5.006;
use strict;
use warnings;
use Exporter    qw( import );
use Sys::Syslog qw( closelog openlog syslog );

=pod

=head1 NAME

App::Baphomet::LogDrek - Exportable syslog helper shared by the Baphomet bins and modules.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

our @EXPORT_OK = qw( log_drek );

=head1 SYNOPSIS

    use App::Baphomet::LogDrek qw( log_drek );

    log_drek( 'info', 'started' );
    log_drek( 'err',  'something broke' );
    log_drek( 'info', 'banished 1.2.3.4 to Kur', undef, 'galla-sshd' );

=head1 DESCRIPTION

The C<log_drek> sub both C<baphomet> and C<galla> and the various
App::Baphomet modules log through... a plain function, no new needed,
exported on request, so everything shares one implementation instead of each
carrying their own copy.

=head1 EXPORTS

Nothing is exported by default. L</log_drek> is available via C<@EXPORT_OK>.

=head1 FUNCTIONS

=head2 log_drek

Writes a message to syslog.

    log_drek( $level, $message, $tracking_int, $ident );

C<$level> defaults to 'info' when undef. When C<$tracking_int> is defined it is
prepended to the message as C<< $tracking_int . ' : ' . $message >>. C<$ident>
is the syslog ident to log under and defaults to 'baphomet' when undef. Galla
instances should pass C<'galla-' . $name> so log lines are attributable per
instance.

=cut

sub log_drek {
	my ( $level, $message, $tracking_int, $ident ) = @_;

	if ( !defined($level) ) {
		$level = 'info';
	}

	if ( !defined($message) ) {
		$message = '';
	}

	chomp($message);

	if ( defined($tracking_int) ) {
		$message = $tracking_int . ' : ' . $message;
	}

	if ( !defined($ident) ) {
		$ident = 'baphomet';
	}

	openlog( $ident, 'cons,pid', 'daemon' );
	syslog( $level, '%s', $message );
	closelog();

	return;
} ## end sub log_drek

1;
