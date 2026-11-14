package App::Baphomet::LogDrek;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
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

# the ident syslog is currently open under, undef till the first message
my $opened_ident;

sub log_drek {
	my ( $level, $message, $tracking_int, $ident ) = @_;

	$level //= 'info';

	$message //= '';

	chomp($message);

	if ( defined($tracking_int) ) {
		$message = $tracking_int . ' : ' . $message;
	}

	$ident //= 'baphomet';

	# a process logs under one ident nearly always, so the connection is kept
	# and only reopened when the ident changes, rather than paying a connect
	# and a close per message... Sys::Syslog stamps the PID per message and
	# reconnects by itself when the socket goes bad, so a kept connection
	# survives a fork and a syslogd restart alike
	if ( !defined($opened_ident) || $opened_ident ne $ident ) {
		if ( defined($opened_ident) ) {
			closelog();
		}
		openlog( $ident, 'cons,pid', 'daemon' );
		$opened_ident = $ident;
	}
	syslog( $level, '%s', $message );

	return;
} ## end sub log_drek

1;
