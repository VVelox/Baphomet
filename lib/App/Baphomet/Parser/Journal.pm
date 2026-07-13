package App::Baphomet::Parser::Journal;

use 5.006;
use strict;
use warnings;
use JSON::MaybeXS qw( decode_json );
# only used at runtime, so the circular use with the dispatcher is harmless
use App::Baphomet::Parser ();

=pod

=head1 NAME

App::Baphomet::Parser::Journal - systemd journal JSON line parser for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser::Journal ();

    my $parsed = App::Baphomet::Parser::Journal::parse($line);

=head1 DESCRIPTION

Parses the JSON export of the systemd journal, one object per line, as
C<journalctl -o json> writes it. A journal watcher of a galla runs
journalctl and feeds its output here.

The journal's field names map onto the syslog shape, so this is a peer in
the syslog family and C<syslog/*> rules work over the journal unchanged.

    - daemon :: SYSLOG_IDENTIFIER, or _COMM as a fallback

    - message :: MESSAGE. Required.

    - pid :: _PID, or SYSLOG_PID

    - hostname :: _HOSTNAME

    - time :: __REALTIME_TIMESTAMP, the raw microseconds string

    - severity / level :: PRIORITY

    - facility :: SYSLOG_FACILITY

    - format :: journal

The journal renders MESSAGE as an array of byte values when it is not
valid UTF-8... such a message is turned back into a string so rules still
have something to match. Fields outside the set above are ignored.

=cut

=head1 FUNCTIONS

=head2 parse

Parses a single line. Returns the parsed hash, as described in
L<App::Baphomet::Parser>, or undef if the line could not be parsed or
carries no MESSAGE.

    my $parsed = App::Baphomet::Parser::Journal::parse($line);

=cut

sub parse {
	my ($line) = @_;

	if ( !defined($line) || $line !~ /^\s*\{/ ) {
		return undef;
	}

	my $decoded;
	eval { $decoded = decode_json($line); };
	if ( $@ || ref($decoded) ne 'HASH' ) {
		return undef;
	}

	my $message = _journal_scalar( $decoded->{MESSAGE} );
	if ( !defined($message) || $message eq '' ) {
		return undef;
	}

	my $daemon = _journal_scalar( $decoded->{SYSLOG_IDENTIFIER} );
	if ( !defined($daemon) ) {
		$daemon = _journal_scalar( $decoded->{_COMM} );
	}

	my $pid = _journal_scalar( $decoded->{_PID} );
	if ( !defined($pid) ) {
		$pid = _journal_scalar( $decoded->{SYSLOG_PID} );
	}

	my $priority = _journal_scalar( $decoded->{PRIORITY} );
	my $severity;
	my $level;
	if ( defined($priority) && $priority =~ /^[0-7]$/ ) {
		$severity = $priority + 0;
		$level    = App::Baphomet::Parser::severity_name($severity);
	}

	return {
		'format'   => 'journal',
		'time'     => _journal_scalar( $decoded->{__REALTIME_TIMESTAMP} ),
		'hostname' => _journal_scalar( $decoded->{_HOSTNAME} ),
		'daemon'   => $daemon,
		'pid'      => $pid,
		'facility' => _journal_scalar( $decoded->{SYSLOG_FACILITY} ),
		'severity' => $severity,
		'level'    => $level,
		'message'  => $message,
	};
} ## end sub parse

# journal field values are usually strings, but a non-UTF-8 value comes as
# a array of byte numbers... turn that back into a string, and treat empty
# strings as absent
sub _journal_scalar {
	my ($value) = @_;

	if ( !defined($value) ) {
		return undef;
	}
	if ( ref($value) eq 'ARRAY' ) {
		my $string = join( '', map { ( defined($_) && $_ =~ /^[0-9]+$/ ) ? chr( $_ & 0xFF ) : '' } @{$value} );
		return $string eq '' ? undef : $string;
	}
	if ( ref($value) ne '' ) {
		return undef;
	}
	if ( $value eq '' ) {
		return undef;
	}

	return $value;
} ## end sub _journal_scalar

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
