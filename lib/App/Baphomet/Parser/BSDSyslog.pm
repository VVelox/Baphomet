package App::Baphomet::Parser::BSDSyslog;

use 5.006;
use strict;
use warnings;
# only used at runtime, so the circular use with the dispatcher is harmless
use App::Baphomet::Parser ();

=pod

=head1 NAME

App::Baphomet::Parser::BSDSyslog - RFC 3164 syslog line parser for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser::BSDSyslog ();

    my $parsed = App::Baphomet::Parser::BSDSyslog::parse($line);

=head1 DESCRIPTION

Parses RFC 3164 style syslog lines, such as what is commonly found in
C</var/log/auth.log> and friends.

    Jul 12 08:15:50 vixen42 sshd-session[66891]: Invalid user moth3r from 216.137.179.214 port 34640

Handled variations...

    - A leading <PRI>, as seen when reading raw forwarded syslog, which is
      where facility and severity come from when present.

    - The FreeBSD syslogd verbose <facility.level> form following the
      timestamp, which is where facility and level come from when present.

    - A missing hostname, as some syslogds write local files with out one.

    - A RFC 3339 timestamp in place of the month-name form, as rsyslog's
      default file format chisels.

    - A relayed hostname that is a bare IPv6 address.

    - A missing [pid].

facility and severity will not always be available as most log files carry
neither a <PRI> nor the verbose form.

=cut

my $month_re = qr/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/;
# the classic month-name form, or the RFC 3339 form rsyslog's default file
# format chisels
my $timestamp_re
	= qr/(?:$month_re\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)/;
# a relayed hostname may be a bare IPv6 address, all hex and colons, which
# the plain colon-free token would otherwise mangle into the daemon slot
my $hostname_re = qr/(?:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+|[0-9A-Fa-f:.]+:|[^\s:\[\]]+)/;

=head1 FUNCTIONS

=head2 parse

Parses a single line. Returns the parsed hash, as described in
L<App::Baphomet::Parser>, or undef if the line could not be parsed.

    my $parsed = App::Baphomet::Parser::BSDSyslog::parse($line);

=cut

sub parse {
	my ($line) = @_;

	if ( !defined($line) ) {
		return undef;
	}
	chomp($line);

	if (
		$line =~ /^
		\s*
		(?:<(\d{1,3})>)?                     # optional PRI
		\s*
		($timestamp_re)                      # timestamp
		(?:\s+<([a-z0-9]+)\.([a-z]+)>)?      # optional FreeBSD verbose facility.level
		(?:\s+($hostname_re))?               # optional hostname
		\s+
		([^\s:\[\]]+)                        # daemon
		(?:\[(\d+)\])?                       # optional pid
		:\s?
		(.*)                                 # message
		$/x
		)
	{
		my ( $pri, $time, $verbose_facility, $verbose_level, $hostname, $daemon, $pid, $message )
			= ( $1, $2, $3, $4, $5, $6, $7, $8 );

		my $facility;
		my $severity;
		my $level;
		if ( defined($pri) ) {
			( $facility, $severity, $level ) = App::Baphomet::Parser::pri_decompose($pri);
			# a PRI past 191 is not syslog, so the line is not either
			if ( !defined($facility) ) {
				return undef;
			}
		}
		if ( defined($verbose_facility) ) {
			$facility = $verbose_facility;
			$level    = $verbose_level;
			my $verbose_severity = App::Baphomet::Parser::severity_number($verbose_level);
			if ( defined($verbose_severity) ) {
				$severity = $verbose_severity;
			}
		}

		return {
			'format'   => 'bsd_syslog',
			'time'     => $time,
			'hostname' => $hostname,
			'daemon'   => $daemon,
			'pid'      => $pid,
			'facility' => $facility,
			'severity' => $severity,
			'level'    => $level,
			'message'  => $message,
		};
	} ## end if ( $line =~ /^ )

	return undef;
} ## end sub parse

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
