package App::Baphomet::Parser::IETFSyslog;

use 5.006;
use strict;
use warnings;
# only used at runtime, so the circular use with the dispatcher is harmless
use App::Baphomet::Parser ();

=pod

=head1 NAME

App::Baphomet::Parser::IETFSyslog - RFC 5424 syslog line parser for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser::IETFSyslog ();

    my $parsed = App::Baphomet::Parser::IETFSyslog::parse($line);

=head1 DESCRIPTION

Parses RFC 5424 style syslog lines.

    <38>1 2026-07-12T08:15:50.313437-05:00 vixen42 sshd-session 66891 - - Invalid user moth3r from 216.137.179.214 port 34640

The PRI is required by the RFC, so facility and severity are always
available for lines this parses. Fields given as the nil value, C<->, come
back as undef. STRUCTURED-DATA is skipped over rather than parsed out.

=cut

=head1 FUNCTIONS

=head2 parse

Parses a single line. Returns the parsed hash, as described in
L<App::Baphomet::Parser>, or undef if the line could not be parsed.

    my $parsed = App::Baphomet::Parser::IETFSyslog::parse($line);

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
		<(\d{1,3})>                              # PRI
		\d+                                      # VERSION
		\s+
		(\S+)                                    # TIMESTAMP
		\s+
		(\S+)                                    # HOSTNAME
		\s+
		(\S+)                                    # APP-NAME
		\s+
		(\S+)                                    # PROCID
		\s+
		(?:\S+)                                  # MSGID
		\s+
		(?:-|(?:\[(?:[^\]\\"]|\\.|"(?:[^"\\]|\\.)*")*\])+) # STRUCTURED-DATA
		(?:\s+(.*))?                             # MSG
		$/x
		)
	{
		my ( $pri, $time, $hostname, $daemon, $pid, $message ) = ( $1, $2, $3, $4, $5, $6 );

		my ( $facility, $severity, $level ) = App::Baphomet::Parser::pri_decompose($pri);
		# a PRI past 191 is not syslog, so the line is not either
		if ( !defined($facility) ) {
			return undef;
		}

		return {
			'format'   => 'ietf_syslog',
			'time'     => $time eq '-'     ? undef : $time,
			'hostname' => $hostname eq '-' ? undef : $hostname,
			'daemon'   => $daemon eq '-'   ? undef : $daemon,
			'pid'      => $pid eq '-'      ? undef : $pid,
			'facility' => $facility,
			'severity' => $severity,
			'level'    => $level,
			'message'  => defined($message) ? $message : '',
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
