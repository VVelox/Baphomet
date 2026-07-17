package App::Baphomet::Parser::HTTPAccess;

use 5.006;
use strict;
use warnings;

=pod

=head1 NAME

App::Baphomet::Parser::HTTPAccess - HTTP access log line parser for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser::HTTPAccess ();

    my $parsed = App::Baphomet::Parser::HTTPAccess::parse($line);

=head1 DESCRIPTION

Parses HTTP access log lines in the common log format and the combined
log format, as written by Apache, nginx, and most everything else...

    %h %l %u %t "%r" %>s %b                                    common
    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"     combined

    203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "GET /.env HTTP/1.1" 404 196 "-" "zgrab/0.x"

Backslash escaped quotes inside the quoted fields are handled... Apache
and nginx write C<\"> there, and attackers put quotes in the request and
user agent on purpose.

This is a different shape from the syslog parsers... access logs have no
daemon or severity, so lines from this parser are for C<http> type rules,
not C<syslog> ones. The keys are as below, undef where the line carries
C<-> or nothing.

    - host :: %h, the client. This is what http rules ban. Can be a
          hostname rather than a IP if the server does hostname lookups.

    - ident :: %l.

    - user :: %u.

    - time :: %t, as the raw string from the line.

    - request :: %r, the raw request line.

    - method / path / protocol :: The request split out, when it is well
          formed. protocol is undef for HTTP/0.9 style two token requests,
          and all three are undef when the "request" is junk... the raw
          request stays matchable either way.

    - status :: %>s.

    - bytes :: %b.

    - referer / user_agent :: The two extra quoted fields of the combined
          format. undef in the common format.

    - format :: clf or combined.

=cut

my $quoted_re = qr/[^"\\]*(?:\\.[^"\\]*)*/;

=head1 FUNCTIONS

=head2 parse

Parses a single line. Returns the parsed hash or undef if the line could
not be parsed.

    my $parsed = App::Baphomet::Parser::HTTPAccess::parse($line);

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
		(\S+)                                  # host
		\s+
		(\S+)                                  # ident
		\s+
		(\S+)                                  # user
		\s+
		\[([^\]]+)\]                           # time
		\s+
		"($quoted_re)"                         # request
		\s+
		(\d{3})                                # status
		\s+
		(\d+|-)                                # bytes
		(?:
			\s+
			"($quoted_re)"                     # referer
			\s+
			"($quoted_re)"                     # user agent
		)?
		\s*$/x
		)
	{
		my ( $host, $ident, $user, $time, $request, $status, $bytes, $referer, $user_agent )
			= ( $1, $2, $3, $4, $5, $6, $7, $8, $9 );

		my $format = defined($user_agent) ? 'combined' : 'clf';

		my $method;
		my $path;
		my $protocol;
		if ( $request =~ /^(\S+)\s+(\S+)\s+(\S+)$/ ) {
			( $method, $path, $protocol ) = ( $1, $2, $3 );
		} elsif ( $request =~ /^(\S+)\s+(\S+)$/ ) {
			# HTTP/0.9 style, no protocol
			( $method, $path ) = ( $1, $2 );
		}

		return {
			'format'     => $format,
			'host'       => $host,
			'ident'      => $ident eq '-' ? undef : $ident,
			'user'       => $user eq '-'  ? undef : $user,
			'time'       => $time,
			'request'    => $request,
			'method'     => $method,
			'path'       => $path,
			'protocol'   => $protocol,
			'status'     => $status,
			'bytes'      => $bytes eq '-' ? undef : $bytes,
			'referer'    => ( defined($referer)    && $referer ne '-' )    ? $referer    : undef,
			'user_agent' => ( defined($user_agent) && $user_agent ne '-' ) ? $user_agent : undef,
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
