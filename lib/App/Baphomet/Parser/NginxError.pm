package App::Baphomet::Parser::NginxError;

use 5.006;
use strict;
use warnings;

=pod

=head1 NAME

App::Baphomet::Parser::NginxError - nginx error log line parser for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser::NginxError ();

    my $parsed = App::Baphomet::Parser::NginxError::parse($line);

=head1 DESCRIPTION

Parses nginx error log lines...

    2026/07/12 08:15:50 [error] 12345#0: *67 user "admin" was not found in "/etc/nginx/.htpasswd", client: 1.2.3.4, server: example.com, request: "GET / HTTP/1.1", host: "example.com"

The head is rigid, and the structured C<, key: value> pairs nginx appends
to the tail... client, server, request, upstream, host, and referrer...
are peeled off into fields of their own, leaving C<message> as just the
leading free text. So a http_error rule matches
C<^user "\S+" was not found in> rather than re-parsing C<client:> out of
a regexp.

Lines from this parser are for C<http_error> type rules. The keys are as
below, undef where the line does not carry the field.

    - time :: The timestamp, as the raw string.

    - level :: error, warn, crit, and the like.

    - pid / tid :: From the pid#tid.

    - cid :: The *N connection id.

    - client :: The client address of the client pair. This is what
          http_error rules ban.

    - client_port :: Always undef... nginx does not log one here. Present
          so the shape matches L<App::Baphomet::Parser::ApacheError>.

    - server / request / upstream / host / referrer :: The other peeled
          pairs, quotes stripped.

    - message :: The leading free text, which is what the message_regexp
          entries of http_error rules are matched against.

    - format :: nginx_error.

=cut

=head1 FUNCTIONS

=head2 parse

Parses a single line. Returns the parsed hash or undef if the line could
not be parsed.

    my $parsed = App::Baphomet::Parser::NginxError::parse($line);

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
		(\d{4}\/\d{2}\/\d{2}\ \d{2}:\d{2}:\d{2})  # time
		\s+
		\[(\w+)\]                                 # level
		\s+
		(\d+)\#(\d+):                             # pid#tid
		\s+
		(?:\*(\d+)\s+)?                           # optional connection id
		(.*)                                      # message plus the pairs
		$/x
		)
	{
		my ( $time, $level, $pid, $tid, $cid, $rest ) = ( $1, $2, $3, $4, $5, $6 );

		my $parsed = {
			'format'      => 'nginx_error',
			'time'        => $time,
			'level'       => $level,
			'pid'         => $pid,
			'tid'         => $tid,
			'cid'         => $cid,
			'client'      => undef,
			'client_port' => undef,
			'server'      => undef,
			'request'     => undef,
			'upstream'    => undef,
			'host'        => undef,
			'referrer'    => undef,
		};

		# peel the structured pairs off the tail... quoted values may
		# carry escaped quotes and commas... rightmost wins for a repeated
		# key, as the true pairs are what nginx itself appended last and
		# anything further left may be injected via a header or username
		while ( $rest =~ s/,\s+(client|server|request|upstream|host|referrer):\s+("(?:[^"\\]|\\.)*"|[^,]*)\s*$// ) {
			my ( $key, $value ) = ( $1, $2 );
			$value =~ s/^"(.*)"$/$1/;
			if ( !defined( $parsed->{$key} ) ) {
				$parsed->{$key} = $value;
			}
		}

		$parsed->{message} = $rest;

		return $parsed;
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
