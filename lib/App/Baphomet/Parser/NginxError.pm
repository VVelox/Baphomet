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
to the tail... client, server, login, request, subrequest, upstream, host,
and referrer, in that order... are parsed into fields of their own, leaving
C<message> as just the leading free text. So a http_error rule matches
C<^user "\S+" was not found in> rather than re-parsing C<client:> out of
a regexp.

nginx writes the request line, the Host header and the referrer unescaped,
and the message ahead of the tail can hold the URI or the account name, so a
client can plant a whole C<, client: E<lt>addrE<gt>, server: ...> before the
real tail or after it. With text of the client's on both sides there is no
telling which tail is nginx's, so a line holding a second one yields no
client at all rather than the wrong one. The tail starts at the first
C<, client: >, the values a client sets may hold no whitespace (every
C<, key: > of a tail has a space in it), and the tail has to run in nginx's
order to the end of the line. A line it does not fit keeps the whole rest of
the line as C<message> and leaves every pair undef. A client can make its own
lines name no address that way, never someone else's.

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

    - server / login / request / subrequest / upstream / host / referrer ::
          The other pairs, quotes stripped. login is the mail module's.

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
			'login'       => undef,
			'request'     => undef,
			'subrequest'  => undef,
			'upstream'    => undef,
			'host'        => undef,
			'referrer'    => undef,
		};

		# The tail starts at the first ", client: " and has to run in
		# nginx's order to the end of the line, with no whitespace in the
		# values a client sets... see the DESCRIPTION for why. A line it
		# does not fit keeps all of the rest as its message and names no
		# client, which is what a forged tail on either side of the real
		# one comes to.
		my $message = $rest;
		my $start   = index( $rest, ', client: ' );
		if ( $start >= 0 ) {
			my $tail = substr( $rest, $start );
			if (
				$tail =~ /^
				,\ client:\ (?<client>[^\s,]+)
				(?:,\ server:\ (?<server>[^\s,]*))?
				(?:,\ login:\ "(?<login>\S*)")?
				(?:,\ request:\ "(?<request>\S+\ \S+(?:\ HTTP\/[\d.]+)?)")?
				(?:,\ subrequest:\ "(?<subrequest>\S*)")?
				(?:,\ upstream:\ "(?<upstream>\S*)")?
				(?:,\ host:\ "(?<host>\S*)")?
				(?:,\ referrer:\ "(?<referrer>\S*)")?
				\s*$/x
				)
			{
				foreach my $key ( keys(%+) ) {
					$parsed->{$key} = $+{$key};
				}
				$message = substr( $rest, 0, $start );
			}
		}

		$parsed->{message} = $message;

		return $parsed;
	} ## end if ( $line =~ /^ )

	return undef;
} ## end sub parse

1;
