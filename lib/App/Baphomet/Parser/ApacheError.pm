package App::Baphomet::Parser::ApacheError;

use 5.006;
use strict;
use warnings;
use Regexp::IPv4 qw( $IPv4_re );
use Regexp::IPv6 qw( $IPv6_re );

=pod

=head1 NAME

App::Baphomet::Parser::ApacheError - Apache error log line parser for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser::ApacheError ();

    my $parsed = App::Baphomet::Parser::ApacheError::parse($line);

=head1 DESCRIPTION

Parses Apache error log lines, both the 2.2 and 2.4 shapes...

    [Wed Oct 11 14:32:52 2000] [error] [client 1.2.3.4] client denied by server configuration: /export/htdocs/test
    [Thu Jun 27 11:55:44.569531 2013] [auth_basic:error] [pid 4101:tid 2992] [client 1.2.3.4:23456] AH01617: user foo: authentication failure for "/": Password Mismatch

Lines from this parser are for C<http_error> type rules. The keys are as
below, undef where the line does not carry the field.

    - time :: The bracketed timestamp, as the raw string.

    - module :: The module of the 2.4 [module:level] form... auth_basic,
          core, and the like. undef on 2.2 lines and for the 2.4 prefork
          empty module form, [:error].

    - level :: error, warn, notice, and the like.

    - pid / tid :: From the 2.4 [pid N:tid N].

    - client :: The client address of [client ...]. This is what
          http_error rules ban. Can be a hostname if the server does
          hostname lookups.

    - client_port :: The port 2.4 appends to the client. For a IPv6
          client with a port the split is ambiguous
          (2001:db8::1:23456 is itself valid IPv6), and the split is
          preferred when the left of the last colon is still a valid
          address, matching what 2.4 actually logs.

    - code :: The AHnnnnn error code of 2.4 lines.

    - message :: The rest of the line, which is what the message_regexp
          entries of http_error rules are matched against.

    - format :: apache_error.

=cut

=head1 FUNCTIONS

=head2 parse

Parses a single line. Returns the parsed hash or undef if the line could
not be parsed.

    my $parsed = App::Baphomet::Parser::ApacheError::parse($line);

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
		\[([^\]]+)\]                            # time
		\s+
		\[(?:([\w\-]*):)?([a-z]+\d*)\]          # optional module (may be empty, as [:error]), level
		(?:\s+\[pid\ (\d+)(?::tid\ (\d+))?\])?  # 2.4 pid and tid
		(?:\s+\[client\ ([^\]]+)\])?            # client, split below
		\s*
		(?:(AH\d+):\s*)?                        # 2.4 error code
		(.*)                                    # message
		$/x
		)
	{
		my ( $time, $module, $level, $pid, $tid, $client_raw, $code, $message )
			= ( $1, $2, $3, $4, $5, $6, $7, $8 );

		# the 2.4 prefork empty module form, [:error]
		if ( defined($module) && $module eq '' ) {
			$module = undef;
		}

		my ( $client, $client_port ) = _split_client($client_raw);

		return {
			'format'      => 'apache_error',
			'time'        => $time,
			'module'      => $module,
			'level'       => $level,
			'pid'         => $pid,
			'tid'         => $tid,
			'client'      => $client,
			'client_port' => $client_port,
			'code'        => $code,
			'message'     => $message,
		};
	} ## end if ( $line =~ /^ ... )

	return undef;
} ## end sub parse

# splits the contents of a [client ...] into the address and the port 2.4
# appends... for IPv6 the split is ambiguous, so the split is preferred
# when what is left of the last colon is still a valid address
sub _split_client {
	my ($raw) = @_;

	if ( !defined($raw) ) {
		return ( undef, undef );
	}

	if ( $raw =~ /^($IPv4_re)(?::(\d{1,5}))?$/ ) {
		return ( $1, $2 );
	}

	if ( $raw =~ /^(.+):(\d{1,5})$/ ) {
		my ( $left, $port ) = ( $1, $2 );
		if ( $left =~ /^$IPv6_re$/ ) {
			return ( $left, $port );
		}
	}

	if ( $raw =~ /^$IPv6_re$/ ) {
		return ( $raw, undef );
	}

	# a hostname, from HostnameLookups
	if ( $raw =~ /^([^\s:]+)(?::(\d{1,5}))?$/ ) {
		return ( $1, $2 );
	}

	return ( $raw, undef );
} ## end sub _split_client

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
