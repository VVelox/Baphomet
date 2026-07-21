package App::Baphomet::Parser::Syslog;

use 5.006;
use strict;
use warnings;
use App::Baphomet::Parser::BSDSyslog  ();
use App::Baphomet::Parser::IETFSyslog ();
use App::Baphomet::Parser::JSONSyslog ();

=pod

=head1 NAME

App::Baphomet::Parser::Syslog - Syslog line parser for Baphomet handling both RFC 3164 and RFC 5424.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser::Syslog ();

    my $parsed = App::Baphomet::Parser::Syslog::parse($line);

=head1 DESCRIPTION

Handles syslog lines of any of the formats by delegating to
L<App::Baphomet::Parser::BSDSyslog>, L<App::Baphomet::Parser::IETFSyslog>,
and L<App::Baphomet::Parser::JSONSyslog>, so there is exactly one
definition of each grammar. Which parser gets tried first is picked by
sniffing the line... a leading C<{> is syslog-ng JSON output, a
C<< <PRI> >> followed by a digit is the RFC 5424 version field, and a RFC
3164 line has a month name there. The sniff is only an ordering hint, not
a gate... a failed attempt falls through to the remaining parsers.

This is the parser to reach for when a log's format is unknown or mixed.
When the format is known, the specific parsers are the stricter choice, as
they refuse lines that should not be in that log to begin with.

The C<format> key of the returned hash says which grammar won,
C<bsd_syslog> or C<ietf_syslog>.

=head1 FUNCTIONS

=head2 parse

Parses a single line. Returns the parsed hash, as described in
L<App::Baphomet::Parser>, or undef if the line could not be parsed by
either grammar.

    my $parsed = App::Baphomet::Parser::Syslog::parse($line);

=cut

# the three sniff orders, built once... this runs per line for every syslog
# watcher, so no rebuilding the dispatch lists per call
my $order_json = [
	\&App::Baphomet::Parser::JSONSyslog::parse,
	\&App::Baphomet::Parser::BSDSyslog::parse,
	\&App::Baphomet::Parser::IETFSyslog::parse,
];
my $order_ietf = [
	\&App::Baphomet::Parser::IETFSyslog::parse,
	\&App::Baphomet::Parser::BSDSyslog::parse,
	\&App::Baphomet::Parser::JSONSyslog::parse,
];
my $order_bsd = [
	\&App::Baphomet::Parser::BSDSyslog::parse,
	\&App::Baphomet::Parser::IETFSyslog::parse,
	\&App::Baphomet::Parser::JSONSyslog::parse,
];

sub parse {
	my ($line) = @_;

	if ( !defined($line) ) {
		return undef;
	}

	my $order;
	if ( $line =~ /^\s*\{/ ) {
		$order = $order_json;
	} elsif ( $line =~ /^\s*<\d{1,3}>\d/ ) {
		$order = $order_ietf;
	} else {
		$order = $order_bsd;
	}

	foreach my $try ( @{$order} ) {
		my $parsed = $try->($line);
		if ( defined($parsed) ) {
			return $parsed;
		}
	}

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
