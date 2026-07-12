package App::Baphomet::Parser::Raw;

use 5.006;
use strict;
use warnings;

=pod

=head1 NAME

App::Baphomet::Parser::Raw - No-op line parser for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser::Raw ();

    my $parsed = App::Baphomet::Parser::Raw::parse($line);

=head1 DESCRIPTION

The escape hatch for logs no other parser fits. The whole chomped line
becomes the message and nothing else is claimed...

    - message :: The line.

    - format :: raw.

Lines from this parser are for C<raw> type rules, which are syslog rules
with out the daemon gate... see L<App::Baphomet::Rules::Raw>, including
its notes on what the missing gate costs.

This parser never fails on defined input, so the unparsed stat of a raw
watcher stays zero by construction... do not read it as a sign of health.
It is also never picked by the format sniffing of the combined C<syslog>
parser... raw is only ever explicitly configured, as it would otherwise
swallow every line every other parser rejects.

=cut

=head1 FUNCTIONS

=head2 parse

Parses, so to speak, a single line.

    my $parsed = App::Baphomet::Parser::Raw::parse($line);

=cut

sub parse {
	my ($line) = @_;

	if ( !defined($line) ) {
		return undef;
	}
	chomp($line);

	return {
		'format'  => 'raw',
		'message' => $line,
	};
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
