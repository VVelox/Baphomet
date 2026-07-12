package App::Baphomet::Parser;

use 5.006;
use strict;
use warnings;
use App::Baphomet::Parser::BSDSyslog  ();
use App::Baphomet::Parser::IETFSyslog ();

=pod

=head1 NAME

App::Baphomet::Parser - Log line parser dispatch for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser ();

    my $parsed = App::Baphomet::Parser::parse( 'bsd_syslog', $line );

=head1 DESCRIPTION

Maps parser names, as used by the C<parser> key of watchers in the config,
to the parser implementations.

The known parsers are as below.

    - bsd_syslog :: RFC 3164 syslog. See L<App::Baphomet::Parser::BSDSyslog>.

    - ietf_syslog :: RFC 5424 syslog. See L<App::Baphomet::Parser::IETFSyslog>.

json and raw are planned but not yet implemented.

Each parser takes a line and hands back either undef, for a line it can not
make sense of, or a hash with the keys below, any of which other than
message may be undef when the line does not carry it.

    - time :: The timestamp, as the raw string from the line.

    - hostname :: The hostname.

    - daemon :: The daemon/program name. This is what the daemons list of
          rules is checked against.

    - pid :: The PID.

    - facility :: The syslog facility. Numeric when derived from a <PRI>,
          the name when from the FreeBSD verbose <facility.level> form.

    - severity :: The numeric syslog severity, 0-7.

    - level :: The severity as a name... emerg, alert, crit, err, warning,
          notice, info, or debug.

    - message :: The message portion of the line, which is what the
          message_regexp entries of rules are matched against.

=head1 FUNCTIONS

=head2 parse

Parses a line via the specified parser. Returns the parsed hash or undef if
the line could not be parsed. Will die if the parser is not a known one.

    my $parsed = App::Baphomet::Parser::parse( $parser, $line );

=cut

my %parsers = (
	'bsd_syslog'  => \&App::Baphomet::Parser::BSDSyslog::parse,
	'ietf_syslog' => \&App::Baphomet::Parser::IETFSyslog::parse,
);

sub parse {
	my ( $parser, $line ) = @_;

	if ( !defined($parser) || !defined( $parsers{$parser} ) ) {
		die( 'Unknown parser, "' . ( defined($parser) ? $parser : 'undef' ) . '"' );
	}

	return $parsers{$parser}->($line);
} ## end sub parse

=head2 is_known

Returns true if the passed parser name is a known one.

    if ( App::Baphomet::Parser::is_known($parser) ) { ... }

=cut

sub is_known {
	my ($parser) = @_;

	return defined($parser) && defined( $parsers{$parser} ) ? 1 : 0;
}

=head2 known_parsers

Returns a sorted list of the known parser names.

    my @parsers = App::Baphomet::Parser::known_parsers;

=cut

sub known_parsers {
	my @known = sort( keys(%parsers) );

	return @known;
}

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
