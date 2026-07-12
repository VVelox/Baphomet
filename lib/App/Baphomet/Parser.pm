package App::Baphomet::Parser;

use 5.006;
use strict;
use warnings;
use App::Baphomet::Parser::ApacheError ();
use App::Baphomet::Parser::BSDSyslog   ();
use App::Baphomet::Parser::HTTPAccess  ();
use App::Baphomet::Parser::IETFSyslog  ();
use App::Baphomet::Parser::JSONSyslog  ();
use App::Baphomet::Parser::NginxError  ();
use App::Baphomet::Parser::Raw         ();
use App::Baphomet::Parser::Syslog      ();

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

    - syslog :: RFC 3164, RFC 5424, or syslog-ng JSON output, sniffed per
          line. The right pick when a log's format is unknown or mixed.
          See L<App::Baphomet::Parser::Syslog>.

    - bsd_syslog :: RFC 3164 syslog. See L<App::Baphomet::Parser::BSDSyslog>.

    - ietf_syslog :: RFC 5424 syslog. See L<App::Baphomet::Parser::IETFSyslog>.

    - json_syslog :: The JSON output of syslog-ng, one object per line.
          See L<App::Baphomet::Parser::JSONSyslog>.

    - http_access :: HTTP access logs, both the common and combined
          formats. Hands back its own shape, for http type rules... see
          L<App::Baphomet::Parser::HTTPAccess>.

    - apache_error :: Apache error logs, both the 2.2 and 2.4 shapes.
          For http_error type rules... see
          L<App::Baphomet::Parser::ApacheError>.

    - nginx_error :: nginx error logs. For http_error type rules... see
          L<App::Baphomet::Parser::NginxError>.

    - raw :: The no-op escape hatch... the whole line becomes the message.
          For raw type rules... see L<App::Baphomet::Parser::Raw>.

A generic json parser for arbitrary application JSON is planned but not
yet implemented.

Each syslog parser takes a line and hands back either undef, for a line it
can not make sense of, or a hash with the keys below, any of which other
than format and message may be undef when the line does not carry it.

    - format :: Which grammar parsed the line, bsd_syslog or ietf_syslog.

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
	'syslog'      => \&App::Baphomet::Parser::Syslog::parse,
	'bsd_syslog'  => \&App::Baphomet::Parser::BSDSyslog::parse,
	'ietf_syslog' => \&App::Baphomet::Parser::IETFSyslog::parse,
	'json_syslog' => \&App::Baphomet::Parser::JSONSyslog::parse,
	'http_access' => \&App::Baphomet::Parser::HTTPAccess::parse,
	'apache_error' => \&App::Baphomet::Parser::ApacheError::parse,
	'nginx_error'  => \&App::Baphomet::Parser::NginxError::parse,
	'raw'          => \&App::Baphomet::Parser::Raw::parse,
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

=head2 severity_name

Returns the name for a numeric syslog severity, 0 through 7... emerg,
alert, crit, err, warning, notice, info, or debug. Returns undef for
anything else. Shared by the syslog family of parsers.

    my $name = App::Baphomet::Parser::severity_name($severity);

=cut

my @severity_names = ( 'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug' );

my %severity_numbers;
{
	my $number = 0;
	foreach my $name (@severity_names) {
		$severity_numbers{$name} = $number;
		$number++;
	}
	# common alternate spellings
	$severity_numbers{'error'} = 3;
	$severity_numbers{'warn'}  = 4;
	$severity_numbers{'panic'} = 0;
}

sub severity_name {
	my ($severity) = @_;

	if ( !defined($severity) || $severity !~ /^[0-7]$/ ) {
		return undef;
	}

	return $severity_names[$severity];
} ## end sub severity_name

=head2 severity_number

Returns the numeric syslog severity for a name, handling the common
alternate spellings error, warn, and panic. Returns undef for anything
unknown. Shared by the syslog family of parsers.

    my $severity = App::Baphomet::Parser::severity_number($level);

=cut

sub severity_number {
	my ($level) = @_;

	if ( !defined($level) ) {
		return undef;
	}

	return $severity_numbers{ lc($level) };
} ## end sub severity_number

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
