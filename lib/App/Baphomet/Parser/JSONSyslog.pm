package App::Baphomet::Parser::JSONSyslog;

use 5.006;
use strict;
use warnings;
use JSON::MaybeXS qw( decode_json );
# only used at runtime, so the circular use with the dispatcher is harmless
use App::Baphomet::Parser ();

=pod

=head1 NAME

App::Baphomet::Parser::JSONSyslog - syslog-ng JSON output line parser for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser::JSONSyslog ();

    my $parsed = App::Baphomet::Parser::JSONSyslog::parse($line);

=head1 DESCRIPTION

Parses the JSON output of syslog-ng, as written by a destination template
along the lines of...

    template("$(format-json --scope rfc3164 --scope rfc5424)\n")

...which is one JSON object per line...

    {"PROGRAM":"sshd-session","PRIORITY":"info","PID":"66891","MESSAGE":"Invalid user moth3r from 216.137.179.214 port 34640","HOST":"vixen42","FACILITY":"auth","DATE":"Jul 12 08:15:50"}

The fields map onto the same shape the other syslog parsers hand back, so
this is a peer in the syslog family and C<syslog/*> rules work over JSON
logs unchanged.

    - daemon :: PROGRAM

    - message :: MESSAGE. Required... a JSON object with out one, such as
          some random application's JSON in the wrong watcher, is not
          regarded as parsed.

    - pid :: PID

    - hostname :: HOST

    - time :: ISODATE if present, else DATE, as the raw string.

    - level :: PRIORITY, which syslog-ng emits as a name such as info, or
          mapped from LEVEL_NUM.

    - severity :: LEVEL_NUM if present, else mapped from the PRIORITY
          name.

    - facility :: FACILITY, a name, or FACILITY_NUM.

    - format :: json_syslog.

Key lookup is case folded, so rekeyed lowercase templates work too. Keys
outside the set above, such as the SDATA ones or custom pairs, are
silently ignored... surfacing arbitrary JSON fields is the business of the
planned generic json parser, not this one. Empty string values count as
absent, matching how syslog-ng renders unset macros.

Only the one object per line form is handled... pretty printed JSON
spanning lines just counts as unparsed.

=cut

=head1 FUNCTIONS

=head2 parse

Parses a single line. Returns the parsed hash, as described in
L<App::Baphomet::Parser>, or undef if the line could not be parsed.

    my $parsed = App::Baphomet::Parser::JSONSyslog::parse($line);

=cut

sub parse {
	my ($line) = @_;

	if ( !defined($line) || $line !~ /^\s*\{/ ) {
		return undef;
	}

	my $decoded;
	eval { $decoded = decode_json($line); };
	if ( $@ || ref($decoded) ne 'HASH' ) {
		return undef;
	}

	# case folded lookup, empty strings counting as absent
	my %fields;
	foreach my $key ( keys( %{$decoded} ) ) {
		if ( defined( $decoded->{$key} ) && ref( $decoded->{$key} ) eq '' && $decoded->{$key} ne '' ) {
			$fields{ uc($key) } = $decoded->{$key};
		}
	}

	if ( !defined( $fields{MESSAGE} ) ) {
		return undef;
	}

	my $severity;
	my $level;
	if ( defined( $fields{LEVEL_NUM} ) && $fields{LEVEL_NUM} =~ /^[0-7]$/ ) {
		$severity = $fields{LEVEL_NUM} + 0;
	}
	if ( defined( $fields{PRIORITY} ) ) {
		$level = $fields{PRIORITY};
		if ( !defined($severity) ) {
			$severity = App::Baphomet::Parser::severity_number($level);
		}
	} elsif ( defined($severity) ) {
		$level = App::Baphomet::Parser::severity_name($severity);
	}

	my $facility = defined( $fields{FACILITY} ) ? $fields{FACILITY} : $fields{FACILITY_NUM};

	return {
		'format'   => 'json_syslog',
		'time'     => defined( $fields{ISODATE} ) ? $fields{ISODATE} : $fields{DATE},
		'hostname' => $fields{HOST},
		'daemon'   => $fields{PROGRAM},
		'pid'      => $fields{PID},
		'facility' => $facility,
		'severity' => $severity,
		'level'    => $level,
		'message'  => $fields{MESSAGE},
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
