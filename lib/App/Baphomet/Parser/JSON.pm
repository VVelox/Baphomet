package App::Baphomet::Parser::JSON;

use 5.006;
use strict;
use warnings;
use JSON::MaybeXS qw( decode_json );

=pod

=head1 NAME

App::Baphomet::Parser::JSON - Generic JSON application log line parser for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Parser::JSON ();

    my $parsed = App::Baphomet::Parser::JSON::parse($line);

=head1 DESCRIPTION

Parses application logs written as one JSON object per line, whatever the
schema... mongod structured logs, Caddy and Traefik access logs, Suricata
eve.json, journalctl -o json output, and the like.

Unlike L<App::Baphomet::Parser::JSONSyslog>, which maps syslog-ng's known
macro names onto the syslog shape, this parser claims nothing about what
any field means. It decodes the object and flattens nesting into a single
level hash of dotted paths...

    {"c":"ACCESS","msg":"Authentication failed","attr":{"remote":"192.0.2.5:54321"}}

...becomes...

    c => "ACCESS", msg => "Authentication failed", attr.remote => "192.0.2.5:54321"

...and rules of the C<json> type address those paths explicitly. See
L<App::Baphomet::Rules::JSON>.

The returned hash is C<< { format => 'json', fields => \%flat } >>...
fields live under their own key so a log carrying a literal "format" key
can not collide.

Flattening details...

    - Nested hashes become dotted paths.

    - Arrays flatten with numeric indices... tags.0, tags.1.

    - JSON booleans become 1 and 0.

    - JSON nulls are skipped, so a null field counts as absent.

    - Nesting is capped at ten levels deep... anything deeper is dropped.

    - A literal dotted key colliding with a nested path, "a.b" alongside
      a hash a carrying b, is last one wins and not worth engineering
      around.

Only the one object per line form is handled... pretty printed JSON
spanning lines, and anything that is not a JSON object, just counts as
unparsed.

=cut

=head1 FUNCTIONS

=head2 parse

Parses a single line. Returns the parsed hash or undef if the line could
not be parsed.

    my $parsed = App::Baphomet::Parser::JSON::parse($line);

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

	my %flat;
	_flatten( $decoded, '', \%flat, 0 );

	return {
		'format' => 'json',
		'fields' => \%flat,
	};
} ## end sub parse

# walks the decoded structure, writing scalars into the flat hash under
# dotted paths
sub _flatten {
	my ( $node, $prefix, $flat, $depth ) = @_;

	if ( $depth > 10 ) {
		return;
	}

	if ( ref($node) eq 'HASH' ) {
		foreach my $key ( keys( %{$node} ) ) {
			_flatten( $node->{$key}, $prefix eq '' ? $key : $prefix . '.' . $key, $flat, $depth + 1 );
		}
	} elsif ( ref($node) eq 'ARRAY' ) {
		my $index = 0;
		foreach my $item ( @{$node} ) {
			_flatten( $item, $prefix eq '' ? $index : $prefix . '.' . $index, $flat, $depth + 1 );
			$index++;
		}
	} elsif ( ref($node) ne '' ) {
		# a blessed scalar-ish thing, which for decoded JSON means a boolean
		$flat->{$prefix} = $node ? 1 : 0;
	} elsif ( defined($node) ) {
		$flat->{$prefix} = $node;
	}
	# JSON null lands here undefined and is skipped

	return;
} ## end sub _flatten

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
