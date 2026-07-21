package App::Baphomet::Rules::HTTP;

use 5.006;
use strict;
use warnings;
use base 'App::Baphomet::Rules::Base';

=pod

=head1 NAME

App::Baphomet::Rules::HTTP - HTTP access log rule handler for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Rules::HTTP;

    my $rule = App::Baphomet::Rules::HTTP->new( name => 'http/badbots', def => $def );

    my $found = $rule->check($parsed);
    if ( defined($found) ) {
        print $found->{data}{host} . "\n";
    }

Normally not used directly but via L<App::Baphomet::Rules>.

=head1 RULE FORMAT

A http rule works on lines parsed by L<App::Baphomet::Parser::HTTPAccess>.
Unlike syslog rules there is nothing to extract... the client is already
the C<host> field of the parsed line, so http rules just decide which
lines are offenses. What gets banned is always C<host>.

    ---
    status:
      - 401
      - 403
      - //^5//
    method:
      - GET
      - POST
    match:
      - field: user_agent
        regexp: '(?i:masscan|zgrab|sqlmap)'
      - field: path
        regexp: '\.(?:env|git)(?:$|/)'
    ignore:
      - field: user_agent
        regexp: 'Googlebot'
    tests:
      positive:
        - message: '203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "GET /.env HTTP/1.1" 404 196 "-" "zgrab/0.x"'
          found: 1
          data:
            host: "203.0.113.9"
      negative:
        - message: '198.51.100.7 - - [12/Jul/2026:08:15:51 -0500] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"'
          found: 0

=head2 status / method

Optional gates, ANDed. Lists of values checked against the status and
method of the parsed line... entries starting and ending with C<//> are
regexps, everything else is string equality. A line whose field does not
match a present gate is not a offense, no matter what the matches say.

=head2 gate / selections / condition / keywords

Optional, the shared predicate matcher run over the parsed access-log fields
(host, method, path, status, referer, user_agent, ...) as a pre-filter ANDed
ahead of the matches. So a C<gate> with the typed operators and C<decode>, a
C<selections>/C<condition> boolean, or a C<keywords> / C<%%%ANY%%%> search
across the fields all work here. See
L<App::Baphomet::Rules::Base/"The predicate gate"> for the forms.

=head2 match

Optional. Regexps checked in order, first hit wins, each a hash naming the
parsed field it runs against and the Perl regexp to use. The fields are
the keys of the L<App::Baphomet::Parser::HTTPAccess> hash... host, ident,
user, time, request, method, path, protocol, status, bytes, referer,
user_agent, and format. A field the line does not carry never matches.

With no match entries at all, passing the gates is itself the offense,
which is how a "every 401" rule works. A rule with neither gates nor
matches is a error.

=head2 ignore

Optional. Same shape as L</match>, but a hit vetoes the line entirely.
Checked before the matches.

=head2 detection_var

Optional. Names a field to count by instead of banishing C<host>, making the
rule detection-only... count by C<path>, C<user_agent>, or any parsed field.
See L<App::Baphomet::Rules::Base/detection_var>.

=head2 The common keys

The counting knobs, the triage metadata, the marks, the
C<country>/C<namtar_list>/C<active_time> gates, and C<tests> (parsed via
C<http_access> unless overridden, the found data being the parsed line's
fields, so a test may check C<data.host> or C<data.path>) are shared by every
type and documented under L<App::Baphomet::Rules::Base/"RULE FORMAT">.

=cut

my %fields = map { $_ => 1 } (
	'host',   'ident', 'user',    'time',       'request', 'method', 'path', 'protocol',
	'status', 'bytes', 'referer', 'user_agent', 'format'
);

=head1 METHODS

=head2 new

Initiates the object, compiling the passed rule def. Will die on a invalid
or uncompilable def.

    - name :: The rule name, for error messages.
        Default :: unnamed

    - def :: The rule def hash, as parsed from the YAML.
        Default :: undef

=cut

sub new {
	my ( $blank, %opts ) = @_;

	my $self = {
		name        => defined( $opts{name} ) ? $opts{name} : 'unnamed',
		def         => $opts{def},
		field_gates => {},
		matches     => [],
		ignores     => [],
	};
	bless( $self, ref($blank) || $blank );

	my $name = $self->{name};
	my $def  = $opts{def};

	if ( ref($def) ne 'HASH' ) {
		die( 'The def for the rule "' . $name . '" is not a hash' );
	}

	foreach my $key ( keys( %{$def} ) ) {
		if ( $key
			!~ /^(?:status|method|gate|selections|condition|keywords|match|ignore|detection_var|ban_not_internal|max_score|find_time|ban_time|weight|eve_only|msg|severity|classtype|references|attack|mark|unmark|marked|not_marked|mark_only|sequence|country|namtar_list|active_time|reverse_dns|distinct|test_parser|tests|src_ip_var|dest_ip_var)$/
			)
		{
			die( 'The rule "' . $name . '" has the unknown key "' . $key . '"' );
		}
	}
	$self->_check_common( $def, $name );

	# an http rule banishes host by default, but naming a detection_var (a URI,
	# a user-agent) makes it detection-only, counting by that instead
	$self->_check_detection_var( $def, $name );

	foreach my $gate ( 'status', 'method' ) {
		if ( !defined( $def->{$gate} ) ) {
			next;
		}
		if ( ref( $def->{$gate} ) ne 'ARRAY' || !@{ $def->{$gate} } ) {
			die( 'The ' . $gate . ' of the rule "' . $name . '" is not a array or is empty' );
		}
		$self->{field_gates}{$gate}
			= $self->_compile_matchers( $def->{$gate}, 'The ' . $gate . ' of the rule "' . $name . '"' );
	} ## end foreach my $gate ( 'status', 'method' )

	# the generic gate / selections / keywords over the parsed fields, the same
	# operator, decode, and boolean machinery the json type uses
	$self->_compile_boolean( $def, $name );

	foreach my $sort ( 'match', 'ignore' ) {
		if ( !defined( $def->{$sort} ) ) {
			next;
		}
		if ( ref( $def->{$sort} ) ne 'ARRAY' || !@{ $def->{$sort} } ) {
			die( 'The ' . $sort . ' of the rule "' . $name . '" is not a array or is empty' );
		}

		my $entry_int = 0;
		foreach my $entry ( @{ $def->{$sort} } ) {
			my $where = 'The ' . $sort . ' entry ' . $entry_int . ' of the rule "' . $name . '"';
			if ( ref($entry) ne 'HASH' || !defined( $entry->{field} ) || !defined( $entry->{regexp} ) ) {
				die( $where . ' is not a hash with a field and a regexp' );
			}
			foreach my $key ( keys( %{$entry} ) ) {
				if ( $key !~ /^(?:field|regexp)$/ ) {
					die( $where . ' has the unknown key "' . $key . '"' );
				}
			}
			if ( !defined( $fields{ $entry->{field} } ) ) {
				die( $where . ' names the unknown field "' . $entry->{field} . '"' );
			}

			my $regexp = $entry->{regexp};
			my $compiled;
			eval { $compiled = qr/$regexp/; };
			if ($@) {
				die( $where . ', "' . $regexp . '", does not compile... ' . $@ );
			}

			push(
				@{ $self->{ $sort eq 'match' ? 'matches' : 'ignores' } },
				{ 'field' => $entry->{field}, 'regexp' => $compiled }
			);
			$entry_int++;
		} ## end foreach my $entry ( @{ $def->{$sort} } )
	} ## end foreach my $sort ( 'match', 'ignore' )

	if (   !keys( %{ $self->{field_gates} } )
		&& !( ref( $self->{gates} ) eq 'ARRAY' && @{ $self->{gates} } )
		&& !defined( $self->{condition_ast} )
		&& !( ref( $self->{keyword_gates} ) eq 'ARRAY' && @{ $self->{keyword_gates} } )
		&& !@{ $self->{matches} } )
	{
		die(      'The rule "'
				. $name
				. '" has no gates, selections, keywords, or matches... it would regard nothing as a offense' );
	} ## end if ( !keys( %{ $self->{field_gates} } ) &&...)

	return $self;
} ## end sub new

=head2 check

Checks a parsed line, as returned by L<App::Baphomet::Parser::HTTPAccess>,
against the rule. Returns undef for no match. For a match, returns a hash
as below, with data holding the defined fields of the parsed line and
regexp being the index of the match entry that hit, or undef for a gates
only rule.

    { 'data' => { 'host' => '203.0.113.9', ... }, 'regexp' => 0 }

    my $found = $rule->check($parsed);

=cut

sub check {
	my ( $self, $parsed ) = @_;

	# must be access log shaped... the syslog parsers never produce these
	if ( ref($parsed) ne 'HASH' || !defined( $parsed->{host} ) || !defined( $parsed->{status} ) ) {
		return undef;
	}

	foreach my $gate ( keys( %{ $self->{field_gates} } ) ) {
		if ( !$self->_matchers_hit( $self->{field_gates}{$gate}, $parsed->{$gate} ) ) {
			return undef;
		}
	}

	# the field space, the parsed access-log fields, for the generic gate and
	# for the returned data
	my %data;
	foreach my $field ( keys(%fields) ) {
		if ( defined( $parsed->{$field} ) ) {
			$data{$field} = $parsed->{$field};
		}
	}

	# the generic gate / selections / keywords, ANDed ahead of the matches
	if ( !$self->_boolean_pass( \%data, undef ) ) {
		return undef;
	}

	foreach my $ignore ( @{ $self->{ignores} } ) {
		my $value = $parsed->{ $ignore->{field} };
		if ( defined($value) && $value =~ $ignore->{regexp} ) {
			return undef;
		}
	}

	my $matched;
	if ( @{ $self->{matches} } ) {
		my $entry_int = 0;
		foreach my $match ( @{ $self->{matches} } ) {
			my $value = $parsed->{ $match->{field} };
			if ( defined($value) && $value =~ $match->{regexp} ) {
				$matched = $entry_int;
				last;
			}
			$entry_int++;
		}
		if ( !defined($matched) ) {
			return undef;
		}
	} ## end if ( @{ $self->{matches} } )

	return { 'data' => \%data, 'regexp' => $matched };
} ## end sub check

=head2 ban_var

Returns the list of capture names to use for bans, which for http rules is
always just host.

    my @ban_var = $rule->ban_var;

=cut

sub ban_var {
	return ('host');
}

=head2 default_test_parser

The parser used for embedded tests that do not name one... http_access for
http rules.

=cut

sub default_test_parser {
	return 'http_access';
}

=head2 run_tests

Runs the tests embedded in the rule. Inherited from
L<App::Baphomet::Rules::Base>.

    my $results = $rule->run_tests;

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
