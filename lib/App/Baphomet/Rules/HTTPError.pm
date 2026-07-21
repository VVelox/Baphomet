package App::Baphomet::Rules::HTTPError;

use 5.006;
use strict;
use warnings;
use base 'App::Baphomet::Rules::Base';

=pod

=head1 NAME

App::Baphomet::Rules::HTTPError - HTTP error log rule handler for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Rules::HTTPError;

    my $rule = App::Baphomet::Rules::HTTPError->new( name => 'http_error/apache-auth', def => $def );

    my $found = $rule->check($parsed);
    if ( defined($found) ) {
        print $found->{data}{client} . "\n";
    }

Normally not used directly but via L<App::Baphomet::Rules>.

=head1 RULE FORMAT

A http_error rule works on lines parsed by
L<App::Baphomet::Parser::ApacheError> or
L<App::Baphomet::Parser::NginxError>. Like http rules there is nothing to
extract... the client is already the C<client> field of the parsed line,
and lines with out one, like startup notices, are never offenses. What
gets banned is always C<client>.

    ---
    level:
      - error
    module:
      - auth_basic
    message_regexp:
      - '^user \S+ not found(?::|$)'
      - '^user \S+: authentication failure'
      - '^user \S+: password mismatch'
    ignore_regexp:
      - 'from the health checker'
    tests:
      positive:
        - message: '[Sat Jun 01 02:17:42 2013] [error] [client 192.0.2.11] user foo not found: /'
          found: 1
          data:
            client: "192.0.2.11"

=head2 level / module

Optional gates, ANDed. Lists of values checked against the level and, for
Apache 2.4 lines, the module of the parsed line... entries starting and
ending with C<//> are regexps, everything else is string equality. A line
whose field does not match a present gate is not a offense. nginx lines
and Apache 2.2 lines carry no module, so a module gate makes a rule
Apache 2.4 only.

=head2 gate / selections / condition / keywords

Optional, the shared predicate matcher run over the parsed error fields
(client, level, module, message) as a pre-filter ANDed ahead of the
message_regexp match. The typed operators and C<decode>, the
C<selections>/C<condition> boolean, and C<keywords> / C<%%%ANY%%%> search all
work here; the C<message> field carries the error text, so keywords search it.
See L<App::Baphomet::Rules::Base/"The predicate gate"> for the forms.

=head2 message_regexp

The regexps checked, in order, against the message free text of a parsed
line. The first to match wins. Plain Perl regexps... there is no
C<%%%%TOKEN%%%%> machinery here as there is nothing to extract, though
named captures in a winning regexp get merged into the data of the found
line.

=head2 ignore_regexp

Optional. Same, but a hit vetoes the line entirely. Checked before the
matches.

=head2 detection_var

Optional. Names a field to count by instead of banishing C<client>, making
the rule detection-only. See L<App::Baphomet::Rules::Base/detection_var>.

=head2 The common keys

The counting knobs, the triage metadata, the marks, the
C<country>/C<namtar_list>/C<active_time> gates, and C<tests> (parsed via
C<apache_error> unless the rule sets C<test_parser> or a test names one... a
nginx rule wants C<test_parser: nginx_error>) are shared by every type and
documented under L<App::Baphomet::Rules::Base/"RULE FORMAT">.

=cut

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
		name           => defined( $opts{name} ) ? $opts{name} : 'unnamed',
		def            => $opts{def},
		field_gates    => {},
		regexps        => [],
		ignore_regexps => [],
	};
	bless( $self, ref($blank) || $blank );

	my $name = $self->{name};
	my $def  = $opts{def};

	if ( ref($def) ne 'HASH' ) {
		die( 'The def for the rule "' . $name . '" is not a hash' );
	}

	foreach my $key ( keys( %{$def} ) ) {
		if ( $key
			!~ /^(?:level|module|gate|selections|condition|keywords|message_regexp|ignore_regexp|detection_var|ban_not_internal|max_score|find_time|ban_time|weight|eve_only|msg|severity|classtype|references|attack|mark|unmark|marked|not_marked|mark_only|sequence|country|namtar_list|active_time|reverse_dns|distinct|test_parser|tests|src_ip_var|dest_ip_var)$/
			)
		{
			die( 'The rule "' . $name . '" has the unknown key "' . $key . '"' );
		}
	}
	$self->_check_common( $def, $name );

	# an http_error rule banishes client by default, but naming a detection_var
	# makes it detection-only, counting by that instead
	$self->_check_detection_var( $def, $name );

	foreach my $gate ( 'level', 'module' ) {
		if ( !defined( $def->{$gate} ) ) {
			next;
		}
		if ( ref( $def->{$gate} ) ne 'ARRAY' || !@{ $def->{$gate} } ) {
			die( 'The ' . $gate . ' of the rule "' . $name . '" is not a array or is empty' );
		}
		$self->{field_gates}{$gate}
			= $self->_compile_matchers( $def->{$gate}, 'The ' . $gate . ' of the rule "' . $name . '"' );
	} ## end foreach my $gate ( 'level', 'module' )

	# the generic gate / selections / keywords over the parsed fields, the same
	# machinery the json type uses, ANDed ahead of the message_regexp match
	$self->_compile_boolean( $def, $name );

	if ( ref( $def->{message_regexp} ) ne 'ARRAY' || !@{ $def->{message_regexp} } ) {
		die( 'The rule "' . $name . '" lacks a message_regexp array or it is empty' );
	}

	foreach my $sort ( 'message_regexp', 'ignore_regexp' ) {
		if ( !defined( $def->{$sort} ) ) {
			next;
		}
		if ( ref( $def->{$sort} ) ne 'ARRAY' ) {
			die( 'The ' . $sort . ' of the rule "' . $name . '" is not a array' );
		}

		my $entry_int = 0;
		foreach my $regexp ( @{ $def->{$sort} } ) {
			my $where = 'The ' . $sort . ' entry ' . $entry_int . ' of the rule "' . $name . '"';
			if ( !defined($regexp) || ref($regexp) ne '' ) {
				die( $where . ' is not a string' );
			}

			my $compiled;
			eval { $compiled = qr/$regexp/; };
			if ($@) {
				die( $where . ', "' . $regexp . '", does not compile... ' . $@ );
			}

			push( @{ $self->{ $sort eq 'message_regexp' ? 'regexps' : 'ignore_regexps' } }, $compiled );
			$entry_int++;
		} ## end foreach my $regexp ( @{ $def->{$sort} } )
	} ## end foreach my $sort ( 'message_regexp', 'ignore_regexp')

	return $self;
} ## end sub new

=head2 check

Checks a parsed line, as returned by the error log parsers, against the
rule. Returns undef for no match. For a match, returns a hash as below,
with data holding the defined fields of the parsed line merged with any
named captures of the winning regexp, and regexp being the index of the
message_regexp entry that hit.

    { 'data' => { 'client' => '192.0.2.11', ... }, 'regexp' => 0 }

    my $found = $rule->check($parsed);

=cut

sub check {
	my ( $self, $parsed ) = @_;

	# must be error log shaped and carry a client... startup notices and
	# worker chatter have no one to blame
	if ( ref($parsed) ne 'HASH' || !defined( $parsed->{client} ) || !defined( $parsed->{message} ) ) {
		return undef;
	}

	foreach my $gate ( keys( %{ $self->{field_gates} } ) ) {
		if ( !$self->_matchers_hit( $self->{field_gates}{$gate}, $parsed->{$gate} ) ) {
			return undef;
		}
	}

	# the generic gate / selections / keywords over the parsed scalar fields
	# (the message included, so keywords search the error text), a pre-filter
	# ANDed ahead of the message_regexp match
	my %field_data;
	foreach my $field ( keys( %{$parsed} ) ) {
		if ( defined( $parsed->{$field} ) && ref( $parsed->{$field} ) eq '' ) {
			$field_data{$field} = $parsed->{$field};
		}
	}
	if ( !$self->_boolean_pass( \%field_data, undef ) ) {
		return undef;
	}

	foreach my $ignore ( @{ $self->{ignore_regexps} } ) {
		if ( $parsed->{message} =~ $ignore ) {
			return undef;
		}
	}

	my $entry_int = 0;
	foreach my $regexp ( @{ $self->{regexps} } ) {
		if ( $parsed->{message} =~ $regexp ) {
			my %caps = %+;

			my %data;
			foreach my $field ( keys( %{$parsed} ) ) {
				if ( defined( $parsed->{$field} ) && ref( $parsed->{$field} ) eq '' ) {
					$data{$field} = $parsed->{$field};
				}
			}
			# the parsed fields are authoritative over captures
			foreach my $cap ( keys(%caps) ) {
				if ( !exists( $data{$cap} ) ) {
					$data{$cap} = $caps{$cap};
				}
			}

			return { 'data' => \%data, 'regexp' => $entry_int };
		} ## end if ( $parsed->{message} =~ $regexp )
		$entry_int++;
	} ## end foreach my $regexp ( @{ $self->{regexps} } )

	return undef;
} ## end sub check

=head2 ban_var

Returns the list of capture names to use for bans, which for http_error
rules is always just client.

    my @ban_var = $rule->ban_var;

=cut

sub ban_var {
	return ('client');
}

=head2 default_test_parser

The parser used for embedded tests when neither the rule's test_parser nor
the test names one... apache_error for http_error rules.

=cut

sub default_test_parser {
	return 'apache_error';
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
