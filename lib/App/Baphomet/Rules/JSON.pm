package App::Baphomet::Rules::JSON;

use 5.006;
use strict;
use warnings;
use base 'App::Baphomet::Rules::Base';

=pod

=head1 NAME

App::Baphomet::Rules::JSON - Generic JSON log rule handler for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Rules::JSON;

    my $rule = App::Baphomet::Rules::JSON->new( name => 'json/mongodb-auth', def => $def );

    my $found = $rule->check($parsed);

Normally not used directly but via L<App::Baphomet::Rules>.

=head1 RULE FORMAT

A json rule works on lines parsed by L<App::Baphomet::Parser::JSON>, which
flattens whatever the application logged into dotted field paths. The rule
says which fields matter and how.

    ---
    gate:
      - field: c
        values: [ ACCESS ]
      - field: msg
        values: [ "Authentication failed" ]
    match:
      - field: attr.remote
        regexp: '^%%%%SRC%%%%:\d+$'
    ignore:
      - field: attr.principalName
        regexp: '^healthcheck$'
    ban_var:
      - SRC
    tests:
      positive:
        - message: '{"c":"ACCESS","msg":"Authentication failed","attr":{"remote":"192.0.2.5:54321","principalName":"root"}}'
          found: 1
          data:
            SRC: "192.0.2.5"

=head2 gate

Optional, ANDed. Each entry names a field and the values it must have...
values entries starting and ending with C<//> are regexps, everything else
is string equality. A field the line does not carry never matches a gate.

An entry may instead use the typed operator form, opt-in and detected by the
presence of an C<op>, C<value>, C<all>, or C<negate> key (a plain
C<field>/C<values> entry stays the legacy equality/regexp form above,
unchanged):

    gate:
      - { field: event,     op: eq,    value: auth_fail }
      - { field: bytes_out, op: gt,    value: 1000000 }
      - { field: src,       op: cidr,  values: [ 10.0.0.0/8, 2001:db8::/32 ] }
      - { field: cmd,       op: contains, values: [ psexec, mimikatz ], all: false }
      - { field: user,      op: eq,    value: healthcheck, negate: true }

    - op :: eq (default), contains, startswith, endswith, re (a tokened
          regexp), gt/lt/ge/le (numeric, the field coerced, a non-number
          missing), or cidr (v4/v6 membership).
    - value / values :: one scalar or a non-empty list, matching if any holds,
          or all when C<all> is true.
    - all :: require every value to match rather than any. Default false.
    - negate :: invert the entry. A negated entry holds when the field is
          absent, matching Sigma's field-absent semantics.
    - decode :: a list of transforms run left to right over the field value
          before the operator, so an obfuscated payload is compared decoded...
          base64, base64offset (the three alignment candidates), utf16le /
          utf16be / utf16 (wide an alias for utf16le), windash, url, lower,
          upper. A transform that can not decode drops that candidate, so a
          bad decode simply does not match. C<decode: [ base64, utf16le ]>
          with C<op: contains> is the PowerShell -enc shape.

=head2 selections / condition

Optional, the boolean form and an alternative to L</gate> (a rule may not
carry both). C<selections> is a table of named selections, each a list of
gate entries (the same predicate and legacy forms) ANDed together.
C<condition> is a string composing the selections with C<and>, C<or>,
C<not>, parens, and the quantifiers C<all of them>, C<1 of them>, and
C<N of E<lt>prefixE<gt>_*>. It is the pre-filter, ANDed ahead of the
matches, and gives the OR, arbitrary nesting, and N-of-M the flat gate can
not... the Sigma detection model.

    selections:
      auth:  [ { field: event, op: eq, value: authFailure } ]
      admin: [ { field: user,  op: eq, values: [ root, admin ] } ]
      trust: [ { field: src,   op: cidr, value: 10.0.0.0/8 } ]
    condition: "auth and admin and not trust"

A selection referenced but not defined, an unbalanced paren, or a stray
token is a load-time error, as is a condition without selections or the two
present together.

=head2 match

Optional. Regexps checked in order, first hit wins, each a hash naming the
flattened field it runs against. The C<%%%%TOKEN%%%%> tokens of syslog
rules work here, as the offender may be inside a string value... see
L<App::Baphomet::Rules::Syslog> for the tokens. With no match entries at
all, passing the gates is itself the offense. A rule with neither gates
nor matches is a error.

=head2 ignore

Optional. Same shape as L</match>, but a hit vetoes the line entirely.
Checked after the gates and before the matches.

=head2 ban_var

Required. What to ban, resolved against the data of a found line, which is
the flattened fields merged with the named captures of the winning match
entry. So a ban_var may name a token capture, like C<SRC> when the address
had to be dug out of a string, or a field path directly, like
C<request.client_ip> when the log hands the address over bare.

=head2 max_score / find_time / ban_time / weight / eve_only

Optional. The rule's own thresholds, honored only when the watcher's
C<allow_per_rule_thresholds> config setting is on. See
L<App::Baphomet::Rules::Syslog> for the semantics.

=head2 mark / unmark / marked / not_marked / mark_only

Optional. Cross-rule marks, keyed by the offender or any capture. A json
rule's C<var>/C<value_var> may name a token capture or a field path. See
L<App::Baphomet::Rules::Syslog> for the semantics.

=head2 country

Optional. A GeoIP gate on the offender or named found vars, its C<vars>
naming token captures or field paths. See L<App::Baphomet::Rules::Syslog>
for the semantics.

=head2 namtar_list

Optional. A blocklist gate on the offender or named found vars, its C<var>
naming a token capture or field path. See L<App::Baphomet::Rules::Syslog>
for the semantics.

=head2 active_time

Optional. A time-of-day gate on the current time or named found vars, its
C<vars> naming token captures or field paths holding a epoch or ISO time.
See L<App::Baphomet::Rules::Syslog> for the semantics.

=head2 test_parser / tests

Positive and negative tests, same shape as everywhere else, with each
message being one line of JSON. Tests parse via C<json> unless overridden.

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
		name    => defined( $opts{name} ) ? $opts{name} : 'unnamed',
		def     => $opts{def},
		gates   => [],
		matches => [],
		ignores => [],
	};
	bless $self;

	my $name = $self->{name};
	my $def  = $opts{def};

	if ( ref($def) ne 'HASH' ) {
		die( 'The def for the rule "' . $name . '" is not a hash' );
	}

	foreach my $key ( keys( %{$def} ) ) {
		if ( $key
			!~ /^(?:gate|selections|condition|match|ignore|ban_var|ban_not_internal|max_score|find_time|ban_time|weight|eve_only|msg|severity|classtype|references|attack|mark|unmark|marked|not_marked|mark_only|country|namtar_list|active_time|distinct|test_parser|tests)$/
			)
		{
			die( 'The rule "' . $name . '" has the unknown key "' . $key . '"' );
		}
	}
	$self->_check_thresholds($def);
	$self->_check_marks($def);
	$self->_check_country($def);
	$self->_check_namtar($def);
	$self->_check_active_time($def);
	$self->_check_distinct($def);

	if ( ref( $def->{ban_var} ) ne 'ARRAY' || !@{ $def->{ban_var} } ) {
		die( 'The rule "' . $name . '" lacks a ban_var array or it is empty' );
	}
	foreach my $item ( @{ $def->{ban_var} } ) {
		if ( !defined($item) || ref($item) ne '' ) {
			die( 'The ban_var of the rule "' . $name . '" contains a non-string entry' );
		}
	}

	if ( defined( $def->{tests} ) && ref( $def->{tests} ) ne 'HASH' ) {
		die( 'The tests of the rule "' . $name . '" is not a hash' );
	}

	# the flat gate or the boolean selections+condition form, compiled in the
	# base class and shared with the syslog and raw types
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

			push(
				@{ $self->{ $sort eq 'match' ? 'matches' : 'ignores' } },
				{
					'field' => $entry->{field},
					'entry' => $self->_compile_tokened_regexp( $entry->{regexp}, $where ),
				}
			);
			$entry_int++;
		} ## end foreach my $entry ( @{ $def->{$sort} } )
	} ## end foreach my $sort ( 'match', 'ignore' )

	if ( !@{ $self->{gates} } && !defined( $self->{condition_ast} ) && !@{ $self->{matches} } ) {
		die( 'The rule "' . $name . '" has no gates, selections, or matches... it would regard nothing as a offense' );
	}

	return $self;
} ## end sub new

=head2 check

Checks a parsed line, as returned by L<App::Baphomet::Parser::JSON>,
against the rule. Returns undef for no match. For a match, returns a hash
as below, with data being the flattened fields merged with the captures of
the winning match entry, fields authoritative, and regexp being the index
of the match entry that hit, or undef for a gates only rule.

    { 'data' => { 'SRC' => '192.0.2.5', 'msg' => '...', ... }, 'regexp' => 0 }

    my $found = $rule->check($parsed);

=cut

sub check {
	my ( $self, $parsed ) = @_;

	if ( ref($parsed) ne 'HASH' || ref( $parsed->{fields} ) ne 'HASH' ) {
		return undef;
	}
	my $fields = $parsed->{fields};

	# the boolean pre-filter... the gate or the selections+condition, ANDed
	# ahead of the matches
	if ( !$self->_boolean_pass( $fields, undef ) ) {
		return undef;
	}

	foreach my $ignore ( @{ $self->{ignores} } ) {
		if ( defined( $self->_match_tokened( $ignore->{entry}, $fields->{ $ignore->{field} } ) ) ) {
			return undef;
		}
	}

	my $matched;
	my $caps = {};
	if ( @{ $self->{matches} } ) {
		my $entry_int = 0;
		foreach my $match ( @{ $self->{matches} } ) {
			my $match_caps = $self->_match_tokened( $match->{entry}, $fields->{ $match->{field} } );
			if ( defined($match_caps) ) {
				$matched = $entry_int;
				$caps    = $match_caps;
				last;
			}
			$entry_int++;
		}
		if ( !defined($matched) ) {
			return undef;
		}
	} ## end if ( @{ $self->{matches} } )

	# the flattened fields merged with the captures, fields authoritative
	my %data = %{$caps};
	foreach my $field ( keys( %{$fields} ) ) {
		$data{$field} = $fields->{$field};
	}

	return { 'data' => \%data, 'regexp' => $matched };
} ## end sub check

=head2 ban_var

Returns the list of data keys to use for bans.

    my @ban_var = $rule->ban_var;

=cut

sub ban_var {
	my ($self) = @_;

	return @{ $self->{def}{ban_var} };
}

=head2 default_test_parser

The parser used for embedded tests that do not name one... json for json
rules.

=cut

sub default_test_parser {
	return 'json';
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
