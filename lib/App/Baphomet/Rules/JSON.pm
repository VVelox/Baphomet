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

=head2 gate / selections / condition / keywords

The predicate layer, and where json earns its keep... the flat C<gate>, the
Sigma-style C<selections>/C<condition> boolean, and the C<keywords>
shorthand. Here a C<field> is a flattened dotted path (C<attr.remote>,
C<request.client_ip>), and the reserved C<%%%ANY%%%> / C<%%%ANY:prefix%%%>
fan a predicate over every field or a subtree. A rule may carry C<gate> or
C<selections>/C<condition>, not both, and needs at least a gate or a
L</match>. The full vocabulary... operators, C<decode>, the quantifiers... is
documented under L<App::Baphomet::Rules::Base/"The predicate gate">.

    gate:
      - field: c
        values: [ ACCESS ]
      - { field: attr.remote, op: startswith, value: "10." }

=head2 match

Optional. Regexps checked in order, first hit wins, each a hash naming the
flattened field it runs against. The C<%%%%TOKEN%%%%> tokens work here, as
the offender may be inside a string value... see
L<App::Baphomet::Rules::Syslog/message_regexp> for the tokens. With no match
entries at all, passing the gates is itself the offense. A rule with neither
gates nor matches is a error.

=head2 ignore

Optional. Same shape as L</match>, but a hit vetoes the line entirely...
context harvest included, so an ignored line neither offends nor remembers.

=head2 capture / key / defer... correlation

For applications that log the offense and the offender's address on
separate events sharing a field, like a connection or request id...
mongod 4.4+ structured logs being the canonical case. The same two-phase
machinery as the syslog and raw types
(L<App::Baphomet::Rules::Syslog/"capture_regexp / keyed message_regexp entries">),
with the key resolved from fields instead of an envelope.

    gate:
      - field: c
        values: [ ACCESS ]
      - field: msg
        values: [ "Authentication failed" ]
    key: [ ctx ]
    defer: 60
    capture:
      - gate:
          - field: msg
            values: [ "Connection ended" ]
        match:
          - field: attr.remote
            regexp: '^%%%%SRC%%%%:\d+$'
        key: [ ctx ]
        ttl: 120
    ban_var:
      - SRC

C<capture> entries harvest context rather than being offenses. Each is a
hash of an optional C<gate> (ANDed predicates, the shapes L</gate> takes),
an optional tokened C<match> list (first hit wins, at least one of the two
required), a required C<key>, and a C<ttl> in seconds context lives
(default 60). A hit stores the event's data... fields merged with the
match's captures... under the key.

The rule-level C<key> makes the rule's own offense a keyed one. On a
match the key is looked up and any stored context merges into the data,
the offense's own values winning. Not found plus C<defer> parks the
offense for that many seconds awaiting a capture with the key, several of
which may complete at once; not found with out defer, the line is not
judged an offense at all, the syslog type's fall-through.

A C<key>, here and on a capture entry, is a field path or a token capture,
or an array of them ANDed into one compound key... every component must
resolve or the entry does nothing (a capture harvests nothing, an offense
stands plain on its own data). There is no envelope on this type, so
C<syslog.*> components are a load error, those names being reserved.
Correlation state is per watcher, in memory only, and bounded... a galla
restart forgets pending correlations. Test with the C<messages:> array
form (see L<App::Baphomet::Rules::Base/tests>).

=head2 ban_var

What to ban, resolved against the data of a found line, which is the
flattened fields merged with the named captures of the winning match entry.
So a ban_var may name a token capture, like C<SRC> when the address had to be
dug out of a string, or a field path directly, like C<request.client_ip>
when the log hands the address over bare. Name
L<App::Baphomet::Rules::Base/detection_var> instead to count without banning.

=head2 The common keys

C<detection_var>, C<ban_not_internal>, the counting knobs, the triage
metadata, the marks, the C<country>/C<namtar_list>/C<active_time> gates, and
C<tests> (which parse via C<json> unless a per-test or C<test_parser> default
overrides) are shared by every type and documented under
L<App::Baphomet::Rules::Base/"RULE FORMAT">. A found var named by any of
them... a mark's C<var>, a gate's C<vars>... may be a token capture or a
dotted field path, the json type's one wrinkle.

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
			!~ /^(?:gate|selections|condition|keywords|match|ignore|capture|key|defer|ban_var|detection_var|ban_not_internal|max_score|find_time|ban_time|weight|eve_only|msg|severity|classtype|references|attack|mark|unmark|marked|not_marked|mark_only|sequence|country|namtar_list|active_time|reverse_dns|distinct|test_parser|tests|src_ip_var|dest_ip_var)$/
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
	$self->_check_reverse_dns($def);
	$self->_check_distinct($def);
	$self->_check_ip_vars($def);

	# a detection-only rule counts by its detection_var subject and never
	# banishes, so it needs no ban_var
	if ( !$self->_check_detection_var( $def, $name ) ) {
		if ( ref( $def->{ban_var} ) ne 'ARRAY' || !@{ $def->{ban_var} } ) {
			die( 'The rule "' . $name . '" lacks a ban_var array or it is empty' );
		}
		foreach my $item ( @{ $def->{ban_var} } ) {
			if ( !defined($item) || ref($item) ne '' ) {
				die( 'The ban_var of the rule "' . $name . '" contains a non-string entry' );
			}
		}
	} ## end if ( !$self->_check_detection_var( $def, $name...))

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

	if (   !@{ $self->{gates} }
		&& !defined( $self->{condition_ast} )
		&& !( ref( $self->{keyword_gates} ) eq 'ARRAY' && @{ $self->{keyword_gates} } )
		&& !@{ $self->{matches} } )
	{
		die(      'The rule "'
				. $name
				. '" has no gates, selections, keywords, or matches... it would regard nothing as a offense' );
	}

	# the correlation layer... capture entries harvest context under a key,
	# and a rule-level key makes the offense resolve through it. the stores,
	# the sweeping, and the key helpers are the base class's, shared with the
	# syslog and raw types... here a key component is a flattened field path
	# or a capture, there being no envelope
	$self->{captures} = [];
	if ( defined( $def->{capture} ) ) {
		if ( ref( $def->{capture} ) ne 'ARRAY' || !@{ $def->{capture} } ) {
			die( 'The capture of the rule "' . $name . '" is not a array or is empty' );
		}
		my $entry_int = 0;
		foreach my $entry ( @{ $def->{capture} } ) {
			my $where = 'The capture entry ' . $entry_int . ' of the rule "' . $name . '"';
			if ( ref($entry) ne 'HASH' ) {
				die( $where . ' is not a hash' );
			}
			foreach my $key ( keys( %{$entry} ) ) {
				if ( $key !~ /^(?:gate|match|key|ttl)$/ ) {
					die( $where . ' has the unknown key "' . $key . '"' );
				}
			}
			if ( !defined( $entry->{key} ) ) {
				die( $where . ' lacks a key' );
			}
			if ( !defined( $entry->{gate} ) && !defined( $entry->{match} ) ) {
				die( $where . ' has neither a gate nor a match... it would harvest every line' );
			}
			if ( defined( $entry->{ttl} ) && ( $entry->{ttl} !~ /^[0-9]+$/ || !$entry->{ttl} ) ) {
				die( $where . ' has a ttl that is not a positive int of seconds' );
			}

			my $compiled = {
				'key'     => $self->_correlation_key_components( $entry->{key}, $where ),
				'ttl'     => defined( $entry->{ttl} ) ? $entry->{ttl} : 60,
				'gates'   => undef,
				'matches' => [],
			};
			if ( defined( $entry->{gate} ) ) {
				$compiled->{gates} = $self->_compile_gates( $entry->{gate}, $where . ' gate' );
			}
			if ( defined( $entry->{match} ) ) {
				if ( ref( $entry->{match} ) ne 'ARRAY' || !@{ $entry->{match} } ) {
					die( $where . ' has a match that is not a array or is empty' );
				}
				my $match_int = 0;
				foreach my $match ( @{ $entry->{match} } ) {
					my $match_where = $where . ' match entry ' . $match_int;
					if ( ref($match) ne 'HASH' || !defined( $match->{field} ) || !defined( $match->{regexp} ) ) {
						die( $match_where . ' is not a hash with a field and a regexp' );
					}
					foreach my $key ( keys( %{$match} ) ) {
						if ( $key !~ /^(?:field|regexp)$/ ) {
							die( $match_where . ' has the unknown key "' . $key . '"' );
						}
					}
					push(
						@{ $compiled->{matches} },
						{
							'field' => $match->{field},
							'entry' => $self->_compile_tokened_regexp( $match->{regexp}, $match_where ),
						}
					);
					$match_int++;
				} ## end foreach my $match ( @{ $entry->{match} } )
			} ## end if ( defined( $entry->{match} ) )
			push( @{ $self->{captures} }, $compiled );
			$entry_int++;
		} ## end foreach my $entry ( @{ $def->{capture} } )
	} ## end if ( defined( $def->{capture} ) )

	if ( defined( $def->{key} ) ) {
		$self->{correlation_key}
			= { 'key' => $self->_correlation_key_components( $def->{key}, 'The key of the rule "' . $name . '"' ) };
	}
	if ( defined( $def->{defer} ) ) {
		if ( !defined( $def->{key} ) ) {
			die( 'The rule "' . $name . '" has a defer but no key for it to wait on' );
		}
		if ( ref( $def->{defer} ) ne '' || $def->{defer} !~ /^[0-9]+$/ || !$def->{defer} ) {
			die( 'The defer of the rule "' . $name . '" is not a positive int of seconds' );
		}
		$self->{defer} = $def->{defer};
	}

	return $self;
} ## end sub new

=head2 check

Checks a parsed line, as returned by L<App::Baphomet::Parser::JSON>,
against the rule. Returns undef for no match. For a match, returns a hash
as below, with data being the flattened fields merged with the captures of
the winning match entry, fields authoritative, and regexp being the index
of the match entry that hit, or undef for a gates only rule. For a
correlating rule the data may carry the merged stored context, a C<more>
array holds any further completed deferred offenses, and the passed scope
(the watcher name) walls one watcher's correlation state off from
another's.

    { 'data' => { 'SRC' => '192.0.2.5', 'msg' => '...', ... }, 'regexp' => 0 }

    my $found = $rule->check( $parsed, $scope );

=cut

sub check {
	my ( $self, $parsed, $scope ) = @_;

	if ( ref($parsed) ne 'HASH' || ref( $parsed->{fields} ) ne 'HASH' ) {
		return undef;
	}
	my $fields = $parsed->{fields};
	if ( !defined($scope) ) {
		$scope = '';
	}
	my $now = time;

	# a ignore hit vetoes the line entirely, context harvest included
	foreach my $ignore ( @{ $self->{ignores} } ) {
		if ( defined( $self->_match_tokened( $ignore->{entry}, $fields->{ $ignore->{field} } ) ) ) {
			return undef;
		}
	}

	# capture entries harvest context and may complete deferred offenses...
	# judged on their own gates and matches, not the rule's, since a context
	# event is rarely shaped like the offense
	my @completions;
	foreach my $capture ( @{ $self->{captures} } ) {
		if ( defined( $capture->{gates} ) && !$self->_gates_pass( $capture->{gates}, $fields, undef ) ) {
			next;
		}
		my $capture_caps;
		if ( @{ $capture->{matches} } ) {
			foreach my $match ( @{ $capture->{matches} } ) {
				$capture_caps = $self->_match_tokened( $match->{entry}, $fields->{ $match->{field} } );
				if ( defined($capture_caps) ) {
					last;
				}
			}
			if ( !defined($capture_caps) ) {
				next;
			}
		} else {
			$capture_caps = {};
		}

		# the stored context is the whole event... captures merged with the
		# flattened fields, fields authoritative, same as a found's data
		my %context = %{$capture_caps};
		foreach my $field ( keys( %{$fields} ) ) {
			$context{$field} = $fields->{$field};
		}

		my $key_value = $self->_correlation_key_value( $capture, \%context, undef );
		if ( !defined($key_value) ) {
			next;
		}
		$self->_context_store( $scope, $key_value, \%context, $capture->{ttl}, $now );

		my $pendings = delete( $self->{pending}{$scope}{$key_value} );
		if ( defined($pendings) ) {
			foreach my $pending ( @{$pendings} ) {
				if ( $pending->{expires} <= $now ) {
					next;
				}
				# the offense's own data is authoritative
				my %data = ( %context, %{ $pending->{caps} } );
				push( @completions, { 'data' => \%data, 'regexp' => $pending->{regexp} } );
			}
		} ## end if ( defined($pendings) )
	} ## end foreach my $capture ( @{ $self->{captures} } )

	# the offense itself... the boolean pre-filter, then the matches
	my $found;
	if ( $self->_boolean_pass( $fields, undef ) ) {
		my $matched;
		my $caps   = {};
		my $missed = 0;
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
				$missed = 1;
			}
		} ## end if ( @{ $self->{matches} } )

		if ( !$missed ) {
			# the flattened fields merged with the captures, fields authoritative
			my %data = %{$caps};
			foreach my $field ( keys( %{$fields} ) ) {
				$data{$field} = $fields->{$field};
			}
			$found = { 'data' => \%data, 'regexp' => $matched };
		}
	} ## end if ( $self->_boolean_pass( $fields, undef ...))

	# a keyed offense resolves through the stored context of a capture with
	# the same key... a key component that does not resolve leaves the
	# offense standing plain, mirroring the syslog type
	if ( defined($found) && defined( $self->{correlation_key} ) ) {
		my $key_value = $self->_correlation_key_value( $self->{correlation_key}, $found->{data}, undef );
		if ( defined($key_value) ) {
			my $stored = $self->{context}{$scope}{$key_value};
			if ( defined($stored) && $stored->{expires} > $now ) {
				my %data = ( %{ $stored->{data} }, %{ $found->{data} } );
				$found->{data} = \%data;
			} elsif ( $self->{defer} ) {
				# park it awaiting a capture with this key... the line was a
				# offense, just one that can not be resolved yet
				my $pendings = $self->{pending}{$scope}{$key_value};
				if ( !defined($pendings) ) {
					$pendings = $self->{pending}{$scope}{$key_value} = [];
				}
				push(
					@{$pendings},
					{ 'caps' => $found->{data}, 'regexp' => $found->{regexp}, 'expires' => $now + $self->{defer} }
				);
				# bound runaway pendings per key
				if ( scalar( @{$pendings} ) > 100 ) {
					shift( @{$pendings} );
				}
				$found = undef;
			} else {
				# unresolved and undeferred... not judged an offense, the
				# syslog type's fall-through
				$found = undef;
			}
		} ## end if ( defined($key_value) )
	} ## end if ( defined($found) && defined( $self->{correlation_key...}))

	my $primary = $found;
	if ( !defined($primary) && @completions ) {
		$primary = shift(@completions);
	}
	if ( defined($primary) && @completions ) {
		$primary->{more} = \@completions;
	}

	return $primary;
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
