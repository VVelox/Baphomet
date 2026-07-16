package App::Baphomet::Rules::Base;

use 5.006;
use strict;
use warnings;
use Regexp::IPv4          qw( $IPv4_re );
use Regexp::IPv6          qw( $IPv6_re );
use MIME::Base64          qw( decode_base64 );
use Encode                ();
use App::Baphomet::Parser ();
use App::Baphomet::Config qw( compile_ignore_ips ip_ignored );

=pod

=head1 NAME

App::Baphomet::Rules::Base - Shared plumbing for the Baphomet rule handlers.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

The bits common to every rule handler... the embedded test runner and the
string-or-C<//regexp//> matcher lists. Not usable on its own... see
L<App::Baphomet::Rules::Syslog> and L<App::Baphomet::Rules::HTTP> for the
handlers.

A handler is expected to provide C<check>, taking a parsed line and
returning undef or a hash with a C<data> hash of what got captured, and to
override L</default_test_parser> if C<bsd_syslog> is not the right default
for its tests.

A rule def may carry a top level C<test_parser> key, which sets the
parser for all of its embedded tests that do not name one themselves,
overriding the handler default... handy for a rule whose tests are all in
a non-default format, like a nginx rule of the http_error type.

=head1 METHODS

=head2 default_test_parser

The parser used for embedded tests that do not name one.

    my $parser = $rule->default_test_parser;

=cut

sub default_test_parser {
	return 'bsd_syslog';
}

=head2 sweep_state

Drops expired correlation context and pending deferred offenses. A no-op
for rules with out any. The galla calls this from its sweeper so expiry
does not depend on traffic.

    $rule->sweep_state($now);

=cut

sub sweep_state {
	my ( $self, $now ) = @_;

	if ( !defined($now) ) {
		$now = time;
	}

	foreach my $scope ( keys( %{ $self->{context} } ) ) {
		foreach my $key ( keys( %{ $self->{context}{$scope} } ) ) {
			if ( $self->{context}{$scope}{$key}{expires} <= $now ) {
				delete( $self->{context}{$scope}{$key} );
			}
		}
		if ( !keys( %{ $self->{context}{$scope} } ) ) {
			delete( $self->{context}{$scope} );
		}
	} ## end foreach my $scope ( keys( %{ $self->{context} }...))

	foreach my $scope ( keys( %{ $self->{pending} } ) ) {
		foreach my $key ( keys( %{ $self->{pending}{$scope} } ) ) {
			my @live = grep { $_->{expires} > $now } @{ $self->{pending}{$scope}{$key} };
			if (@live) {
				$self->{pending}{$scope}{$key} = \@live;
			} else {
				delete( $self->{pending}{$scope}{$key} );
			}
		}
		if ( !keys( %{ $self->{pending}{$scope} } ) ) {
			delete( $self->{pending}{$scope} );
		}
	} ## end foreach my $scope ( keys( %{ $self->{pending} }...))

	return;
} ## end sub sweep_state

=head2 ban_not_internal

Returns true if the rule wants only the found IPs that are not internal
banished, for rules like the Suricata ones where the offender may be the
src or the dest of a flow. The galla is what has the internal list and
does the filtering... this just exposes the rule's C<ban_not_internal>
def key. A rule type that does not allow the key never sees it set, so
this is false there.

    if ( $rule->ban_not_internal ) { ... }

=cut

sub ban_not_internal {
	my ($self) = @_;

	return $self->{def}{ban_not_internal} ? 1 : 0;
}

=head2 thresholds

Returns a hash of the rule's own threshold overrides, max_score,
find_time, and ban_time, holding only the keys the def actually sets...
a empty hash for a rule carrying none. The galla is what has the watcher
settings and decides if these are honored, per its
C<allow_per_rule_thresholds>... this just exposes the def keys. Cached,
as the def does not change.

    my $thresholds = $rule->thresholds;
    if ( %{$thresholds} ) { ... }

=cut

sub thresholds {
	my ($self) = @_;

	if ( !defined( $self->{thresholds} ) ) {
		my $thresholds = {};
		foreach my $item ( 'max_score', 'find_time', 'ban_time' ) {
			if ( defined( $self->{def}{$item} ) ) {
				$thresholds->{$item} = $self->{def}{$item};
			}
		}
		$self->{thresholds} = $thresholds;
	}

	return $self->{thresholds};
} ## end sub thresholds

=head2 weight

Returns the rule's weight, a positive number defaulting to 1... what a match
contributes to the offender's accumulated score toward a ban, so a dangerous
signature can weigh more and a noisy one less. Honored by the galla only when
the watcher's C<allow_per_rule_thresholds> is on, like the thresholds, so a
shipped rule can not quietly reshape an operator's tuning.

    my $weight = $rule->weight;

=cut

sub weight {
	my ($self) = @_;

	return defined( $self->{def}{weight} ) ? $self->{def}{weight} + 0 : 1;
}

=head2 eve_only

Returns the rule's own C<eve_only> as 0 or 1, or undef when the rule does not
set it... undef meaning inherit the watcher-resolved setting. When in force
the rule is in observe mode: its matches are written to EVE but never count
toward a real ban, and a would-be banish surfaces as an alert instead.

    my $eve_only = $rule->eve_only;   # undef, 0, or 1

=cut

sub eve_only {
	my ($self) = @_;

	if ( !exists( $self->{def}{eve_only} ) ) {
		return undef;
	}

	return $self->{def}{eve_only} ? 1 : 0;
}

=head2 msg

Returns the rule's msg, the human-readable signature naming what it detects,
Sagan/Suricata style (C<[TAG] description>). Falls back to the rule's name
when the def sets none, so the EVE msg field is always present and meaningful,
the way Suricata always has a signature.

    my $msg = $rule->msg;

=cut

sub msg {
	my ($self) = @_;

	if ( defined( $self->{def}{msg} ) ) {
		return $self->{def}{msg};
	}

	return $self->{name};
}

=head2 severity

Returns the rule's own severity (one of info/low/medium/high/critical), or
undef when the def sets none... undef meaning inherit the watcher-resolved
C<default_severity>. Triage metadata, inert to matching.

    my $severity = $rule->severity;   # undef or a level name

=cut

sub severity {
	my ($self) = @_;

	return $self->{def}{severity};
}

=head2 classtype

Returns the rule's classtype, a category string in the Snort/Sagan/Suricata
sense, or undef when unset. Emitted to EVE as-is.

    my $classtype = $rule->classtype;

=cut

sub classtype {
	my ($self) = @_;

	return $self->{def}{classtype};
}

=head2 references

Returns the rule's references (an array of URLs, CVE ids, or doc links) as an
array ref, or undef when the def sets none.

    my $references = $rule->references;

=cut

sub references {
	my ($self) = @_;

	return $self->{def}{references};
}

=head2 attack

Returns the rule's MITRE ATT&CK technique ids as an array ref, or undef when
the def sets none.

    my $attack = $rule->attack;

=cut

sub attack {
	my ($self) = @_;

	return $self->{def}{attack};
}

=head2 marks

Returns the array of marks the rule sets on match, each a hash of C<name>,
C<ttl>, and optionally C<var> (key by this capture instead of the offender
IP) and C<value_var> (store this capture as the mark's value)... a empty
array for a rule setting none. The galla is what has the marks store and
does the branding, this just exposes the def key.

    foreach my $mark ( @{ $rule->marks } ) { ... }

=cut

sub marks {
	my ($self) = @_;

	return ref( $self->{def}{mark} ) eq 'ARRAY' ? $self->{def}{mark} : [];
}

=head2 unmarks

Returns the array of marks the rule lifts on match, each a hash of C<name>
and optionally C<var>... a empty array for a rule lifting none.

    foreach my $unmark ( @{ $rule->unmarks } ) { ... }

=cut

sub unmarks {
	my ($self) = @_;

	return ref( $self->{def}{unmark} ) eq 'ARRAY' ? $self->{def}{unmark} : [];
}

=head2 mark_gates

Returns the rule's mark gates as a hash of two arrays, C<marked> and
C<not_marked>, either possibly empty. Each entry is a hash of C<name> and
optionally C<var>, and marked entries may also carry one of C<value_is> or
C<value_not>, naming a capture the stored value must equal or differ from.
The galla evaluates these against its marks store... a found result only
counts if every gate holds.

    my $gates = $rule->mark_gates;
    foreach my $gate ( @{ $gates->{marked} } ) { ... }

=cut

sub mark_gates {
	my ($self) = @_;

	return {
		'marked'     => ref( $self->{def}{marked} ) eq 'ARRAY'     ? $self->{def}{marked}     : [],
		'not_marked' => ref( $self->{def}{not_marked} ) eq 'ARRAY' ? $self->{def}{not_marked} : [],
	};
}

=head2 mark_only

Returns true if the rule only brands and gates, never counting toward a
ban... and a mark_only rule does not consume the line either, so matching
falls through to the watcher's later rules.

    if ( $rule->mark_only ) { ... }

=cut

sub mark_only {
	my ($self) = @_;

	return $self->{def}{mark_only} ? 1 : 0;
}

=head2 country

Returns the rule's country gate normalized, or undef when it has none. The
gate is a hash of C<mode> (C<is> or C<isnot>), C<entries> (the raw list, 2-
letter codes and C<%%%country_codes{name}%%%> imports still unexpanded, as
the config to expand against is the galla's per watcher), and C<vars> (the
found vars to check the country of, or undef to check the offender IP). The
galla resolves the imports and does the lookups. Cached.

    my $country = $rule->country;

=cut

sub country {
	my ($self) = @_;

	if ( !exists( $self->{country_parsed} ) ) {
		my $def = $self->{def}{country};
		if ( ref($def) ne 'HASH' ) {
			$self->{country_parsed} = undef;
		} else {
			my $mode = defined( $def->{is} ) ? 'is' : 'isnot';
			$self->{country_parsed} = {
				'mode'    => $mode,
				'entries' => [ ref( $def->{$mode} ) eq 'ARRAY' ? @{ $def->{$mode} } : ( $def->{$mode} ) ],
				'vars'    => ref( $def->{vars} ) eq 'ARRAY' ? $def->{vars}
				: defined( $def->{vars} ) ? [ $def->{vars} ]
				:                           undef,
			};
		} ## end else [ if ( ref($def) ne 'HASH' ) ]
	} ## end if ( !exists( $self->{country_parsed} ) )

	return $self->{country_parsed};
} ## end sub country

=head2 namtar_list

Returns the rule's namtar_list gate normalized, or undef when it has none.
The gate is a array of entries, each a hash of C<lists> (the named list
references, still unresolved as the config to resolve against is the
galla's per watcher) and C<var> (the found var to check, or undef for the
offender IP). The galla resolves the list names to files and does the
membership tests. Cached.

    foreach my $entry ( @{ $rule->namtar_list } ) { ... }

=cut

sub namtar_list {
	my ($self) = @_;

	if ( !exists( $self->{namtar_parsed} ) ) {
		my $def = $self->{def}{namtar_list};
		if ( ref($def) ne 'ARRAY' ) {
			$self->{namtar_parsed} = undef;
		} else {
			my @entries;
			foreach my $entry ( @{$def} ) {
				my $lists = defined( $entry->{lists} ) ? $entry->{lists} : $entry->{list};
				push(
					@entries,
					{
						'lists' => [ ref($lists) eq 'ARRAY' ? @{$lists} : ($lists) ],
						'var'   => $entry->{var},
					}
				);
			} ## end foreach my $entry ( @{$def} )
			$self->{namtar_parsed} = \@entries;
		} ## end else [ if ( ref($def) ne 'ARRAY' ) ]
	} ## end if ( !exists( $self->{namtar_parsed} ) )

	return $self->{namtar_parsed};
} ## end sub namtar_list

=head2 active_time

Returns the rule's active_time gate normalized, or undef when it has none.
The gate is a hash of C<mode> (C<is> or C<isnot>), C<windows> (the named
window references, still unresolved as the config to resolve against is the
galla's per watcher), and C<vars> (the found vars holding the times to
check, or undef to check the current time). The galla resolves the window
names to specs and does the time tests. Cached.

    my $active = $rule->active_time;

=cut

sub active_time {
	my ($self) = @_;

	if ( !exists( $self->{active_parsed} ) ) {
		my $def = $self->{def}{active_time};
		if ( ref($def) ne 'HASH' ) {
			$self->{active_parsed} = undef;
		} else {
			my $mode = defined( $def->{is} ) ? 'is' : 'isnot';
			$self->{active_parsed} = {
				'mode'    => $mode,
				'windows' => [ ref( $def->{$mode} ) eq 'ARRAY' ? @{ $def->{$mode} } : ( $def->{$mode} ) ],
				'vars'    => ref( $def->{vars} ) eq 'ARRAY' ? $def->{vars}
				: defined( $def->{vars} ) ? [ $def->{vars} ]
				:                           undef,
			};
		} ## end else [ if ( ref($def) ne 'HASH' ) ]
	} ## end if ( !exists( $self->{active_parsed} ) )

	return $self->{active_parsed};
} ## end sub active_time

=head2 distinct

Returns the rule's distinct-cardinality spec, a hash naming C<of> (the found
var whose distinct values are counted per offender), or undef when the rule
counts hits the usual way. The galla is what does the counting... this just
exposes the def key.

    my $distinct = $rule->distinct;   # undef or { of => 'USER' }

=cut

sub distinct {
	my ($self) = @_;

	return ( ref( $self->{def}{distinct} ) eq 'HASH' ) ? $self->{def}{distinct} : undef;
}

=head2 info

Returns the rule's name and def with the embedded tests stripped, for the
EVE log's rule field... the tests would bloat every event for no value.
Cached, as the def does not change.

    my $info = $rule->info;

=cut

sub info {
	my ($self) = @_;

	if ( !defined( $self->{info} ) ) {
		my %def = %{ $self->{def} };
		delete( $def{tests} );
		$self->{info} = { 'name' => $self->{name}, 'def' => \%def };
	}

	return $self->{info};
} ## end sub info

=head2 dump_state

Returns the live correlation state, context and pendings, as a plain data
structure for persisting... undef when there is none. The galla writes
this to a tablet so a restart does not forget a half correlated offense.

    my $state = $rule->dump_state;

=cut

sub dump_state {
	my ($self) = @_;

	if ( !( $self->{context} && %{ $self->{context} } ) && !( $self->{pending} && %{ $self->{pending} } ) ) {
		return undef;
	}

	return {
		'context' => $self->{context},
		'pending' => $self->{pending},
	};
} ## end sub dump_state

=head2 restore_state

Restores correlation state from what L</dump_state> returned, dropping
anything already expired as of $now. Merges into whatever is present
rather than replacing, so it is safe to call at start.

    $rule->restore_state( $state, $now );

=cut

sub restore_state {
	my ( $self, $state, $now ) = @_;

	if ( ref($state) ne 'HASH' ) {
		return;
	}
	if ( !defined($now) ) {
		$now = time;
	}

	if ( ref( $state->{context} ) eq 'HASH' ) {
		foreach my $scope ( keys( %{ $state->{context} } ) ) {
			foreach my $key ( keys( %{ $state->{context}{$scope} } ) ) {
				my $entry = $state->{context}{$scope}{$key};
				if ( ref($entry) eq 'HASH' && defined( $entry->{expires} ) && $entry->{expires} > $now ) {
					$self->{context}{$scope}{$key} = $entry;
				}
			}
		}
	} ## end if ( ref( $state->{context} ) eq 'HASH' )

	if ( ref( $state->{pending} ) eq 'HASH' ) {
		foreach my $scope ( keys( %{ $state->{pending} } ) ) {
			foreach my $key ( keys( %{ $state->{pending}{$scope} } ) ) {
				my @live = grep { ref($_) eq 'HASH' && defined( $_->{expires} ) && $_->{expires} > $now }
					@{ $state->{pending}{$scope}{$key} };
				if (@live) {
					push( @{ $self->{pending}{$scope}{$key} }, @live );
				}
			}
		}
	} ## end if ( ref( $state->{pending} ) eq 'HASH' )

	return;
} ## end sub restore_state

=head2 run_tests

Runs the tests embedded in the rule. Returns a hash as below. Does not die
on test failures... that is the caller's call to make.

    {
        'pass'     => 3,
        'fail'     => 0,
        'failures' => [],
    }

    my $results = $rule->run_tests;

=cut

sub run_tests {
	my ($self) = @_;

	my $results = {
		'pass'     => 0,
		'fail'     => 0,
		'failures' => [],
	};

	my $tests = $self->{def}{tests};
	if ( ref($tests) ne 'HASH' ) {
		return $results;
	}

	foreach my $sort ( 'positive', 'negative' ) {
		if ( !defined( $tests->{$sort} ) ) {
			next;
		}
		if ( ref( $tests->{$sort} ) ne 'ARRAY' ) {
			$results->{fail}++;
			push( @{ $results->{failures} }, $sort . ' tests is not a array' );
			next;
		}

		my $test_int = 0;
		foreach my $test ( @{ $tests->{$sort} } ) {
			my $where = $sort . ' test ' . $test_int;
			$test_int++;

			if ( ref($test) ne 'HASH' || ( !defined( $test->{message} ) && ref( $test->{messages} ) ne 'ARRAY' ) ) {
				$results->{fail}++;
				push( @{ $results->{failures} }, $where . ' is not a hash with a message or a messages array' );
				next;
			}

			my @messages = defined( $test->{message} ) ? ( $test->{message} ) : @{ $test->{messages} };

			my $parser
				= defined( $test->{parser} )           ? $test->{parser}
				: defined( $self->{def}{test_parser} ) ? $self->{def}{test_parser}
				:                                        $self->default_test_parser;

			# each test entry gets a throwaway correlation scope of its own
			my $test_scope = 'run_tests ' . $where;

			my @found_all;
			my $parse_failed = 0;
			foreach my $message (@messages) {
				my $parsed;
				eval { $parsed = App::Baphomet::Parser::parse( $parser, $message ); };
				if ($@) {
					$results->{fail}++;
					push( @{ $results->{failures} }, $where . ' has a unusable parser... ' . $@ );
					$parse_failed = 1;
					last;
				}
				if ( !defined($parsed) ) {
					$results->{fail}++;
					push(
						@{ $results->{failures} },
						$where . ' message did not parse via ' . $parser . '... "' . $message . '"'
					);
					$parse_failed = 1;
					last;
				}

				my $found = $self->check( $parsed, $test_scope );
				if ( defined($found) ) {
					push( @found_all, $found );
					if ( ref( $found->{more} ) eq 'ARRAY' ) {
						push( @found_all, @{ $found->{more} } );
					}
				}
			} ## end foreach my $message (@messages)
			if ($parse_failed) {
				next;
			}

			my $expected_found = defined( $test->{found} ) ? $test->{found} : ( $sort eq 'positive' ? 1 : 0 );
			my $got_found      = scalar(@found_all);

			if ( $got_found != $expected_found ) {
				$results->{fail}++;
				push(
					@{ $results->{failures} },
					$where
						. ' expected found='
						. $expected_found
						. ' but got found='
						. $got_found
						. ' for "'
						. $messages[-1] . '"'
				);
				next;
			} ## end if ( $got_found != $expected_found )

			my $found = @found_all ? $found_all[-1] : undef;

			my $data_failed = 0;
			if ( defined( $test->{data} ) && ref( $test->{data} ) eq 'HASH' ) {
				foreach my $key ( sort( keys( %{ $test->{data} } ) ) ) {
					my $got = defined($found) ? $found->{data}{$key} : undef;
					if ( !defined($got) || $got ne $test->{data}{$key} ) {
						$results->{fail}++;
						push(
							@{ $results->{failures} },
							$where
								. ' expected data.'
								. $key . '="'
								. $test->{data}{$key}
								. '" but got '
								. ( defined($got) ? '"' . $got . '"' : 'undef' )
						);
						$data_failed = 1;
						last;
					} ## end if ( !defined($got) || $got ne $test->{data...})
				} ## end foreach my $key ( sort( keys( %{ $test->{data} ...})))
			} ## end if ( defined( $test->{data} ) && ref( $test...))

			if ( defined( $test->{undefed} ) && ref( $test->{undefed} ) eq 'ARRAY' && !$data_failed ) {
				foreach my $key ( @{ $test->{undefed} } ) {
					my $got = defined($found) ? $found->{data}{$key} : undef;
					if ( defined($got) ) {
						$results->{fail}++;
						push(
							@{ $results->{failures} },
							$where . ' expected ' . $key . ' to be undef but got "' . $got . '"'
						);
						$data_failed = 1;
						last;
					}
				} ## end foreach my $key ( @{ $test->{undefed} } )
			} ## end if ( defined( $test->{undefed} ) && ref( $test...))

			if ( !$data_failed ) {
				$results->{pass}++;
			}
		} ## end foreach my $test ( @{ $tests->{$sort} } )
	} ## end foreach my $sort ( 'positive', 'negative' )

	return $results;
} ## end sub run_tests

my $dns_re = qr/(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9\-]{0,62}/;

my %tokens = (
	'IP4'    => qr/$IPv4_re/,
	'IP6'    => qr/$IPv6_re/,
	'ADDR'   => qr/(?:$IPv4_re|$IPv6_re)/,
	'DNS'    => $dns_re,
	'HOST'   => qr/(?:$IPv4_re|$IPv6_re|$dns_re)/,
	'SUBNET' => qr/(?:$IPv4_re|$IPv6_re)(?:\/[0-9]{1,3})?/,
	'SRC'    => qr/(?:$IPv4_re|$IPv6_re)/,
	'DEST'   => qr/(?:$IPv4_re|$IPv6_re)/,
);

# the severity scale, worst last... the ordinal is unused for now but keeps
# the order canonical if anything ever wants to sort or compare
our %SEVERITY = ( 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4 );

# dies if the def's threshold overrides, max_score, find_time, and
# ban_time, or its weight or eve_only, hold unusable values... positive ints
# for the thresholds (non-negative ban_time, 0 meaning eternal), a positive
# number for weight, a boolean for eve_only... called by every handler's new,
# as the keys are legal on every type
sub _check_thresholds {
	my ( $self, $def ) = @_;

	my $name = $self->{name};

	foreach my $item ( 'max_score', 'find_time' ) {
		if ( defined( $def->{$item} )
			&& ( ref( $def->{$item} ) ne '' || $def->{$item} !~ /^[0-9]+$/ || !$def->{$item} ) )
		{
			die( 'The rule "' . $name . '" has a ' . $item . ', "' . $def->{$item} . '", that is not a positive int' );
		}
	}
	if ( defined( $def->{ban_time} ) && ( ref( $def->{ban_time} ) ne '' || $def->{ban_time} !~ /^[0-9]+$/ ) ) {
		die(      'The rule "'
				. $name
				. '" has a ban_time, "'
				. $def->{ban_time}
				. '", that is not a non-negative int of seconds' );
	}
	if (
		defined( $def->{weight} )
		&& (   ref( $def->{weight} ) ne ''
			|| $def->{weight} !~ /^[0-9]+(?:\.[0-9]+)?$/
			|| $def->{weight} + 0 <= 0 )
		)
	{
		die( 'The rule "' . $name . '" has a weight, "' . $def->{weight} . '", that is not a positive number' );
	}
	if ( defined( $def->{eve_only} ) && ref( $def->{eve_only} ) ne '' ) {
		die( 'The rule "' . $name . '" has a eve_only that is not a boolean' );
	}
	if ( defined( $def->{msg} ) && ( ref( $def->{msg} ) ne '' || $def->{msg} eq '' ) ) {
		die( 'The rule "' . $name . '" has a msg that is not a non-empty string' );
	}
	if ( defined( $def->{severity} ) && ( ref( $def->{severity} ) ne '' || !exists( $SEVERITY{ $def->{severity} } ) ) )
	{
		die( 'The rule "' . $name . '" has a severity that is not one of info/low/medium/high/critical' );
	}
	if ( defined( $def->{classtype} ) && ( ref( $def->{classtype} ) ne '' || $def->{classtype} eq '' ) ) {
		die( 'The rule "' . $name . '" has a classtype that is not a non-empty string' );
	}
	foreach my $listkey ( 'references', 'attack' ) {
		if ( !defined( $def->{$listkey} ) ) {
			next;
		}
		if ( ref( $def->{$listkey} ) ne 'ARRAY' || !@{ $def->{$listkey} } ) {
			die( 'The rule "' . $name . '" has a ' . $listkey . ' that is not a non-empty array' );
		}
		foreach my $item ( @{ $def->{$listkey} } ) {
			if ( !defined($item) || ref($item) ne '' || $item eq '' ) {
				die( 'The rule "' . $name . '" has a ' . $listkey . ' entry that is not a non-empty string' );
			}
		}
	} ## end foreach my $listkey ( 'references', 'attack' )

	return;
} ## end sub _check_thresholds

# dies if the def's mark keys, mark, unmark, marked, not_marked, and
# mark_only, hold unusable values... called by every handler's new, as the
# keys are legal on every type. Names are constrained like rule names so
# they ride tablets and commands cleanly.
sub _check_marks {
	my ( $self, $def ) = @_;

	my $name = $self->{name};

	my %shapes = (
		'mark'       => { 'name' => 'required', 'ttl' => 'ttl', 'var' => 'string', 'value_var' => 'string' },
		'unmark'     => { 'name' => 'required', 'var' => 'string' },
		'marked'     => { 'name' => 'required', 'var' => 'string', 'value_is' => 'string', 'value_not' => 'string' },
		'not_marked' => { 'name' => 'required', 'var' => 'string' },
	);

	foreach my $key ( keys(%shapes) ) {
		if ( !defined( $def->{$key} ) ) {
			next;
		}
		my $where = 'The ' . $key . ' of the rule "' . $name . '"';
		if ( ref( $def->{$key} ) ne 'ARRAY' || !@{ $def->{$key} } ) {
			die( $where . ' is not a non-empty array' );
		}
		foreach my $entry ( @{ $def->{$key} } ) {
			if ( ref($entry) ne 'HASH' ) {
				die( $where . ' contains a entry that is not a hash' );
			}
			foreach my $entry_key ( keys( %{$entry} ) ) {
				if ( !defined( $shapes{$key}{$entry_key} ) ) {
					die( $where . ' has a entry with the unknown key "' . $entry_key . '"' );
				}
			}
			if ( !defined( $entry->{name} ) || ref( $entry->{name} ) ne '' || $entry->{name} !~ /^[a-zA-Z0-9_\-]+$/ ) {
				die( $where . ' has a entry lacking a name matching /^[a-zA-Z0-9_\-]+$/' );
			}
			if (
				defined( $shapes{$key}{ttl} )
				&& (  !defined( $entry->{ttl} )
					|| ref( $entry->{ttl} ) ne ''
					|| $entry->{ttl} !~ /^[0-9]+$/
					|| !$entry->{ttl} )
				)
			{
				die( $where . ' entry "' . $entry->{name} . '" lacks a ttl that is a positive int of seconds' );
			} ## end if ( defined( $shapes{$key}{ttl} ) && ( !defined...))
			foreach my $string_key (
				grep { defined( $shapes{$key}{$_} ) && $shapes{$key}{$_} eq 'string' }
				keys( %{$entry} )
				)
			{
				if (  !defined( $entry->{$string_key} )
					|| ref( $entry->{$string_key} ) ne ''
					|| $entry->{$string_key} eq '' )
				{
					die(      $where
							. ' entry "'
							. $entry->{name}
							. '" has a '
							. $string_key
							. ' that is not a non-empty string' );
				} ## end if ( !defined( $entry->{$string_key} ) || ...)
			} ## end foreach my $string_key ( grep { defined( $shapes...)})
			if ( defined( $entry->{value_is} ) && defined( $entry->{value_not} ) ) {
				die( $where . ' entry "' . $entry->{name} . '" carries both value_is and value_not' );
			}
		} ## end foreach my $entry ( @{ $def->{$key} } )
	} ## end foreach my $key ( keys(%shapes) )

	return;
} ## end sub _check_marks

# dies if the def's country gate is malformed... is xor isnot, each a 2-
# letter code or a %%%country_codes{name}%%% import, vars an optional list
# of found vars to check instead of the offender. the token names are
# resolved against the config later, by the galla, per watcher
sub _check_country {
	my ( $self, $def ) = @_;

	if ( !defined( $def->{country} ) ) {
		return;
	}

	my $name  = $self->{name};
	my $where = 'The country gate of the rule "' . $name . '"';
	my $c     = $def->{country};

	if ( ref($c) ne 'HASH' ) {
		die( $where . ' is not a hash' );
	}
	foreach my $key ( keys( %{$c} ) ) {
		if ( $key !~ /^(?:is|isnot|vars)$/ ) {
			die( $where . ' has the unknown key "' . $key . '"' );
		}
	}
	if ( defined( $c->{is} ) && defined( $c->{isnot} ) ) {
		die( $where . ' carries both is and isnot' );
	}
	if ( !defined( $c->{is} ) && !defined( $c->{isnot} ) ) {
		die( $where . ' has neither is nor isnot' );
	}

	my $mode    = defined( $c->{is} )           ? 'is'             : 'isnot';
	my @entries = ref( $c->{$mode} ) eq 'ARRAY' ? @{ $c->{$mode} } : ( $c->{$mode} );
	if ( !@entries ) {
		die( $where . ' ' . $mode . ' is empty' );
	}
	foreach my $entry (@entries) {
		if (  !defined($entry)
			|| ref($entry) ne ''
			|| $entry !~ /^(?:[A-Za-z]{2}|%%%country_codes\{[a-zA-Z0-9_\-]+\}%%%)$/ )
		{
			die(      $where . ' '
					. $mode
					. ' has a entry that is not a 2-letter code or a %%%country_codes{name}%%% import' );
		}
	} ## end foreach my $entry (@entries)

	if ( defined( $c->{vars} ) ) {
		my @vars = ref( $c->{vars} ) eq 'ARRAY' ? @{ $c->{vars} } : ( $c->{vars} );
		if ( !@vars ) {
			die( $where . ' vars is empty' );
		}
		foreach my $var (@vars) {
			if ( !defined($var) || ref($var) ne '' || $var eq '' ) {
				die( $where . ' vars has a entry that is not a non-empty string' );
			}
		}
	} ## end if ( defined( $c->{vars} ) )

	return;
} ## end sub _check_country

# dies if the def's namtar_list gate is malformed... a array of entries,
# each naming one or more lists (list or lists) and a optional var to check
# instead of the offender. the list names are resolved against the config
# later, by the galla, per watcher
sub _check_namtar {
	my ( $self, $def ) = @_;

	if ( !defined( $def->{namtar_list} ) ) {
		return;
	}

	my $name  = $self->{name};
	my $where = 'The namtar_list gate of the rule "' . $name . '"';

	if ( ref( $def->{namtar_list} ) ne 'ARRAY' || !@{ $def->{namtar_list} } ) {
		die( $where . ' is not a non-empty array' );
	}
	foreach my $entry ( @{ $def->{namtar_list} } ) {
		if ( ref($entry) ne 'HASH' ) {
			die( $where . ' has a entry that is not a hash' );
		}
		foreach my $key ( keys( %{$entry} ) ) {
			if ( $key !~ /^(?:list|lists|var)$/ ) {
				die( $where . ' has a entry with the unknown key "' . $key . '"' );
			}
		}
		if ( defined( $entry->{list} ) && defined( $entry->{lists} ) ) {
			die( $where . ' has a entry carrying both list and lists' );
		}
		my $lists = defined( $entry->{lists} ) ? $entry->{lists} : $entry->{list};
		if ( !defined($lists) ) {
			die( $where . ' has a entry lacking a list or lists' );
		}
		my @lists = ref($lists) eq 'ARRAY' ? @{$lists} : ($lists);
		if ( !@lists ) {
			die( $where . ' has a entry with a empty lists' );
		}
		foreach my $list (@lists) {
			if ( !defined($list) || ref($list) ne '' || $list !~ /^[a-zA-Z0-9_\-]+$/ ) {
				die( $where . ' has a list name that is not a /^[a-zA-Z0-9_\-]+$/ string' );
			}
		}
		if ( defined( $entry->{var} ) && ( ref( $entry->{var} ) ne '' || $entry->{var} eq '' ) ) {
			die( $where . ' has a var that is not a non-empty string' );
		}
	} ## end foreach my $entry ( @{ $def->{namtar_list} } )

	return;
} ## end sub _check_namtar

# dies if the def's active_time gate is malformed... is xor isnot, each a
# window name or a array of them, vars an optional list of found vars whose
# times to check instead of now. the window names are resolved against the
# config later, by the galla, per watcher
sub _check_active_time {
	my ( $self, $def ) = @_;

	if ( !defined( $def->{active_time} ) ) {
		return;
	}

	my $name  = $self->{name};
	my $where = 'The active_time gate of the rule "' . $name . '"';
	my $a     = $def->{active_time};

	if ( ref($a) ne 'HASH' ) {
		die( $where . ' is not a hash' );
	}
	foreach my $key ( keys( %{$a} ) ) {
		if ( $key !~ /^(?:is|isnot|vars)$/ ) {
			die( $where . ' has the unknown key "' . $key . '"' );
		}
	}
	if ( defined( $a->{is} ) && defined( $a->{isnot} ) ) {
		die( $where . ' carries both is and isnot' );
	}
	if ( !defined( $a->{is} ) && !defined( $a->{isnot} ) ) {
		die( $where . ' has neither is nor isnot' );
	}

	my $mode    = defined( $a->{is} )           ? 'is'             : 'isnot';
	my @windows = ref( $a->{$mode} ) eq 'ARRAY' ? @{ $a->{$mode} } : ( $a->{$mode} );
	if ( !@windows ) {
		die( $where . ' ' . $mode . ' is empty' );
	}
	foreach my $window (@windows) {
		if ( !defined($window) || ref($window) ne '' || $window !~ /^[a-zA-Z0-9_\-]+$/ ) {
			die( $where . ' ' . $mode . ' has a window name that is not a /^[a-zA-Z0-9_\-]+$/ string' );
		}
	}

	if ( defined( $a->{vars} ) ) {
		my @vars = ref( $a->{vars} ) eq 'ARRAY' ? @{ $a->{vars} } : ( $a->{vars} );
		if ( !@vars ) {
			die( $where . ' vars is empty' );
		}
		foreach my $var (@vars) {
			if ( !defined($var) || ref($var) ne '' || $var eq '' ) {
				die( $where . ' vars has a entry that is not a non-empty string' );
			}
		}
	} ## end if ( defined( $a->{vars} ) )

	return;
} ## end sub _check_active_time

# checks the distinct-cardinality spec, dieing on anything unusable... a table
# with a of naming the found var whose distinct values the galla counts
sub _check_distinct {
	my ( $self, $def ) = @_;

	if ( !defined( $def->{distinct} ) ) {
		return;
	}
	my $name = $self->{name};
	my $spec = $def->{distinct};

	if ( ref($spec) ne 'HASH' ) {
		die( 'The distinct of the rule "' . $name . '" is not a table' );
	}
	foreach my $key ( keys( %{$spec} ) ) {
		if ( $key ne 'of' ) {
			die( 'The distinct of the rule "' . $name . '" has the unknown key "' . $key . '"' );
		}
	}
	if ( !defined( $spec->{of} ) || ref( $spec->{of} ) ne '' || $spec->{of} eq '' ) {
		die(      'The distinct of the rule "'
				. $name
				. '" lacks a non-empty of naming the field to count distinct values of' );
	}

	return;
} ## end sub _check_distinct

# compiles the message_regexp and ignore_regexp of the passed def,
# expanding %%%%TOKEN%%%% tokens into named captures, and populates
# regexps and ignore_regexps on the object... shared by the handlers
# whose matching is regexps against a message with something to extract
sub _compile_message_regexps {
	my ( $self, $def, $allow_empty ) = @_;

	my $name = $self->{name};

	$self->{regexps}        = [];
	$self->{ignore_regexps} = [];

	# a message_json rule may have no message_regexp, the json fields being
	# what it matches on, so the caller can allow an empty list. a missing key
	# is fine then; a present but malformed one is still an error
	if ( !defined( $def->{message_regexp} ) && $allow_empty ) {
		return;
	}
	if ( ref( $def->{message_regexp} ) ne 'ARRAY' || !@{ $def->{message_regexp} } ) {
		if ( $allow_empty && !defined( $def->{message_regexp} ) ) {
			return;
		}
		die( 'The rule "' . $name . '" lacks a message_regexp array or it is empty' );
	}
	foreach my $item ( @{ $def->{message_regexp} } ) {
		if ( !defined($item) || ( ref($item) ne '' && ref($item) ne 'HASH' ) ) {
			die( 'The message_regexp of the rule "' . $name . '" contains a entry that is not a string or a hash' );
		}
		if ( ref($item) eq 'HASH' ) {
			foreach my $key ( keys( %{$item} ) ) {
				if ( $key !~ /^(?:regexp|key|defer)$/ ) {
					die( 'A message_regexp entry of the rule "' . $name . '" has the unknown key "' . $key . '"' );
				}
			}
			if ( !defined( $item->{regexp} ) || ref( $item->{regexp} ) ne '' ) {
				die( 'A message_regexp entry of the rule "' . $name . '" lacks a regexp string' );
			}
			if ( !defined( $item->{key} ) || ref( $item->{key} ) ne '' || $item->{key} eq '' ) {
				die( 'A message_regexp hash entry of the rule "' . $name . '" lacks a key' );
			}
			if ( defined( $item->{defer} ) && ( $item->{defer} !~ /^[0-9]+$/ || !$item->{defer} ) ) {
				die(      'The defer of a message_regexp entry of the rule "'
						. $name
						. '" is not a positive int of seconds' );
			}
		} ## end if ( ref($item) eq 'HASH' )
	} ## end foreach my $item ( @{ $def->{message_regexp} } )

	if ( defined( $def->{ignore_regexp} ) ) {
		if ( ref( $def->{ignore_regexp} ) ne 'ARRAY' ) {
			die( 'The ignore_regexp of the rule "' . $name . '" is not a array' );
		}
		foreach my $item ( @{ $def->{ignore_regexp} } ) {
			if ( !defined($item) || ref($item) ne '' ) {
				die( 'The ignore_regexp of the rule "' . $name . '" contains a non-string entry' );
			}
		}

		# tokens work here too, but nothing is captured from them, so the
		# aliases are just thrown away
		my $ignore_int = 0;
		foreach my $regexp ( @{ $def->{ignore_regexp} } ) {
			my $entry = $self->_compile_tokened_regexp( $regexp,
				'The ignore_regexp entry ' . $ignore_int . ' of the rule "' . $name . '"' );
			push( @{ $self->{ignore_regexps} }, $entry->{regexp} );
			$ignore_int++;
		}
	} ## end if ( defined( $def->{ignore_regexp} ) )

	my $entry_int = 0;
	foreach my $item ( @{ $def->{message_regexp} } ) {
		my $regexp   = ref($item) eq 'HASH' ? $item->{regexp} : $item;
		my $compiled = $self->_compile_tokened_regexp( $regexp,
			'The message_regexp entry ' . $entry_int . ' of the rule "' . $name . '"' );
		if ( ref($item) eq 'HASH' ) {
			$compiled->{key}   = $item->{key};
			$compiled->{defer} = $item->{defer};
		}
		push( @{ $self->{regexps} }, $compiled );
		$entry_int++;
	} ## end foreach my $item ( @{ $def->{message_regexp} } )

	return;
} ## end sub _compile_message_regexps

# compiles the capture_regexp of the passed def... entries harvest
# correlation context rather than being offenses, each a hash of a
# tokened regexp, the capture name serving as the correlation key, and a
# ttl for how long the harvested captures live
sub _compile_capture_regexps {
	my ( $self, $def ) = @_;

	my $name = $self->{name};

	$self->{capture_regexps} = [];

	if ( !defined( $def->{capture_regexp} ) ) {
		return;
	}
	if ( ref( $def->{capture_regexp} ) ne 'ARRAY' || !@{ $def->{capture_regexp} } ) {
		die( 'The capture_regexp of the rule "' . $name . '" is not a array or is empty' );
	}

	my $entry_int = 0;
	foreach my $item ( @{ $def->{capture_regexp} } ) {
		my $where = 'The capture_regexp entry ' . $entry_int . ' of the rule "' . $name . '"';
		if ( ref($item) ne 'HASH' || !defined( $item->{regexp} ) || !defined( $item->{key} ) ) {
			die( $where . ' is not a hash with a regexp and a key' );
		}
		foreach my $key ( keys( %{$item} ) ) {
			if ( $key !~ /^(?:regexp|key|ttl)$/ ) {
				die( $where . ' has the unknown key "' . $key . '"' );
			}
		}
		if ( ref( $item->{key} ) ne '' || $item->{key} eq '' ) {
			die( $where . ' has a invalid key' );
		}
		if ( defined( $item->{ttl} ) && ( $item->{ttl} !~ /^[0-9]+$/ || !$item->{ttl} ) ) {
			die( $where . ' has a ttl that is not a positive int of seconds' );
		}

		my $compiled = $self->_compile_tokened_regexp( $item->{regexp}, $where );
		$compiled->{key} = $item->{key};
		$compiled->{ttl} = defined( $item->{ttl} ) ? $item->{ttl} : 60;

		push( @{ $self->{capture_regexps} }, $compiled );
		$entry_int++;
	} ## end foreach my $item ( @{ $def->{capture_regexp} } )

	return;
} ## end sub _compile_capture_regexps

# compiles a single regexp string, expanding %%%%TOKEN%%%% tokens into
# named captures... returns a hash of the compiled regexp, the original,
# the alias map for folding, and whether SRC and DEST are paired in it...
# $where is the lead in for error messages
sub _compile_tokened_regexp {
	my ( $self, $regexp, $where ) = @_;

	my %aliases;
	my $expanded = $regexp;
	$expanded =~ s/%%%%([A-Z0-9]+)%%%%/$self->_expand_token( $1, \%aliases, $where, $regexp )/ge;

	my $compiled;
	eval { $compiled = qr/$expanded/; };
	if ($@) {
		die( $where . ', "' . $regexp . '", does not compile... ' . $@ );
	}

	return {
		'regexp'   => $compiled,
		'original' => $regexp,
		'aliases'  => \%aliases,
		'paired'   => ( defined( $aliases{SRC} ) && defined( $aliases{DEST} ) ) ? 1 : 0,
	};
} ## end sub _compile_tokened_regexp

# expands a single token occurrence into a named capture group, numbering
# the capture name if the token has already been seen in this entry given
# perl does not allow duplicate capture names in a single regexp
sub _expand_token {
	my ( $self, $token, $aliases, $where, $original ) = @_;

	if ( !defined( $tokens{$token} ) ) {
		die( $where . ', "' . $original . '", uses the unknown token "' . $token . '"' );
	}

	if ( !defined( $aliases->{$token} ) ) {
		$aliases->{$token} = [$token];
		return '(?<' . $token . '>' . $tokens{$token} . ')';
	}

	my $alias = $token . '_' . ( scalar( @{ $aliases->{$token} } ) + 1 );
	push( @{ $aliases->{$token} }, $alias );

	return '(?<' . $alias . '>' . $tokens{$token} . ')';
} ## end sub _expand_token

# checks a message against the compiled capture, ignore, and message
# regexps... returns undef or a found hash with the folded captures,
# possibly carrying a more array of further completions when a capture
# line resolved deferred offenses
sub _check_message {
	my ( $self, $message, $scope, $extra ) = @_;

	if ( !defined($message) ) {
		return undef;
	}
	if ( !defined($scope) ) {
		$scope = '';
	}
	my $now = time;

	# a ignore_regexp match vetoes the line entirely
	foreach my $ignore ( @{ $self->{ignore_regexps} } ) {
		if ( $message =~ $ignore ) {
			return undef;
		}
	}

	# capture lines harvest context and may complete deferred offenses
	my @completions;
	foreach my $capture ( @{ $self->{capture_regexps} } ) {
		my $caps = $self->_match_tokened( $capture, $message );
		if ( !defined($caps) ) {
			next;
		}
		my $key_value = $caps->{ $capture->{key} };
		if ( !defined($key_value) ) {
			next;
		}

		$self->_context_store( $scope, $key_value, $caps, $capture->{ttl}, $now );

		my $pendings = delete( $self->{pending}{$scope}{$key_value} );
		if ( defined($pendings) ) {
			foreach my $pending ( @{$pendings} ) {
				if ( $pending->{expires} <= $now ) {
					next;
				}
				# the offense's own captures are authoritative
				my %data = ( %{$caps}, %{ $pending->{caps} } );
				push( @completions, { 'data' => \%data, 'regexp' => $pending->{regexp} } );
			}
		} ## end if ( defined($pendings) )
	} ## end foreach my $capture ( @{ $self->{capture_regexps...}})

	my $found;
	my $entry_int = 0;
	foreach my $entry ( @{ $self->{regexps} } ) {
		my $caps = $self->_match_tokened( $entry, $message );
		if ( !defined($caps) ) {
			$entry_int++;
			next;
		}

		if ( !defined( $entry->{key} ) ) {
			$found = { 'data' => $caps, 'regexp' => $entry_int };
			last;
		}

		my $key_value = $caps->{ $entry->{key} };
		if ( !defined($key_value) ) {
			# the key capture did not participate, so nothing to correlate
			$found = { 'data' => $caps, 'regexp' => $entry_int };
			last;
		}

		my $stored = $self->{context}{$scope}{$key_value};
		if ( defined($stored) && $stored->{expires} > $now ) {
			my %data = ( %{ $stored->{data} }, %{$caps} );
			$found = { 'data' => \%data, 'regexp' => $entry_int };
			last;
		}

		if ( $entry->{defer} ) {
			# park it awaiting a capture line with this key... the line was
			# a offense, just one that can not be resolved yet, so further
			# entries are not tried
			my $pendings = $self->{pending}{$scope}{$key_value};
			if ( !defined($pendings) ) {
				$pendings = $self->{pending}{$scope}{$key_value} = [];
			}
			push( @{$pendings}, { 'caps' => $caps, 'regexp' => $entry_int, 'expires' => $now + $entry->{defer} } );
			# bound runaway pendings per key
			if ( scalar( @{$pendings} ) > 100 ) {
				shift( @{$pendings} );
			}
			last;
		} ## end if ( $entry->{defer} )

		# unresolved and undeferred, so this entry is not a offense here...
		# fall through to the remaining entries
		$entry_int++;
	} ## end foreach my $entry ( @{ $self->{regexps} } )

	# message_json... with no message_regexp the offense is the extra fields
	# themselves (the json body and syslog envelope), synthesized here so the
	# gate below decides on them. with message_regexp present the regexp stays
	# the matcher, so nothing is synthesized when it did not fire
	if ( defined($extra) && !defined($found) && !@completions && !@{ $self->{regexps} } ) {
		$found = { 'data' => {}, 'regexp' => undef };
	}

	# merge the extra json+envelope fields into the field space, the line's
	# own captures winning on a clash, so the gate and ban_var see both
	if ( defined($extra) ) {
		if ( defined($found) ) {
			$found->{data} = { %{$extra}, %{ $found->{data} } };
		}
		foreach my $completion (@completions) {
			$completion->{data} = { %{$extra}, %{ $completion->{data} } };
		}
	}

	# the rule's boolean matcher (the gate or the selections+condition, over the
	# captures, and the json fields when message_json) filters the offense and
	# each completion, dropping those that do not pass... none skips this
	if ( ( ref( $self->{gates} ) eq 'ARRAY' && @{ $self->{gates} } ) || defined( $self->{condition_ast} ) ) {
		if ( defined($found) && !$self->_boolean_pass( $found->{data}, $message ) ) {
			$found = undef;
		}
		@completions = grep { $self->_boolean_pass( $_->{data}, $message ) } @completions;
	}

	my $primary = $found;
	if ( !defined($primary) && @completions ) {
		$primary = shift(@completions);
	}
	if ( defined($primary) && @completions ) {
		$primary->{more} = \@completions;
	}

	return $primary;
} ## end sub _check_message

# flattens a message that is a JSON object into dotted-path fields, reusing
# the json parser's flattener... a message that is not a JSON object gives a
# empty hash, so a message_json rule simply finds no fields and falls through
sub _flatten_json_message {
	my ( $self, $message ) = @_;

	if ( !defined($message) ) {
		return {};
	}
	my $parsed;
	eval { $parsed = App::Baphomet::Parser::parse( 'json', $message ); };
	if ( ref($parsed) eq 'HASH' && ref( $parsed->{fields} ) eq 'HASH' ) {
		return $parsed->{fields};
	}

	return {};
} ## end sub _flatten_json_message

# stores harvested captures under (scope, key), bounding the per scope
# key count... on hitting the cap expired entries are pruned first and
# then the soonest to expire is evicted
sub _context_store {
	my ( $self, $scope, $key_value, $caps, $ttl, $now ) = @_;

	my $context = $self->{context}{$scope};
	if ( !defined($context) ) {
		$context = $self->{context}{$scope} = {};
	}

	if ( !defined( $context->{$key_value} ) && scalar( keys( %{$context} ) ) >= 10000 ) {
		foreach my $key ( keys( %{$context} ) ) {
			if ( $context->{$key}{expires} <= $now ) {
				delete( $context->{$key} );
			}
		}
		if ( scalar( keys( %{$context} ) ) >= 10000 ) {
			my ($soonest) = sort { $context->{$a}{expires} <=> $context->{$b}{expires} } keys( %{$context} );
			delete( $context->{$soonest} );
		}
	} ## end if ( !defined( $context->{$key_value} ) &&...)

	$context->{$key_value} = { 'data' => $caps, 'expires' => $now + $ttl };

	return;
} ## end sub _context_store

# checks a value against a single compiled tokened entry... returns undef
# for no match, or the captures hash with numbered token occurrences
# folded back under the plain token name... a SRC/DEST paired entry with
# only one of the two captured is not regarded as matched
sub _match_tokened {
	my ( $self, $entry, $value ) = @_;

	if ( !defined($value) || $value !~ $entry->{regexp} ) {
		return undef;
	}

	my %caps = %+;

	foreach my $token ( keys( %{ $entry->{aliases} } ) ) {
		foreach my $alias ( @{ $entry->{aliases}{$token} } ) {
			if ( defined( $caps{$alias} ) && !defined( $caps{$token} ) ) {
				$caps{$token} = $caps{$alias};
			}
			if ( $alias ne $token ) {
				delete( $caps{$alias} );
			}
		}
	} ## end foreach my $token ( keys( %{ $entry->{aliases} ...}))

	# SRC/DEST only regard as being found if matched together
	if ( $entry->{paired} && ( !defined( $caps{SRC} ) || !defined( $caps{DEST} ) ) ) {
		return undef;
	}

	return \%caps;
} ## end sub _match_tokened

# compiles a list of string-or-//regexp// entries into a matcher hash...
# entries starting and ending with // are regexps, the rest are string
# equality checks... $where is for error messages
sub _compile_matchers {
	my ( $self, $list, $where ) = @_;

	my $matchers = {
		'strings' => {},
		'regexps' => [],
	};

	foreach my $item ( @{$list} ) {
		if ( !defined($item) || ref($item) ne '' ) {
			die( $where . ' contains a non-string entry' );
		}
		if ( $item =~ /^\/\/(.*)\/\/$/ ) {
			my $regexp = $1;
			my $compiled;
			eval { $compiled = qr/$regexp/; };
			if ($@) {
				die( $where . ' entry "' . $item . '" does not compile... ' . $@ );
			}
			push( @{ $matchers->{regexps} }, $compiled );
		} else {
			$matchers->{strings}{$item} = 1;
		}
	} ## end foreach my $item ( @{$list} )

	return $matchers;
} ## end sub _compile_matchers

# checks a value against a matcher hash from _compile_matchers... a undef
# value never matches
sub _matchers_hit {
	my ( $self, $matchers, $value ) = @_;

	if ( !defined($value) ) {
		return 0;
	}

	if ( defined( $matchers->{strings}{$value} ) ) {
		return 1;
	}

	foreach my $regexp ( @{ $matchers->{regexps} } ) {
		if ( $value =~ $regexp ) {
			return 1;
		}
	}

	return 0;
} ## end sub _matchers_hit

# the typed field operators, the opt-in richer form of a gate entry. legacy
# entries (field + values, equality or //regex//) are untouched and never reach
# here... this only fires for an entry carrying op/value/all/negate
our %PREDICATE_OPS = map { $_ => 1 } qw( eq contains startswith endswith re gt lt ge le cidr );

# the decode transforms, each string -> zero or more candidate strings, run
# left to right over a field value before the operator so an obfuscated payload
# is compared decoded. a transform that can not decode yields no candidate and
# that branch drops. base64offset yields the three alignment candidates
our %PREDICATE_TRANSFORMS = (
	'lower' => sub { return ( lc( $_[0] ) ); },
	'upper' => sub { return ( uc( $_[0] ) ); },
	'url'   => sub {
		my $string = $_[0];
		$string =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
		return ($string);
	},
	'windash' => sub {
		my $string = $_[0];
		# the unicode dash variants a Windows flag accepts, folded to ascii -
		$string =~ s/[\x{2010}\x{2011}\x{2012}\x{2013}\x{2014}\x{2015}]/-/g;
		return ($string);
	},
	'base64' => sub {
		my $decoded;
		eval { $decoded = decode_base64( $_[0] ); };
		return ( defined($decoded) && $decoded ne '' ) ? ($decoded) : ();
	},
	'base64offset' => sub {
		my $string = $_[0];
		my @out;
		foreach my $offset ( 0, 1, 2 ) {
			my $slice = substr( $string, $offset );
			my $trim  = length($slice) - ( length($slice) % 4 );
			if ( $trim <= 0 ) {
				next;
			}
			my $decoded;
			eval { $decoded = decode_base64( substr( $slice, 0, $trim ) ); };
			if ( defined($decoded) && $decoded ne '' ) {
				push( @out, $decoded );
			}
		} ## end foreach my $offset ( 0, 1, 2 )
		return @out;
	},
	'utf16le' => sub {
		my $d;
		eval { $d = Encode::decode( 'UTF-16LE', $_[0], Encode::FB_CROAK() ); };
		return defined($d) ? ($d) : ();
	},
	'utf16be' => sub {
		my $d;
		eval { $d = Encode::decode( 'UTF-16BE', $_[0], Encode::FB_CROAK() ); };
		return defined($d) ? ($d) : ();
	},
	'utf16' => sub {
		my $d;
		eval { $d = Encode::decode( 'UTF-16', $_[0], Encode::FB_CROAK() ); };
		return defined($d) ? ($d) : ();
	},
);
# wide is a Sigma alias for utf16le
$PREDICATE_TRANSFORMS{wide} = $PREDICATE_TRANSFORMS{utf16le};

# true if a gate entry is the predicate form rather than the legacy
# field/values form, so the compiler can branch and leave the old path alone
sub _is_predicate {
	my ( $self, $entry ) = @_;

	return (
		ref($entry) eq 'HASH' && ( exists( $entry->{op} )
			|| exists( $entry->{value} )
			|| exists( $entry->{all} )
			|| exists( $entry->{negate} )
			|| exists( $entry->{decode} ) )
		)
		? 1
		: 0;
} ## end sub _is_predicate

# compiles a predicate entry into a runnable form, dieing on anything
# unusable. shape: { field, op (default eq), value | values, all, negate }.
# op eq/contains/startswith/endswith are string tests, re a regexp (tokened),
# gt/lt/ge/le numeric, cidr a v4/v6 membership reusing the ignore-list machine
sub _compile_predicate {
	my ( $self, $entry, $where ) = @_;

	foreach my $key ( keys( %{$entry} ) ) {
		if ( $key !~ /^(?:field|op|value|values|all|negate|decode)$/ ) {
			die( $where . ' has the unknown key "' . $key . '"' );
		}
	}

	my $op = defined( $entry->{op} ) ? $entry->{op} : 'eq';
	if ( ref($op) ne '' || !$PREDICATE_OPS{$op} ) {
		die( $where . ' has the unknown op "' . ( ref($op) ? ref($op) : $op ) . '"' );
	}

	my @values;
	if ( exists( $entry->{values} ) ) {
		if ( ref( $entry->{values} ) ne 'ARRAY' || !@{ $entry->{values} } ) {
			die( $where . ' values is not a non-empty array' );
		}
		@values = @{ $entry->{values} };
	} elsif ( exists( $entry->{value} ) ) {
		@values = ( $entry->{value} );
	} else {
		die( $where . ' lacks a value or values' );
	}
	foreach my $v (@values) {
		if ( !defined($v) || ref($v) ne '' ) {
			die( $where . ' has a non-scalar value' );
		}
	}

	my $predicate = {
		'field'  => $entry->{field},
		'op'     => $op,
		'all'    => $entry->{all}    ? 1 : 0,
		'negate' => $entry->{negate} ? 1 : 0,
	};

	if ( exists( $entry->{decode} ) ) {
		if ( ref( $entry->{decode} ) ne 'ARRAY' || !@{ $entry->{decode} } ) {
			die( $where . ' decode is not a non-empty array' );
		}
		foreach my $transform ( @{ $entry->{decode} } ) {
			if ( !defined($transform) || ref($transform) ne '' || !$PREDICATE_TRANSFORMS{$transform} ) {
				die(      $where
						. ' has the unknown decode transform "'
						. ( defined($transform) ? ( ref($transform) ? ref($transform) : $transform ) : 'undef' )
						. '"' );
			}
		}
		$predicate->{decode} = [ @{ $entry->{decode} } ];
	} ## end if ( exists( $entry->{decode} ) )

	if ( $op eq 're' ) {
		my @regexps;
		foreach my $v (@values) {
			push( @regexps, $self->_compile_tokened_regexp( $v, $where )->{regexp} );
		}
		$predicate->{regexps} = \@regexps;
	} elsif ( $op =~ /^(?:gt|lt|ge|le)$/ ) {
		my @numbers;
		foreach my $v (@values) {
			if ( $v !~ /^-?[0-9]+(?:\.[0-9]+)?$/ ) {
				die( $where . ' op ' . $op . ' needs numeric values, got "' . $v . '"' );
			}
			push( @numbers, $v + 0 );
		}
		$predicate->{numbers} = \@numbers;
	} elsif ( $op eq 'cidr' ) {
		# dies on a bad CIDR, exactly as the ignore/namtar lists do
		$predicate->{cidr} = compile_ignore_ips( \@values, $where );
	} else {
		$predicate->{strings} = \@values;
	}

	return $predicate;
} ## end sub _compile_predicate

# runs a compiled predicate against a field value, honoring negate. a missing
# field is a false core, so a plain predicate misses and a negated one holds,
# matching Sigma's "field absent" semantics
sub _predicate_hit {
	my ( $self, $predicate, $value ) = @_;

	my $core = $self->_predicate_core( $predicate, $value );
	if ( $predicate->{negate} ) {
		return $core ? 0 : 1;
	}
	return $core;
}

sub _predicate_core {
	my ( $self, $predicate, $value ) = @_;

	if ( !defined($value) ) {
		return 0;
	}

	# the field value, run through any decode chain into one or more candidate
	# strings, the operator matching if any candidate satisfies it. with no
	# decode the candidate is just the value, so this is the plain path
	foreach my $candidate ( $self->_decode_candidates( $predicate->{decode}, "$value" ) ) {
		if ( $self->_predicate_test_one( $predicate, $candidate ) ) {
			return 1;
		}
	}

	return 0;
} ## end sub _predicate_core

# applies a predicate's decode chain to a value, fanning out... each transform
# maps every current candidate to zero or more, so base64offset widens and a
# failed decode narrows. no decode chain is the value unchanged
sub _decode_candidates {
	my ( $self, $decode, $value ) = @_;

	if ( !defined($decode) ) {
		return ($value);
	}

	my @candidates = ($value);
	foreach my $transform ( @{$decode} ) {
		my @next;
		foreach my $candidate (@candidates) {
			push( @next, $PREDICATE_TRANSFORMS{$transform}->($candidate) );
		}
		@candidates = @next;
		if ( !@candidates ) {
			return ();
		}
	} ## end foreach my $transform ( @{$decode} )

	return @candidates;
} ## end sub _decode_candidates

# tests one candidate string against a predicate's operator and values
sub _predicate_test_one {
	my ( $self, $predicate, $value ) = @_;

	my $op = $predicate->{op};

	if ( $op eq 'cidr' ) {
		return ip_ignored( $predicate->{cidr}, $value ) ? 1 : 0;
	}

	if ( $op =~ /^(?:gt|lt|ge|le)$/ ) {
		if ( $value !~ /^-?[0-9]+(?:\.[0-9]+)?$/ ) {
			return 0;
		}
		my $number = $value + 0;
		return $self->_predicate_any_all(
			$predicate->{all},
			$predicate->{numbers},
			sub {
				my ($t) = @_;
				return
					  $op eq 'gt' ? ( $number > $t )
					: $op eq 'lt' ? ( $number < $t )
					: $op eq 'ge' ? ( $number >= $t )
					:               ( $number <= $t );
			}
		);
	} ## end if ( $op =~ /^(?:gt|lt|ge|le)$/ )

	if ( $op eq 're' ) {
		return $self->_predicate_any_all( $predicate->{all}, $predicate->{regexps},
			sub { my ($r) = @_; return ( $value =~ $r ) ? 1 : 0; } );
	}

	# the string ops... eq/contains/startswith/endswith
	return $self->_predicate_any_all(
		$predicate->{all},
		$predicate->{strings},
		sub {
			my ($s) = @_;
			if ( $op eq 'eq' ) {
				return ( $value eq $s ) ? 1 : 0;
			}
			if ( $op eq 'contains' ) {
				return ( index( $value, $s ) >= 0 ) ? 1 : 0;
			}
			if ( $op eq 'startswith' ) {
				return ( substr( $value, 0, length($s) ) eq $s ) ? 1 : 0;
			}
			# endswith
			return ( length($s) <= length($value) && substr( $value, length($value) - length($s) ) eq $s )
				? 1
				: 0;
		}
	);
} ## end sub _predicate_test_one

# folds a test over the values... any by default, all when the predicate's
# all flag is set
sub _predicate_any_all {
	my ( $self, $all, $list, $test ) = @_;

	if ($all) {
		foreach my $item ( @{$list} ) {
			if ( !$test->($item) ) {
				return 0;
			}
		}
		return 1;
	}

	foreach my $item ( @{$list} ) {
		if ( $test->($item) ) {
			return 1;
		}
	}

	return 0;
} ## end sub _predicate_any_all

# compiles a rule's gate array into runnable entries, each either a legacy
# field/values matcher set or a typed predicate. shared by every type that
# carries a gate... json runs it as a pre-filter over parsed fields, syslog and
# raw as a post-match refinement over the captures, and a selection is one such
# gate list too. $where_prefix names it in errors, so a selection reads clearly
sub _compile_gates {
	my ( $self, $gate_def, $where_prefix ) = @_;

	if ( ref($gate_def) ne 'ARRAY' || !@{$gate_def} ) {
		die( $where_prefix . ' is not a array or is empty' );
	}

	my @gates;
	my $entry_int = 0;
	foreach my $entry ( @{$gate_def} ) {
		my $where = $where_prefix . ' entry ' . $entry_int;
		if ( ref($entry) ne 'HASH' || !defined( $entry->{field} ) ) {
			die( $where . ' is not a hash with a field' );
		}
		if ( $self->_is_predicate($entry) ) {
			push( @gates, { 'field' => $entry->{field}, 'predicate' => $self->_compile_predicate( $entry, $where ) } );
		} else {
			if ( ref( $entry->{values} ) ne 'ARRAY' ) {
				die( $where . ' is not a hash with a field and a values array' );
			}
			foreach my $key ( keys( %{$entry} ) ) {
				if ( $key !~ /^(?:field|values)$/ ) {
					die( $where . ' has the unknown key "' . $key . '"' );
				}
			}
			push( @gates,
				{ 'field' => $entry->{field}, 'matchers' => $self->_compile_matchers( $entry->{values}, $where ) }
			);
		} ## end else [ if ( $self->_is_predicate($entry) ) ]
		$entry_int++;
	} ## end foreach my $entry ( @{$gate_def} )

	return \@gates;
} ## end sub _compile_gates

# runs the rule's own gates over a data hash. the message, when passed, is
# exposed under the reserved field MESSAGE for a gate that names it and no
# capture already has, so a predicate can decode or test the whole message
sub _gate_pass {
	my ( $self, $data, $message ) = @_;

	return $self->_gates_pass( $self->{gates}, $data, $message );
}

# compiles a rule's boolean matcher, the flat gate or the selections+condition
# form, onto the object... they are mutually exclusive, a condition needs
# selections and the reverse. shared by every type that carries a gate, so json,
# syslog, and raw all get the operators, decode, and the boolean form uniformly
sub _compile_boolean {
	my ( $self, $def, $name ) = @_;

	if ( defined( $def->{gate} ) && defined( $def->{selections} ) ) {
		die( 'The rule "' . $name . '" has both a gate and selections, which are two forms of the same thing' );
	}

	if ( defined( $def->{gate} ) ) {
		$self->{gates} = $self->_compile_gates( $def->{gate}, 'The gate of the rule "' . $name . '"' );
	}

	if ( defined( $def->{selections} ) ) {
		if ( !defined( $def->{condition} ) ) {
			die( 'The rule "' . $name . '" has selections but no condition' );
		}
		if ( ref( $def->{selections} ) ne 'HASH' || !%{ $def->{selections} } ) {
			die( 'The selections of the rule "' . $name . '" is not a non-empty table' );
		}
		my %compiled;
		foreach my $sel_name ( keys( %{ $def->{selections} } ) ) {
			if ( $sel_name !~ /^[A-Za-z_][A-Za-z0-9_]*$/ || $sel_name =~ /^(?:and|or|not|of|them|all)$/i ) {
				die( 'The selection name "' . $sel_name . '" of the rule "' . $name . '" is not a plain identifier' );
			}
			$compiled{$sel_name} = $self->_compile_gates( $def->{selections}{$sel_name},
				'The selection "' . $sel_name . '" of the rule "' . $name . '"' );
		}
		$self->{selections} = \%compiled;
		$self->{condition_ast}
			= $self->_compile_condition( $def->{condition}, \%compiled, 'The condition of the rule "' . $name . '"' );
	} elsif ( defined( $def->{condition} ) ) {
		die( 'The rule "' . $name . '" has a condition but no selections' );
	}

	return;
} ## end sub _compile_boolean

# runs a rule's boolean matcher over a data hash, true when it passes... the
# selections folded by their condition when the rule has them, else the flat
# gate, else true (no boolean filter). the one entry point for json's pre-filter
# and the syslog/raw post-match refinement alike
sub _boolean_pass {
	my ( $self, $data, $message ) = @_;

	if ( defined( $self->{condition_ast} ) ) {
		my %results;
		foreach my $sel_name ( keys( %{ $self->{selections} } ) ) {
			$results{$sel_name} = $self->_gates_pass( $self->{selections}{$sel_name}, $data, $message );
		}
		return $self->_eval_condition( $self->{condition_ast}, \%results );
	}

	if ( ref( $self->{gates} ) eq 'ARRAY' && @{ $self->{gates} } ) {
		return $self->_gates_pass( $self->{gates}, $data, $message );
	}

	return 1;
} ## end sub _boolean_pass

# the core... runs a given gate list (ANDed) over a data hash, true when all
# pass. shared by the rule gate and by each selection of the boolean form
sub _gates_pass {
	my ( $self, $gates, $data, $message ) = @_;

	foreach my $gate ( @{$gates} ) {
		my $value
			= ( $gate->{field} eq 'MESSAGE' && defined($message) && !exists( $data->{MESSAGE} ) )
			? $message
			: $data->{ $gate->{field} };
		my $hit
			= defined( $gate->{predicate} )
			? $self->_predicate_hit( $gate->{predicate}, $value )
			: $self->_matchers_hit( $gate->{matchers}, $value );
		if ( !$hit ) {
			return 0;
		}
	} ## end foreach my $gate ( @{$gates} )

	return 1;
} ## end sub _gates_pass

# parses a Sigma-style condition string over the named selections into an AST,
# dieing on a syntax error or a reference to a unknown selection. the grammar
# is or > and > not > primary, primary being a paren group, a selection name,
# or a quantifier... "all of them", "1 of them", "N of <prefix>_*"
sub _compile_condition {
	my ( $self, $string, $selections, $where ) = @_;

	if ( !defined($string) || ref($string) ne '' || $string !~ /\S/ ) {
		die( $where . ' is not a non-empty string' );
	}

	my @tokens;
	while ( $string =~ /\G\s*([()]|[^\s()]+)/gc ) {
		push( @tokens, $1 );
	}

	my $pos  = 0;
	my $peek = sub { return $pos < scalar(@tokens) ? $tokens[$pos] : undef; };
	my $next = sub { return $tokens[ $pos++ ]; };

	my ( $parse_or, $parse_and, $parse_not, $parse_primary );

	$parse_primary = sub {
		my $tok = $peek->();
		if ( !defined($tok) ) {
			die( $where . ' ends unexpectedly' );
		}
		if ( $tok eq '(' ) {
			$next->();
			my $node  = $parse_or->();
			my $close = $next->();
			if ( !defined($close) || $close ne ')' ) {
				die( $where . ' has an unbalanced paren' );
			}
			return $node;
		}
		# a quantifier... (all|N) of (them | <prefix>_*)
		if (   ( lc($tok) eq 'all' || $tok =~ /^[0-9]+$/ )
			&& defined( $tokens[ $pos + 1 ] )
			&& lc( $tokens[ $pos + 1 ] ) eq 'of' )
		{
			my $qty = $next->();
			$next->();    # of
			my $target = $next->();
			if ( !defined($target) ) {
				die( $where . ' has an "of" with no target' );
			}
			my @names     = $self->_cond_resolve( $target, $selections, $where );
			my $threshold = ( lc($qty) eq 'all' ) ? scalar(@names) : $qty + 0;
			return [ 'count', $threshold, \@names ];
		} ## end if ( ( lc($tok) eq 'all' || $tok =~ /^[0-9]+$/...))
		my $name = $next->();
		if ( $name =~ /^(?:and|or|not|of|them|all)$/i || $name eq ')' ) {
			die( $where . ' has a misplaced "' . $name . '"' );
		}
		if ( !exists( $selections->{$name} ) ) {
			die( $where . ' references the unknown selection "' . $name . '"' );
		}
		return [ 'sel', $name ];
	}; ## end $parse_primary = sub

	$parse_not = sub {
		my $tok = $peek->();
		if ( defined($tok) && lc($tok) eq 'not' ) {
			$next->();
			return [ 'not', $parse_not->() ];
		}
		return $parse_primary->();
	};

	$parse_and = sub {
		my $node = $parse_not->();
		while ( defined( $peek->() ) && lc( $peek->() ) eq 'and' ) {
			$next->();
			$node = [ 'and', $node, $parse_not->() ];
		}
		return $node;
	};

	$parse_or = sub {
		my $node = $parse_and->();
		while ( defined( $peek->() ) && lc( $peek->() ) eq 'or' ) {
			$next->();
			$node = [ 'or', $node, $parse_and->() ];
		}
		return $node;
	};

	my $ast = $parse_or->();
	if ( $pos != scalar(@tokens) ) {
		die( $where . ' has trailing tokens after "' . $tokens[$pos] . '"' );
	}

	return $ast;
} ## end sub _compile_condition

# resolves a quantifier target to the list of selection names it covers...
# "them" is all, a trailing * is a name prefix, else a single named selection
sub _cond_resolve {
	my ( $self, $target, $selections, $where ) = @_;

	if ( lc($target) eq 'them' ) {
		my @names = sort( keys( %{$selections} ) );
		return @names;
	}
	if ( $target =~ /^(.*)\*$/ ) {
		my $prefix = $1;
		my @names  = grep { index( $_, $prefix ) == 0 } sort( keys( %{$selections} ) );
		return @names;
	}
	if ( !exists( $selections->{$target} ) ) {
		die( $where . ' has an "of" target "' . $target . '" that is not a selection or a *-pattern' );
	}
	return ($target);
} ## end sub _cond_resolve

# folds a condition AST over a hash of selection name to boolean result
sub _eval_condition {
	my ( $self, $ast, $results ) = @_;

	my $op = $ast->[0];
	if ( $op eq 'sel' ) {
		return $results->{ $ast->[1] } ? 1 : 0;
	}
	if ( $op eq 'not' ) {
		return $self->_eval_condition( $ast->[1], $results ) ? 0 : 1;
	}
	if ( $op eq 'and' ) {
		return ( $self->_eval_condition( $ast->[1], $results ) && $self->_eval_condition( $ast->[2], $results ) )
			? 1
			: 0;
	}
	if ( $op eq 'or' ) {
		return ( $self->_eval_condition( $ast->[1], $results ) || $self->_eval_condition( $ast->[2], $results ) )
			? 1
			: 0;
	}
	# count... at least threshold of the named selections are true
	my ( $threshold, $names ) = ( $ast->[1], $ast->[2] );
	my $hits = 0;
	foreach my $name ( @{$names} ) {
		if ( $results->{$name} ) {
			$hits++;
		}
	}
	return ( $hits >= $threshold ) ? 1 : 0;
} ## end sub _eval_condition

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
