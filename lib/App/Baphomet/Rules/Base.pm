package App::Baphomet::Rules::Base;

use 5.006;
use strict;
use warnings;
use Regexp::IPv4 qw( $IPv4_re );
use Regexp::IPv6 qw( $IPv6_re );
use App::Baphomet::Parser ();

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
		} ## end foreach my $key ( keys( %{ $self->{pending}{$scope...}}))
		if ( !keys( %{ $self->{pending}{$scope} } ) ) {
			delete( $self->{pending}{$scope} );
		}
	} ## end foreach my $scope ( keys( %{ $self->{pending} }...))

	return;
} ## end sub sweep_state

=head2 ban_not_internal

Returns true if the rule wants only the found IPs that are not internal
consigned, for rules like the Suricata ones where the offender may be the
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
		} ## end foreach my $scope ( keys( %{ $state->{context...}}))
	} ## end if ( ref( $state->{context...}))

	if ( ref( $state->{pending} ) eq 'HASH' ) {
		foreach my $scope ( keys( %{ $state->{pending} } ) ) {
			foreach my $key ( keys( %{ $state->{pending}{$scope} } ) ) {
				my @live = grep { ref($_) eq 'HASH' && defined( $_->{expires} ) && $_->{expires} > $now }
					@{ $state->{pending}{$scope}{$key} };
				if (@live) {
					push( @{ $self->{pending}{$scope}{$key} }, @live );
				}
			} ## end foreach my $key ( keys( %{ $state->{pending}{$scope...}}))
		} ## end foreach my $scope ( keys( %{ $state->{pending...}}))
	} ## end if ( ref( $state->{pending...}))

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

			if ( ref($test) ne 'HASH' || ( !defined( $test->{message} ) && ref( $test->{messages} ) ne 'ARRAY' ) )
			{
				$results->{fail}++;
				push( @{ $results->{failures} }, $where . ' is not a hash with a message or a messages array' );
				next;
			}

			my @messages = defined( $test->{message} ) ? ( $test->{message} ) : @{ $test->{messages} };

			my $parser
				= defined( $test->{parser} ) ? $test->{parser}
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
					push( @{ $results->{failures} },
						$where . ' message did not parse via ' . $parser . '... "' . $message . '"' );
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
				push( @{ $results->{failures} },
						  $where
						. ' expected found='
						. $expected_found
						. ' but got found='
						. $got_found
						. ' for "'
						. $messages[-1]
						. '"' );
				next;
			} ## end if ( $got_found != $expected_found )

			my $found = @found_all ? $found_all[-1] : undef;

			my $data_failed = 0;
			if ( defined( $test->{data} ) && ref( $test->{data} ) eq 'HASH' ) {
				foreach my $key ( sort( keys( %{ $test->{data} } ) ) ) {
					my $got = defined($found) ? $found->{data}{$key} : undef;
					if ( !defined($got) || $got ne $test->{data}{$key} ) {
						$results->{fail}++;
						push( @{ $results->{failures} },
								  $where
								. ' expected data.'
								. $key . '="'
								. $test->{data}{$key}
								. '" but got '
								. ( defined($got) ? '"' . $got . '"' : 'undef' ) );
						$data_failed = 1;
						last;
					} ## end if ( !defined($got) || $got ne $test->{data...})
				} ## end foreach my $key ( sort( keys( %{ $test->{data}...})))
			} ## end if ( defined( $test->{data} ) && ref( $test...))

			if ( defined( $test->{undefed} ) && ref( $test->{undefed} ) eq 'ARRAY' && !$data_failed ) {
				foreach my $key ( @{ $test->{undefed} } ) {
					my $got = defined($found) ? $found->{data}{$key} : undef;
					if ( defined($got) ) {
						$results->{fail}++;
						push( @{ $results->{failures} },
							$where . ' expected ' . $key . ' to be undef but got "' . $got . '"' );
						$data_failed = 1;
						last;
					}
				} ## end foreach my $key ( @{ $test->{undefed} } )
			} ## end if ( defined( $test->{undefed} ) && ref( ...))

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

# compiles the message_regexp and ignore_regexp of the passed def,
# expanding %%%%TOKEN%%%% tokens into named captures, and populates
# regexps and ignore_regexps on the object... shared by the handlers
# whose matching is regexps against a message with something to extract
sub _compile_message_regexps {
	my ( $self, $def ) = @_;

	my $name = $self->{name};

	$self->{regexps}        = [];
	$self->{ignore_regexps} = [];

	if ( ref( $def->{message_regexp} ) ne 'ARRAY' || !@{ $def->{message_regexp} } ) {
		die( 'The rule "' . $name . '" lacks a message_regexp array or it is empty' );
	}
	foreach my $item ( @{ $def->{message_regexp} } ) {
		if ( !defined($item) || ( ref($item) ne '' && ref($item) ne 'HASH' ) ) {
			die( 'The message_regexp of the rule "' . $name . '" contains a entry that is not a string or a hash' );
		}
		if ( ref($item) eq 'HASH' ) {
			foreach my $key ( keys( %{$item} ) ) {
				if ( $key !~ /^(?:regexp|key|defer)$/ ) {
					die(      'A message_regexp entry of the rule "'
							. $name
							. '" has the unknown key "'
							. $key
							. '"' );
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
		my $regexp = ref($item) eq 'HASH' ? $item->{regexp} : $item;
		my $compiled = $self->_compile_tokened_regexp( $regexp,
			'The message_regexp entry ' . $entry_int . ' of the rule "' . $name . '"' );
		if ( ref($item) eq 'HASH' ) {
			$compiled->{key}   = $item->{key};
			$compiled->{defer} = $item->{defer};
		}
		push( @{ $self->{regexps} }, $compiled );
		$entry_int++;
	} ## end foreach my $item ( @{ $def->{message_regexp} }...)

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
	} ## end foreach my $item ( @{ $def->{capture_regexp} }...)

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
	my ( $self, $message, $scope ) = @_;

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

	my $primary = $found;
	if ( !defined($primary) && @completions ) {
		$primary = shift(@completions);
	}
	if ( defined($primary) && @completions ) {
		$primary->{more} = \@completions;
	}

	return $primary;
} ## end sub _check_message

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
	} ## end foreach my $token ( keys( %{ $entry->{aliases}...}))

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
