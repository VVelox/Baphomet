package App::Baphomet::Rules::SelfTest;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Exporter              qw( import );
use Ref::Util             qw( is_plain_arrayref is_plain_hashref );
use List::Util            qw( all any );
use App::Baphomet::Parser ();
use App::Baphomet::Tracks qw( track_get );
use App::Baphomet::Gate   qw( bind_rule_gates walk_offense );

our @EXPORT_OK = qw( run_tests );

=head1 NAME

App::Baphomet::Rules::SelfTest - The runner for the tests a Baphomet rule embeds.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    my $rule = App::Baphomet::Rules->new( 'rules_dir' => $dir )->load( 'syslog/sshd', 'skip_tests' => 1 );

    my $results = $rule->run_tests;
    if ( $results->{fail} ) {
        print join( "\n", @{ $results->{failures} } ) . "\n";
    }

=head1 DESCRIPTION

Every rule file carries its own C<tests>, and a rule that fails them does
not load. This is what runs them... a throwaway mark store, tracked-record
store, and virtual clock per test entry, with the DNS and GeoIP lookups
fixtured, so a rule proves its matching, its brands, and its gates with no
galla up. What a test entry may hold is documented for rule authors under
the tests section of F<docs/rules.md>,
L<https://github.com/LilithSec/Baphomet/blob/main/docs/rules.md#tests>.

L</run_tests> takes the rule as its first argument and
L<App::Baphomet::Rule> imports it, which makes it a method of every rule.
It takes each line down the rule's gates the same way the galla does, with
L<App::Baphomet::Rule/walk_line> and L<App::Baphomet::Gate/walk_offense>,
so the self-test can not drift from the engine.

=head1 FUNCTIONS

=head2 run_tests

Runs the tests embedded in the rule. Returns a hash as below. Does not die
on test failures... that is the caller's call to make.

    {
        'pass'     => 3,
        'fail'     => 0,
        'failures' => [],
    }

    my $results = $rule->run_tests;

Each test entry runs the galla's own order per message... parse, then the
rule's gates in the order it wrote them, the mark ones against a throwaway
store, so C<found> counts what would really have fired. The
store starts empty per entry, seedable via C<marks_before> (each
C<< {name, key, value?, set?, ttl?} >>, C<key> a string or a list joined
as a C<vars> compound is), and assertable after the run via
C<marks_expected> (each C<< {name, key, value?, absent?} >>). Time is a
virtual clock, base 1000000000, threaded through matching and the store
both... a C<messages> entry may be a hash C<< {message, advance?|at?,
found_after?, marks_after?, tracked_after?} >> to steer it and assert
mid-run.

The gates are bound and asked as the galla binds and asks them, through
L<App::Baphomet::Gate>. One that can not judge with out something no
fixture stands in for goes unjudged, which namtar_list and active_time
always do, their lists and windows being config a rule file has none of.

The tracked-record store gets the same treatment, a throwaway per entry
seedable via C<tracked_before> (each C<< {name, key, fields, ttl?} >>) and
assertable via C<tracked_expected> (each
C<< {name, key, fields?, absent?} >>). A rule that both harvests and reads
is better proved without the seed at all: a multiline C<messages> test
walks a harvest line and a reading line through one scope, so the record
the gate reads is one the rule really built.

A C<dns> fixture (C<ptr> and C<forward> maps, answers a list, C<nxdomain>,
or C<servfail>, anything unfixtured answering servfail) stands in for the
resolver, and a C<geo> fixture (a C<countries> map and the C<lists> a
C<%%%country_codes{name}%%%> token resolves against) for the GeoIP
locator... with one present the reverse_dns or country gate runs exactly
as in the galla, and absent it the gate is skipped.

The other lookups are fixtured the same way, each gate skipped with out
its own. The C<dns> fixture's C<dnsbl> map, of a zone to a map of address
to answer, stands in for the blocklists a dnsbl gate asks. The C<geo>
fixture's C<asns> map, of a address to a AS number, a C<< {number, org} >>
hash, or C<unknown>, and its C<asn_lists>, stand in for the ASN database
and the lists a C<%%%asn_lists{name}%%%> token resolves against. And a
C<accounts> list names the accounts a account gate finds, every other name
being nobody's, or as a hash of name to C<< {uid, shell, groups} >> says
what is known of each. The C<geo> fixture's C<locations> map, of a address to a
C<[ latitude, longitude ]> pair, a C<< {lat, lon, radius} >> hash, or
C<unknown>, stands in for the city database a travel gate places a address
with. And a C<pressure> number is what a pressure gate reads however far
back it asks. A forgive gate has no fixture, the counts it takes hits back
out of being the galla's, and always goes unjudged.

=cut

sub run_tests {
	my ($self) = @_;

	my $results = {
		'pass'     => 0,
		'fail'     => 0,
		'failures' => [],
		'warnings' => [],
	};

	# start from clean matching state. each test entry already gets its own
	# correlation scope, but the per-object stores outlive a single run... so a
	# repeat call (load validates once, a harness may run again) could inherit a
	# half-built staged sequence or correlation window under a reused scope and
	# complete it spuriously. swept as of the end of time, which everything
	# held has expired by, so run_tests is idempotent
	$self->sweep_state( 9**9**9 );

	my $tests = $self->{def}{tests};
	if ( !is_plain_hashref($tests) ) {
		return $results;
	}

	# a typo'd section name would otherwise mean zero tests and a clean
	# load, quietly defeating the prove-itself-at-load design
	foreach my $section ( keys( %{$tests} ) ) {
		if ( $section !~ /^(?:positive|negative|injection)$/ ) {
			push( @{ $results->{failures} }, 'unknown tests section "' . $section . '"' );
		}
	}

	# A pattern that reaches its offender over a lazy wildcard takes the first
	# candidate on the line, so where anything a client writes can precede the
	# real field, the client picks the ban target. Whether that is so depends on
	# the log and not on the pattern, which no reading of the rule can settle...
	# so this is a warning and not a failure, and the rule loads either way. A
	# tests.injection entry answers it, whichever way the answer goes.
	my ($open_to_injection) = grep { defined($_) } map { $_->{open_to_injection} } @{ $self->rule_gates };
	if ( defined($open_to_injection) && !is_plain_arrayref( $tests->{injection} ) ) {
		push(
			@{ $results->{warnings} },
			$open_to_injection
				. ' is reached over a lazy wildcard with nothing anchoring it, so the first candidate on the'
				. ' line wins. If a client can write ahead of the real field they choose who is banned.'
				. ' A tests.injection entry settles whether that is reachable here'
		);
	}

	foreach my $sort ( 'positive', 'negative', 'injection' ) {
		if ( !defined( $tests->{$sort} ) ) {
			next;
		}
		if ( !is_plain_arrayref( $tests->{$sort} ) ) {
			push( @{ $results->{failures} }, $sort . ' tests is not a array' );
			next;
		}

		# any failure below records itself and moves on with next TEST... the
		# entry is done the moment one check fails, and reaching the bottom is
		# a pass
		my $test_int = 0;
	TEST: foreach my $test ( @{ $tests->{$sort} } ) {
			my $where = $sort . ' test ' . $test_int;
			$test_int++;

			if ( !is_plain_hashref($test)
				|| ( !defined( $test->{message} ) && !is_plain_arrayref( $test->{messages} ) ) )
			{
				push( @{ $results->{failures} }, $where . ' is not a hash with a message or a messages array' );
				next TEST;
			}

			# a injection test with no data block asserts only that the forged
			# line matched, which is the half that was never in doubt... naming
			# the offender is the whole assertion
			if ( $sort eq 'injection' && !is_plain_hashref( $test->{data} ) ) {
				push(
					@{ $results->{failures} },
					$where . ' has no data block naming the offender the forged line must still aim at'
				);
				next TEST;
			}

			# a typo'd assertion key would otherwise be a assertion that
			# never runs... the very silence this machinery exists to end
			my @unknown_keys = grep {
				!/^(?:message|messages|parser|found|data|undefed|marks_before|marks_expected|tracked_before|tracked_expected|dns|geo|accounts|pressure)$/
			} keys( %{$test} );
			if (@unknown_keys) {
				foreach my $test_key (@unknown_keys) {
					push( @{ $results->{failures} }, $where . ' has the unknown key "' . $test_key . '"' );
				}
				next TEST;
			}

			my @messages = defined( $test->{message} ) ? ( $test->{message} ) : @{ $test->{messages} };

			my $parser = $test->{parser} // $self->{def}{test_parser} // $self->default_test_parser;

			# each test entry gets a throwaway correlation scope of its own,
			# a throwaway mark store, and a virtual clock... the galla state
			# a rule file may seed, exercise, and assert with no galla up
			my $test_scope = 'run_tests ' . $where;
			my %marks_store;
			my %tracked_store;
			my $clock = 1_000_000_000;

			if ( defined( $test->{marks_before} )
				&& _test_marks_seed( \%marks_store, $test->{marks_before}, $clock, $where, $results ) )
			{
				next TEST;
			}

			if ( defined( $test->{tracked_before} )
				&& _test_tracked_seed( \%tracked_store, $test->{tracked_before}, $clock, $where, $results ) )
			{
				next TEST;
			}

			# what the gates of this entry are judged over... the throwaway store
			# always, and a fixture where the test has one
			my %gate_context = ( 'marks' => sub { return \%marks_store; } );

			# the dns fixture... a resolver the reverse_dns gate judges over and
			# a asker the dnsbl gate does, so each runs here exactly as it would
			# in the galla. a fixture of blocklists alone stands in for no
			# resolver, so a reverse_dns gate beside the dnsbl one is skipped
			# and not failed on questions the test never meant to answer
			if ( defined( $test->{dns} ) ) {
				my $dns_resolver = _test_dns_resolver( $test->{dns}, $where, $results );
				if ( !defined($dns_resolver) ) {
					next TEST;
				}
				my $has_dnsbl = defined( $test->{dns}{dnsbl} );
				if ($has_dnsbl) {
					$gate_context{dnsbl} = sub { return $dns_resolver->{listed}; };
				}
				if ( !$has_dnsbl || defined( $test->{dns}{ptr} ) || defined( $test->{dns}{forward} ) ) {
					$gate_context{resolver} = sub { return $dns_resolver; };
				}
			} ## end if ( defined( $test->{dns} ) )

			# the geo fixture likewise... a locator and the named code lists a
			# %%%country_codes{...}%%% token resolves against, and a asn locator
			# and the lists a %%%asn_lists{...}%%% token does. a fixture of
			# networks alone stands in for no country locator, as with dns
			if ( defined( $test->{geo} ) ) {
				my $geo = _test_geo_locator( $test->{geo}, $where, $results );
				if ( !defined($geo) ) {
					next TEST;
				}
				my $has_asn = defined( $test->{geo}{asns} ) || defined( $test->{geo}{asn_lists} );
				if ($has_asn) {
					$gate_context{asn_locator} = $geo->{asn_locator};
					$gate_context{asn_lists}   = $geo->{asn_lists};
				}
				my $has_locations = defined( $test->{geo}{locations} );
				if ($has_locations) {
					$gate_context{city_locator} = $geo->{city_locator};
				}
				if (   !( $has_asn || $has_locations )
					|| defined( $test->{geo}{countries} )
					|| defined( $test->{geo}{lists} ) )
				{
					$gate_context{locator}       = $geo->{locator};
					$gate_context{country_codes} = $geo->{country_codes};
				}
			} ## end if ( defined( $test->{geo} ) )

			# the pressure fixture... what a pressure gate reads, the same
			# however far back and over whatever scope it asks
			if ( defined( $test->{pressure} ) ) {
				my $matched = $test->{pressure};
				if ( ref($matched) ne '' || $matched !~ /^[0-9]+$/ ) {
					push( @{ $results->{failures} }, $where . ' pressure is not a count of matched lines' );
					next TEST;
				}
				$gate_context{pressure} = sub { return $matched; };
			}

			# the accounts fixture... the names a account gate finds
			if ( defined( $test->{accounts} ) ) {
				my ( $accounts, $groups ) = _test_accounts( $test->{accounts}, $where, $results );
				if ( !defined($accounts) ) {
					next TEST;
				}
				$gate_context{accounts} = sub { return $accounts->{ $_[0] }; };
				$gate_context{groups}   = sub { return $groups->{ $_[0] }; };
			}

			# the rule's gates, bound over that and sorted by phase, as the
			# galla binds them... less any that can not judge
			# with out something no fixture stands in for, which go unjudged
			# here. namtar_list and active_time are always among those, as they
			# resolve against a watcher's lists and windows and a rule file has
			# neither
			my @judgeable = grep {
				my $gate = $_;
				all { defined( $gate_context{$_} ) } $gate->needs;
			} @{ $self->rule_gates };
			my $gates;
			try {
				$gates = bind_rule_gates( \@judgeable, \%gate_context, $where );
			} catch ($caught) {
				push( @{ $results->{failures} }, $where . ' has a gate that did not bind... ' . $caught );
				next TEST;
			}

			my @found_all;
			my $message_index = -1;
			foreach my $message_entry (@messages) {
				$message_index++;
				my $message = $message_entry;
				my ( $found_after, $marks_after, $tracked_after );
				if ( is_plain_hashref($message_entry) ) {
					my @unknown_entry_keys = grep { !/^(?:message|advance|at|found_after|marks_after|tracked_after)$/ }
						keys( %{$message_entry} );
					if (@unknown_entry_keys) {
						foreach my $entry_key (@unknown_entry_keys) {
							push(
								@{ $results->{failures} },
								$where . ' has a messages entry with the unknown key "' . $entry_key . '"'
							);
						}
						next TEST;
					}
					if ( !defined( $message_entry->{message} ) ) {
						push( @{ $results->{failures} }, $where . ' has a messages entry hash with no message' );
						next TEST;
					}
					$message = $message_entry->{message};
					# the clock steered ahead of the line, absolute or relative
					if ( defined( $message_entry->{at} ) ) {
						$clock = $message_entry->{at};
					} elsif ( defined( $message_entry->{advance} ) ) {
						$clock += $message_entry->{advance};
					}
					$found_after   = $message_entry->{found_after};
					$marks_after   = $message_entry->{marks_after};
					$tracked_after = $message_entry->{tracked_after};
				} ## end if ( is_plain_hashref($message_entry) )

				my $parsed;
				try {
					$parsed = App::Baphomet::Parser::parse( $parser, $message );
				} catch ($caught) {
					push( @{ $results->{failures} }, $where . ' has a unusable parser... ' . $caught );
					next TEST;
				}
				if ( !defined($parsed) ) {
					push(
						@{ $results->{failures} },
						$where . ' message did not parse via ' . $parser . '... "' . $message . '"'
					);
					next TEST;
				}

				# the line context a staged rule's skip bound reads... the
				# message index is the sequence with in the test entry, and
				# now the virtual clock, so windows prove deterministically
				my $offenses = $self->walk_line(
					$gates, $parsed,
					$test_scope,
					{
						'seq'    => $message_index,
						'source' => '',
						'now'    => $clock,
						# the throwaway record store, what the tracked and
						# track gates both read... a rule that tracks proves
						# it cold, the same way branding does
						'tracked' => \%tracked_store,
					}
				);

				# a capture line may have completed several deferred offenses
				foreach my $one ( @{$offenses} ) {
					# the offense goes down the gates of the offense phase as it
					# does in the galla, over the virtual clock as it stands... the
					# ones that read it, the naming of who it counts against, the
					# ones keyed by the offender, and the brands. a vetoed offense
					# did not fire, so it is neither branded nor counted as found
					$one->{now}    = $clock;
					$one->{set}    = [];
					$one->{lifted} = [];
					$one->{scope}  = $test_scope;
					if ( walk_offense( $gates, $one ) ) {
						push( @found_all, $one );
					}
				} ## end foreach my $one ( @{$offenses} )

				# the mid-run assertions a hash entry carries
				my $after_where = $where . ' after message ' . $message_index;
				if ( defined($found_after) && scalar(@found_all) != $found_after ) {
					push(
						@{ $results->{failures} },
						$where
							. ' expected found_after='
							. $found_after
							. ' but had found='
							. scalar(@found_all)
							. ' after message '
							. $message_index
					);
					next TEST;
				} ## end if ( defined($found_after) && scalar(@found_all...))
				if ( defined($marks_after)
					&& _test_marks_assert( \%marks_store, $marks_after, $clock, $after_where, $results ) )
				{
					next TEST;
				}
				if ( defined($tracked_after)
					&& _test_tracked_assert( \%tracked_store, $tracked_after, $clock, $after_where, $results ) )
				{
					next TEST;
				}
			} ## end foreach my $message_entry (@messages)

			# a injection test is a positive by default, and deliberately so: the
			# thing being proven is that a forged line STILL MATCHES and merely
			# aims right. Hardening one of these by tightening the field run
			# until the forged line stops matching at all looks like a fix and is
			# not... it trades a wrong ban for no ban, so a brute forcer who
			# plants the right bytes simply goes uncounted, and silently. That
			# happened once already, to syslog/dovecot, and this default is what
			# would have caught it
			my $expected_found = 1;
			if ( defined( $test->{found} ) ) {
				$expected_found = $test->{found};
			} elsif ( $sort eq 'negative' ) {
				$expected_found = 0;
			}
			my $got_found = scalar(@found_all);

			if ( $got_found != $expected_found ) {
				my $last_message = is_plain_hashref( $messages[-1] ) ? $messages[-1]{message} : $messages[-1];
				push(
					@{ $results->{failures} },
					$where
						. ' expected found='
						. $expected_found
						. ' but got found='
						. $got_found
						. ' for "'
						. $last_message . '"'
				);
				next TEST;
			} ## end if ( $got_found != $expected_found )

			my $found = @found_all ? $found_all[-1] : undef;

			if ( is_plain_hashref( $test->{data} ) ) {
				foreach my $key ( sort( keys( %{ $test->{data} } ) ) ) {
					my $got = defined($found) ? $found->{data}{$key} : undef;
					if ( !defined($got) || $got ne $test->{data}{$key} ) {
						push(
							@{ $results->{failures} },
							$where
								. ' expected data.'
								. $key . '="'
								. $test->{data}{$key}
								. '" but got '
								. ( defined($got) ? '"' . $got . '"' : 'undef' )
						);
						next TEST;
					} ## end if ( !defined($got) || $got ne $test->{data...})
				} ## end foreach my $key ( sort( keys( %{ $test->{data} ...})))
			} ## end if ( is_plain_hashref( $test->{data} ) )

			if ( is_plain_arrayref( $test->{undefed} ) ) {
				foreach my $key ( @{ $test->{undefed} } ) {
					my $got = defined($found) ? $found->{data}{$key} : undef;
					if ( defined($got) ) {
						push(
							@{ $results->{failures} },
							$where . ' expected ' . $key . ' to be undef but got "' . $got . '"'
						);
						next TEST;
					}
				} ## end foreach my $key ( @{ $test->{undefed} } )
			} ## end if ( is_plain_arrayref( $test->{undefed} ))

			if ( defined( $test->{marks_expected} )
				&& _test_marks_assert( \%marks_store, $test->{marks_expected}, $clock, $where, $results ) )
			{
				next TEST;
			}

			if ( defined( $test->{tracked_expected} )
				&& _test_tracked_assert( \%tracked_store, $test->{tracked_expected}, $clock, $where, $results ) )
			{
				next TEST;
			}

			$results->{pass}++;
		} ## end TEST: foreach my $test ( @{ $tests->{$sort} } )
	} ## end foreach my $sort ( 'positive', 'negative', 'injection')

	# every failure above pushed its text, so the count is the list's length
	$results->{fail} = scalar( @{ $results->{failures} } );

	return $results;
} ## end sub run_tests

# builds the resolver from a test entry's dns fixture, what the reverse_dns
# and dnsbl gates ask with. anything unfixtured answers servfail, fail-closed
# as an unanswerable question is in the galla.
#
# args:
#   $fixture :: the dns hash of the test entry... ptr maps a address to its
#               names, forward a name to its addresses, and dnsbl a zone to
#               a map of address to the addresses the zone lists it under.
#               each answer is a list, the string nxdomain (authoritative
#               absence), or the string servfail (a failure)
#   $where   :: the lead in for a failure message, naming the test entry
#   $results :: the results hash of the run, whose failures a malformed
#               fixture is pushed onto
#
# returns a hash ref of reverse and forward, each a sub taking a address or
# a name, and listed, a sub taking a zone and a address, all three answering
# a array ref, a empty one for nxdomain, or undef for servfail. undef on a
# malformed fixture.
#
#   my $resolver = _test_dns_resolver( { 'ptr' => { '192.0.2.7' => ['crawl.example.org'] } }, $where, $results );
#   my $names = $resolver->{reverse}->('192.0.2.7');    # ['crawl.example.org']
sub _test_dns_resolver {
	my ( $fixture, $where, $results ) = @_;

	if ( !is_plain_hashref($fixture) ) {
		push( @{ $results->{failures} }, $where . ' dns is not a hash' );
		return undef;
	}

	# every map of subject to answer in the fixture, by what it is called in a
	# failure message... ptr and forward are one each, and dnsbl one per zone
	my %answer_maps;
	foreach my $fixture_key ( keys( %{$fixture} ) ) {
		if ( $fixture_key !~ /^(?:ptr|forward|dnsbl)$/ ) {
			push( @{ $results->{failures} }, $where . ' dns has the unknown key "' . $fixture_key . '"' );
			return undef;
		}
		if ( !is_plain_hashref( $fixture->{$fixture_key} ) ) {
			push( @{ $results->{failures} }, $where . ' dns ' . $fixture_key . ' is not a hash' );
			return undef;
		}
		if ( $fixture_key ne 'dnsbl' ) {
			$answer_maps{$fixture_key} = $fixture->{$fixture_key};
			next;
		}
		foreach my ( $zone, $zone_map ) ( %{ $fixture->{dnsbl} } ) {
			if ( !is_plain_hashref($zone_map) ) {
				push( @{ $results->{failures} }, $where . ' dns dnsbl "' . $zone . '" is not a hash' );
				return undef;
			}
			$answer_maps{ 'dnsbl "' . $zone . '"' } = $zone_map;
		}
	} ## end foreach my $fixture_key ( keys( %{$fixture} ) )
	foreach my ( $map_name, $answer_map ) (%answer_maps) {
		foreach my ( $subject, $answer ) ( %{$answer_map} ) {
			if ( !is_plain_arrayref($answer) && ( ref($answer) ne '' || $answer !~ /^(?:nxdomain|servfail)$/ ) ) {
				push(
					@{ $results->{failures} },
					$where . ' dns '
						. $map_name . ' "'
						. $subject
						. '" is not a list of names/addresses, nxdomain, or servfail'
				);
				return undef;
			} ## end if ( !is_plain_arrayref($answer) && ( ref(...)))
		} ## end foreach my ( $subject, $answer ) ( %{$answer_map...})
	} ## end foreach my ( $map_name, $answer_map ) (%answer_maps)

	my $answer_for = sub {
		my ( $map, $subject ) = @_;
		my $answer = defined($map) ? $map->{$subject} : undef;
		if ( !defined($answer) || ( !ref($answer) && $answer eq 'servfail' ) ) {
			return undef;
		}
		if ( !ref($answer) && $answer eq 'nxdomain' ) {
			return [];
		}
		return $answer;
	}; ## end $answer_for = sub

	return {
		'reverse' => sub { return $answer_for->( $fixture->{ptr},            $_[0] ); },
		'forward' => sub { return $answer_for->( $fixture->{forward},        $_[0] ); },
		'listed'  => sub { return $answer_for->( $fixture->{dnsbl}{ $_[0] }, $_[1] ); },
	};
} ## end sub _test_dns_resolver

# builds the accounts and groups from a test entry's accounts fixture, what
# a account gate is judged over. every name the fixture does not have is
# nobody's.
#
# args:
#   $fixture :: the accounts of the test entry... a array of the names that
#               are accounts, of which nothing more is then known, or a hash
#               of name to a hash of any of uid, shell, and groups, the last
#               a array of the groups the account is in
#   $where   :: the lead in for a failure message, naming the test entry
#   $results :: the results hash of the run, whose failures a malformed
#               fixture is pushed onto
#
# returns a hash ref of name to account, each a hash of the uid and shell
# the fixture gave, and a hash ref of group name to group, each a hash of
# members keyed by name. a lone undef on a malformed fixture.
#
#   my ( $accounts, $groups ) = _test_accounts( { 'neti' => { 'uid' => 1001, 'groups' => ['wheel'] } }, $where, $results );
#   $accounts->{neti}{uid};              # 1001
#   $groups->{wheel}{members}{neti};     # 1
sub _test_accounts {
	my ( $fixture, $where, $results ) = @_;

	if ( is_plain_arrayref($fixture) ) {
		if ( any { !defined($_) || ref($_) ne '' } @{$fixture} ) {
			push( @{ $results->{failures} }, $where . ' accounts is not a array of names or a hash of them' );
			return undef;
		}
		return ( { map { $_ => {} } @{$fixture} }, {} );
	}
	if ( !is_plain_hashref($fixture) ) {
		push( @{ $results->{failures} }, $where . ' accounts is not a array of names or a hash of them' );
		return undef;
	}

	my ( %accounts, %groups );
	foreach my ( $name, $details ) ( %{$fixture} ) {
		$details //= {};
		my $malformed
			= !is_plain_hashref($details)
			|| ( grep { !/^(?:uid|shell|groups)$/ } keys( %{$details} ) )
			|| ( defined( $details->{uid} )    && $details->{uid} !~ /^[0-9]+$/ )
			|| ( defined( $details->{shell} )  && ref( $details->{shell} ) ne '' )
			|| ( defined( $details->{groups} ) && !is_plain_arrayref( $details->{groups} ) );
		if ($malformed) {
			push(
				@{ $results->{failures} },
				$where . ' accounts "' . $name . '" is not a hash of uid, shell, and groups'
			);
			return undef;
		}
		$accounts{$name} = { map { $_ => $details->{$_} } grep { defined( $details->{$_} ) } ( 'uid', 'shell' ) };
		foreach my $group_name ( @{ $details->{groups} // [] } ) {
			$groups{$group_name}{members}{$name} = 1;
		}
	} ## end foreach my ( $name, $details ) ( %{$fixture} )

	return ( \%accounts, \%groups );
} ## end sub _test_accounts

# builds the locators and lists from a test entry's geo fixture, what the
# country, asn, and travel gates are judged over. anything unfixtured is unknown,
# fail-closed as an unplaceable address is in the galla.
#
# args:
#   $fixture :: the geo hash of the test entry... countries maps a address
#               to its ISO code, asns a address to its AS number, bare or
#               written AS64496, or to a hash of number and org, either map
#               taking the string unknown for a address the database would
#               not place. lists and asn_lists name the sets a
#               %%%country_codes{name}%%% and a %%%asn_lists{name}%%% token
#               resolve against. locations maps a address to where it is,
#               a [ latitude, longitude ] pair or a hash of lat, lon, and
#               radius, or to the string unknown
#   $where   :: the lead in for a failure message, naming the test entry
#   $results :: the results hash of the run, whose failures a malformed
#               fixture is pushed onto
#
# returns a hash ref of locator, a sub taking a address and returning its
# code upcased or undef, country_codes, the named code lists, asn_locator, a
# sub taking a address and returning a hash ref of number and org or undef,
# asn_lists, the named number lists with any AS off, and city_locator, a sub
# taking a address and returning a hash ref of lat, lon, and radius or
# undef. undef on a malformed fixture.
#
#   my $geo = _test_geo_locator( { 'countries' => { '203.0.113.9' => 'nl' } }, $where, $results );
#   my $code = $geo->{locator}->('203.0.113.9');    # 'NL'
sub _test_geo_locator {
	my ( $fixture, $where, $results ) = @_;

	if ( !is_plain_hashref($fixture) ) {
		push( @{ $results->{failures} }, $where . ' geo is not a hash' );
		return undef;
	}
	foreach my $fixture_key ( keys( %{$fixture} ) ) {
		if ( $fixture_key !~ /^(?:countries|lists|asns|asn_lists|locations)$/ ) {
			push( @{ $results->{failures} }, $where . ' geo has the unknown key "' . $fixture_key . '"' );
			return undef;
		}
		if ( !is_plain_hashref( $fixture->{$fixture_key} ) ) {
			push( @{ $results->{failures} }, $where . ' geo ' . $fixture_key . ' is not a hash' );
			return undef;
		}
	} ## end foreach my $fixture_key ( keys( %{$fixture} ) )
	foreach my $address ( keys( %{ $fixture->{countries} || {} } ) ) {
		my $code = $fixture->{countries}{$address};
		if ( ref($code) ne '' || $code !~ /^(?:[a-zA-Z]{2}|unknown)$/ ) {
			push(
				@{ $results->{failures} },
				$where . ' geo countries "' . $address . '" is not a 2-letter code or unknown'
			);
			return undef;
		}
	} ## end foreach my $address ( keys( %{ $fixture->{countries...}}))
	foreach my $list_key ( 'lists', 'asn_lists' ) {
		foreach my $list_name ( keys( %{ $fixture->{$list_key} || {} } ) ) {
			if ( !is_plain_arrayref( $fixture->{$list_key}{$list_name} ) ) {
				push( @{ $results->{failures} },
					$where . ' geo ' . $list_key . ' "' . $list_name . '" is not a array' );
				return undef;
			}
		}
	}

	# the networks, each as the asn locator answers one... a lone number is a
	# network with no name
	my %networks;
	foreach my ( $address, $network ) ( %{ $fixture->{asns} || {} } ) {
		my $number = is_plain_hashref($network) ? $network->{number} : $network;
		my $org    = is_plain_hashref($network) ? $network->{org}    : undef;
		if ( !defined($number) || ref($number) ne '' || $number !~ /^(?:(?:[Aa][Ss])?[0-9]{1,10}|unknown)$/ ) {
			push(
				@{ $results->{failures} },
				$where
					. ' geo asns "'
					. $address
					. '" is not a AS number, a hash with one as its number, or unknown'
			);
			return undef;
		} ## end if ( !defined($number) || ref($number) ne ...)
		if ( $number ne 'unknown' ) {
			$networks{$address} = { 'number' => ( $number =~ s/^[Aa][Ss]//r ) + 0, 'org' => $org };
		}
	} ## end foreach my ( $address, $network ) ( %{ $fixture...})
	my %asn_lists;
	foreach my ( $list_name, $numbers ) ( %{ $fixture->{asn_lists} || {} } ) {
		$asn_lists{$list_name} = [ map { ( $_ =~ s/^[Aa][Ss]//r ) + 0 } @{$numbers} ];
	}

	# the places, each as the city locator answers one... a pair is a place
	# good to the kilometre
	my %places;
	my $degrees = qr/^-?[0-9]+(?:\.[0-9]+)?$/;
	foreach my ( $address, $location ) ( %{ $fixture->{locations} || {} } ) {
		if ( !ref($location) && defined($location) && $location eq 'unknown' ) {
			next;
		}
		my ( $lat, $lon, $radius );
		if ( is_plain_arrayref($location) ) {
			( $lat, $lon, $radius ) = ( @{$location}[ 0, 1 ], 0 );
		} elsif ( is_plain_hashref($location) ) {
			( $lat, $lon, $radius ) = ( @{$location}{ 'lat', 'lon' }, $location->{radius} // 0 );
		}
		if ( grep { !defined($_) || ref($_) ne '' || $_ !~ $degrees } ( $lat, $lon, $radius ) ) {
			push(
				@{ $results->{failures} },
				$where
					. ' geo locations "'
					. $address
					. '" is not a [ latitude, longitude ] pair, a hash of lat, lon, and radius, or unknown'
			);
			return undef;
		} ## end if ( grep { !defined($_) || ref($_) ne '' ...})
		$places{$address} = { 'lat' => $lat + 0, 'lon' => $lon + 0, 'radius' => $radius + 0 };
	} ## end foreach my ( $address, $location ) ( %{ $fixture...})

	my $countries = $fixture->{countries} || {};

	return {
		'city_locator' => sub { return $places{ $_[0] }; },
		'locator'      => sub {
			my ($address) = @_;
			my $code = $countries->{$address};
			if ( !defined($code) || $code eq 'unknown' ) {
				return undef;
			}
			return uc($code);
		},
		'country_codes' => $fixture->{lists} || {},
		'asn_locator'   => sub { return $networks{ $_[0] }; },
		'asn_lists'     => \%asn_lists,
	};
} ## end sub _test_geo_locator

# checks one marks_before, tracked_before, marks_expected/marks_after, or
# tracked_expected/tracked_after entry for the shape all four share... a hash
# with a name, a key, nothing its list does not allow, and for a tracked seed
# a fields hash. what each list then does with a sound entry is its own.
#
# args:
#   $entry        :: the list entry as the rule file wrote it
#   $label        :: what the entry is, for the failure text... 'marks_before
#                    entry', 'tracked_before entry', 'marks assertion', or
#                    'tracked assertion'
#   $allowed      :: arrayref of the keys the entry may carry
#   $needs_fields :: true when the entry must also carry a fields hash
#   $where        :: the test entry's where string, leading each failure
#   $results      :: the run_tests results hash, each failure counted and
#                    pushed onto its failures
#
# returns true when the entry is malformed, false when it is sound. a entry
# missing what it needs is one failure, and otherwise every unknown key is one
# failure each, not just the first found.
#
#   if ( _test_store_entry_malformed( $seed, 'marks_before entry', [ 'name', 'key', 'value', 'set', 'ttl' ],
#       0, $where, $results ) )
#   {
#       return 1;
#   }
sub _test_store_entry_malformed {
	my ( $entry, $label, $allowed, $needs_fields, $where, $results ) = @_;

	if (   !is_plain_hashref($entry)
		|| !defined( $entry->{name} )
		|| !defined( $entry->{key} )
		|| ( $needs_fields && !is_plain_hashref( $entry->{fields} ) ) )
	{
		my $lacking = $needs_fields ? 'a name, key, and fields hash' : 'a name and key';
		push( @{ $results->{failures} }, $where . ' has a ' . $label . ' lacking ' . $lacking );
		return 1;
	}

	my %allowed_keys = map  { $_ => 1 } @{$allowed};
	my @unknown_keys = grep { !$allowed_keys{$_} } keys( %{$entry} );
	foreach my $unknown_key (@unknown_keys) {
		push( @{ $results->{failures} }, $where . ' has a ' . $label . ' with the unknown key "' . $unknown_key . '"' );
	}

	return @unknown_keys ? 1 : 0;
} ## end sub _test_store_entry_malformed

# turns a seed or assertion key into the key the throwaway store holds it
# under, and the form failure text shows it in... a list is a vars compound,
# joined the way the store joins one, and shown joined on | for reading.
#
# args:
#   $key :: the key as the rule file wrote it, a string or a arrayref of the
#           compound's parts
#
# returns a two item list, the store key and the shown key. both are the
# string itself for a plain key.
#
#   my ( $store_key, $shown ) = _test_store_key( [ '192.0.2.7', 'admin' ] );
#   # $store_key is "192.0.2.7\x1fadmin", $shown is "192.0.2.7|admin"
sub _test_store_key {
	my ($key) = @_;

	if ( is_plain_arrayref($key) ) {
		return ( join( "\x1f", @{$key} ), join( '|', @{$key} ) );
	}
	return ( $key, $key );
}

# seeds a test entry's throwaway tracked store from its tracked_before...
# records earlier lines of a transaction would have left, without which a
# reading rule's tracked gate can never be armed from its own file. a
# multiline messages: test can build the record for real instead, walking a
# harvest line and a reading line through one scope, which is the better
# proof where the rule file owns both halves.
#
# args:
#   $store   :: the throwaway tracked store hash ref
#   $seeds   :: the tracked_before list, each a hash of name, key (a string,
#               or a array for a compound key), fields (the hash the record
#               holds), and a optional ttl defaulting to 3600
#   $clock   :: the virtual clock, which the ttl counts from
#   $where   :: the test entry's where string, for failures
#   $results :: the run_tests results hash
#
# returns true on a malformed list or entry, the failure pushed, false on
# success.
#
#     tracked_before:
#       - name: mail-queue
#         key: 1C36D185729
#         fields: { postfix_client_ip: 203.0.113.9 }
sub _test_tracked_seed {
	my ( $store, $seeds, $clock, $where, $results ) = @_;

	if ( !is_plain_arrayref($seeds) ) {
		push( @{ $results->{failures} }, $where . ' tracked_before is not a array' );
		return 1;
	}

	foreach my $seed ( @{$seeds} ) {
		if (
			_test_store_entry_malformed(
				$seed,
				'tracked_before entry',
				[ 'name', 'key', 'fields', 'ttl' ],
				1, $where, $results
			)
			)
		{
			return 1;
		} ## end if ( _test_store_entry_malformed( $seed, 'tracked_before entry'...))
		my ($key) = _test_store_key( $seed->{key} );
		my $ttl = $seed->{ttl} // 3600;
		$store->{ $seed->{name} }{$key} = {
			'expires' => $clock + $ttl,
			'fields'  => { %{ $seed->{fields} } },
		};
	} ## end foreach my $seed ( @{$seeds} )

	return 0;
} ## end sub _test_tracked_seed

# asserts a tracked_expected/tracked_after list against the throwaway tracked
# store... that the record is live and holds the named fields by default,
# that it is not live at all under absent. every assertion is checked, so one
# run reports every miss.
#
# args:
#   $store    :: the throwaway tracked store hash ref
#   $expected :: the assertion list, each a hash of name, key (a string or a
#                compound array), and either fields (a hash of field to
#                expected value, each compared as a string) or a true absent
#   $clock    :: the virtual clock, which liveness is judged at
#   $where    :: the where string for failures, the test entry's, plus the
#                message index for a tracked_after
#   $results  :: the run_tests results hash
#
# returns true on any miss, the failures pushed, false when every assertion
# held.
#
#     tracked_expected:
#       - name: mail-queue
#         key: 1C36D185729
#         fields: { postfix_to: victim@example.org }
sub _test_tracked_assert {
	my ( $store, $expected, $clock, $where, $results ) = @_;

	if ( !is_plain_arrayref($expected) ) {
		push( @{ $results->{failures} }, $where . ' tracked assertion is not a array' );
		return 1;
	}

	my $failed = 0;
	foreach my $expect ( @{$expected} ) {
		if (
			_test_store_entry_malformed(
				$expect,
				'tracked assertion',
				[ 'name', 'key', 'fields', 'absent' ],
				0, $where, $results
			)
			)
		{
			$failed = 1;
			next;
		} ## end if ( _test_store_entry_malformed( $expect,...))

		my ( $key, $shown ) = _test_store_key( $expect->{key} );
		my $record = track_get( $store, $expect->{name}, $key, $clock );

		if ( $expect->{absent} ) {
			if ( defined($record) ) {
				push(
					@{ $results->{failures} },
					$where . ' expected no live ' . $expect->{name} . ' record for "' . $shown . '" but found one'
				);
				$failed = 1;
			}
			next;
		} ## end if ( $expect->{absent} )

		if ( !defined($record) ) {
			push(
				@{ $results->{failures} },
				$where . ' expected a live ' . $expect->{name} . ' record for "' . $shown . '" but found none'
			);
			$failed = 1;
			next;
		}

		if ( !is_plain_hashref( $expect->{fields} ) ) {
			next;
		}
		foreach my $field ( sort( keys( %{ $expect->{fields} } ) ) ) {
			my $got  = $record->{$field};
			my $want = $expect->{fields}{$field};
			if ( !defined($got) || "$got" ne "$want" ) {
				push(
					@{ $results->{failures} },
					$where . ' '
						. $expect->{name}
						. ' record "'
						. $shown
						. '" field '
						. $field
						. ' expected "'
						. $want
						. '" but got '
						. ( defined($got) ? '"' . $got . '"' : 'undef' )
				);
				$failed = 1;
			} ## end if ( !defined($got) || "$got" ne "$want" )
		} ## end foreach my $field ( sort( keys( %{ $expect->{fields...}})))
	} ## end foreach my $expect ( @{$expected} )

	return $failed;
} ## end sub _test_tracked_assert

# seeds a test entry's throwaway mark store from its marks_before... brands
# other rules would have set, without which a reader rule's gate can never be
# armed from its own file.
#
# args:
#   $store   :: the throwaway mark store hash ref
#   $seeds   :: the marks_before list, each a hash of name, key (a string, or
#               a array for a vars compound), a optional value, a optional
#               set time defaulting to the clock, and a optional ttl
#               defaulting to 3600
#   $clock   :: the virtual clock, which the ttl counts from
#   $where   :: the test entry's where string, for failures
#   $results :: the run_tests results hash
#
# returns true on a malformed list or entry, the failure pushed, false on
# success.
#
#     marks_before:
#       - name: brute_force
#         key: 192.0.2.7
#         value: ssh
sub _test_marks_seed {
	my ( $store, $seeds, $clock, $where, $results ) = @_;

	if ( !is_plain_arrayref($seeds) ) {
		push( @{ $results->{failures} }, $where . ' marks_before is not a array' );
		return 1;
	}

	foreach my $seed ( @{$seeds} ) {
		if (
			_test_store_entry_malformed(
				$seed,
				'marks_before entry',
				[ 'name', 'key', 'value', 'set', 'ttl' ],
				0, $where, $results
			)
			)
		{
			return 1;
		} ## end if ( _test_store_entry_malformed( $seed, 'marks_before entry'...))
		my ($key) = _test_store_key( $seed->{key} );
		my $ttl = $seed->{ttl} // 3600;
		$store->{ $seed->{name} }{$key} = {
			'expires' => $clock + $ttl,
			'set'     => $seed->{set} // $clock,
			defined( $seed->{value} ) ? ( 'value' => $seed->{value} ) : (),
		};
	} ## end foreach my $seed ( @{$seeds} )

	return 0;
} ## end sub _test_marks_seed

# asserts a marks_expected/marks_after list against the throwaway mark
# store... that the mark is live and, when a value is named, holds it, or
# under absent that it is not live at all. every assertion is checked, so one
# run reports every miss.
#
# args:
#   $store    :: the throwaway mark store hash ref
#   $expected :: the assertion list, each a hash of name, key (a string or a
#                vars compound array), and either a optional value, compared
#                as a string, or a true absent
#   $clock    :: the virtual clock, which liveness is judged at
#   $where    :: the where string for failures, the test entry's, plus the
#                message index for a marks_after
#   $results  :: the run_tests results hash
#
# returns true on any miss, the failures pushed, false when every assertion
# held.
#
#     marks_expected:
#       - name: brute_force
#         key: 192.0.2.7
#         value: ssh
sub _test_marks_assert {
	my ( $store, $expected, $clock, $where, $results ) = @_;

	if ( !is_plain_arrayref($expected) ) {
		push( @{ $results->{failures} }, $where . ' marks assertion is not a array' );
		return 1;
	}

	my $failed = 0;
	foreach my $expect ( @{$expected} ) {
		if (
			_test_store_entry_malformed(
				$expect,
				'marks assertion',
				[ 'name', 'key', 'value', 'absent' ],
				0, $where, $results
			)
			)
		{
			$failed = 1;
			next;
		} ## end if ( _test_store_entry_malformed( $expect,...))

		my ( $key, $shown ) = _test_store_key( $expect->{key} );
		my $mark = $store->{ $expect->{name} }{$key};
		my $live = defined($mark) && $mark->{expires} > $clock;
		if ( $expect->{absent} ) {
			if ($live) {
				push(
					@{ $results->{failures} },
					$where . ' expected no live mark ' . $expect->{name} . ' on "' . $shown . '" but one is'
				);
				$failed = 1;
			}
			next;
		} ## end if ( $expect->{absent} )
		if ( !$live ) {
			push(
				@{ $results->{failures} },
				$where . ' expected a live mark ' . $expect->{name} . ' on "' . $shown . '" but found none'
			);
			$failed = 1;
			next;
		}
		if ( defined( $expect->{value} )
			&& ( !defined( $mark->{value} ) || $mark->{value} ne $expect->{value} ) )
		{
			push(
				@{ $results->{failures} },
				$where
					. ' expected mark '
					. $expect->{name} . ' on "'
					. $shown
					. '" to hold value "'
					. $expect->{value}
					. '" but it holds '
					. ( defined( $mark->{value} ) ? '"' . $mark->{value} . '"' : 'none' )
			);
			$failed = 1;
		} ## end if ( defined( $expect->{value} ) && ( !defined...))
	} ## end foreach my $expect ( @{$expected} )

	return $failed;
} ## end sub _test_marks_assert

1;
