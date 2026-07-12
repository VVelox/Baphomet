package App::Baphomet::Rules::Base;

use 5.006;
use strict;
use warnings;
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

=head1 METHODS

=head2 default_test_parser

The parser used for embedded tests that do not name one.

    my $parser = $rule->default_test_parser;

=cut

sub default_test_parser {
	return 'bsd_syslog';
}

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

			if ( ref($test) ne 'HASH' || !defined( $test->{message} ) ) {
				$results->{fail}++;
				push( @{ $results->{failures} }, $where . ' is not a hash with a message' );
				next;
			}

			my $parser = defined( $test->{parser} ) ? $test->{parser} : $self->default_test_parser;
			my $parsed;
			eval { $parsed = App::Baphomet::Parser::parse( $parser, $test->{message} ); };
			if ($@) {
				$results->{fail}++;
				push( @{ $results->{failures} }, $where . ' has a unusable parser... ' . $@ );
				next;
			}
			if ( !defined($parsed) ) {
				$results->{fail}++;
				push( @{ $results->{failures} },
					$where . ' message did not parse via ' . $parser . '... "' . $test->{message} . '"' );
				next;
			}

			my $expected_found = defined( $test->{found} ) ? $test->{found} : ( $sort eq 'positive' ? 1 : 0 );
			my $found          = $self->check($parsed);
			my $got_found      = defined($found) ? 1 : 0;

			if ( $got_found != $expected_found ) {
				$results->{fail}++;
				push( @{ $results->{failures} },
						  $where
						. ' expected found='
						. $expected_found
						. ' but got found='
						. $got_found
						. ' for "'
						. $test->{message}
						. '"' );
				next;
			} ## end if ( $got_found != $expected_found )

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
