package App::Baphomet::Rules::Syslog;

use 5.006;
use strict;
use warnings;
use Regexp::IPv4 qw( $IPv4_re );
use Regexp::IPv6 qw( $IPv6_re );
use App::Baphomet::Parser ();

=pod

=head1 NAME

App::Baphomet::Rules::Syslog - Syslog rule handler for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Rules::Syslog;

    my $rule = App::Baphomet::Rules::Syslog->new( name => 'syslog/sshd', def => $def );

    my $found = $rule->check($parsed);
    if ( defined($found) ) {
        print $found->{data}{SRC} . "\n";
    }

Normally not used directly but via L<App::Baphomet::Rules>.

=head1 RULE FORMAT

A syslog rule is a YAML hash with the keys below.

    ---
    daemons:
      - sshd
      - sshd-session
    message_regexp:
      - '^[iI]nvalid user \S+ from %%%%SRC%%%%'
    ban_var:
      - SRC
    tests:
      positive:
        - message: "Jul 12 08:15:50 vixen42 sshd-session[66891]: Invalid user moth3r from 216.137.179.214 port 34640"
          found: 1
          data:
            SRC: "216.137.179.214"
      negative:
        - message: "Jul 12 08:25:49 vixen42 sshd-session[36748]: Accepted publickey for kitsune from 127.0.0.1 port 21680 ssh2: ED25519 SHA256:hjUfLIEAIR3ueytAg+XlbiVHmCQSQ6MCEdo2xYbyJ48"
          found: 0
          undefed: ["SRC"]

=head2 daemons

Which daemons this rule processes. The daemon of a parsed line is checked
against this list and if it does not match, further checking is skipped.
Entries starting and ending with C<//> are treated as regexps, so
C<//^sshd//> is the regexp C<^sshd>, while everything else is just a string
equality check.

=head2 message_regexp

The regexps checked, in order, against the message portion of a parsed
line. The first to match wins. These are Perl regexps with the addition of
C<%%%%TOKEN%%%%> style tokens, each of which is replaced at compile time
with a named capture group implementing the matching, so a match makes the
matched text available under the token name for use via L</ban_var>.

    - HOST :: Matches a domain name, IPv4 address, or IPv6 address.

    - SUBNET :: Matches a IPv6 or IPv4 subnet or address.

    - IP4 :: Matches a IPv4 address.

    - IP6 :: Matches a IPv6 address.

    - ADDR :: Matches a IPv4 or IPv6 address.

    - DNS :: Matches a domainname.

    - SRC / DEST :: These two are meant to be used in combination and only
          regard as being found if matched together. It will match either a
          IPv4 or IPv6 address.

A token may be used more than once in a single regexp... internally the
extra occurrences get numbered capture names and whichever occurrence
matched is folded back under the plain token name.

=head2 ignore_regexp

Optional. Regexps that veto a line. Checked after the daemon gate and
before L</message_regexp>, and if any matches the message, the line is not
regarded as found no matter what the message regexps would of said. The
fail2ban equivalent is C<ignoreregex>. Tokens work here too.

    ignore_regexp:
      - 'from %%%%SRC%%%% whom we like'

=head2 ban_var

The named regexp matches to use for bans. For each name here that a
matching line captured, the captured value is what gets handed to
Ereshkigal.

=head2 tests

Positive and negative tests for verifying the rule works. These are ran at
load time and a rule failing its own tests refuses to load. Each test is a
hash with the keys below.

    - message :: The full log line to test with. Required.

    - parser :: The parser to parse it with.
        Default :: bsd_syslog

    - found :: If the rule should match the line or not, 1 or 0.
        Default :: 1 for positive, 0 for negative

    - data :: For positive tests, a hash of capture names to the values
          they should of captured.

    - undefed :: For negative tests, a array of capture names that should
          not be defined.

=cut

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
		name            => defined( $opts{name} ) ? $opts{name} : 'unnamed',
		def             => $opts{def},
		daemon_strings  => {},
		daemon_regexps  => [],
		regexps         => [],
		ignore_regexps  => [],
	};
	bless $self;

	my $name = $self->{name};
	my $def  = $opts{def};

	if ( ref($def) ne 'HASH' ) {
		die( 'The def for the rule "' . $name . '" is not a hash' );
	}

	foreach my $key ( keys( %{$def} ) ) {
		if ( $key !~ /^(?:daemons|message_regexp|ignore_regexp|ban_var|tests)$/ ) {
			die( 'The rule "' . $name . '" has the unknown key "' . $key . '"' );
		}
	}

	if ( defined( $def->{ignore_regexp} ) ) {
		if ( ref( $def->{ignore_regexp} ) ne 'ARRAY' ) {
			die( 'The ignore_regexp of the rule "' . $name . '" is not a array' );
		}
		foreach my $item ( @{ $def->{ignore_regexp} } ) {
			if ( !defined($item) || ref($item) ne '' ) {
				die( 'The ignore_regexp of the rule "' . $name . '" contains a non-string entry' );
			}
		}
	} ## end if ( defined( $def->{ignore_regexp} ) )

	foreach my $key ( 'daemons', 'message_regexp', 'ban_var' ) {
		if ( ref( $def->{$key} ) ne 'ARRAY' || !@{ $def->{$key} } ) {
			die( 'The rule "' . $name . '" lacks a ' . $key . ' array or it is empty' );
		}
		foreach my $item ( @{ $def->{$key} } ) {
			if ( !defined($item) || ref($item) ne '' ) {
				die( 'The ' . $key . ' of the rule "' . $name . '" contains a non-string entry' );
			}
		}
	} ## end foreach my $key ( 'daemons', 'message_regexp',...)

	if ( defined( $def->{tests} ) && ref( $def->{tests} ) ne 'HASH' ) {
		die( 'The tests of the rule "' . $name . '" is not a hash' );
	}

	# compile the daemons list... //...// entries are regexps, the rest are
	# string equality checks
	foreach my $daemon ( @{ $def->{daemons} } ) {
		if ( $daemon =~ /^\/\/(.*)\/\/$/ ) {
			my $regexp = $1;
			my $compiled;
			eval { $compiled = qr/$regexp/; };
			if ($@) {
				die( 'The daemons entry "' . $daemon . '" of the rule "' . $name . '" does not compile... ' . $@ );
			}
			push( @{ $self->{daemon_regexps} }, $compiled );
		} else {
			$self->{daemon_strings}{$daemon} = 1;
		}
	} ## end foreach my $daemon ( @{ $def->{daemons} } )

	# compile the ignore regexps... tokens work here too, but nothing is
	# captured from them, so the aliases are just thrown away
	if ( defined( $def->{ignore_regexp} ) ) {
		my $ignore_int = 0;
		foreach my $regexp ( @{ $def->{ignore_regexp} } ) {
			my %ignore_aliases;
			my $expanded = $regexp;
			$expanded =~ s/%%%%([A-Z0-9]+)%%%%/$self->_expand_token( $1, \%ignore_aliases, 'ignore ' . $ignore_int, $regexp )/ge;

			my $compiled;
			eval { $compiled = qr/$expanded/; };
			if ($@) {
				die(      'The ignore_regexp entry '
						. $ignore_int
						. ' of the rule "'
						. $name
						. '", "'
						. $regexp
						. '", does not compile... '
						. $@ );
			}

			push( @{ $self->{ignore_regexps} }, $compiled );
			$ignore_int++;
		} ## end foreach my $regexp ( @{ $def->{ignore_regexp} ...})
	} ## end if ( defined( $def->{ignore_regexp} ) )

	# compile the message regexps, expanding tokens into named captures
	my $entry_int = 0;
	foreach my $regexp ( @{ $def->{message_regexp} } ) {
		my %aliases;
		my $expanded = $regexp;
		$expanded =~ s/%%%%([A-Z0-9]+)%%%%/$self->_expand_token( $1, \%aliases, $entry_int, $regexp )/ge;

		my $compiled;
		eval { $compiled = qr/$expanded/; };
		if ($@) {
			die(      'The message_regexp entry '
					. $entry_int
					. ' of the rule "'
					. $name
					. '", "'
					. $regexp
					. '", does not compile... '
					. $@ );
		}

		push(
			@{ $self->{regexps} },
			{
				'regexp'   => $compiled,
				'original' => $regexp,
				'aliases'  => \%aliases,
				'paired'   => ( defined( $aliases{SRC} ) && defined( $aliases{DEST} ) ) ? 1 : 0,
			}
		);

		$entry_int++;
	} ## end foreach my $regexp ( @{ $def->{message_regexp}...})

	return $self;
} ## end sub new

# expands a single token occurrence into a named capture group, numbering
# the capture name if the token has already been seen in this entry given
# perl does not allow duplicate capture names in a single regexp
sub _expand_token {
	my ( $self, $token, $aliases, $entry_int, $original ) = @_;

	if ( !defined( $tokens{$token} ) ) {
		die(      'The message_regexp entry '
				. $entry_int
				. ' of the rule "'
				. $self->{name}
				. '", "'
				. $original
				. '", uses the unknown token "'
				. $token
				. '"' );
	}

	if ( !defined( $aliases->{$token} ) ) {
		$aliases->{$token} = [$token];
		return '(?<' . $token . '>' . $tokens{$token} . ')';
	}

	my $alias = $token . '_' . ( scalar( @{ $aliases->{$token} } ) + 1 );
	push( @{ $aliases->{$token} }, $alias );

	return '(?<' . $alias . '>' . $tokens{$token} . ')';
} ## end sub _expand_token

=head2 check

Checks a parsed line, as returned by L<App::Baphomet::Parser>, against the
rule. Returns undef for no match. For a match, returns a hash as below,
with data holding the named captures, token occurrences folded back under
the plain token name.

    { 'data' => { 'SRC' => '1.2.3.4' }, 'regexp' => 0 }

    my $found = $rule->check($parsed);

=cut

sub check {
	my ( $self, $parsed ) = @_;

	if ( ref($parsed) ne 'HASH' || !defined( $parsed->{message} ) ) {
		return undef;
	}

	# the daemon gate
	my $daemon = $parsed->{daemon};
	if ( !defined($daemon) ) {
		return undef;
	}
	my $daemon_matched = 0;
	if ( defined( $self->{daemon_strings}{$daemon} ) ) {
		$daemon_matched = 1;
	} else {
		foreach my $regexp ( @{ $self->{daemon_regexps} } ) {
			if ( $daemon =~ $regexp ) {
				$daemon_matched = 1;
				last;
			}
		}
	}
	if ( !$daemon_matched ) {
		return undef;
	}

	# a ignore_regexp match vetoes the line entirely
	foreach my $ignore ( @{ $self->{ignore_regexps} } ) {
		if ( $parsed->{message} =~ $ignore ) {
			return undef;
		}
	}

	my $entry_int = 0;
	foreach my $entry ( @{ $self->{regexps} } ) {
		if ( $parsed->{message} =~ $entry->{regexp} ) {
			my %caps = %+;

			# fold numbered token occurrences back under the plain token name
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
				$entry_int++;
				next;
			}

			return { 'data' => \%caps, 'regexp' => $entry_int };
		} ## end if ( $parsed->{message} =~ $entry->{regexp...})
		$entry_int++;
	} ## end foreach my $entry ( @{ $self->{regexps} } )

	return undef;
} ## end sub check

=head2 ban_var

Returns the list of capture names to use for bans.

    my @ban_var = $rule->ban_var;

=cut

sub ban_var {
	my ($self) = @_;

	return @{ $self->{def}{ban_var} };
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

			my $parser = defined( $test->{parser} ) ? $test->{parser} : 'bsd_syslog';
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
