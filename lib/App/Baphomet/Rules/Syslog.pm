package App::Baphomet::Rules::Syslog;

use 5.006;
use strict;
use warnings;
use base 'App::Baphomet::Rules::Base';

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

=head2 capture_regexp / keyed message_regexp entries

For daemons that log the offense and the offender's address on separate
lines sharing a correlation key, like a connection or queue id.

    capture_regexp:
      - regexp: '^\[conn(?<KEY>\d+)\] end connection %%%%SRC%%%%:\d+'
        key: KEY
        ttl: 600
    message_regexp:
      - regexp: '^\[conn(?<KEY>\d+)\] Failed to authenticate'
        key: KEY
        defer: 600

capture_regexp entries harvest context rather than being offenses... a hit
stores the folded captures under the value of the named capture C<key>
names, for C<ttl> seconds (default 60). message_regexp entries may be
hashes instead of plain strings... on match the key is looked up and any
stored captures merge into the data, the line's own captures winning. Not
found plus C<defer> parks the offense for that many seconds awaiting a
capture line with the key, several of which may complete at once. Not
found with out defer falls through to the next entry.

Correlation state is per watcher, in memory only, and bounded... a galla
restart forgets pending correlations.

=head2 ban_var

The named regexp matches to use for bans. For each name here that a
matching line captured, the captured value is what gets handed to
Ereshkigal.

=head2 tests

Positive and negative tests for verifying the rule works. These are ran at
load time and a rule failing its own tests refuses to load. Each test is a
hash with the keys below. A top level C<test_parser> key sets the default
parser for all of them.

    - message :: The full log line to test with. Either this or messages
          is required.

    - messages :: A array of lines fed through in order, for testing
          correlation... each test entry runs in its own throwaway scope,
          found is the expected count of found results across the
          sequence, and data asserts against the last of them.

    - parser :: The parser to parse it with.
        Default :: bsd_syslog

    - found :: If the rule should match the line or not, 1 or 0.
        Default :: 1 for positive, 0 for negative

    - data :: For positive tests, a hash of capture names to the values
          they should of captured.

    - undefed :: For negative tests, a array of capture names that should
          not be defined.

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
		daemon_strings => {},
		daemon_regexps => [],
	};
	bless $self;

	my $name = $self->{name};
	my $def  = $opts{def};

	if ( ref($def) ne 'HASH' ) {
		die( 'The def for the rule "' . $name . '" is not a hash' );
	}

	foreach my $key ( keys( %{$def} ) ) {
		if ( $key !~ /^(?:daemons|message_regexp|ignore_regexp|capture_regexp|ban_var|ban_not_internal|test_parser|tests)$/ )
		{
			die( 'The rule "' . $name . '" has the unknown key "' . $key . '"' );
		}
	}

	foreach my $key ( 'daemons', 'ban_var' ) {
		if ( ref( $def->{$key} ) ne 'ARRAY' || !@{ $def->{$key} } ) {
			die( 'The rule "' . $name . '" lacks a ' . $key . ' array or it is empty' );
		}
		foreach my $item ( @{ $def->{$key} } ) {
			if ( !defined($item) || ref($item) ne '' ) {
				die( 'The ' . $key . ' of the rule "' . $name . '" contains a non-string entry' );
			}
		}
	} ## end foreach my $key ( 'daemons', 'ban_var' )

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

	# the token and regexp machinery lives in the base class
	$self->_compile_message_regexps($def);
	$self->_compile_capture_regexps($def);

	return $self;
} ## end sub new

=head2 check

Checks a parsed line, as returned by L<App::Baphomet::Parser>, against the
rule. Returns undef for no match. For a match, returns a hash as below,
with data holding the named captures, token occurrences folded back under
the plain token name.

    { 'data' => { 'SRC' => '1.2.3.4' }, 'regexp' => 0 }

    my $found = $rule->check($parsed);

=cut

sub check {
	my ( $self, $parsed, $scope ) = @_;

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

	return $self->_check_message( $parsed->{message}, $scope );
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

Runs the tests embedded in the rule. Inherited from
L<App::Baphomet::Rules::Base>, with tests defaulting to the bsd_syslog
parser.

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
