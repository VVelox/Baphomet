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

=head2 max_retrys / find_time / ban_time

Optional. The rule's own thresholds, honored only when the watcher's
C<allow_per_rule_thresholds> config setting is on, at which point the
layering is rule over watcher over kur over global. A rule overriding
C<max_retrys> or C<find_time> is counted in its own bucket, apart from
the shared per-IP count, while a C<ban_time>-only override counts in the
shared bucket and just bans with its own duration.

=head2 mark / unmark / marked / not_marked / mark_only

Optional. Marks are a galla wide, expiring, named store one rule brands and
another gates on, so rules can carry state across each other the way
correlation carries it across lines. The key defaults to the offender IP
but any capture or field can be it, and a value can be harvested from the
line too.

    - mark :: Array of brands to set on match, each a hash of C<name> and
          C<ttl>, and optionally C<var> (key by this capture instead of the
          offender IP) and C<value_var> (store this capture on the brand).

    - unmark :: Array of brands to lift on match, each C<name> and
          optionally C<var>.

    - marked :: Gate array, ANDed... the result only counts if every named
          brand is set. Each a hash of C<name>, optionally C<var>, and at
          most one of C<value_is> or C<value_not> naming a capture the
          stored value must equal or differ from. A var entry is checked
          against the line's captures, a var-less one against each offender.

    - not_marked :: The inverse gate... the result only counts if none of
          the named brands is set.

    - mark_only :: When true the rule only brands and gates, never counting
          toward a ban, and does not consume the line, so matching falls
          through to the later rules.

A rule whose mark gates veto, like a mark_only rule, falls through rather
than consuming the line, so the brander and the gater can both fire on it.
Marks live per galla, cross watchers and rules but not kurs, survive a
restart, and are visible with C<baphomet marked>. The ignored are never
branded. See C<syslog/sshd-mark-users> and C<syslog/sshd-spray> for a
shipped pair.

=head2 country

Optional. A gate that only lets a match count when a IP is in, or not in, a
set of countries, needing the C<geoip_db> config setting and the optional
IP::Geolocation::MMDB module. A hash of:

    - is / isnot :: At most one. A list of ISO 3166 2-letter codes and
          C<%%%country_codes{name}%%%> imports of named lists from the
          config (resolved per watcher). A bare string is a one-element
          list. is counts only IPs in the set, isnot only those not in it.

    - vars :: Optional. Found vars to check the country of instead of the
          offender. Without it the gate is offender-keyed, checked per
          ban_var candidate in the ban loop. With it the gate is data-keyed,
          checked once per result against those vars (resolved like ban_var)
          and vetoing the whole result on a failure... so a rule can gate on
          the geography of a value it is not banning.

The gate fails closed: a IP that does not locate, or a missing database,
blocks the count rather than risking a wrong ban. A galla with country
gated rules and no database says so loudly at start.

=head2 namtar_list

Optional. A gate that only lets a match count when a IP is on a named
blocklist, the inverse of ignore_ips. The lists are CIDR files named in
the config's C<namtar_lists>, layered per watcher and reloaded on mtime
change. A array of entries, each:

    - list / lists :: One or more named lists to check against. A value on
          any of them (union) satisfies the entry.

    - var :: Optional. The found var to check, resolved like ban_var. With
          it the entry is data-keyed and vets the whole result, without it
          the entry is offender-keyed and filters candidates... so a rule
          can gate on a captured address it is not banning.

Every entry must hold. The gate fails closed: a IP on no list, or a list
whose file is unreadable, blocks the count. ignore_ips still wins, so a
ignored IP is never banished even when blocklisted.

=head2 active_time

Optional. A gate that only lets a match count when a time is in, or not in,
named windows from the config's C<active_time>, resolved per watcher. A
hash of:

    - is / isnot :: At most one. A window name or a list of them. Multiple
          are unioned. is counts only when the time is in a window, isnot
          only when in none.

    - vars :: Optional. Found vars holding the time to check, read as a
          epoch or a ISO 8601 datetime. Without it the gate checks the
          current time. A value that does not parse fails closed.

Unlike the other gates active_time is never per-offender... time is a
property of the line, so it is checked once per result and vetoes the whole
result. Times are local.

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
		if ( $key
			!~ /^(?:daemons|message_regexp|ignore_regexp|capture_regexp|ban_var|ban_not_internal|max_retrys|find_time|ban_time|mark|unmark|marked|not_marked|mark_only|country|namtar_list|active_time|test_parser|tests)$/
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
