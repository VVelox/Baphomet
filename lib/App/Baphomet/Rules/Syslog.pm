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

A C<key> may also be a array of components, and a component may name a
reserved envelope field... C<syslog.daemon>, C<syslog.host>, or
C<syslog.pid>... in place of a capture. So a daemon whose lines share
nothing but the logging process itself, the fail2ban F-MLFID shape,
correlates by its session with no key in the message at all:

    capture_regexp:
      - regexp: '^Connection from %%%%SRC%%%%'
        key: [ syslog.host, syslog.daemon, syslog.pid ]
        ttl: 120
    message_regexp:
      - regexp: '^Too many authentication failures'
        key: [ syslog.host, syslog.daemon, syslog.pid ]
        defer: 60

Components resolve captures first and envelope fields by their reserved
names, and every component must resolve... a message_regexp entry any of
whose components is missing (a daemon logging with no pid, say) is judged
as a plain unkeyed offense, and a capture_regexp entry harvests nothing.
Keying on C<syslog.pid> alone correlates lines of one process life...
include C<syslog.host> when several hosts share the log.

Correlation state is per watcher, in memory only, and bounded... a galla
restart forgets pending correlations.

=head2 stages / per... ordered sequences with in one rule

A staged rule matches a sequence rather than a line... ordered stages,
each a tokened C<message_regexp> list with an optional hit C<count>
(default 1), a C<within> bound in seconds on the gap since the previous
hit, and a C<skip> bound on the log lines allowed between hits. The final
stage completing is the offense, its data every hit's captures merged,
later stages authoritative. C<stages> is the whole matcher... it refuses
to load beside C<message_regexp>, C<capture_regexp>, or C<message_json>,
while C<ignore_regexp> still vetoes lines ahead of the stages and the
predicate gate still filters the completed offense.

    stages:
      - message_regexp:
          - '^Failed (?:password|publickey) for .* from %%%%SRC%%%%'
        count: 5
        within: 300
      - message_regexp:
          - '^Accepted \w+ for .* from %%%%SRC%%%%'
        within: 60
    per: [ SRC ]
    detection_var: [ SRC ]

C<per> keys the sequence state... captures and the envelope fields
(C<syslog.host>/C<syslog.daemon>/C<syslog.pid>), every component required
to resolve for a line to join. With out C<per> the state is one slot per
followed file, pure adjacency... only sound for serialized logs, since a
multi-client daemon interleaves sessions. A hit landing past C<within> or
C<skip> kills the sequence (the line may then head a fresh one); a line
matching the first stage never tramples a sequence already in flight for
its key; intermediate hits do not consume the line, so plain rules beside
a staged one still see it. State is per watcher, memory only, and
bounded. The found carries a C<stages> array of every hit (stage index,
epoch, line), written to EVE beside the usual fields.

=head2 message_json

Optional boolean. When a daemon logs a JSON object as its message, this
decodes it and flattens it into fields the L</gate> can test by their dotted
paths, the way a C<json> rule works, so operators and decode fall on the
message's own fields. The syslog envelope stays reachable under reserved keys
(C<syslog.daemon>, C<syslog.host>, C<syslog.pid>, C<syslog.time>,
C<syslog.message>), and C<ban_var> may name a json field or a capture.

    daemons:
      - myapp
    message_json: true
    gate:
      - { field: event, op: eq, value: auth_fail }
      - { field: cmd,   op: contains, value: mimikatz, decode: [ base64 ] }
    ban_var:
      - src

With message_json on, C<message_regexp> becomes optional... the gate is the
matcher, so a rule may have none. A message that is not a JSON object yields
no fields, so the gate falls through and the line is not an offense (and any
C<message_regexp>, if present, still runs on the raw message as the matcher,
the gate then refining over both its captures and the json fields). The decode
is memoised per line, so several message_json rules on one watcher share the
one parse. A rule with message_json, no message_regexp, and no gate is a error,
as it would banish every line.

=head2 gate

Optional. A post-match refinement over the captures, ANDed... after a
C<message_regexp> matches and its captures are extracted, each gate entry
tests one of them, and any failure drops the line to a non-offense. With
L</message_json> the gate also sees the decoded json fields and the reserved
C<syslog.*> envelope. Here the C<field> names a capture... a token capture
like C<SRC>, a named group like C<CMD>, or the reserved C<MESSAGE> for the
whole message. The entry forms, operators, and C<decode>, along with
C<selections>/C<condition> and C<keywords>, are the shared predicate
vocabulary documented under L<App::Baphomet::Rules::Base/"The predicate gate">.

    message_regexp:
      - 'ran command (?<CMD>\S+) as %%%%SRC%%%%'
    gate:
      - { field: CMD, decode: [ base64 ], op: contains, value: mimikatz }
      - { field: SRC, op: cidr, value: 10.0.0.0/8 }

=head2 ban_var

The capture names to ban by. For each name here that a matching line
captured, the captured value is the offender handed to Ereshkigal. Usually
just C<SRC>. To count without banning, name L<App::Baphomet::Rules::Base/detection_var>
in its place.

=head2 The common keys

Everything past the matcher... C<detection_var>, C<ban_not_internal>, the
counting knobs (C<max_score>/C<find_time>/C<ban_time>/C<weight>, C<eve_only>,
C<distinct>), the triage metadata (C<msg>,
C<severity>/C<classtype>/C<references>/C<attack>), the C<selections> /
C<condition> / C<keywords> boolean forms, the marks
(C<mark>/C<unmark>/C<marked>/C<not_marked>/C<mark_only>, C<sequence>), the
C<country> / C<namtar_list> / C<active_time> gates, and C<tests>... is shared
by every rule type and documented in full under
L<App::Baphomet::Rules::Base/"RULE FORMAT">.

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
		gates          => [],
		message_json   => 0,
	};
	bless $self;

	my $name = $self->{name};
	my $def  = $opts{def};

	if ( ref($def) ne 'HASH' ) {
		die( 'The def for the rule "' . $name . '" is not a hash' );
	}

	foreach my $key ( keys( %{$def} ) ) {
		if ( $key
			!~ /^(?:daemons|message_regexp|ignore_regexp|capture_regexp|message_json|stages|per|gate|selections|condition|keywords|ban_var|detection_var|ban_not_internal|max_score|find_time|ban_time|weight|eve_only|msg|severity|classtype|references|attack|mark|unmark|marked|not_marked|mark_only|sequence|country|namtar_list|active_time|reverse_dns|distinct|test_parser|tests|src_ip_var|dest_ip_var)$/
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
	# banishes, so it needs no ban_var... daemons is required either way
	my $is_detection = $self->_check_detection_var( $def, $name );
	my @required     = $is_detection ? ('daemons') : ( 'daemons', 'ban_var' );
	foreach my $key (@required) {
		if ( ref( $def->{$key} ) ne 'ARRAY' || !@{ $def->{$key} } ) {
			die( 'The rule "' . $name . '" lacks a ' . $key . ' array or it is empty' );
		}
		foreach my $item ( @{ $def->{$key} } ) {
			if ( !defined($item) || ref($item) ne '' ) {
				die( 'The ' . $key . ' of the rule "' . $name . '" contains a non-string entry' );
			}
		}
	} ## end foreach my $key (@required)

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

	# when the daemon logs a JSON object as its message, decode it into fields
	# the gate can test... message_regexp is then optional, the gate matching
	if ( defined( $def->{message_json} ) && ref( $def->{message_json} ) ne '' ) {
		die( 'The message_json of the rule "' . $name . '" is not a boolean' );
	}
	$self->{message_json} = $def->{message_json} ? 1 : 0;

	# the envelope fields a correlation key may name beside the captures...
	# how a session-scoped daemon correlates lines carrying no key of their own
	$self->{envelope_key_fields} = {
		'syslog.daemon' => 1,
		'syslog.host'   => 1,
		'syslog.pid'    => 1,
	};

	# a staged rule... its stages are the whole matcher, exclusive with the
	# per-line matchers and the keyed correlation
	if ( defined( $def->{stages} ) ) {
		if ( defined( $def->{message_regexp} ) || defined( $def->{capture_regexp} ) || $self->{message_json} ) {
			die(      'The rule "'
					. $name
					. '" has stages beside message_regexp, capture_regexp, or message_json... stages are the whole matcher'
			);
		}
		$self->_compile_ignore_regexps($def);
		$self->_compile_stages($def);
		$self->_compile_boolean( $def, $name );
		return $self;
	} ## end if ( defined( $def->{stages} ) )
	if ( defined( $def->{per} ) ) {
		die( 'The rule "' . $name . '" has a per but no stages for it to key' );
	}

	# the token and regexp machinery lives in the base class
	$self->_compile_message_regexps( $def, $self->{message_json} );
	$self->_compile_capture_regexps($def);

	# an optional gate or selections+condition refines the match on its
	# captures, and when message_json on the decoded fields too... operators and
	# decode over the extracted vars, the json fields, and the reserved MESSAGE
	$self->_compile_boolean( $def, $name );

	# a message_json rule with no message_regexp must match on something, else
	# it would regard every JSON line from the daemon as a offense
	if ( $self->{message_json} && !@{ $self->{regexps} } && !@{ $self->{gates} } && !defined( $self->{condition_ast} ) )
	{
		die(      'The rule "'
				. $name
				. '" is message_json with no message_regexp and no gate or selections, so it would banish every line' );
	}

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
	my ( $self, $parsed, $scope, $line_ctx ) = @_;

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

	# only built for rules whose correlation or per keys name envelope fields
	my $envelope;
	if ( $self->{wants_envelope} ) {
		$envelope = {
			'syslog.daemon' => $parsed->{daemon},
			'syslog.host'   => $parsed->{hostname},
			'syslog.pid'    => $parsed->{pid},
		};
	}

	if ( defined( $self->{stages} ) ) {
		return $self->_check_stages( $parsed->{message}, $scope, $line_ctx, $envelope );
	}

	if ( $self->{message_json} ) {
		return $self->_check_message( $parsed->{message}, $scope, $self->_message_json_extra($parsed), $envelope );
	}

	return $self->_check_message( $parsed->{message}, $scope, undef, $envelope );
} ## end sub check

# builds the extra field space a message_json rule gates over... the JSON body
# flattened (memoised on the parsed line so several rules share the one decode)
# plus the syslog envelope under reserved syslog.* keys that can not clash
sub _message_json_extra {
	my ( $self, $parsed ) = @_;

	if ( !exists( $parsed->{_message_json_fields} ) ) {
		$parsed->{_message_json_fields} = $self->_flatten_json_message( $parsed->{message} );
	}
	my %extra = %{ $parsed->{_message_json_fields} };

	if ( defined( $parsed->{daemon} ) )   { $extra{'syslog.daemon'}  = $parsed->{daemon}; }
	if ( defined( $parsed->{hostname} ) ) { $extra{'syslog.host'}    = $parsed->{hostname}; }
	if ( defined( $parsed->{pid} ) )      { $extra{'syslog.pid'}     = $parsed->{pid}; }
	if ( defined( $parsed->{time} ) )     { $extra{'syslog.time'}    = $parsed->{time}; }
	if ( defined( $parsed->{message} ) )  { $extra{'syslog.message'} = $parsed->{message}; }

	return \%extra;
} ## end sub _message_json_extra

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
