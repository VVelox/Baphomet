package App::Baphomet::Rules::MessageRegexp;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util qw( is_plain_arrayref is_plain_hashref );
use App::Baphomet::Correlation
	qw( correlation_key context_put context_get pending_park pending_complete fold_completions );
use App::Baphomet::Marks         ();
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp match_tokened );
use App::Baphomet::Shape         qw( check_hash check_entries );
use base 'App::Baphomet::Rules::Base';

=pod

=head1 NAME

App::Baphomet::Rules::MessageRegexp - The regexp matcher the syslog and raw rule handlers share.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

What a rule that matches regexps against a message is made of... the
C<message_regexp>, C<ignore_regexp>, and C<capture_regexp> lists, the
C<stages> and C<per> of a staged rule, and the check that runs them. The
syslog and raw types are the two built on it, the syslog type adding its
daemon gate, C<message_json>, and the envelope. Not usable on its own... see
L<App::Baphomet::Rules::Syslog> and L<App::Baphomet::Rules::Raw>.

=head1 METHODS

=head2 check

Checks a parsed line against the rule. Returns undef for no match. For a
match, returns a hash as below, with data holding the named captures, token
occurrences folded back under the plain token name.

    { 'data' => { 'SRC' => '1.2.3.4' }, 'regexp' => 0 }

The raw type uses this as it stands. The syslog type runs its daemon gate
first, then calls this with the envelope and the extra fields only it has.

    - parsed :: The parsed line, as returned by L<App::Baphomet::Parser>. A
          line with no message matches nothing.

    - scope :: The correlation scope, the watcher name.

    - line_ctx :: Hash ref of the line context the galla builds, the clock,
          the line's sequence and source, and the tracked store, or undef.

    - envelope :: Hash ref of the reserved C<syslog.*> envelope fields a
          correlation or C<per> key may name, or undef.

    - extra :: Hash ref of further fields to lay under the captures, the
          C<message_json> body, or undef.

    my $found = $rule->check( $parsed, $scope, $line_ctx );

=cut

sub check {
	my ( $self, $parsed, $scope, $line_ctx, $envelope, $extra ) = @_;

	if ( !is_plain_hashref($parsed) || !defined( $parsed->{message} ) ) {
		return undef;
	}

	# mungers run first, their decoded fields laid down under the offense so
	# the rule's own captures overwrite them on a name clash. a staged rule
	# enriches the completed sequence from its final (completing) line
	my $munge = $self->_munge_enrich($parsed);

	if ( defined( $self->{stages} ) ) {
		return $self->_check_stages( $parsed->{message}, $scope, $line_ctx, $envelope, $munge );
	}

	if ( defined($munge) && %{$munge} ) {
		$extra = defined($extra) ? { %{$munge}, %{$extra} } : { %{$munge} };
	}

	return $self->_check_message( $parsed->{message}, $scope, $extra, $envelope, $line_ctx );
} ## end sub check

=head2 sweep_state

Drops the staged sequences nothing has fed since their stage's within, or
the default hold, then the expired correlation state every rule sweeps. The
galla calls this from its sweeper so expiry does not depend on traffic.

    $rule->sweep_state($now);

=cut

sub sweep_state {
	my ( $self, $now ) = @_;

	$now //= time;

	# only a staged rule has the slots, and only once a line has opened one
	my $stage_state = $self->{stage_state} // {};
	foreach my $scope ( keys( %{$stage_state} ) ) {
		foreach my $key ( keys( %{ $stage_state->{$scope} } ) ) {
			if ( $stage_state->{$scope}{$key}{expires} <= $now ) {
				delete( $stage_state->{$scope}{$key} );
			}
		}
		if ( !%{ $stage_state->{$scope} } ) {
			delete( $stage_state->{$scope} );
		}
	} ## end foreach my $scope ( keys( %{$stage_state} ) )

	$self->SUPER::sweep_state($now);

	return;
} ## end sub sweep_state

# Names the first message_regexp whose shape leaves the offender open to being
# chosen by whoever wrote the line, or undef when none does. Sets
# needs_injection_test, which run_tests turns into a warning when the rule
# carries no tests.injection to answer it... a warning and not a failure,
# because the shape alone does not make a rule exploitable.
#
# The shape is a LAZY unbounded wildcard between the head of the pattern and the
# offender token, with nothing anchoring the token's tail. Lazy takes the first
# candidate it reaches, so wherever the log lets a client write text ahead of the
# real field... an account name, a mail subject, a user agent... the client picks
# the ban target by planting a copy of the delimiter. Every real instance of this
# found in the shipped set had exactly this shape.
#
# Greedy is deliberately NOT flagged. It takes the LAST candidate, and a forgery
# can only ever be planted ahead of the field the daemon writes, so the ordering
# is itself the defence.
#
# This is a shape and nothing more. Whether a client can actually reach that
# wildcard is a property of the log format, which no amount of reading the
# pattern will settle: the two raw/palo-alto rules are the same shape and
# opposite verdicts, one writing the account before the address and one after.
# So this does not judge the pattern, and must not refuse it... it points at a
# question only a test can answer, and the answer may well be "safe here".
sub _detect_injection_shape {
	my ($self) = @_;

	my $def = $self->{def};

	$self->{needs_injection_test} = undef;

	foreach my $item ( @{ $def->{message_regexp} || [] } ) {
		my $re = is_plain_hashref($item) ? $item->{regexp} : $item;
		next if ( !defined($re) || ref($re) ne '' );

		my ( $pre, $token, $post ) = $re =~ /^(.*?)%%%%(SRC|DEST|ADDR|HOST|IP4|IP6|SUBNET)%%%%(.*)$/s;
		next if ( !defined($token) );

		# an unbounded run that yields the shortest match... ".*?", "\S+?" and
		# the like. a bounded one ("[^"]*", "{0,3}") cannot cross a delimiter
		next if ( $pre !~ /(?:\.|\\S|\\w|\\d|\\D|\\W)[*+]\?/ );

		# peel the tail down to whatever really has to be there... an all
		# optional group, a trailing space run, and a word boundary each anchor
		# nothing at all
		my $tail    = $post;
		my $peeling = 1;
		while ($peeling) {
			$peeling = 0;
			$peeling = 1 if ( $tail =~ s/\((?:\?:)?[^()]*\)[?*]// );
			$peeling = 1 if ( $tail =~ s/\\s\*// );
			$peeling = 1 if ( $tail =~ s/\\b// );
		}
		next if ( $tail =~ /\S/ );

		$self->{needs_injection_test} = 'the offender of "' . $re . '"';
		return;
	} ## end foreach my $item ( @{ $def->{message_regexp} ||...})

	return;
} ## end sub _detect_injection_shape

# compiles the matcher of the syslog and raw types, which is one of two
# things... a staged rule, whose stages are the whole matcher, or the
# per-line message_regexp with its capture_regexp correlation, and either way
# the ignore_regexp and the boolean. shared by the two types so a change to
# what a regexp rule may carry lands once.
#
# message_regexp may be left off when something else does the matching...
# message_json, whose decoded fields the gate tests, or mungers, whose
# decomposed fields it tests the same way, which is what lets an appliance
# rule name a parsed field as its offender instead of scanning the line for
# an address. either makes the gate the matcher, so such a rule must carry
# one.
#
# takes nothing, reading the def, the mungers, and message_json, which only
# the syslog type sets, off the object... so it is called after those are
# settled. returns nothing, dying on stages beside the per-line matchers, a
# per with no stages, anything the compiles it calls refuse, or a rule that
# would regard every line it decodes as a offense.
#
#   $self->_compile_message_matchers;
sub _compile_message_matchers {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	# a staged rule... its stages are the whole matcher, exclusive with the
	# per-line matchers and the keyed correlation
	if ( defined( $def->{stages} ) ) {
		my @beside = grep { defined( $def->{$_} ) } ( 'message_regexp', 'capture_regexp' );
		if ( $self->{message_json} ) {
			push( @beside, 'message_json' );
		}
		if (@beside) {
			die(      'The rule "'
					. $name
					. '" has stages beside '
					. join( ', ', @beside )
					. '... stages are the whole matcher' );
		}
		$self->_compile_ignore_regexps;
		$self->_compile_stages;
		$self->_compile_boolean;
		return;
	} ## end if ( defined( $def->{stages} ) )
	if ( defined( $def->{per} ) ) {
		die( 'The rule "' . $name . '" has a per but no stages for it to key' );
	}

	my $gate_may_match = ( $self->{message_json} || @{ $self->{mungers} } ) ? 1 : 0;
	$self->_compile_message_regexps($gate_may_match);
	$self->_compile_capture_regexps;

	# an optional gate or selections+condition refines the match on its
	# captures, and on the message_json or munger fields too... operators and
	# decode over the extracted vars, those fields, and the reserved MESSAGE
	$self->_compile_boolean;

	# a message_json or munger rule with no message_regexp must match on
	# something, else it would regard every line it decodes as a offense
	if ( $gate_may_match && !@{ $self->{regexps} } && !$self->{has_boolean} ) {
		die(      'The rule "'
				. $name . '" is '
				. ( $self->{message_json} ? 'message_json' : 'munger driven' )
				. ' with no message_regexp and no gate, selections, or keywords, so it would banish every line' );
	}

	return;
} ## end sub _compile_message_matchers

# compiles the def's message_regexp and ignore_regexp onto the object,
# expanding %%%%TOKEN%%%% tokens into named captures... a entry is the regexp
# as a plain string, or a hash keying it for correlation, regexp and key with
# a optional defer. the entries are all vetted before anything is compiled, so
# a misshapen one is named ahead of a regexp that will not compile.
#
# args:
#   $allow_empty :: true when the def may leave message_regexp off, something
#                   else, message_json or the mungers, doing the matching
#
# returns nothing, dying on anything unusable. regexps is left a arrayref of
# compiled entries, each as compile_tokened_regexp returns with, for a hash
# entry, key, the arrayref of its key components, and defer, the seconds a
# unresolved offense waits or undef. ignore_regexps is left a arrayref of
# compiled regexps.
#
#   $self->_compile_message_regexps(0);
#   # $self->{regexps}[0]{key} is ['SESSION'] for { regexp: ..., key: SESSION }
sub _compile_message_regexps {
	my ( $self, $allow_empty ) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	$self->{regexps} = [];

	# does any pattern leave the offender open to being chosen by whoever wrote
	# the line? run_tests turns a yes into a demand for a tests.injection entry
	$self->_detect_injection_shape;

	# a message_json rule may have no message_regexp, the json fields being
	# what it matches on, so the caller can allow an empty list. a missing key
	# is fine then; a present but malformed one is still an error
	if ( !defined( $def->{message_regexp} ) && $allow_empty ) {
		$self->_compile_ignore_regexps;
		return;
	}
	if ( !is_plain_arrayref( $def->{message_regexp} ) || !@{ $def->{message_regexp} } ) {
		die( 'The rule "' . $name . '" lacks a message_regexp array or it is empty' );
	}
	my $entries_where = 'The message_regexp of the rule "' . $name . '"';
	foreach my ( $entry_int, $item ) ( indexed @{ $def->{message_regexp} } ) {
		my $where = $entries_where . ' entry ' . $entry_int;
		if ( is_plain_hashref($item) ) {
			check_hash(
				$item,
				{ 'required' => { 'regexp' => 'scalar', 'key' => 'any' }, 'optional' => { 'defer' => 'seconds' } },
				$where
			);
		} elsif ( !defined($item) || ref($item) ne '' ) {
			die( $where . ' is not a string or a hash' );
		}
	} ## end foreach my ( $entry_int, $item ) ( indexed @{ $def...})

	$self->_compile_ignore_regexps;

	foreach my ( $entry_int, $item ) ( indexed @{ $def->{message_regexp} } ) {
		my $where    = $entries_where . ' entry ' . $entry_int;
		my $regexp   = is_plain_hashref($item) ? $item->{regexp} : $item;
		my $compiled = compile_tokened_regexp( $regexp, $where );
		if ( is_plain_hashref($item) ) {
			$compiled->{key}   = $self->_correlation_key_components( $item->{key}, $where );
			$compiled->{defer} = $item->{defer};
		}
		push( @{ $self->{regexps} }, $compiled );
	} ## end foreach my ( $entry_int, $item ) ( indexed @{ $def...})

	return;
} ## end sub _compile_message_regexps

# compiles the def's ignore_regexp onto the object... tokens
# work here too, but nothing is captured from them, so the aliases are
# just thrown away. shared by the message_regexp and stages matchers
sub _compile_ignore_regexps {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	$self->{ignore_regexps} = [];

	if ( !defined( $def->{ignore_regexp} ) ) {
		return;
	}
	if ( !is_plain_arrayref( $def->{ignore_regexp} ) ) {
		die( 'The ignore_regexp of the rule "' . $name . '" is not a array' );
	}
	foreach my $item ( @{ $def->{ignore_regexp} } ) {
		if ( !defined($item) || ref($item) ne '' ) {
			die( 'The ignore_regexp of the rule "' . $name . '" contains a non-string entry' );
		}
	}

	foreach my ( $ignore_int, $regexp ) ( indexed @{ $def->{ignore_regexp} } ) {
		my $entry = compile_tokened_regexp( $regexp,
			'The ignore_regexp entry ' . $ignore_int . ' of the rule "' . $name . '"' );
		push( @{ $self->{ignore_regexps} }, $entry->{regexp} );
	}

	return;
} ## end sub _compile_ignore_regexps

# compiles the stages of a staged rule onto the object... ordered matchers
# with counted hits and gap bounds, the in-rule temporal correlation. the per
# key components ride the correlation key machinery, so envelope fields work
# where the type has them.
#
# takes nothing. returns nothing, dying on anything unusable. stages is left
# a arrayref, each stage a hash ref of matchers, the arrayref of its compiled
# regexps, count, the hits it needs, 1 when the def names none, and within and
# skip, the most seconds and the most lines since the last hit, each undef
# when the def names none. a def with a per also leaves per_key, the arrayref
# of its key components.
#
#   $self->_compile_stages;
#   # $self->{stages}[0] is { 'matchers' => [...], 'count' => 3, 'within' => 60, 'skip' => undef }
sub _compile_stages {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	my $stages_where = 'The stages of the rule "' . $name . '"';
	check_entries(
		$def->{stages},
		{
			'required' => {
				'message_regexp' =>
					{ 'each' => 'scalar', 'min' => 1, 'says' => 'a non-empty array of regexp strings' },
			},
			'optional' => { 'count' => 'positive_int', 'within' => 'positive_int', 'skip' => 'positive_int' },
		},
		$stages_where
	);

	my @compiled_stages;
	foreach my ( $stage_int, $stage ) ( indexed @{ $def->{stages} } ) {
		my $where = $stages_where . ' entry ' . $stage_int;

		my @matchers;
		foreach my ( $entry_int, $regexp ) ( indexed @{ $stage->{message_regexp} } ) {
			push( @matchers, compile_tokened_regexp( $regexp, $where . ' message_regexp entry ' . $entry_int ) );
		}

		push(
			@compiled_stages,
			{
				'matchers' => \@matchers,
				'count'    => defined( $stage->{count} )  ? $stage->{count} + 0  : 1,
				'within'   => defined( $stage->{within} ) ? $stage->{within} + 0 : undef,
				'skip'     => defined( $stage->{skip} )   ? $stage->{skip} + 0   : undef,
			}
		);
	} ## end foreach my ( $stage_int, $stage ) ( indexed @{ ...})
	$self->{stages} = \@compiled_stages;

	if ( defined( $def->{per} ) ) {
		$self->{per_key} = $self->_correlation_key_components( $def->{per}, 'The per of the rule "' . $name . '"' );
	}

	return;
} ## end sub _compile_stages

# checks a message against a staged rule... ordered stages, counted hits,
# and gap bounds, the state per (scope, per key) and memory only. returns
# undef until the final stage completes, then the found carrying the
# merged captures and the stage hits
sub _check_stages {
	my ( $self, $message, $scope, $line_ctx, $envelope, $munge ) = @_;

	if ( !defined($message) ) {
		return undef;
	}

	# 1.5, and lifted above the core so it stops the harvest too... a ignore
	# hit is the operator saying this line is not evidence, which no amount of
	# wanting a complete record overrides
	foreach my $ignore ( @{ $self->{ignore_regexps} } ) {
		if ( $message =~ $ignore ) {
			return undef;
		}
	}

	my $found = $self->_check_stages_core( $message, $scope, $line_ctx, $envelope, $munge );

	# the harvest runs on every line of a sequence, not only the one that
	# completed it... the completing line's whole accumulated field space when
	# there is one, this line's munger enrichment when there is not
	if ( defined( $self->{tracks} ) ) {
		my $source
			= defined($found)          ? $found->{data}
			: is_plain_hashref($munge) ? $munge
			:                            {};
		$self->_track_sweep( [$source], $line_ctx );
	}

	return $found;
} ## end sub _check_stages

# how long, in seconds, a staged slot waits for its next stage when that stage
# names no within of its own... also the life of a slot just opened
my $STAGE_DEFAULT_WITHIN = 600;

# the staged matcher proper, wrapped by _check_stages so the ignore veto and
# the track sweep sit either side of it. returns undef until the final stage
# completes, then the found carrying the merged captures and the stage hits
sub _check_stages_core {
	my ( $self, $message, $scope, $line_ctx, $envelope, $munge ) = @_;

	$scope //= '';
	# a missing line context reads as a empty one
	if ( !is_plain_hashref($line_ctx) ) {
		$line_ctx = {};
	}
	my $now = $line_ctx->{now} // time;
	my $seq = $line_ctx->{seq};

	my $stages = $self->{stages};
	my $store  = $self->{stage_state}{$scope};
	$store //= $self->{stage_state}{$scope} = {};

	# which stages this line hits, tried lazily and remembered
	my @stage_caps;
	my $stage_match = sub {
		my ($stage_int) = @_;
		if ( !exists( $stage_caps[$stage_int] ) ) {
			my $caps;
			foreach my $matcher ( @{ $stages->[$stage_int]{matchers} } ) {
				$caps = match_tokened( $matcher, $message );
				if ( defined($caps) ) {
					last;
				}
			}
			$stage_caps[$stage_int] = $caps;
		} ## end if ( !exists( $stage_caps[$stage_int] ) )
		return $stage_caps[$stage_int];
	}; ## end $stage_match = sub

	# the slot key... the per components off this line's captures and the
	# envelope, or the source for the keyless adjacency form
	my $slot_key = sub {
		my ($caps) = @_;
		if ( !defined( $self->{per_key} ) ) {
			return $line_ctx->{source} // '';
		}
		return correlation_key( $self->{per_key}, $caps, $envelope );
	};

	# a hit on the stage a slot is awaiting advances it, gap bounds
	# permitting... too late or too far kills the sequence, and the line
	# may then head a fresh one below
	foreach my ( $stage_int, $stage ) ( indexed @{$stages} ) {
		my $caps = $stage_match->($stage_int);
		if ( !defined($caps) ) {
			next;
		}
		my $key_value = $slot_key->($caps);
		if ( !defined($key_value) ) {
			next;
		}
		my $slot = $store->{$key_value};
		if ( !defined($slot) || $slot->{stage} != $stage_int ) {
			next;
		}
		# a slot past its expiry is dead even if the sweeper has not gotten
		# to it yet, same as the context and pending stores judge at read
		if ( $slot->{expires} <= $now ) {
			delete( $store->{$key_value} );
			next;
		}

		my $gap_ok = 1;
		if ( defined( $stage->{within} ) && ( $now - $slot->{last_time} ) > $stage->{within} ) {
			$gap_ok = 0;
		}
		if (   $gap_ok
			&& defined( $stage->{skip} )
			&& defined($seq)
			&& defined( $slot->{last_seq} )
			&& ( $seq - $slot->{last_seq} - 1 ) > $stage->{skip} )
		{
			$gap_ok = 0;
		}
		if ( !$gap_ok ) {
			delete( $store->{$key_value} );
			last;
		}

		return $self->_stage_hit( $store, $key_value, $stage_int, $caps, $message, $now, $seq, $munge, $line_ctx );
	} ## end foreach my ( $stage_int, $stage ) ( indexed @{$stages...})

	# no slot advanced... a line matching the first stage heads a fresh
	# sequence, but never tramples one already in flight for its key
	my $caps = $stage_match->(0);
	if ( !defined($caps) ) {
		return undef;
	}
	my $key_value = $slot_key->($caps);
	if ( !defined($key_value) || defined( $store->{$key_value} ) ) {
		return undef;
	}
	# a fresh slot awaiting the first stage, the per scope slot count bounded
	# the way the correlation context is bounded
	App::Baphomet::Marks::bound_expiring_store( $store, $key_value, $now );
	$store->{$key_value} = {
		'stage'     => 0,
		'count'     => 0,
		'data'      => {},
		'hits'      => [],
		'last_time' => $now,
		'last_seq'  => undef,
		'expires'   => $now + $STAGE_DEFAULT_WITHIN,
	};

	return $self->_stage_hit( $store, $key_value, 0, $caps, $message, $now, $seq, $munge, $line_ctx );
} ## end sub _check_stages_core

# lands a hit on a slot's awaited stage... counts, merges captures later
# stages authoritative, and fires the found when the final stage completes
sub _stage_hit {
	my ( $self, $store, $key_value, $stage_int, $caps, $message, $now, $seq, $munge, $line_ctx ) = @_;

	my $slot  = $store->{$key_value};
	my $stage = $self->{stages}[$stage_int];

	$slot->{count}++;
	$slot->{data} = { %{ $slot->{data} }, %{$caps} };
	push( @{ $slot->{hits} }, { 'stage' => $stage_int, 'time' => $now, 'line' => $message } );
	$slot->{last_time} = $now;
	$slot->{last_seq}  = $seq;

	if ( $slot->{count} < $stage->{count} ) {
		$slot->{expires} = $now + ( $stage->{within} // $STAGE_DEFAULT_WITHIN );
		return undef;
	}

	# the final stage completing is the found... the rule's boolean matcher
	# filters the completed sequence like any other found
	if ( $stage_int == scalar( @{ $self->{stages} } ) - 1 ) {
		delete( $store->{$key_value} );
		# the completing line's munger enrichment rides under the sequence's
		# accumulated captures, which win on a clash... the same precedence a
		# non-staged rule gives, and the completing line is what EVE records
		my $data = $slot->{data};
		if ( is_plain_hashref($munge) && %{$munge} ) {
			$data = { %{$munge}, %{ $slot->{data} } };
		}
		my $found = { 'data' => $data, 'regexp' => undef, 'stages' => $slot->{hits} };
		if ( $self->{has_boolean} || defined( $self->{track_gates} ) ) {
			if ( !$self->_offense_boolean_pass( $found->{data}, $message, $line_ctx ) ) {
				return undef;
			}
		}
		return $found;
	} ## end if ( $stage_int == scalar( @{ $self->{stages...}}))

	$slot->{stage}++;
	$slot->{count} = 0;
	my $next_stage = $self->{stages}[ $slot->{stage} ];
	$slot->{expires} = $now + ( $next_stage->{within} // $STAGE_DEFAULT_WITHIN );

	return undef;
} ## end sub _stage_hit

# compiles the def's capture_regexp onto the object... its entries harvest
# correlation context rather than being offenses, each a hash of a tokened
# regexp, the key its captures are stored under, and a optional ttl for how
# long they are held.
#
# takes nothing. returns nothing, dying on anything unusable. capture_regexps
# is left a arrayref, empty for a def with no capture_regexp, of compiled
# entries, each as compile_tokened_regexp returns with key, the arrayref of
# its key components, and ttl, the seconds its captures are held, 60 when the
# def names none.
#
#   $self->_compile_capture_regexps;
#   # $self->{capture_regexps}[0]{ttl} is 60 for { regexp: ..., key: SESSION }
sub _compile_capture_regexps {
	my ($self) = @_;

	my $def  = $self->{def};
	my $name = $self->{name};

	$self->{capture_regexps} = [];

	if ( !defined( $def->{capture_regexp} ) ) {
		return;
	}
	my $captures_where = 'The capture_regexp of the rule "' . $name . '"';
	check_entries(
		$def->{capture_regexp},
		{ 'required' => { 'regexp' => 'scalar', 'key' => 'any' }, 'optional' => { 'ttl' => 'seconds' } },
		$captures_where
	);

	foreach my ( $entry_int, $item ) ( indexed @{ $def->{capture_regexp} } ) {
		my $where    = $captures_where . ' entry ' . $entry_int;
		my $compiled = compile_tokened_regexp( $item->{regexp}, $where );
		$compiled->{key} = $self->_correlation_key_components( $item->{key}, $where );
		$compiled->{ttl} = $item->{ttl} // 60;

		push( @{ $self->{capture_regexps} }, $compiled );
	}

	return;
} ## end sub _compile_capture_regexps

# checks a message against the compiled capture, ignore, and message
# regexps... returns undef or a found hash with the folded captures,
# possibly carrying a more array of further completions when a capture
# line resolved deferred offenses
sub _check_message {
	my ( $self, $message, $scope, $extra, $envelope, $line_ctx ) = @_;

	if ( !defined($message) ) {
		return undef;
	}
	$scope //= '';
	# a missing line context reads as a empty one
	if ( !is_plain_hashref($line_ctx) ) {
		$line_ctx = {};
	}
	my $now = $line_ctx->{now} // time;

	# a ignore_regexp match vetoes the line entirely
	foreach my $ignore ( @{ $self->{ignore_regexps} } ) {
		if ( $message =~ $ignore ) {
			return undef;
		}
	}

	# capture lines harvest context and may complete deferred offenses
	my @completions;
	foreach my $capture ( @{ $self->{capture_regexps} } ) {
		my $caps = match_tokened( $capture, $message );
		if ( !defined($caps) ) {
			next;
		}
		my $key_value = correlation_key( $capture->{key}, $caps, $envelope );
		if ( !defined($key_value) ) {
			next;
		}

		context_put( $self->{correlation}, $scope, $key_value, $caps, $capture->{ttl}, $now );
		push( @completions, pending_complete( $self->{correlation}, $scope, $key_value, $caps, $now ) );
	} ## end foreach my $capture ( @{ $self->{capture_regexps...}})

	my $found;
	foreach my ( $entry_int, $entry ) ( indexed @{ $self->{regexps} } ) {
		my $caps = match_tokened( $entry, $message );
		if ( !defined($caps) ) {
			next;
		}

		# a entry with no key, or a key component that did not participate,
		# has nothing to correlate, so it is the offense as it stands
		my $key_value = defined( $entry->{key} ) ? correlation_key( $entry->{key}, $caps, $envelope ) : undef;
		if ( !defined($key_value) ) {
			$found = { 'data' => $caps, 'regexp' => $entry_int };
			last;
		}

		my $stored_data = context_get( $self->{correlation}, $scope, $key_value, $now );
		if ( defined($stored_data) ) {
			$found = { 'data' => { %{$stored_data}, %{$caps} }, 'regexp' => $entry_int };
			last;
		}

		if ( $entry->{defer} ) {
			# park it awaiting a capture line with this key... it was the
			# offense, so further entries are not tried
			pending_park( $self->{correlation}, $scope, $key_value, $caps, $entry_int, $entry->{defer}, $now );
			last;
		}

		# unresolved and undeferred, so this entry is not a offense here...
		# fall through to the remaining entries
	} ## end foreach my ( $entry_int, $entry ) ( indexed @{ ...})

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

	# the field spaces the track sweep will harvest, taken here because the
	# boolean below may drop the very records holding them and the harvest
	# does not care whether the line was a offense. a line that matched
	# nothing still contributes what the mungers and the JSON body gave it
	my @sweep;
	if ( defined( $self->{tracks} ) ) {
		@sweep = map { $_->{data} }
			grep { defined($_) } ( $found, @completions );
		if ( !@sweep ) {
			@sweep = ( $extra // {} );
		}
	}

	# the rule's boolean matcher (the tracked clause, then the keywords, the
	# gate, or the selections+condition, over the captures, and the json
	# fields when message_json) filters the offense and each completion,
	# dropping those that do not pass... none skips this
	if ( $self->{has_boolean} || defined( $self->{track_gates} ) ) {
		if ( defined($found) && !$self->_offense_boolean_pass( $found->{data}, $message, $line_ctx ) ) {
			$found = undef;
		}
		@completions = grep { $self->_offense_boolean_pass( $_->{data}, $message, $line_ctx ) } @completions;
	}

	# the harvest, after the read above and never before it
	if (@sweep) {
		$self->_track_sweep( \@sweep, $line_ctx );
	}

	return fold_completions( $found, \@completions );
} ## end sub _check_message

1;
