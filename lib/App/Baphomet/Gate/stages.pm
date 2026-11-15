package App::Baphomet::Gate::stages;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util                   qw( first uniqstr );
use App::Baphomet::Gate          qw( passage_envelope );
use App::Baphomet::Shape         qw( check_entries );
use App::Baphomet::Marks         qw( bound_expiring_store );
use App::Baphomet::Correlation   qw( correlation_key );
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp match_tokened );

=head1 NAME

App::Baphomet::Gate::stages - The stages gate, making a offense of a sequence of lines.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - daemons: [ sshd ]
      - stages:
          - message_regexp: [ '^Connection from %%%%SRC%%%%' ]
          - message_regexp: [ '^Bad protocol version identification' ]
            count: 3
            within: 60
      - per: SRC
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Makes a offense when its stages have been hit in order, each as many times
as it asks, and of no line before the one that completes the last. The
offense's data is the captures of every hit, a later one winning, with the
fields of the completing line underneath, and its C<stages> is the hits that
made it. A line that completes nothing makes no offense of its own.

The sequences are kept apart by the C<per> gate beside it, or with out one
there is a single sequence per log file. A line that hits the stage a
sequence is waiting on advances it. One that hits the first stage and has no
sequence under way opens one, never trampling one already in flight. A hit
that comes too late or too far on kills the sequence, and the line may then
open a fresh one. Sequences are held in memory only, and a restart forgets
them.

A gate above it that judges the line's fields has judged before it is asked,
so a line already refused does not feed a sequence. A gate that is to judge
the completed sequence goes below it.

It is told a array of stages, each a hash of...

    - message_regexp :: A non-empty array of regexp strings, which may use
          the C<%%%%TOKEN%%%%> tokens. The stage is hit by a line any of
          them matches.

    - count :: Optional. How many hits complete the stage, 1 by default.

    - within :: Optional. The most seconds since the last hit of the
          sequence, 600 when a sequence is waiting on a stage with out one.

    - skip :: Optional. The most lines of the log that may come between the
          last hit of the sequence and this one.

It is the whole matcher, so a rule with one can have no C<message_regexp>,
C<capture_regexp>, or C<message_json>. Only a syslog or raw rule can have
one, and only one.

=head1 METHODS

=head2 compile

Vets and compiles the stages.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'syslog', 'raw' );
	check_entries(
		$args,
		{
			'required' => {
				'message_regexp' =>
					{ 'each' => 'scalar', 'min' => 1, 'says' => 'a non-empty array of regexp strings' },
			},
			'optional' => { 'count' => 'positive_int', 'within' => 'positive_int', 'skip' => 'positive_int' },
		},
		$where
	);

	my @stages;
	foreach my ( $stage_int, $stage ) ( indexed @{$args} ) {
		my $stage_where = $where . ' entry ' . $stage_int;

		my @matchers;
		foreach my ( $entry_int, $regexp ) ( indexed @{ $stage->{message_regexp} } ) {
			push( @matchers, compile_tokened_regexp( $regexp, $stage_where . ' message_regexp entry ' . $entry_int ) );
		}

		push(
			@stages,
			{
				'matchers' => \@matchers,
				'count'    => defined( $stage->{count} )  ? $stage->{count} + 0  : 1,
				'within'   => defined( $stage->{within} ) ? $stage->{within} + 0 : undef,
				'skip'     => defined( $stage->{skip} )   ? $stage->{skip} + 0   : undef,
			}
		);
	} ## end foreach my ( $stage_int, $stage ) ( indexed @{$args...})
	$self->{stages} = \@stages;

	# the sequences under way, by scope and then by what per keys them on
	$self->{sequences} = {};

	return;
} ## end sub compile

=head2 settle

Takes the key of the rule's C<per> gate, when it has one. Dies when the rule
has another matcher beside the stages.

=cut

sub settle {
	my ( $self, $gates ) = @_;

	my @beside = uniqstr(
		map { $_->{type} }
		grep {
				   $_->{type} eq 'message_regexp'
				|| $_->{type} eq 'capture_regexp'
				|| ( $_->{type} eq 'message_json' && !$_->idle )
		} @{$gates}
	);
	if (@beside) {
		die( $self->{where} . ' is beside ' . join( ', ', @beside ) . '... stages are the whole matcher' );
	}

	my $per = first { $_->{type} eq 'per' } @{$gates};
	if ( defined($per) ) {
		$self->{per_key}        = $per->{key};
		$self->{wants_envelope} = $per->{wants_envelope};
	}

	return;
} ## end sub settle

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 once

Returns 1, a rule having the one matcher.

=cut

sub once {
	return 1;
}

=head2 sweep_state

Drops the sequences nothing has fed since the within of the stage they wait
on, or the default hold.

    $gate->sweep_state($now);

=cut

sub sweep_state {
	my ( $self, $now ) = @_;

	my $sequences = $self->{sequences};
	foreach my $scope ( keys( %{$sequences} ) ) {
		foreach my $key ( keys( %{ $sequences->{$scope} } ) ) {
			if ( $sequences->{$scope}{$key}{expires} <= $now ) {
				delete( $sequences->{$scope}{$key} );
			}
		}
		if ( !%{ $sequences->{$scope} } ) {
			delete( $sequences->{$scope} );
		}
	} ## end foreach my $scope ( keys( %{$sequences} ) )

	return;
} ## end sub sweep_state

# how long, in seconds, a sequence waits for its next stage when that stage
# names no within of its own... also the life of one just opened
my $DEFAULT_WITHIN = 600;

=head2 ask

Feeds the line to the sequences, making the line's own offense when it
completes one and refusing it when it does not. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	if ( $passage->{refused} ) {
		return 1;
	}
	# nothing is made of a line unless it completes a sequence
	$passage->{refused} = 1;

	my $message  = $passage->{message};
	my $now      = $passage->{now};
	my $seq      = $passage->{line_ctx}{seq};
	my $stages   = $self->{stages};
	my $envelope = $self->{wants_envelope} ? passage_envelope($passage) : undef;
	my $store    = $self->{sequences}{ $passage->{scope} } //= {};

	# which stages this line hits, tried as asked for and remembered
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

	# what a hit's sequence is kept under... the per components off this
	# line's captures and the envelope, or the log file when there is no per
	my $sequence_key = sub {
		my ($caps) = @_;
		if ( !defined( $self->{per_key} ) ) {
			return $passage->{line_ctx}{source} // '';
		}
		return correlation_key( $self->{per_key}, $caps, $envelope );
	};

	# a hit on the stage a sequence is waiting on advances it, the gap bounds
	# permitting... too late or too far kills the sequence, and the line may
	# then open a fresh one below
	foreach my ( $stage_int, $stage ) ( indexed @{$stages} ) {
		my $caps = $stage_match->($stage_int);
		if ( !defined($caps) ) {
			next;
		}
		my $key_value = $sequence_key->($caps);
		if ( !defined($key_value) ) {
			next;
		}
		my $sequence = $store->{$key_value};
		if ( !defined($sequence) || $sequence->{stage} != $stage_int ) {
			next;
		}
		# one past its expiry is dead even if the sweep has not gotten to it
		# yet, same as the context and the waiting offenses are judged at read
		if ( $sequence->{expires} <= $now ) {
			delete( $store->{$key_value} );
			next;
		}

		my $gap_ok = 1;
		if ( defined( $stage->{within} ) && ( $now - $sequence->{last_time} ) > $stage->{within} ) {
			$gap_ok = 0;
		}
		if (   $gap_ok
			&& defined( $stage->{skip} )
			&& defined($seq)
			&& defined( $sequence->{last_seq} )
			&& ( $seq - $sequence->{last_seq} - 1 ) > $stage->{skip} )
		{
			$gap_ok = 0;
		}
		if ( !$gap_ok ) {
			delete( $store->{$key_value} );
			last;
		}

		$self->_hit( $passage, $store, $key_value, $stage_int, $caps );
		return 1;
	} ## end foreach my ( $stage_int, $stage ) ( indexed @{$stages...})

	# no sequence advanced... a line hitting the first stage opens a fresh one,
	# but never tramples one already in flight for its key
	my $caps = $stage_match->(0);
	if ( !defined($caps) ) {
		return 1;
	}
	my $key_value = $sequence_key->($caps);
	if ( !defined($key_value) || defined( $store->{$key_value} ) ) {
		return 1;
	}
	# the count of sequences per scope is bounded the way the correlation
	# context is
	bound_expiring_store( $store, $key_value, $now );
	$store->{$key_value} = {
		'stage'     => 0,
		'count'     => 0,
		'data'      => {},
		'hits'      => [],
		'last_time' => $now,
		'last_seq'  => undef,
		'expires'   => $now + $DEFAULT_WITHIN,
	};
	$self->_hit( $passage, $store, $key_value, 0, $caps );

	return 1;
} ## end sub ask

# lands a hit on the stage a sequence is waiting on... counts it, merges its
# captures in, later ones winning, and moves the sequence on to the next stage
# once this one has its count. The hit that completes the last stage makes
# the line's own offense, of the sequence's captures with the completing
# line's fields underneath, and ends the sequence.
#
# args:
#   $passage   :: the passage of the line that hit
#   $store     :: the sequences of the passage's scope, hash ref of key to
#                 sequence
#   $key_value :: the key the hit sequence is under in that store
#   $stage_int :: which stage was hit, the one the sequence is waiting on
#   $caps      :: hash ref of the captures of the hit
#
# returns nothing. On completion the passage's own is set, standing first in
# its results, and its refused is cleared.
#
#   $self->_hit( $passage, $store, $key_value, $stage_int, $caps );
sub _hit {
	my ( $self, $passage, $store, $key_value, $stage_int, $caps ) = @_;

	my $sequence = $store->{$key_value};
	my $stage    = $self->{stages}[$stage_int];
	my $now      = $passage->{now};

	$sequence->{count}++;
	$sequence->{data} = { %{ $sequence->{data} }, %{$caps} };
	push( @{ $sequence->{hits} }, { 'stage' => $stage_int, 'time' => $now, 'line' => $passage->{message} } );
	$sequence->{last_time} = $now;
	$sequence->{last_seq}  = $passage->{line_ctx}{seq};

	if ( $sequence->{count} < $stage->{count} ) {
		$sequence->{expires} = $now + ( $stage->{within} // $DEFAULT_WITHIN );
		return;
	}

	if ( $stage_int < $#{ $self->{stages} } ) {
		$sequence->{stage}++;
		$sequence->{count}   = 0;
		$sequence->{expires} = $now + ( $self->{stages}[ $sequence->{stage} ]{within} // $DEFAULT_WITHIN );
		return;
	}

	# the last stage complete... what the mungers made of the completing line
	# goes under the sequence's captures, which win on a clash, the same as
	# for a rule that is not staged
	delete( $store->{$key_value} );
	my $data = $sequence->{data};
	if ( defined( $passage->{fields} ) ) {
		$data = { %{ $passage->{fields} }, %{$data} };
	}
	$passage->{own}     = { 'data' => $data, 'regexp' => undef, 'stages' => $sequence->{hits} };
	$passage->{refused} = 0;
	unshift( @{ $passage->{results} //= [] }, $passage->{own} );

	return;
} ## end sub _hit

1;
