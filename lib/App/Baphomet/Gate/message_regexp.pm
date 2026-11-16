package App::Baphomet::Gate::message_regexp;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util                    qw( is_plain_arrayref is_plain_hashref );
use App::Baphomet::Gate          qw( passage_fields passage_envelope );
use App::Baphomet::Shape         qw( check_hash );
use App::Baphomet::Correlation   qw( correlation_key_components correlation_key context_get pending_park );
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp match_tokened );

=head1 NAME

App::Baphomet::Gate::message_regexp - The message_regexp gate, making a offense of a line whose message matches.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - daemons: [ sshd ]
      - message_regexp:
          - '^Invalid user .*? from %%%%SRC%%%%'
          - '^Failed password for .*? from %%%%SRC%%%%'
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Makes the line's own offense when one of its regexps matches the line's
message, tried in order and the first to hit winning, which one it was going
down as the offense's C<regexp>. The offense's data is the named captures,
with whatever fields the line has. A line none of them matches makes no
offense of its own.

A gate above it that judges the line's fields has judged before it is asked,
so a line already refused is not matched at all. A gate that is to judge the
captures goes below it.

On a syslog or raw rule a regexp may use the C<%%%%TOKEN%%%%> tokens, a
token's occurrences folding back under the plain token name, and the
captures win over a field of the same name that C<message_json> or
C<mungers> laid down. A entry is the regexp as a string, or a hash keying it
to the context a C<capture_regexp> gate of the rule keeps...

    - regexp :: The regexp.

    - key :: The capture the offense is keyed by, or a array of them to join
          into one key. On a syslog rule a component may be one of the
          reserved C<syslog.daemon>, C<syslog.host>, and C<syslog.pid>.

    - defer :: Optional. How many seconds a offense whose key has no context
          waits for a capture line to bring it.

A keyed entry that matches takes the context kept under its key beneath its
own captures. One with out a value for the whole key has nothing to resolve
by and is the offense as it stands. One whose key has no context is left
waiting when it has a C<defer>, the entries after it then not being tried,
and is otherwise passed over for the entries after it.

On a http_error rule a regexp is a plain one, every entry is a string, and
the line's fields win over a capture of the same name.

Only a syslog, raw, or http_error rule can have one, and only one. The types
that match on fields have C<match>.

=head1 METHODS

=head2 compile

Vets and compiles the entries the way the rule's type reads them, and takes
the rule's correlation store. C<open_to_injection> is left naming the first
regexp whose shape leaves the offender open to being chosen by whoever wrote
the line, for L<App::Baphomet::Rules::SelfTest/run_tests> to ask a
C<tests.injection> entry of.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	$self->of_types( $rule, $where, 'syslog', 'raw', 'http_error' );
	if ( !is_plain_arrayref($args) || !@{$args} ) {
		die( $where . ' is not a array or is empty' );
	}
	$self->{plain} = $rule->type eq 'http_error' ? 1 : 0;

	# every entry is vetted before any is compiled, so a misshapen one is
	# named ahead of a regexp that will not compile
	foreach my ( $entry_int, $entry ) ( indexed @{$args} ) {
		my $entry_where = $where . ' entry ' . $entry_int;
		if ( !$self->{plain} && is_plain_hashref($entry) ) {
			check_hash(
				$entry,
				{ 'required' => { 'regexp' => 'scalar', 'key' => 'any' }, 'optional' => { 'defer' => 'seconds' } },
				$entry_where
			);
		} elsif ( !defined($entry) || ref($entry) ne '' ) {
			die( $entry_where . ( $self->{plain} ? ' is not a string' : ' is not a string or a hash' ) );
		}
	} ## end foreach my ( $entry_int, $entry ) ( indexed @{$args...})

	my @entries;
	foreach my ( $entry_int, $entry ) ( indexed @{$args} ) {
		my $entry_where = $where . ' entry ' . $entry_int;
		if ( $self->{plain} ) {
			my $compiled;
			try {
				$compiled = qr/$entry/;
			} catch ($caught) {
				die( $entry_where . ', "' . $entry . '", does not compile... ' . $caught );
			}
			push( @entries, $compiled );
			next;
		} ## end if ( $self->{plain} )

		my $compiled = compile_tokened_regexp( is_plain_hashref($entry) ? $entry->{regexp} : $entry, $entry_where );
		if ( is_plain_hashref($entry) ) {
			( $compiled->{key}, my $wants_envelope )
				= correlation_key_components( $entry->{key}, $entry_where, $rule->envelope_fields );
			$compiled->{defer} = $entry->{defer};
			# the envelope is only built for a rule with a key that reads it
			if ($wants_envelope) {
				$self->{wants_envelope} = 1;
			}
		}
		push( @entries, $compiled );
	} ## end foreach my ( $entry_int, $entry ) ( indexed @{$args...})
	$self->{entries}     = \@entries;
	$self->{correlation} = $rule->correlation;

	# The first regexp whose shape leaves the offender open to being chosen by
	# whoever wrote the line. The shape is a LAZY unbounded wildcard between
	# the head of the pattern and the offender token, with nothing anchoring
	# the token's tail. Lazy takes the first candidate it reaches, so wherever
	# the log lets a client write text ahead of the real field... a account
	# name, a mail subject, a user agent... the client picks the ban target by
	# planting a copy of the delimiter. Every real instance of this found in
	# the shipped set had exactly this shape.
	#
	# Greedy is deliberately not flagged. It takes the LAST candidate, and a
	# forgery can only ever be planted ahead of the field the daemon writes,
	# so the ordering is itself the defence.
	#
	# This is a shape and nothing more. Whether a client can reach that
	# wildcard is a property of the log format, which no reading of the
	# pattern will settle, so the rule is not refused for it... it points at a
	# question only a test can answer, and the answer may well be "safe here".
	foreach my $entry ( $self->{plain} ? () : @{$args} ) {
		my $regexp = is_plain_hashref($entry) ? $entry->{regexp} : $entry;
		my ( $head, $token, $tail ) = $regexp =~ /^(.*?)%%%%(SRC|DEST|ADDR|HOST|IP4|IP6|SUBNET)%%%%(.*)$/s;
		if ( !defined($token) ) {
			next;
		}

		# a unbounded run that yields the shortest match... ".*?", "\S+?" and
		# the like. a bounded one, "[^"]*" or "{0,3}", can not cross a
		# delimiter
		if ( $head !~ /(?:\.|\\S|\\w|\\d|\\D|\\W)[*+]\?/ ) {
			next;
		}

		# the tail peeled down to whatever really has to be there... a all
		# optional group, a trailing space run, and a word boundary each
		# anchor nothing at all
		my $peeled = 1;
		while ($peeled) {
			$peeled = 0;
			if ( $tail =~ s/\((?:\?:)?[^()]*\)[?*]// ) { $peeled = 1; }
			if ( $tail =~ s/\\s\*// )                  { $peeled = 1; }
			if ( $tail =~ s/\\b// )                    { $peeled = 1; }
		}
		if ( $tail =~ /\S/ ) {
			next;
		}

		$self->{open_to_injection} = 'the offender of "' . $regexp . '"';
		last;
	} ## end foreach my $entry ( $self->{plain} ? () : @{$args...})

	return;
} ## end sub compile

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

=head2 ask

Makes the line's own offense of the first entry to match, or refuses it when
none does or the one that did is left waiting. For a rule that harvests,
what stands once it has is noted for the C<track> gate, the gates between
the two not getting to judge any of it away first. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	if ( $passage->{refused} || defined( $passage->{own} ) ) {
		return 1;
	}

	my $own;
	if ( $self->{plain} ) {
		my $message = $passage->{parsed}{message};
		foreach my ( $entry_int, $regexp ) ( indexed @{ $self->{entries} } ) {
			if ( $message =~ $regexp ) {
				# the line's fields over the captures, the fields
				# authoritative
				my %caps = %+;
				$own = { 'data' => { %caps, %{ passage_fields($passage) } }, 'regexp' => $entry_int };
				last;
			}
		}
	} else {
		my $message  = $passage->{message};
		my $envelope = $self->{wants_envelope} ? passage_envelope($passage) : undef;
		foreach my ( $entry_int, $entry ) ( indexed @{ $self->{entries} } ) {
			my $caps = match_tokened( $entry, $message );
			if ( !defined($caps) ) {
				next;
			}

			# a entry with no key, or a key component that did not
			# participate, has nothing to correlate, so it is the offense as
			# it stands
			my $key_value = defined( $entry->{key} ) ? correlation_key( $entry->{key}, $caps, $envelope ) : undef;
			if ( !defined($key_value) ) {
				$own = { 'data' => $caps, 'regexp' => $entry_int };
				last;
			}

			my $stored = context_get( $self->{correlation}, $passage->{scope}, $key_value, $passage->{now} );
			if ( defined($stored) ) {
				$own = { 'data' => { %{$stored}, %{$caps} }, 'regexp' => $entry_int };
				last;
			}

			if ( $entry->{defer} ) {
				# left waiting on a capture line with this key... it was the
				# offense, so the entries after it are not tried. the fields
				# message_json and the mungers made of this line are parked
				# with it, as the capture line that completes it has fields of
				# its own and they are not this offense's
				pending_park( $self->{correlation}, $passage->{scope}, $key_value, $caps, $entry_int, $entry->{defer},
					$passage->{now}, $passage->{fields} );
				last;
			}

			# unresolved and not deferred, so this entry is not a offense
			# here... on to the ones after it
		} ## end foreach my ( $entry_int, $entry ) ( indexed @{ ...})

		# what message_json and the mungers made of the line goes under the
		# offense, its own captures winning on a clash
		if ( defined($own) && defined( $passage->{fields} ) ) {
			$own->{data} = { %{ $passage->{fields} }, %{ $own->{data} } };
		}
	} ## end else [ if ( $self->{plain} ) ]

	if ( defined($own) ) {
		$passage->{own} = $own;
		unshift( @{ $passage->{results} //= [] }, $own );
	} else {
		$passage->{refused} = 1;
	}

	# a record is of the transaction and not of the offenses, so the harvest
	# takes what the line made before the gates below can judge it away
	if ( $passage->{rule}{harvests} ) {
		$passage->{harvest} = [ map { $_->{data} } @{ $passage->{results} // [] } ];
	}

	return 1;
} ## end sub ask

1;
