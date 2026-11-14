package App::Baphomet::Rules::Gates;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Exporter                     qw( import );
use Ref::Util                    qw( is_plain_arrayref is_plain_hashref );
use List::Util                   qw( any );
use MIME::Base64                 qw( decode_base64 );
use Encode                       ();
use App::Baphomet::Config        qw( compile_ignore_ips ip_ignored );
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp );

our @EXPORT_OK = qw( compile_matchers matchers_hit compile_gates gates_pass compile_condition eval_condition );

=head1 NAME

App::Baphomet::Rules::Gates - The gate vocabulary of the Baphomet rules, compiled and run.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Rules::Gates qw( compile_gates gates_pass );

    my $gates = compile_gates(
        [ { 'field' => 'event_type', 'values' => ['alert'] }, { 'field' => 'src_port', 'op' => 'lt', 'value' => 1024 }, ],
        'The gate of the rule "json/example"'
    );

    if ( gates_pass( $gates, $fields, undef ) ) { ... }

=head1 DESCRIPTION

What a rule's C<gate>, C<selections>, C<condition>, and C<keywords> are
made of... the string-or-C<//regexp//> matcher lists, the typed predicates
with their operators and decode chains, the gate lists built from either,
and the Sigma-style condition that folds named selections. The vocabulary
itself is documented for rule authors under the predicate gate section of
F<docs/rules.md>,
L<https://github.com/LilithSec/Baphomet/blob/main/docs/rules.md#gate--selections--condition--keywords>.

Everything here is a plain function holding no rule state. A def's gate
array goes in and a compiled list comes out, then a compiled list and a
hash of field values go in and a verdict comes out. Which lists a rule has,
and how they combine into its one boolean, is the rule's business and lives
in L<App::Baphomet::Rules::Base>.

=head1 FUNCTIONS

=head2 compile_matchers

Compiles a list of string-or-C<//regexp//> entries into a matcher set. A
entry starting and ending with C<//> is a regexp, the rest are string
equality checks. Dies on a entry that is not a string or a regexp that does
not compile.

    - list :: Array ref of the entries as the rule file wrote them.

    - where :: The lead in for the die messages, naming the rule and the
          key, such as C<The daemons of the rule "syslog/sshd">.

Returns a hash ref of C<strings>, a hash of each plain string to 1, and
C<regexps>, a array ref of the compiled regexps.

    my $matchers = compile_matchers( [ 'sshd', '//^sshd-session//' ], $where );

=cut

sub compile_matchers {
	my ( $list, $where ) = @_;

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
			try {
				$compiled = qr/$regexp/;
			} catch ($caught) {
				die( $where . ' entry "' . $item . '" does not compile... ' . $caught );
			}
			push( @{ $matchers->{regexps} }, $compiled );
		} else {
			$matchers->{strings}{$item} = 1;
		}
	} ## end foreach my $item ( @{$list} )

	return $matchers;
} ## end sub compile_matchers

=head2 matchers_hit

Checks a value against a matcher set from L</compile_matchers>.

    - matchers :: The matcher set.

    - value :: The value to check. A undef never matches.

Returns 1 when the value equals one of the strings or matches one of the
regexps, else 0.

    if ( matchers_hit( $matchers, $parsed->{daemon} ) ) { ... }

=cut

sub matchers_hit {
	my ( $matchers, $value ) = @_;

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
} ## end sub matchers_hit

# the typed field operators, the opt-in richer form of a gate entry. legacy
# entries (field + values, equality or //regex//) are untouched and never reach
# here... this only fires for an entry carrying op/value/all/negate
our %PREDICATE_OPS = map { $_ => 1 } qw( eq contains startswith endswith re gt lt ge le cidr exists );

# the comparators, resolved once at compile time onto the predicate as
# op_code so the per-line path dispatches straight to a static code ref
# instead of re-matching the op name per candidate
my %PREDICATE_NUM_OPS = (
	'gt' => sub { return ( $_[0] > $_[1] )  ? 1 : 0; },
	'lt' => sub { return ( $_[0] < $_[1] )  ? 1 : 0; },
	'ge' => sub { return ( $_[0] >= $_[1] ) ? 1 : 0; },
	'le' => sub { return ( $_[0] <= $_[1] ) ? 1 : 0; },
);
my %PREDICATE_STR_OPS = (
	'eq'         => sub { return ( $_[0] eq $_[1] )                               ? 1 : 0; },
	'contains'   => sub { return ( index( $_[0], $_[1] ) >= 0 )                   ? 1 : 0; },
	'startswith' => sub { return ( substr( $_[0], 0, length( $_[1] ) ) eq $_[1] ) ? 1 : 0; },
	'endswith'   => sub {
		return ( length( $_[1] ) <= length( $_[0] ) && substr( $_[0], length( $_[0] ) - length( $_[1] ) ) eq $_[1] )
			? 1
			: 0;
	},
);

# the decode transforms, each string -> zero or more candidate strings, run
# left to right over a field value before the operator so an obfuscated payload
# is compared decoded. a transform that can not decode yields no candidate and
# that branch drops. base64offset yields the three alignment candidates
our %PREDICATE_TRANSFORMS = (
	'lower' => sub { return ( lc( $_[0] ) ); },
	'upper' => sub { return ( uc( $_[0] ) ); },
	'url'   => sub {
		my $string = $_[0];
		$string =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
		return ($string);
	},
	'windash' => sub {
		my $string = $_[0];
		# the unicode dash variants a Windows flag accepts, folded to ascii -
		$string =~ s/[\x{2010}\x{2011}\x{2012}\x{2013}\x{2014}\x{2015}]/-/g;
		return ($string);
	},
	'base64' => sub {
		my $decoded;
		eval { $decoded = decode_base64( $_[0] ); };
		return ( defined($decoded) && $decoded ne '' ) ? ($decoded) : ();
	},
	'base64offset' => sub {
		my $string = $_[0];
		my @out;
		foreach my $offset ( 0, 1, 2 ) {
			my $slice = substr( $string, $offset );
			my $trim  = length($slice) - ( length($slice) % 4 );
			if ( $trim <= 0 ) {
				next;
			}
			my $decoded;
			eval { $decoded = decode_base64( substr( $slice, 0, $trim ) ); };
			if ( defined($decoded) && $decoded ne '' ) {
				push( @out, $decoded );
			}
		} ## end foreach my $offset ( 0, 1, 2 )
		return @out;
	},
	'utf16le' => sub {
		my $d;
		eval { $d = Encode::decode( 'UTF-16LE', $_[0], Encode::FB_CROAK() ); };
		return defined($d) ? ($d) : ();
	},
	'utf16be' => sub {
		my $d;
		eval { $d = Encode::decode( 'UTF-16BE', $_[0], Encode::FB_CROAK() ); };
		return defined($d) ? ($d) : ();
	},
	'utf16' => sub {
		my $d;
		eval { $d = Encode::decode( 'UTF-16', $_[0], Encode::FB_CROAK() ); };
		return defined($d) ? ($d) : ();
	},
);
# wide is a Sigma alias for utf16le
$PREDICATE_TRANSFORMS{wide} = $PREDICATE_TRANSFORMS{utf16le};

# the gate entry keys only the predicate form carries... a entry naming any of
# them is a predicate, else it is the legacy field/values form
my @PREDICATE_ONLY_KEYS = qw( op value all negate nocase fieldref decode );

# compiles a predicate entry into a runnable form, dieing on anything
# unusable. shape: { field, op (default eq), value | values, all, negate }.
# op eq/contains/startswith/endswith are string tests, re a regexp (tokened),
# gt/lt/ge/le numeric, cidr a v4/v6 membership reusing the ignore-list machine
sub _compile_predicate {
	my ( $entry, $where ) = @_;

	foreach my $key ( keys( %{$entry} ) ) {
		if ( $key !~ /^(?:field|op|value|values|all|negate|nocase|fieldref|decode)$/ ) {
			die( $where . ' has the unknown key "' . $key . '"' );
		}
	}

	my $op = $entry->{op} // 'eq';
	if ( ref($op) ne '' || !$PREDICATE_OPS{$op} ) {
		die( $where . ' has the unknown op "' . ( ref($op) ? ref($op) : $op ) . '"' );
	}

	# nocase case-folds the string and re comparisons... meaningless on the
	# numeric and cidr ops, so a set there is a mistake worth naming
	my $nocase = $entry->{nocase} ? 1 : 0;
	if ( $nocase && ( $op eq 'cidr' || $op =~ /^(?:gt|lt|ge|le)$/ ) ) {
		die( $where . ' nocase does not apply to the ' . $op . ' op' );
	}

	# fieldref names another field to compare against, its value the needle
	# resolved from the line at match time rather than a literal. it stands in
	# for value/values and only the string ops, which compare a needle, take it
	my $fieldref = $entry->{fieldref};
	if ( defined($fieldref) ) {
		if ( ref($fieldref) ne '' || $fieldref eq '' ) {
			die( $where . ' fieldref is not a non-empty field name' );
		}
		if ( exists( $entry->{value} ) || exists( $entry->{values} ) ) {
			die( $where . ' sets both fieldref and a literal value' );
		}
		if ( $op !~ /^(?:eq|contains|startswith|endswith)$/ ) {
			die( $where . ' fieldref works only with the eq, contains, startswith, and endswith ops' );
		}
	} ## end if ( defined($fieldref) )

	# exists tests only whether the field is present, so it takes no needle...
	# negate turns it into the field-absent test, Sigma's C<|exists: false>
	if ( $op eq 'exists' ) {
		if (   exists( $entry->{value} )
			|| exists( $entry->{values} )
			|| defined($fieldref)
			|| exists( $entry->{decode} )
			|| $nocase
			|| $entry->{all} )
		{
			die( $where . ' the exists op takes no value, fieldref, decode, nocase, or all' );
		}
		return {
			'field'  => $entry->{field},
			'op'     => 'exists',
			'negate' => $entry->{negate} ? 1 : 0,
		};
	} ## end if ( $op eq 'exists' )

	my @values;
	if ( defined($fieldref) ) {
		# no literal needle... the referenced field is resolved at match time
	} elsif ( exists( $entry->{values} ) ) {
		if ( !is_plain_arrayref( $entry->{values} ) || !@{ $entry->{values} } ) {
			die( $where . ' values is not a non-empty array' );
		}
		@values = @{ $entry->{values} };
	} elsif ( exists( $entry->{value} ) ) {
		@values = ( $entry->{value} );
	} else {
		die( $where . ' lacks a value or values' );
	}
	foreach my $v (@values) {
		if ( !defined($v) || ref($v) ne '' ) {
			die( $where . ' has a non-scalar value' );
		}
	}

	my $predicate = {
		'field'    => $entry->{field},
		'op'       => $op,
		'all'      => $entry->{all}    ? 1 : 0,
		'negate'   => $entry->{negate} ? 1 : 0,
		'nocase'   => $nocase,
		'fieldref' => $fieldref,
	};

	if ( exists( $entry->{decode} ) ) {
		if ( !is_plain_arrayref( $entry->{decode} ) || !@{ $entry->{decode} } ) {
			die( $where . ' decode is not a non-empty array' );
		}
		foreach my $transform ( @{ $entry->{decode} } ) {
			if ( !defined($transform) || ref($transform) ne '' || !$PREDICATE_TRANSFORMS{$transform} ) {
				die(      $where
						. ' has the unknown decode transform "'
						. ( defined($transform) ? ( ref($transform) ? ref($transform) : $transform ) : 'undef' )
						. '"' );
			}
		}
		$predicate->{decode} = [ @{ $entry->{decode} } ];
	} ## end if ( exists( $entry->{decode} ) )

	if ( $op eq 're' ) {
		my @regexps;
		foreach my $v (@values) {
			# a leading (?i) applies to the whole pattern, token expansions
			# and all, so nocase folds a re without touching the tokens
			my $pat = $nocase ? '(?i)' . $v : $v;
			push( @regexps, compile_tokened_regexp( $pat, $where )->{regexp} );
		}
		$predicate->{regexps} = \@regexps;
		$predicate->{kind}    = 're';
	} elsif ( defined( $PREDICATE_NUM_OPS{$op} ) ) {
		my @numbers;
		foreach my $v (@values) {
			if ( $v !~ /^-?[0-9]+(?:\.[0-9]+)?$/ ) {
				die( $where . ' op ' . $op . ' needs numeric values, got "' . $v . '"' );
			}
			push( @numbers, $v + 0 );
		}
		$predicate->{numbers} = \@numbers;
		$predicate->{kind}    = 'num';
		$predicate->{op_code} = $PREDICATE_NUM_OPS{$op};
	} elsif ( $op eq 'cidr' ) {
		# dies on a bad CIDR, exactly as the ignore/namtar lists do
		$predicate->{cidr} = compile_ignore_ips( \@values, $where );
		$predicate->{kind} = 'cidr';
	} elsif ( defined($fieldref) ) {
		# the needle is the referenced field, injected at match time, so there
		# are no static strings to compile
		$predicate->{kind}    = 'string';
		$predicate->{op_code} = $PREDICATE_STR_OPS{$op};
	} else {
		# nocase folds the needles once here, the candidate folded to match at
		# test time, so a case-insensitive compare costs no per-hit lc of these
		$predicate->{strings} = $nocase ? [ map { lc } @values ] : \@values;
		$predicate->{kind}    = 'string';
		$predicate->{op_code} = $PREDICATE_STR_OPS{$op};
	}

	return $predicate;
} ## end sub _compile_predicate

# runs a compiled predicate's operator against one field value, without its
# negate... _gate_hit applies negate, once per value for a plain gate and once
# over the whole fan for a keyword gate, so a keyword's OR stays clean. a
# missing field is a false core, except under exists, which tests presence.
#
# args:
#   $predicate :: a compiled predicate from _compile_predicate
#   $value     :: the field value, undef when the field is absent
#   $ref       :: the referenced field's value for a fieldref predicate, the
#                 needle compared against, else undef
#
# returns 1 when the operator holds for the value, or for any candidate its
# decode chain fans it out to, else 0.
#
#   my $core = _predicate_core( $gate->{predicate}, $data->{user} );
sub _predicate_core {
	my ( $predicate, $value, $ref ) = @_;

	# exists tests presence, so it must see undef rather than short-circuit on
	# it... negate (applied by the caller) flips it to the field-absent test
	if ( $predicate->{op} eq 'exists' ) {
		return defined($value) ? 1 : 0;
	}

	if ( !defined($value) ) {
		return 0;
	}

	# the field value, run through any decode chain into one or more candidate
	# strings, the operator matching if any candidate satisfies it. with no
	# decode the candidate is just the value, so this is the plain path. $ref is
	# the referenced field's value for a fieldref predicate, the dynamic needle
	foreach my $candidate ( _decode_candidates( $predicate->{decode}, "$value" ) ) {
		if ( _predicate_test_one( $predicate, $candidate, $ref ) ) {
			return 1;
		}
	}

	return 0;
} ## end sub _predicate_core

# applies a predicate's decode chain to a value, fanning out... each transform
# maps every current candidate to zero or more, so base64offset widens and a
# failed decode narrows. no decode chain is the value unchanged
sub _decode_candidates {
	my ( $decode, $value ) = @_;

	if ( !defined($decode) ) {
		return ($value);
	}

	my @candidates = ($value);
	foreach my $transform ( @{$decode} ) {
		my @next;
		foreach my $candidate (@candidates) {
			push( @next, $PREDICATE_TRANSFORMS{$transform}->($candidate) );
		}
		@candidates = @next;
		if ( !@candidates ) {
			return ();
		}
	} ## end foreach my $transform ( @{$decode} )

	return @candidates;
} ## end sub _decode_candidates

# tests one candidate string against a predicate's operator and values. $ref,
# the referenced field's value, is the dynamic needle for a fieldref predicate.
# the operator was resolved to kind and op_code at compile time and the any/all
# folds are inlined, as this is the innermost per-line call
sub _predicate_test_one {
	my ( $predicate, $value, $ref ) = @_;

	my $kind = $predicate->{kind};

	# the string ops... eq/contains/startswith/endswith. under nocase the
	# needle was folded at compile time, so folding the candidate here makes
	# the compare case-insensitive
	if ( $kind eq 'string' ) {
		my $candidate = $predicate->{nocase} ? lc($value) : $value;

		# a fieldref predicate compares against another field's live value,
		# injected as the needle here, folded to match under nocase since it
		# was not folded at compile time... an absent referenced field is a
		# non-match
		my $needles = $predicate->{strings};
		if ( defined( $predicate->{fieldref} ) ) {
			if ( !defined($ref) ) {
				return 0;
			}
			$needles = [ $predicate->{nocase} ? lc($ref) : $ref ];
		}

		my $test = $predicate->{op_code};
		if ( $predicate->{all} ) {
			foreach my $needle ( @{$needles} ) {
				if ( !$test->( $candidate, $needle ) ) {
					return 0;
				}
			}
			return 1;
		}
		foreach my $needle ( @{$needles} ) {
			if ( $test->( $candidate, $needle ) ) {
				return 1;
			}
		}
		return 0;
	} ## end if ( $kind eq 'string' )

	if ( $kind eq 're' ) {
		if ( $predicate->{all} ) {
			foreach my $regexp ( @{ $predicate->{regexps} } ) {
				if ( $value !~ $regexp ) {
					return 0;
				}
			}
			return 1;
		}
		foreach my $regexp ( @{ $predicate->{regexps} } ) {
			if ( $value =~ $regexp ) {
				return 1;
			}
		}
		return 0;
	} ## end if ( $kind eq 're' )

	if ( $kind eq 'num' ) {
		if ( $value !~ /^-?[0-9]+(?:\.[0-9]+)?$/ ) {
			return 0;
		}
		my $number = $value + 0;
		my $test   = $predicate->{op_code};
		if ( $predicate->{all} ) {
			foreach my $threshold ( @{ $predicate->{numbers} } ) {
				if ( !$test->( $number, $threshold ) ) {
					return 0;
				}
			}
			return 1;
		}
		foreach my $threshold ( @{ $predicate->{numbers} } ) {
			if ( $test->( $number, $threshold ) ) {
				return 1;
			}
		}
		return 0;
	} ## end if ( $kind eq 'num' )

	# cidr
	return ip_ignored( $predicate->{cidr}, $value ) ? 1 : 0;
} ## end sub _predicate_test_one

=head2 compile_gates

Compiles a gate array into runnable entries, each either a legacy
field/values matcher set or a typed predicate. Shared by every type that
carries a gate... json runs it as a pre-filter over parsed fields, syslog
and raw as a post-match refinement over the captures, and a selection, a
tracked entry's C<where>, and the keywords shorthand are each one such list
too. Dies on anything unusable.

    - gate_def :: Array ref of the gate entries as the rule file wrote
          them, each a hash with a C<field>.

    - where_prefix :: The lead in for the die messages, naming the rule and
          which list this is, such as C<The gate of the rule
          "json/example">, so a selection reads clearly.

Returns a array ref of compiled gates, each a hash as below.

    - field :: The field the gate reads.

    - matchers :: The matcher set of a legacy entry, as
          L</compile_matchers> returns.

    - predicate :: The compiled predicate of a typed entry, in place of
          C<matchers>.

    - keyword :: 1 when the field is C<%%%ANY%%%> or a C<%%%ANY:prefix%%%>,
          the gate fanning over many values.

    - prefix :: The prefix of a C<%%%ANY:prefix%%%> field.

    - code :: A code ref taking the data hash ref and returning 1 or 0, for
          a plain field/values gate, else undef and L</gates_pass> judges
          the gate the general way.

    my $gates = compile_gates( $def->{gate}, 'The gate of the rule "' . $name . '"' );

=cut

sub compile_gates {
	my ( $gate_def, $where_prefix ) = @_;

	if ( !is_plain_arrayref($gate_def) || !@{$gate_def} ) {
		die( $where_prefix . ' is not a array or is empty' );
	}

	my @gates;
	my $entry_int = 0;
	foreach my $entry ( @{$gate_def} ) {
		my $where = $where_prefix . ' entry ' . $entry_int;
		if ( !is_plain_hashref($entry) || !defined( $entry->{field} ) ) {
			die( $where . ' is not a hash with a field' );
		}
		my $gate;
		if ( any { exists( $entry->{$_} ) } @PREDICATE_ONLY_KEYS ) {
			$gate = { 'field' => $entry->{field}, 'predicate' => _compile_predicate( $entry, $where ) };
		} else {
			if ( !is_plain_arrayref( $entry->{values} ) ) {
				die( $where . ' is not a hash with a field and a values array' );
			}
			foreach my $key ( keys( %{$entry} ) ) {
				if ( $key !~ /^(?:field|values)$/ ) {
					die( $where . ' has the unknown key "' . $key . '"' );
				}
			}
			$gate = { 'field' => $entry->{field}, 'matchers' => compile_matchers( $entry->{values}, $where ) };
		} ## end else [ if ( any { exists( $entry->{$_} ) } @PREDICATE_ONLY_KEYS)]

		# the reserved keyword fields, flagged at compile so the runtime fans
		# the predicate over many values... %%%ANY%%% every field, %%%ANY:pre%%%
		# the subtree at or under `pre`, so a keyword can search everything or
		# just a known branch without touching the rest
		if ( $entry->{field} eq '%%%ANY%%%' ) {
			$gate->{keyword} = 1;
		} elsif ( $entry->{field} =~ /^%%%ANY:(.+)%%%$/ ) {
			$gate->{keyword} = 1;
			$gate->{prefix}  = $1;
		}
		# the keyword fan carries no referenced value, so a fieldref under it
		# would compile and then silently never match
		if ( $gate->{keyword} && defined( $gate->{predicate} ) && defined( $gate->{predicate}{fieldref} ) ) {
			die( $where . ' pairs fieldref with a keyword field, which can never match' );
		}
		$gate->{code} = _compile_gate_code($gate);
		push( @gates, $gate );
		$entry_int++;
	} ## end foreach my $entry ( @{$gate_def} )

	return \@gates;
} ## end sub compile_gates

# compiles one gate to the code ref that runs it, or undef for a gate shape
# that is left to _gate_hit.
#
# _gate_hit asks the same three questions of every gate on every line...
# keyword or not, predicate or matchers, MESSAGE or a plain field... and the
# answers were settled when the rule was read. Resolving them once here, into
# a closure that does only what this gate needs, is where the saving is: a
# plain gate becomes one hash lookup with no branching around it, and the
# _gate_hit and matchers_hit frames both go.
#
# Only the plain-matchers shape compiles, which is the shape the per-line
# path is made of. A keyword fan, a typed predicate, and the MESSAGE field
# each keep their branching at runtime and stay with _gate_hit... they are
# the rare shapes, MESSAGE only reaching a gate at all after a syslog rule's
# regexp has already matched, so compiling them would restate three more
# paths to buy nothing.
#
# The closure takes the data hash alone and closes over nothing but the gate's
# own field and matchers, so it holds no reference to any rule. A gate whose
# values carry a //regexp// hands the test to matchers_hit rather than
# restating the walk... it is the strings-only case that is worth
# specializing, and it is the only one specialized here.
#
# Args...
#
#    - gate :: One compiled gate, as built above.
#
# Returns a code ref taking the data hash ref and returning 1 or 0, or undef
# when the gate is a shape this does not compile.
#
#    my $code = _compile_gate_code($gate);
#    my $hit = defined($code) ? $code->($data) : _gate_hit( $gate, $data, $message );
sub _compile_gate_code {
	my ($gate) = @_;

	if ( $gate->{keyword} || defined( $gate->{predicate} ) || !defined( $gate->{field} ) ) {
		return undef;
	}
	if ( $gate->{field} eq 'MESSAGE' ) {
		return undef;
	}

	my $field    = $gate->{field};
	my $matchers = $gate->{matchers};

	if ( @{ $matchers->{regexps} } ) {
		return sub {
			my ($data) = @_;

			return matchers_hit( $matchers, $data->{$field} );
		};
	}

	my $strings = $matchers->{strings};

	return sub {
		my $value = $_[0]->{$field};

		return ( defined($value) && $strings->{$value} ) ? 1 : 0;
	};
} ## end sub _compile_gate_code

=head2 gates_pass

Runs a compiled gate list over a data hash, the entries ANDed. Shared by
each selection of the boolean form, by the json type's capture entries, by
a tracked entry's C<where>, and by the keyword fan... a rule whose boolean
is nothing but a plain gate list is walked by the rule itself and never
reaches here. A entry that compiled to a code ref is run through it, the
rest the general way, so a list of mixed shapes still pays only for what it
is.

    - gates :: A compiled gate list, as L</compile_gates> returns.

    - data :: Hash ref of field or capture name to value, what the gates
          read.

    - message :: The line's message, read by a gate on the reserved
          C<MESSAGE> field and searched by a C<%%%ANY%%%> keyword. undef
          when the caller has none.

Returns 1 when every gate holds, else 0.

    if ( gates_pass( $gates, $found->{data}, $parsed->{message} ) ) { ... }

=cut

sub gates_pass {
	my ( $gates, $data, $message ) = @_;

	foreach my $gate ( @{$gates} ) {
		my $code = $gate->{code};
		if ( defined($code) ) {
			if ( !$code->($data) ) {
				return 0;
			}
		} elsif ( !_gate_hit( $gate, $data, $message ) ) {
			return 0;
		}
	} ## end foreach my $gate ( @{$gates} )

	return 1;
} ## end sub gates_pass

# tests one gate against a data hash, true when it holds. an ordinary gate reads
# its one field (MESSAGE reaching the whole message); a keyword gate fans its
# predicate over many field values, matching if any hits, so a string can be
# searched across every field or a subtree
sub _gate_hit {
	my ( $gate, $data, $message ) = @_;

	if ( $gate->{keyword} ) {
		my @values = _keyword_values( $data, $message, $gate->{prefix} );
		my $hit    = 0;
		foreach my $value (@values) {
			# the predicate core, no negate, so the fan is a clean OR
			my $core
				= defined( $gate->{predicate} )
				? _predicate_core( $gate->{predicate}, $value )
				: matchers_hit( $gate->{matchers}, $value );
			if ($core) {
				$hit = 1;
				last;
			}
		} ## end foreach my $value (@values)
		# a negated keyword means no field matched, so negate the whole fan once
		if ( defined( $gate->{predicate} ) && $gate->{predicate}{negate} ) {
			$hit = $hit ? 0 : 1;
		}
		return $hit;
	} ## end if ( $gate->{keyword} )

	my $value
		= ( $gate->{field} eq 'MESSAGE' && defined($message) && !exists( $data->{MESSAGE} ) )
		? $message
		: $data->{ $gate->{field} };
	if ( !defined( $gate->{predicate} ) ) {
		return matchers_hit( $gate->{matchers}, $value );
	}

	# a fieldref predicate's needle is another field's live value, resolved
	# here where the data hash is in hand and threaded into the compare
	my $ref;
	if ( defined( $gate->{predicate}{fieldref} ) ) {
		$ref = $data->{ $gate->{predicate}{fieldref} };
	}
	my $hit = _predicate_core( $gate->{predicate}, $value, $ref );
	# a missing field is a false core, so a plain predicate misses and a
	# negated one holds, matching Sigma's "field absent" semantics
	if ( $gate->{predicate}{negate} ) {
		$hit = $hit ? 0 : 1;
	}
	return $hit;
} ## end sub _gate_hit

# the values a keyword gate fans over... every field value plus the message for
# a bare %%%ANY%%%, or the values whose flattened path is the prefix or under it
# for a scoped %%%ANY:prefix%%%, so nothing unrelated is searched
sub _keyword_values {
	my ( $data, $message, $prefix ) = @_;

	if ( defined($prefix) ) {
		my @values;
		my $under = $prefix . '.';
		foreach my $field ( keys( %{$data} ) ) {
			if ( $field eq $prefix || index( $field, $under ) == 0 ) {
				push( @values, $data->{$field} );
			}
		}
		return @values;
	} ## end if ( defined($prefix) )

	my @values = values( %{$data} );
	if ( defined($message) ) {
		push( @values, $message );
	}
	return @values;
} ## end sub _keyword_values

=head2 compile_condition

Parses a Sigma-style condition string over the named selections into a
AST, dying on a syntax error or a reference to a unknown selection. The
grammar is or > and > not > primary, primary being a paren group, a
selection name, or a quantifier... C<all of them>, C<1 of them>,
C<N of prefix_*>.

    - string :: The condition as the rule file wrote it.

    - selections :: Hash ref keyed by selection name, the names the
          condition may reference. Only the keys are read.

    - where :: The lead in for the die messages, such as C<The condition
          of the rule "json/example">.

Returns the AST, nested array refs each led by its kind... C<sel> with a
selection name, C<not> with one node, C<and> or C<or> with two, or C<count>
with a threshold and a array ref of selection names.

    my $ast = compile_condition( 'is_alert and not is_internal', \%compiled, $where );
    # [ 'and', [ 'sel', 'is_alert' ], [ 'not', [ 'sel', 'is_internal' ] ] ]

=cut

sub compile_condition {
	my ( $string, $selections, $where ) = @_;

	if ( !defined($string) || ref($string) ne '' || $string !~ /\S/ ) {
		die( $where . ' is not a non-empty string' );
	}

	my @tokens;
	while ( $string =~ /\G\s*([()]|[^\s()]+)/gc ) {
		push( @tokens, $1 );
	}

	my $pos  = 0;
	my $peek = sub { return $pos < scalar(@tokens) ? $tokens[$pos] : undef; };
	my $next = sub { return $tokens[ $pos++ ]; };

	my ( $parse_or, $parse_and, $parse_not, $parse_primary );

	$parse_primary = sub {
		my $tok = $peek->();
		if ( !defined($tok) ) {
			die( $where . ' ends unexpectedly' );
		}
		if ( $tok eq '(' ) {
			$next->();
			my $node  = $parse_or->();
			my $close = $next->();
			if ( !defined($close) || $close ne ')' ) {
				die( $where . ' has an unbalanced paren' );
			}
			return $node;
		}
		# a quantifier... (all|N) of (them | <prefix>_*)
		if (   ( lc($tok) eq 'all' || $tok =~ /^[0-9]+$/ )
			&& defined( $tokens[ $pos + 1 ] )
			&& lc( $tokens[ $pos + 1 ] ) eq 'of' )
		{
			my $qty = $next->();
			$next->();    # of
			my $target = $next->();
			if ( !defined($target) ) {
				die( $where . ' has an "of" with no target' );
			}
			my @names = _cond_resolve( $target, $selections, $where );
			# a *-pattern matching nothing would make "all of" vacuously
			# true, turning a typo into match-everything
			if ( !@names ) {
				die( $where . ' has an "of" target "' . $target . '" that covers no selections' );
			}
			my $threshold = ( lc($qty) eq 'all' ) ? scalar(@names) : $qty + 0;
			if ( $threshold < 1 ) {
				die( $where . ' asks for 0 of, which is vacuously true' );
			}
			if ( $threshold > scalar(@names) ) {
				die(      $where
						. ' asks for '
						. $threshold . ' of '
						. scalar(@names)
						. ' selections, which can never be met' );
			}
			return [ 'count', $threshold, \@names ];
		} ## end if ( ( lc($tok) eq 'all' || $tok =~ /^[0-9]+$/...))
		my $name = $next->();
		if ( $name =~ /^(?:and|or|not|of|them|all)$/i || $name eq ')' ) {
			die( $where . ' has a misplaced "' . $name . '"' );
		}
		if ( !exists( $selections->{$name} ) ) {
			die( $where . ' references the unknown selection "' . $name . '"' );
		}
		return [ 'sel', $name ];
	}; ## end $parse_primary = sub

	$parse_not = sub {
		my $tok = $peek->();
		if ( defined($tok) && lc($tok) eq 'not' ) {
			$next->();
			return [ 'not', $parse_not->() ];
		}
		return $parse_primary->();
	};

	$parse_and = sub {
		my $node = $parse_not->();
		while ( defined( $peek->() ) && lc( $peek->() ) eq 'and' ) {
			$next->();
			$node = [ 'and', $node, $parse_not->() ];
		}
		return $node;
	};

	$parse_or = sub {
		my $node = $parse_and->();
		while ( defined( $peek->() ) && lc( $peek->() ) eq 'or' ) {
			$next->();
			$node = [ 'or', $node, $parse_and->() ];
		}
		return $node;
	};

	my $ast = $parse_or->();
	if ( $pos != scalar(@tokens) ) {
		die( $where . ' has trailing tokens after "' . $tokens[$pos] . '"' );
	}

	return $ast;
} ## end sub compile_condition

# resolves a quantifier target to the list of selection names it covers...
# "them" is all, a trailing * is a name prefix, else a single named selection
sub _cond_resolve {
	my ( $target, $selections, $where ) = @_;

	if ( lc($target) eq 'them' ) {
		my @names = sort( keys( %{$selections} ) );
		return @names;
	}
	if ( $target =~ /^(.*)\*$/ ) {
		my $prefix = $1;
		my @names  = grep { index( $_, $prefix ) == 0 } sort( keys( %{$selections} ) );
		return @names;
	}
	if ( !exists( $selections->{$target} ) ) {
		die( $where . ' has an "of" target "' . $target . '" that is not a selection or a *-pattern' );
	}
	return ($target);
} ## end sub _cond_resolve

=head2 eval_condition

Folds a condition AST into its verdict, asking for each selection's boolean
only as it is needed... the and/or arms short-circuit, and the count fold
bails as soon as the threshold is met or can no longer be.

    - ast :: The AST, as L</compile_condition> returns.

    - eval_sel :: A code ref taking a selection name and returning whether
          that selection holds for the line being judged.

Returns 1 when the condition holds, else 0.

    my $holds = eval_condition( $ast, sub { return gates_pass( $selections{ $_[0] }, $data, $message ); } );

=cut

sub eval_condition {
	my ( $ast, $eval_sel ) = @_;

	my $op = $ast->[0];
	if ( $op eq 'sel' ) {
		return $eval_sel->( $ast->[1] ) ? 1 : 0;
	}
	if ( $op eq 'not' ) {
		return eval_condition( $ast->[1], $eval_sel ) ? 0 : 1;
	}
	if ( $op eq 'and' ) {
		return ( eval_condition( $ast->[1], $eval_sel ) && eval_condition( $ast->[2], $eval_sel ) )
			? 1
			: 0;
	}
	if ( $op eq 'or' ) {
		return ( eval_condition( $ast->[1], $eval_sel ) || eval_condition( $ast->[2], $eval_sel ) )
			? 1
			: 0;
	}
	# count... at least threshold of the named selections are true
	my ( $threshold, $names ) = ( $ast->[1], $ast->[2] );
	my $hits      = 0;
	my $remaining = scalar( @{$names} );
	foreach my $name ( @{$names} ) {
		$remaining--;
		if ( $eval_sel->($name) ) {
			$hits++;
			if ( $hits >= $threshold ) {
				return 1;
			}
		} elsif ( ( $hits + $remaining ) < $threshold ) {
			return 0;
		}
	} ## end foreach my $name ( @{$names} )
	return 0;
} ## end sub eval_condition

1;
