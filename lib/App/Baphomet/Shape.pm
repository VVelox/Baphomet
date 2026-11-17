package App::Baphomet::Shape;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util  qw( is_plain_arrayref is_plain_hashref );
use List::Util qw( any );
use Exporter   qw( import );

our @EXPORT_OK = qw( check_hash check_entries check_value is_kind is_non_negative_int is_positive_int );

=head1 NAME

App::Baphomet::Shape - Checks what a rule or config author wrote against the shape it should have.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Shape qw( check_entries );

    my $mark_shape = {
        'required' => { 'name' => 'name', 'ttl' => 'seconds' },
        'optional' => { 'var'  => 'string', 'vars' => 'strings' },
        'not_both' => [ [ 'var', 'vars' ] ],
    };

    check_entries( $def->{mark}, $mark_shape, 'The mark of the rule "syslog/sshd"' );

=head1 DESCRIPTION

A rule file is a hash of keys, many of them lists of smaller hashes, and all
of it has to be vetted before the rule may load... a misspelled key or a
string where a list belongs is otherwise a setting that silently never
applies. This is that vetting, written once.

A B<shape> says what a hash may hold and a B<kind> says what one value must
be. A caller keeps its shapes as plain data, a row per key, and passes a hash
and a shape here. Each kind holds the words for failing it, so a failure
reads the same wherever it is raised.

Everything here is a plain function holding no state. The C<check_>
functions die on the first problem found, the passed C<where> leading the
message, and the C<is_> functions only answer.

=head1 SHAPES

A shape is a hash ref of any of the below.

    - required :: Hash ref of key to kind. Each must be set and of its kind.

    - optional :: Hash ref of key to kind. Each must be of its kind when
          set. A key in neither this nor C<required> is a unknown key.

    - not_both :: Array ref of key pairs. At most one of a pair may be set.

    - one_of :: Array ref of key pairs. Exactly one of a pair must be set.

    - any_of :: Array ref of key pairs. At least one of a pair must be set.

A pair is a array ref of the two keys, and may hold a third item saying why,
which the die message then ends on. A key set to undef is regarded as not
set, a YAML null being how a author blanks one.

=head1 KINDS

A kind is the name of one of the below, or a hash ref spelling one out in
place for a caller with a kind of its own.

    - any :: Anything at all, for a value vetted elsewhere.

    - scalar :: A string or number, possibly empty.

    - string :: A non-empty string.

    - name :: A string of letters, digits, C<_>, and C<->.

    - positive_int / seconds :: A whole number of one or more.

    - non_negative_int / seconds_or_zero :: A whole number of zero or more.

    - positive_number :: A number above zero, with or with out a fraction.

    - boolean :: A string or number, read only for its truth.

    - hash :: A hash.

    - severity :: One of info, low, medium, high, or critical.

    - strings :: A non-empty array of C<string>.

    - string_list :: A array of C<string>, possibly empty.

    - string_or_strings :: A C<string>, or C<strings>.

    - names :: A non-empty array of C<name>.

    - name_or_names :: A C<name>, or C<names>.

A kind spelled out in place is a hash ref of C<says>, the words for failing
it, and one of the below.

    - test :: A code ref taking the value and returning true when it is of
          the kind.

    - match :: A regexp a string or number must match.

    - in :: Array ref of the strings it may be.

    - each :: The kind every item of a array must be. Beside it, C<min> is
          the fewest items allowed, none when left off, and a true C<or_one>
          lets a lone item stand for a array of one.

=cut

# what the name of a mark, a tracked record, a namtar list, or a active_time
# window must look like... the alphabet of a rule name, so one rides tablets,
# commands, and config tables cleanly. the words for it sit beside it so the
# alphabet is typed in one place
my $NAME_RE   = qr/^[a-zA-Z0-9_\-]+\z/;
my $NAME_SAYS = 'a name matching /^[a-zA-Z0-9_\-]+$/';

# a string or a number, and never a ref or undef... also all a boolean is
# held to, a rule file's YAML giving one as a plain scalar that is only ever
# read for its truth
my $is_plain_scalar = sub { return ( defined( $_[0] ) && ref( $_[0] ) eq '' ) ? 1 : 0; };

# every named kind, each a hash of says, the words for failing it, and one of
# test, match, in, or each, as the KINDS section of the POD lists them... any
# has no says, there being no value that fails it
my %KINDS = (
	'any'    => { 'test' => sub { return 1; } },
	'scalar' => { 'test' => $is_plain_scalar, 'says' => 'a string' },
	'string' => {
		'test' => sub { return ( defined( $_[0] ) && ref( $_[0] ) eq '' && $_[0] ne '' ) ? 1 : 0; },
		'says' => 'a non-empty string',
	},
	'name'             => { 'match' => $NAME_RE,              'says' => $NAME_SAYS },
	'positive_int'     => { 'test'  => \&is_positive_int,     'says' => 'a positive int' },
	'seconds'          => { 'test'  => \&is_positive_int,     'says' => 'a positive int of seconds' },
	'non_negative_int' => { 'test'  => \&is_non_negative_int, 'says' => 'a non-negative int' },
	'seconds_or_zero'  => { 'test'  => \&is_non_negative_int, 'says' => 'a non-negative int of seconds' },
	'positive_number'  => {
		'test' => sub {
			my ($value) = @_;
			if ( !defined($value) || ref($value) ne '' || $value !~ /^[0-9]+(?:\.[0-9]+)?\z/ ) {
				return 0;
			}
			return ( $value + 0 > 0 ) ? 1 : 0;
		},
		'says' => 'a positive number',
	},
	'boolean'  => { 'test' => $is_plain_scalar,                                  'says' => 'a boolean' },
	'hash'     => { 'test' => sub { return is_plain_hashref( $_[0] ) ? 1 : 0; }, 'says' => 'a hash' },
	'severity' =>
		{ 'in' => [qw( info low medium high critical )], 'says' => 'one of info/low/medium/high/critical' },
	'strings'           => { 'each' => 'string', 'min'  => 1, 'says' => 'a non-empty array of non-empty strings' },
	'string_list'       => { 'each' => 'string', 'says' => 'a array of non-empty strings' },
	'string_or_strings' =>
		{ 'each' => 'string', 'min' => 1, 'or_one' => 1, 'says' => 'a non-empty string or a non-empty array of them' },
	'names'         => { 'each' => 'name', 'min' => 1, 'says' => 'a non-empty array, each ' . $NAME_SAYS },
	'name_or_names' =>
		{ 'each' => 'name', 'min' => 1, 'or_one' => 1, 'says' => $NAME_SAYS . ' or a non-empty array of them' },
);

=head1 FUNCTIONS

=head2 check_hash

Checks a hash against a shape, dying on the first problem found. The keys
are walked sorted, so of several problems the one named is always the same.
Unknown keys are named first, then missing ones, then a value of the wrong
kind, then the pairs.

    - hash :: The hash ref as the author wrote it.

    - shape :: The shape, as under L</SHAPES>.

    - where :: The lead in for the die messages, naming what the hash is,
          such as C<The distinct of the rule "syslog/sshd">.

Returns nothing.

    check_hash( $def->{distinct}, { 'required' => { 'of' => 'string' }, 'optional' => { 'by' => 'string' } }, $where );

=cut

sub check_hash {
	my ( $hash, $shape, $where ) = @_;

	if ( !is_plain_hashref($hash) ) {
		die( $where . ' is not a hash' );
	}

	my $required = $shape->{required} // {};
	my $optional = $shape->{optional} // {};

	foreach my $key ( sort( keys( %{$hash} ) ) ) {
		if ( !defined( $required->{$key} ) && !defined( $optional->{$key} ) ) {
			die( $where . ' has the unknown key "' . $key . '"' );
		}
	}
	foreach my $key ( sort( keys( %{$required} ) ) ) {
		if ( !defined( $hash->{$key} ) ) {
			die( $where . ' lacks a ' . $key );
		}
	}
	foreach my $key ( sort( keys( %{$hash} ) ) ) {
		my $kind = $required->{$key} // $optional->{$key};
		if ( defined( $hash->{$key} ) && !is_kind( $hash->{$key}, $kind ) ) {
			die( $where . ' has a ' . $key . ' that is not ' . _kind_rule($kind)->{says} );
		}
	}

	# a pair may say why as its third item, which then ends the message
	foreach my $pair ( @{ $shape->{not_both} // [] }, @{ $shape->{one_of} // [] } ) {
		my ( $first, $second, $why ) = @{$pair};
		if ( defined( $hash->{$first} ) && defined( $hash->{$second} ) ) {
			die( $where . ' has both ' . $first . ' and ' . $second . ( defined($why) ? ', ' . $why : '' ) );
		}
	}
	foreach my $pair ( @{ $shape->{one_of} // [] }, @{ $shape->{any_of} // [] } ) {
		my ( $first, $second, $why ) = @{$pair};
		if ( !defined( $hash->{$first} ) && !defined( $hash->{$second} ) ) {
			die( $where . ' has neither ' . $first . ' nor ' . $second . ( defined($why) ? ', ' . $why : '' ) );
		}
	}

	return;
} ## end sub check_hash

=head2 check_entries

Checks a list of hashes, each against the one shape, dying on the first
problem found. The list must be a non-empty array, and a entry is named in
the message by its place in it, counted from zero.

    - list :: The array ref as the author wrote it.

    - shape :: The shape every entry must have, as under L</SHAPES>.

    - where :: The lead in for the die messages, naming what the list is,
          such as C<The mark of the rule "syslog/sshd">.

Returns nothing.

    check_entries( $def->{mark}, $mark_shape, 'The mark of the rule "' . $name . '"' );

=cut

sub check_entries {
	my ( $list, $shape, $where ) = @_;

	if ( !is_plain_arrayref($list) || !@{$list} ) {
		die( $where . ' is not a non-empty array' );
	}
	foreach my ( $entry_int, $entry ) ( indexed @{$list} ) {
		check_hash( $entry, $shape, $where . ' entry ' . $entry_int );
	}

	return;
} ## end sub check_entries

=head2 check_value

Checks one value against a kind, dying when it is not of it.

    - value :: The value as the author wrote it.

    - kind :: The kind, as under L</KINDS>.

    - where :: The lead in for the die message, naming what the value is,
          such as C<The mungers of the rule "syslog/sshd">.

Returns nothing.

    check_value( $def->{mungers}, 'strings', 'The mungers of the rule "' . $name . '"' );

=cut

sub check_value {
	my ( $value, $kind, $where ) = @_;

	if ( !is_kind( $value, $kind ) ) {
		die( $where . ' is not ' . _kind_rule($kind)->{says} );
	}

	return;
}

=head2 is_kind

Says whether a value is of a kind, with out dying over it.

    - value :: The value to judge.

    - kind :: The kind, as under L</KINDS>.

Returns 1 when it is, else 0. Dies only on a kind name that is not a known
one, which is a mistake in the caller's shape and not in what was checked.

    if ( !is_kind( $settings->{default_severity}, 'severity' ) ) { ... }

=cut

sub is_kind {
	my ( $value, $kind ) = @_;

	my $rule = _kind_rule($kind);

	if ( defined( $rule->{test} ) ) {
		return $rule->{test}->($value) ? 1 : 0;
	}
	if ( defined( $rule->{match} ) ) {
		return ( $is_plain_scalar->($value) && $value =~ $rule->{match} ) ? 1 : 0;
	}
	if ( defined( $rule->{in} ) ) {
		return ( $is_plain_scalar->($value) && any { $_ eq $value } @{ $rule->{in} } ) ? 1 : 0;
	}

	# a list kind... every item of the one kind, at least min of them, and a
	# lone item standing for a list of one where the kind allows it
	my @items;
	if ( is_plain_arrayref($value) ) {
		@items = @{$value};
	} elsif ( $rule->{or_one} && defined($value) ) {
		@items = ($value);
	} else {
		return 0;
	}
	if ( scalar(@items) < ( $rule->{min} // 0 ) ) {
		return 0;
	}
	foreach my $item (@items) {
		if ( !is_kind( $item, $rule->{each} ) ) {
			return 0;
		}
	}

	return 1;
} ## end sub is_kind

# resolves a kind to the rule it names... a hash ref is a kind spelled out in
# place and is its own rule, anything else is the name of one in %KINDS.
#
# args:
#   $kind :: the kind as a shape gave it, a name or a hash ref
#
# returns the rule hash ref, holding says and one of test, match, in, or each.
# dies on a name that is not a known kind.
#
#   my $says = _kind_rule('seconds')->{says};    # 'a positive int of seconds'
sub _kind_rule {
	my ($kind) = @_;

	if ( is_plain_hashref($kind) ) {
		return $kind;
	}
	if ( !defined( $KINDS{$kind} ) ) {
		die( 'The kind "' . $kind . '" is not a known one' );
	}

	return $KINDS{$kind};
} ## end sub _kind_rule

=head2 is_non_negative_int

Returns 1 when the passed value is a whole number of zero or more, written
as plain digits, else 0... a ref, undef, a sign, a point, or a space all
fail.

    if ( !is_non_negative_int( $config->{checkpoint} ) ) { die(...) }

=cut

sub is_non_negative_int {
	my ($value) = @_;

	return ( defined($value) && ref($value) eq '' && $value =~ /^[0-9]+\z/ ) ? 1 : 0;
}

=head2 is_positive_int

Returns 1 when the passed value is a whole number of one or more, written as
plain digits, else 0... a value of all zeros, such as C<0> or C<00>, fails.

    if ( !is_positive_int( $config->{timeout} ) ) { die(...) }

=cut

sub is_positive_int {
	my ($value) = @_;

	return ( is_non_negative_int($value) && $value > 0 ) ? 1 : 0;
}

1;
