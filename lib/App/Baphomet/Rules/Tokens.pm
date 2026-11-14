package App::Baphomet::Rules::Tokens;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Exporter                  qw( import );
use Regexp::IPv4              qw( $IPv4_re );
use Regexp::IPv6              qw( $IPv6_re );
use App::Baphomet::Primitives ();

our @EXPORT_OK = qw( compile_tokened_regexp match_tokened );

=head1 NAME

App::Baphomet::Rules::Tokens - The %%%%TOKEN%%%% regexps of the Baphomet rules, compiled and matched.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp match_tokened );

    my $entry = compile_tokened_regexp( '^Invalid user \S+ from %%%%SRC%%%%',
        'The message_regexp entry 0 of the rule "syslog/sshd"' );

    my $caps = match_tokened( $entry, $message );
    if ( defined($caps) ) { ... }    # $caps->{SRC} is the address

=head1 DESCRIPTION

A rule regexp names what it is after with C<%%%%NAME%%%%> tokens instead of
spelling the pattern out. There are two kinds. The offender tokens (IP4,
IP6, ADDR, DNS, HOST, SUBNET, SRC, and DEST) capture under their own name,
and the primitive fragments of L<App::Baphomet::Primitives> do not capture
at all. What each matches is documented for rule authors under
L<App::Baphomet::Rules::Syslog>.

This is the compile and the match of those regexps, shared by every rule
type that takes them. Both are plain functions holding no rule state... a
regexp string in and a compiled entry out, then a entry and a value in and
the captures out.

=head1 FUNCTIONS

=cut

# the TLD atom, like the label atoms ahead of it, may not end on a hyphen
my $dns_re = qr/(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?/;

# the IPv4 mapped IPv6 form, ::ffff:1.2.3.4, spelled out and tried ahead of
# the plain IPv6 atom. $IPv6_re is an alternation of the address forms and,
# unanchored, the first arm to succeed wins rather than the longest... on
# "::ffff:1.2.3.4" the compressed arm matches "::ffff:1" and the engine stops
# there, so a token built as (v4|v6) would hand the ban path a truncated
# address, "::ffff:218" for "::ffff:218.249.210.161". Naming the mapped form
# first makes the longest form win. Downstream already reads the ::ffff: form
# as its IPv4 self... see ignore_ips and the family/CIDR bucketing in
# App::Baphomet::Config... so the whole address is what wants capturing.
my $v4mapped_re = qr/::[fF]{4}:$IPv4_re/;
my $addr_re     = qr/(?:$v4mapped_re|$IPv4_re|$IPv6_re)/;

my %tokens = (
	'IP4'    => qr/$IPv4_re/,
	'IP6'    => qr/(?:$v4mapped_re|$IPv6_re)/,
	'ADDR'   => $addr_re,
	'DNS'    => $dns_re,
	'HOST'   => qr/(?:$addr_re|$dns_re)/,
	'SUBNET' => qr/$addr_re(?:\/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])(?![0-9]))?/,
	'SRC'    => $addr_re,
	'DEST'   => $addr_re,
);

=head2 compile_tokened_regexp

Compiles a single regexp string, expanding its C<%%%%TOKEN%%%%> tokens...
a offender token into a named capture, a primitive fragment into a
non-capturing group. Dies if the string names a token that is neither, or
if what it expands to does not compile.

    - regexp :: The regexp as the rule file wrote it, tokens and all.

    - where :: The lead in for the die messages, naming the rule and the
          entry, such as C<The message_regexp entry 0 of the rule
          "syslog/sshd">.

Returns a hash ref as below.

    - regexp :: The compiled regexp.

    - original :: The string as it was passed.

    - aliases :: A hash of offender token name to the array of capture
          names its occurrences were given, the first the token's own and
          each repeat numbered, which is what L</match_tokened> folds back.

    - paired :: 1 when the regexp carries both SRC and DEST, else 0.

    my $entry = compile_tokened_regexp( $regexp, $where );

=cut

sub compile_tokened_regexp {
	my ( $regexp, $where ) = @_;

	my %aliases;
	my $expanded = $regexp;
	# token names may carry underscores now that the primitive fragment
	# library (TIMESTAMP_ISO8601, DATE_US, ...) rides the same syntax
	$expanded =~ s/%%%%([A-Z0-9_]+)%%%%/_expand_token( $1, \%aliases, $where, $regexp )/ge;

	my $compiled;
	try {
		$compiled = qr/$expanded/;
	} catch ($caught) {
		die( $where . ', "' . $regexp . '", does not compile... ' . $caught );
	}

	return {
		'regexp'   => $compiled,
		'original' => $regexp,
		'aliases'  => \%aliases,
		'paired'   => ( defined( $aliases{SRC} ) && defined( $aliases{DEST} ) ) ? 1 : 0,
	};
} ## end sub compile_tokened_regexp

# expands a single token occurrence. two flavors, dispatched by which map
# the name is in. the offender tokens (SRC/ADDR/HOST/...) are CAPTURING:
# each becomes a named capture (?<NAME>...) whose name is the found field,
# numbered on repeat since perl forbids duplicate capture names in one
# regexp. the primitive fragments (INT/USERNAME/TIMESTAMP_ISO8601/...) are
# NON-capturing: each becomes a bare (?:...) building block that adds no
# field, so a author composes patterns without hand-rolling sub-regexps
# and wraps one in their own (?<FIELD>...) when they do want the capture.
# an offender token wins any name collision, being checked first.
#
# args:
#   $token    :: the token's name, the text between the percent signs
#   $aliases  :: hash ref of offender token name to the arrayref of capture
#                names handed out for it so far in this regexp, added to here
#   $where    :: the lead in for the die message
#   $original :: the whole regexp string as the rule file wrote it, quoted in
#                the die message
#
# returns the regexp text that takes the token's place. dies on a name that
# is neither a offender token nor a primitive fragment.
#
#   my %aliases;
#   my $first  = _expand_token( 'SRC', \%aliases, $where, $regexp );    # (?<SRC>...)
#   my $second = _expand_token( 'SRC', \%aliases, $where, $regexp );    # (?<SRC_2>...)
sub _expand_token {
	my ( $token, $aliases, $where, $original ) = @_;

	if ( defined( $tokens{$token} ) ) {
		if ( !defined( $aliases->{$token} ) ) {
			$aliases->{$token} = [$token];
			return '(?<' . $token . '>' . $tokens{$token} . ')';
		}

		my $alias = $token . '_' . ( scalar( @{ $aliases->{$token} } ) + 1 );
		push( @{ $aliases->{$token} }, $alias );

		return '(?<' . $alias . '>' . $tokens{$token} . ')';
	} ## end if ( defined( $tokens{$token} ) )

	# a primitive fragment... non-capturing, so it may repeat freely and
	# nest inside a caller's own capture without aliasing. resolved lazily
	# (and cached) from Log-Munger's base library the first time any rule
	# reaches for one, so a offender-tokens-only deployment never pays it
	my $primitives = App::Baphomet::Primitives::primitives();
	if ( defined( $primitives->{$token} ) ) {
		return '(?:' . $primitives->{$token} . ')';
	}

	die( $where . ', "' . $original . '", uses the unknown token "' . $token . '"' );
} ## end sub _expand_token

=head2 match_tokened

Checks a value against a single compiled entry. A offender token that
appeared more than once was captured under numbered names, and those are
folded back under the plain token name here, the first occurrence that
took part winning. A entry pairing SRC and DEST is only regarded as matched
when both were captured.

    - entry :: A compiled entry, as L</compile_tokened_regexp> returns.

    - value :: The string to match, such as a syslog message or a JSON
          field's value. A undef never matches.

Returns undef for no match, else a hash ref of capture name to value.

    my $caps = match_tokened( $entry, $parsed->{message} );

=cut

sub match_tokened {
	my ( $entry, $value ) = @_;

	if ( !defined($value) || $value !~ $entry->{regexp} ) {
		return undef;
	}

	my %caps = %+;

	foreach my $token ( keys( %{ $entry->{aliases} } ) ) {
		foreach my $alias ( @{ $entry->{aliases}{$token} } ) {
			if ( defined( $caps{$alias} ) && !defined( $caps{$token} ) ) {
				$caps{$token} = $caps{$alias};
			}
			if ( $alias ne $token ) {
				delete( $caps{$alias} );
			}
		}
	} ## end foreach my $token ( keys( %{ $entry->{aliases} ...}))

	# SRC/DEST only regard as being found if matched together
	if ( $entry->{paired} && ( !defined( $caps{SRC} ) || !defined( $caps{DEST} ) ) ) {
		return undef;
	}

	return \%caps;
} ## end sub match_tokened

1;
