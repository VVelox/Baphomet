package App::Baphomet::Rules::HTTP;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util qw( is_plain_hashref );
use base 'App::Baphomet::Rules::Base';

=pod

=head1 NAME

App::Baphomet::Rules::HTTP - HTTP access log rule handler for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Rules::HTTP;

    my $rule = App::Baphomet::Rules::HTTP->new( name => 'http/badbots', def => $def );

    my $found = $rule->check($parsed);
    if ( defined($found) ) {
        print $found->{data}{host} . "\n";
    }

Normally not used directly but via L<App::Baphomet::Rules>.

=head1 RULE FORMAT

A http rule works on lines parsed by L<App::Baphomet::Parser::HTTPAccess>.
Unlike syslog rules there is nothing to extract... the client is already
the C<host> field of the parsed line, so http rules just decide which
lines are offenses. What gets banned is always C<host>.

    ---
    status:
      - 401
      - 403
      - //^5//
    method:
      - GET
      - POST
    match:
      - field: user_agent
        regexp: '(?i:masscan|zgrab|sqlmap)'
      - field: path
        regexp: '\.(?:env|git)(?:$|/)'
    ignore:
      - field: user_agent
        regexp: 'Googlebot'
    tests:
      positive:
        - message: '203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "GET /.env HTTP/1.1" 404 196 "-" "zgrab/0.x"'
          found: 1
          data:
            host: "203.0.113.9"
      negative:
        - message: '198.51.100.7 - - [12/Jul/2026:08:15:51 -0500] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"'
          found: 0

=head2 status / method

Optional gates, ANDed. Lists of values checked against the status and
method of the parsed line... entries starting and ending with C<//> are
regexps, everything else is string equality. A line whose field does not
match a present gate is not a offense, no matter what the matches say.

=head2 gate / selections / condition / keywords

Optional, the shared predicate matcher run over the parsed access-log fields
(host, method, path, status, referer, user_agent, ...) as a pre-filter ANDed
ahead of the matches. So a C<gate> with the typed operators and C<decode>, a
C<selections>/C<condition> boolean, or a C<keywords> / C<%%%ANY%%%> search
across the fields all work here. See the predicate gate section of
F<docs/rules.md> for the forms,
L<https://github.com/LilithSec/Baphomet/blob/main/docs/rules.md#gate--selections--condition--keywords>.

=head2 match

Optional. Regexps checked in order, first hit wins, each a hash naming the
parsed field it runs against and the Perl regexp to use. The fields are
the keys of the L<App::Baphomet::Parser::HTTPAccess> hash... host, ident,
user, time, request, method, path, protocol, status, bytes, referer,
user_agent, and format. A field the line does not carry never matches.

With no match entries at all, passing the gates is itself the offense,
which is how a "every 401" rule works. A rule with neither gates nor
matches is a error.

=head2 ignore

Optional. Same shape as L</match>, but a hit vetoes the line entirely.
Checked before the matches.

=head2 detection_var

Optional. Names a field to count by instead of banishing C<host>, making the
rule detection-only... count by C<path>, C<user_agent>, or any parsed field.
See L<App::Baphomet::Rules::Base/detection_var>.

=head2 The common keys

The counting knobs, the triage metadata, the marks, the
C<country>/C<namtar_list>/C<active_time> gates, and C<tests> (parsed via
C<http_access> unless overridden, the found data being the parsed line's
fields, so a test may check C<data.host> or C<data.path>) are shared by every
type and documented under L<App::Baphomet::Rules::Base/"RULE FORMAT">.

=cut

my %fields = map { $_ => 1 } (
	'host',   'ident', 'user',    'time',       'request', 'method', 'path', 'protocol',
	'status', 'bytes', 'referer', 'user_agent', 'format'
);

=head1 METHODS

=head2 new

Initiates the object, compiling the passed rule def. Will die on a invalid
or uncompilable def. Inherited from L<App::Baphomet::Rules::Base>, which
calls this type's own compile of the def.

    - name :: The rule name, for error messages.
        Default :: unnamed

    - def :: The rule def hash, as parsed from the YAML.
        Default :: undef

=cut

# compiles the rule's def onto the object, this type's half of new... checks
# the def, then compiles the status and method gates, the boolean, and the
# match and ignore entries. called once, by the new every handler inherits
# from App::Baphomet::Rules::Base, after it has set name and def.
#
# takes nothing. returns nothing, dying on a invalid or uncompilable def.
#
#   $self->_compile;
sub _compile {
	my ($self) = @_;

	my $name = $self->{name};
	my $def  = $self->{def};

	# the slots only this type fills, empty till the def says otherwise
	$self->{field_gates} = {};
	$self->{matches}     = [];
	$self->{ignores}     = [];

	$self->_check_common( [qw( status method match ignore )] );

	# an http rule banishes host by default, but naming a detection_var (a URI,
	# a user-agent) makes it detection-only, counting by that instead
	$self->_check_detection_var;

	$self->_compile_field_gates( [ 'status', 'method' ] );

	# the generic gate / selections / keywords over the parsed fields, the same
	# operator, decode, and boolean machinery the json type uses
	$self->_compile_boolean;

	$self->_compile_match_ignore(
		sub {
			my ( $entry, $where ) = @_;
			if ( !defined( $fields{ $entry->{field} } ) ) {
				die( $where . ' names the unknown field "' . $entry->{field} . '"' );
			}
			my $regexp = $entry->{regexp};
			my $compiled;
			try {
				$compiled = qr/$regexp/;
			} catch ($caught) {
				die( $where . ', "' . $regexp . '", does not compile... ' . $caught );
			}
			return { 'field' => $entry->{field}, 'regexp' => $compiled };
		}
	);

	if ( !keys( %{ $self->{field_gates} } ) && !$self->{has_boolean} && !@{ $self->{matches} } ) {
		die(      'The rule "'
				. $name
				. '" has no gates, selections, keywords, or matches... it would regard nothing as a offense' );
	}

	return;
} ## end sub _compile

=head2 check

Checks a parsed line, as returned by L<App::Baphomet::Parser::HTTPAccess>,
against the rule. Returns undef for no match. For a match, returns a hash
as below, with data holding the defined fields of the parsed line and
regexp being the index of the match entry that hit, or undef for a gates
only rule.

    { 'data' => { 'host' => '203.0.113.9', ... }, 'regexp' => 0 }

    my $found = $rule->check($parsed);

=cut

sub check {
	my ( $self, $parsed, $scope, $line_ctx ) = @_;

	# must be access log shaped... the syslog parsers never produce these
	if ( !is_plain_hashref($parsed) || !defined( $parsed->{host} ) || !defined( $parsed->{status} ) ) {
		return undef;
	}

	if ( !$self->_field_gates_pass($parsed) ) {
		return undef;
	}

	# a ignore hit vetoes the line entirely, the track harvest included, so it
	# is asked ahead of both. it sat below the boolean before tracking existed,
	# where the two orders gave the same answer, both simply refusing the line
	foreach my $ignore ( @{ $self->{ignores} } ) {
		my $value = $parsed->{ $ignore->{field} };
		if ( defined($value) && $value =~ $ignore->{regexp} ) {
			return undef;
		}
	}

	# the tracked clause and then the generic gate / selections / keywords,
	# ANDed ahead of the matches, with the harvest run either way
	my ( $passed, $data ) = $self->_boolean_and_harvest( $parsed, $line_ctx );
	if ( !$passed ) {
		return undef;
	}

	# with match entries the first to match makes the offense, else the gates
	# alone did
	my $matched;
	foreach my ( $entry_int, $match ) ( indexed @{ $self->{matches} } ) {
		my $value = $parsed->{ $match->{field} };
		if ( defined($value) && $value =~ $match->{regexp} ) {
			$matched = $entry_int;
			last;
		}
	}
	if ( @{ $self->{matches} } && !defined($matched) ) {
		return undef;
	}

	return { 'data' => $data // $self->_field_space($parsed), 'regexp' => $matched };
} ## end sub check

# the field space a http rule's gates, harvest, and found data read... the
# parsed access-log fields this type knows, those the line carries.
#
# args:
#   $parsed :: the parsed access-log line's hash
#
# returns a fresh hash ref of field to value, the undefined fields left out.
#
#   my $field_space = $self->_field_space($parsed);
sub _field_space {
	my ( $self, $parsed ) = @_;

	my %data;
	foreach my $field ( keys(%fields) ) {
		if ( defined( $parsed->{$field} ) ) {
			$data{$field} = $parsed->{$field};
		}
	}

	return \%data;
} ## end sub _field_space

=head2 ban_var

Returns the list of capture names to use for bans, which for http rules is
always just host.

    my @ban_var = $rule->ban_var;

=cut

sub ban_var {
	return ('host');
}

=head2 src_ip_var

The http offender is the parsed C<host>, the client address, so the
flow-source var defaults to C<host> here rather than the base C<src_ip>...
so a hit carries the client in the EVE event's top-level C<src_ip>. A rule
naming its own C<src_ip_var> still wins.

    my $src_ip_var = $rule->src_ip_var;   # 'host', or the named var

=cut

sub src_ip_var {
	my ($self) = @_;

	return $self->{def}{src_ip_var} // 'host';
}

=head2 default_test_parser

The parser used for embedded tests that do not name one... http_access for
http rules.

=cut

sub default_test_parser {
	return 'http_access';
}

=head2 run_tests

Runs the tests embedded in the rule. Inherited from
L<App::Baphomet::Rules::Base>.

    my $results = $rule->run_tests;

=cut

1;
