package App::Baphomet::Rules::Raw;

use 5.006;
use strict;
use warnings;
use base 'App::Baphomet::Rules::Base';

=pod

=head1 NAME

App::Baphomet::Rules::Raw - Raw line rule handler for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Rules::Raw;

    my $rule = App::Baphomet::Rules::Raw->new( name => 'raw/mysqld-auth', def => $def );

    my $found = $rule->check($parsed);

Normally not used directly but via L<App::Baphomet::Rules>.

=head1 RULE FORMAT

A raw rule works on lines from the C<raw> parser, where the whole line is
the message. It is a syslog rule with out the daemon gate... the same
matcher, the C<message_regexp> with its C<%%%%TOKEN%%%%> tokens, the
C<ignore_regexp>, the C<capture_regexp> correlation, the C<stages>/C<per>
staged sequences (with no envelope, a raw C<per> keys on captures only),
and the C<gate> over the captures (the reserved C<MESSAGE> being the
whole line). See L<App::Baphomet::Rules::Syslog> for that matcher. C<ban_var> and every common
key... C<detection_var>, the counting knobs, the metadata, the marks, the
C<country>/C<namtar_list>/C<active_time> gates, and C<tests> (defaulting to
the C<raw> parser)... are documented under
L<App::Baphomet::Rules::Base/"RULE FORMAT">.

    ---
    message_regexp:
      - '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} auth failure from %%%%SRC%%%%$'
    ban_var:
      - SRC
    tests:
      positive:
        - message: "2026-07-12 08:15:50 auth failure from 1.2.3.4"
          found: 1
          data:
            SRC: "1.2.3.4"

With no gate, B<every regexp runs against every line> of the log. Anchor
with C<^> and lead each regexp with the log's own timestamp shape, which
restores most of the gate's cheap rejection, and keep raw watchers on
single purpose app logs rather than busy shared ones.

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
		name  => defined( $opts{name} ) ? $opts{name} : 'unnamed',
		def   => $opts{def},
		gates => [],
	};
	bless( $self, ref($blank) || $blank );

	my $name = $self->{name};
	my $def  = $opts{def};

	if ( ref($def) ne 'HASH' ) {
		die( 'The def for the rule "' . $name . '" is not a hash' );
	}

	foreach my $key ( keys( %{$def} ) ) {
		if ( $key
			!~ /^(?:message_regexp|ignore_regexp|capture_regexp|stages|per|gate|selections|condition|keywords|ban_var|detection_var|ban_not_internal|max_score|find_time|ban_time|weight|eve_only|msg|severity|classtype|references|attack|rev|mark|unmark|marked|not_marked|mark_only|sequence|country|namtar_list|active_time|reverse_dns|distinct|test_parser|tests|src_ip_var|dest_ip_var)$/
			)
		{
			die( 'The rule "' . $name . '" has the unknown key "' . $key . '"' );
		}
	}
	$self->_check_common( $def, $name );

	# a detection-only rule counts by its detection_var subject and never
	# banishes, so it needs no ban_var
	$self->_check_ban_var( $def, $name );

	# a staged rule... its stages are the whole matcher, exclusive with the
	# per-line matchers and the keyed correlation. the raw type has no
	# envelope, so a per naming syslog.* refuses in the shared compile
	if ( defined( $def->{stages} ) ) {
		if ( defined( $def->{message_regexp} ) || defined( $def->{capture_regexp} ) ) {
			die(      'The rule "'
					. $name
					. '" has stages beside message_regexp or capture_regexp... stages are the whole matcher' );
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
	$self->_compile_message_regexps($def);
	$self->_compile_capture_regexps($def);

	# an optional gate or selections+condition refines the match on its
	# captures... operators and decode over the extracted vars, and MESSAGE
	$self->_compile_boolean( $def, $name );

	return $self;
} ## end sub new

=head2 check

Checks a parsed line against the rule. Returns undef for no match. For a
match, returns a hash as below, same as syslog rules.

    { 'data' => { 'SRC' => '1.2.3.4' }, 'regexp' => 0 }

    my $found = $rule->check($parsed);

=cut

sub check {
	my ( $self, $parsed, $scope, $line_ctx ) = @_;

	if ( ref($parsed) ne 'HASH' || !defined( $parsed->{message} ) ) {
		return undef;
	}

	if ( defined( $self->{stages} ) ) {
		return $self->_check_stages( $parsed->{message}, $scope, $line_ctx, undef );
	}

	return $self->_check_message( $parsed->{message}, $scope, undef, undef, $line_ctx );
} ## end sub check

=head2 ban_var

Returns the list of capture names to use for bans. Inherited from
L<App::Baphomet::Rules::Base>.

=head2 default_test_parser

The parser used for embedded tests that do not name one... raw for raw
rules.

=cut

sub default_test_parser {
	return 'raw';
}

=head2 run_tests

Runs the tests embedded in the rule. Inherited from
L<App::Baphomet::Rules::Base>.

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
