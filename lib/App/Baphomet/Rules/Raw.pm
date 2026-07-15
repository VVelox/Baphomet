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
C<message_regexp> with the same C<%%%%TOKEN%%%%> tokens, the same
C<ignore_regexp>, the same C<ban_var> naming which captures to ban, the
same per-rule C<max_score>/C<find_time>/C<ban_time>, the same cross-rule
marks (C<mark>/C<unmark>/C<marked>/C<not_marked>/C<mark_only>), and the
same C<country>, C<namtar_list>, and C<active_time> gates. See
L<App::Baphomet::Rules::Syslog> for those. Tests default to the C<raw>
parser.

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
		name => defined( $opts{name} ) ? $opts{name} : 'unnamed',
		def  => $opts{def},
	};
	bless $self;

	my $name = $self->{name};
	my $def  = $opts{def};

	if ( ref($def) ne 'HASH' ) {
		die( 'The def for the rule "' . $name . '" is not a hash' );
	}

	foreach my $key ( keys( %{$def} ) ) {
		if ( $key
			!~ /^(?:message_regexp|ignore_regexp|capture_regexp|ban_var|ban_not_internal|max_score|find_time|ban_time|weight|eve_only|mark|unmark|marked|not_marked|mark_only|country|namtar_list|active_time|test_parser|tests)$/
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

	if ( ref( $def->{ban_var} ) ne 'ARRAY' || !@{ $def->{ban_var} } ) {
		die( 'The rule "' . $name . '" lacks a ban_var array or it is empty' );
	}
	foreach my $item ( @{ $def->{ban_var} } ) {
		if ( !defined($item) || ref($item) ne '' ) {
			die( 'The ban_var of the rule "' . $name . '" contains a non-string entry' );
		}
	}

	if ( defined( $def->{tests} ) && ref( $def->{tests} ) ne 'HASH' ) {
		die( 'The tests of the rule "' . $name . '" is not a hash' );
	}

	# the token and regexp machinery lives in the base class
	$self->_compile_message_regexps($def);
	$self->_compile_capture_regexps($def);

	return $self;
} ## end sub new

=head2 check

Checks a parsed line against the rule. Returns undef for no match. For a
match, returns a hash as below, same as syslog rules.

    { 'data' => { 'SRC' => '1.2.3.4' }, 'regexp' => 0 }

    my $found = $rule->check($parsed);

=cut

sub check {
	my ( $self, $parsed, $scope ) = @_;

	if ( ref($parsed) ne 'HASH' || !defined( $parsed->{message} ) ) {
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
