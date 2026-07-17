package App::Baphomet::Rules;

use 5.006;
use strict;
use warnings;
use YAML::XS                        ();
use App::Baphomet::Rules::HTTP      ();
use App::Baphomet::Rules::HTTPError ();
use App::Baphomet::Rules::JSON      ();
use App::Baphomet::Rules::Raw       ();
use App::Baphomet::Rules::Syslog    ();

=pod

=head1 NAME

App::Baphomet::Rules - Rule loading for Baphomet.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Rules;

    my $rules = App::Baphomet::Rules->new( rules_dir => '/usr/local/etc/baphomet/rules' );

    my $rule = $rules->load('syslog/sshd');

    my $found = $rule->check($parsed);

=head1 DESCRIPTION

Loads rules from YAML files under the rules dir. A rule name is a relative
path with out the C<.yaml>, so the rule C<syslog/sshd> is the file
C<syslog/sshd.yaml> under the rules dir. The first component of the name is
the rule type, which picks the handler the rest of the file is handed to.

The known types are as below.

    - syslog :: L<App::Baphomet::Rules::Syslog>

    - http :: L<App::Baphomet::Rules::HTTP>

    - http_error :: L<App::Baphomet::Rules::HTTPError>

    - json :: L<App::Baphomet::Rules::JSON>

    - raw :: L<App::Baphomet::Rules::Raw>

Each type consumes lines of specific parsers... syslog rules take the
syslog parsers, http rules take http_access, http_error rules take
apache_error and nginx_error, json rules take json, and raw rules take
raw. See L</type_accepts_parser>.

Loading compiles the rule and then runs the tests embedded in it, refusing
to hand back a rule whose own tests do not pass, so a broken rule fails
loudly at load time instead of silently matching nothing while logs scroll
past. Loaded rules are cached, so two watchers sharing a rule compile it
once.

=head1 METHODS

=head2 new

Initiates the object. Will die on errors.

    - rules_dir :: The dir holding the rules. Must be specified and must
          exist.
        Default :: undef

=cut

my %types = (
	'syslog'     => 'App::Baphomet::Rules::Syslog',
	'http'       => 'App::Baphomet::Rules::HTTP',
	'http_error' => 'App::Baphomet::Rules::HTTPError',
	'json'       => 'App::Baphomet::Rules::JSON',
	'raw'        => 'App::Baphomet::Rules::Raw',
);

my %type_parsers = (
	'syslog'     => { 'syslog'       => 1, 'bsd_syslog' => 1, 'ietf_syslog' => 1, 'json_syslog' => 1, 'journal' => 1 },
	'http'       => { 'http_access'  => 1 },
	'http_error' => { 'apache_error' => 1, 'nginx_error' => 1 },
	'json'       => { 'json'         => 1 },
	'raw'        => { 'raw'          => 1 },
);

sub new {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{rules_dir} ) ) {
		die('No rules_dir specified');
	}
	if ( !-d $opts{rules_dir} ) {
		die( 'The rules_dir, "' . $opts{rules_dir} . '", does not exist or is not a directory' );
	}

	my $self = {
		rules_dir => $opts{rules_dir},
		cache     => {},
	};
	bless $self;

	return $self;
} ## end sub new

=head2 load

Loads the specified rule, returning the compiled handler object for it.
Will die on a unloadable rule... bad name, no such file, unparsable YAML,
a compile failure, or its embedded tests failing.

    my $rule = $rules->load($name);

Takes the following options.

    - skip_tests :: Skip running the embedded tests. Used by check_rules,
          which wants to run them itself for reporting.
        Default :: 0

    my $rule = $rules->load( $name, skip_tests => 1 );

=cut

sub load {
	my ( $self, $name, %opts ) = @_;

	if ( !defined($name) || $name !~ /^[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+$/ ) {
		die( 'The rule name, "' . ( defined($name) ? $name : 'undef' ) . '", is not in the form "type/name"' );
	}

	if ( defined( $self->{cache}{$name} ) ) {
		return $self->{cache}{$name};
	}

	my ($type) = split( /\//, $name );
	if ( !defined( $types{$type} ) ) {
		die( 'The rule "' . $name . '" is of the unknown type "' . $type . '"' );
	}

	my $path = $self->rule_path($name);
	if ( !-f $path ) {
		die( 'The rule "' . $name . '" does not exist... no such file "' . $path . '"' );
	}

	my $def;
	eval { $def = YAML::XS::LoadFile($path); };
	if ($@) {
		die( 'Failed to parse the rule "' . $name . '", "' . $path . '"... ' . $@ );
	}
	if ( ref($def) ne 'HASH' ) {
		die( 'The rule "' . $name . '", "' . $path . '", did not parse to a hash' );
	}

	my $rule = $types{$type}->new( 'name' => $name, 'def' => $def );

	if ( !$opts{skip_tests} ) {
		my $results = $rule->run_tests;
		if ( $results->{fail} ) {
			die(      'The rule "'
					. $name
					. '" failed '
					. $results->{fail} . ' of '
					. ( $results->{pass} + $results->{fail} )
					. ' of its own tests...' . "\n"
					. join( "\n", @{ $results->{failures} } )
					. "\n" );
		} ## end if ( $results->{fail} )
	} ## end if ( !$opts{skip_tests} )

	$self->{cache}{$name} = $rule;

	return $rule;
} ## end sub load

=head2 rule_path

Returns the path of the file for the specified rule name. Does not check it
exists.

    my $path = $rules->rule_path($name);

=cut

sub rule_path {
	my ( $self, $name ) = @_;

	return $self->{rules_dir} . '/' . $name . '.yaml';
}

=head2 known_type

Returns true if the passed rule type is a known one. Usable as a plain
function.

    if ( App::Baphomet::Rules::known_type($type) ) { ... }

=cut

sub known_type {
	my ($type) = @_;

	# allow being called as a method as well
	if ( ref($type) || ( defined($type) && $type eq __PACKAGE__ ) ) {
		$type = $_[1];
	}

	return defined($type) && defined( $types{$type} ) ? 1 : 0;
} ## end sub known_type

=head2 type_accepts_parser

Returns true if rules of the passed type can consume lines from the passed
parser. Usable as a plain function.

    if ( App::Baphomet::Rules::type_accepts_parser( $type, $parser ) ) { ... }

=cut

sub type_accepts_parser {
	my ( $type, $parser ) = @_;

	# allow being called as a method as well
	if ( ref($type) || ( defined($type) && $type eq __PACKAGE__ ) ) {
		( $type, $parser ) = ( $_[1], $_[2] );
	}

	if ( !defined($type) || !defined($parser) || !defined( $type_parsers{$type} ) ) {
		return 0;
	}

	return defined( $type_parsers{$type}{$parser} ) ? 1 : 0;
} ## end sub type_accepts_parser

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
