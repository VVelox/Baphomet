package App::Baphomet::Rules;

use 5.006;
use strict;
use warnings;
use File::Find                      ();
use File::ShareDir                  ();
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

Loads rules from YAML files. A rule name is a relative path with out the
C<.yaml>, so the rule C<syslog/sshd> is the file C<syslog/sshd.yaml>. The
first component of the name is the rule type, which picks the handler the
rest of the file is handed to.

Rules are resolved across an ordered search path... a site's override dir
first, then the rules shipped with the dist. The override dir is
C<rules_dir> from the config, C<$base/etc/baphomet/rules> by convention; the
shipped rules are installed under the dist share dir and resolved with
L<File::ShareDir>. A rule present in the override dir shadows the shipped one
of the same name, so a site can override or extend the shipped set with out
touching what ships.

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

    - rules_dir :: The override dir searched ahead of the shipped rules,
          C<$base/etc/baphomet/rules> by convention. Searched only if it
          exists... a specified but absent dir is not an error, as the
          shipped rules still answer for the name. May be undef, in which
          case only the shipped rules are used.
        Default :: undef

    - shipped :: Whether to append the shipped rules dir, resolved with
          L<File::ShareDir>, to the search path. Turned off by callers that
          want to look at a single dir in isolation. Also gates the shipped
          groups dir.
        Default :: 1

    - groups_dir :: The override dir for rule groups, searched ahead of the
          shipped C<share/groups>, C<$base/etc/baphomet/groups> by
          convention. Searched only if it exists. May be undef. Unlike the
          rules dirs, no groups dir resolving is not an error... a config
          referencing no C<%group%> needs none. See L</expand_rules>.
        Default :: undef

At least one usable rules dir must resolve or new dies.

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

	if ( !defined( $opts{shipped} ) ) {
		$opts{shipped} = 1;
	}

	my @rules_dirs;

	# the override dir, searched ahead of the shipped rules so a site can
	# shadow or extend what ships... a specified but absent dir is not an
	# error, as the shipped rules still answer for the name
	if ( defined( $opts{rules_dir} ) && -d $opts{rules_dir} ) {
		push( @rules_dirs, $opts{rules_dir} );
	}

	# the shipped rules, installed under the dist share dir via
	# File::ShareDir::Install... resolved only when actually installed, so a
	# bare source checkout with out a share dir just falls back to rules_dir.
	# kept aside too, so a resolved path can be told shipped from override for
	# the EVE gid
	my $shipped_dir;
	if ( $opts{shipped} ) {
		eval { $shipped_dir = File::ShareDir::dist_dir('App-Baphomet') . '/rules'; };
		if ( defined($shipped_dir) && -d $shipped_dir ) {
			push( @rules_dirs, $shipped_dir );
		} else {
			$shipped_dir = undef;
		}
	}

	if ( !@rules_dirs ) {
		die(      'No usable rules dir... neither the configured rules_dir'
				. ( defined( $opts{rules_dir} ) ? ', "' . $opts{rules_dir} . '",' : '' )
				. ' nor the shipped rules dir exists' );
	}

	# the groups search path mirrors the rules one... an override groups_dir
	# ahead of the shipped share/groups, resolved the same way. unlike the
	# rules path an empty groups path is not fatal here... a config that never
	# references a %group% needs none, and expand_rules is where a
	# unresolvable reference dies loudly
	my @groups_dirs;
	if ( defined( $opts{groups_dir} ) && -d $opts{groups_dir} ) {
		push( @groups_dirs, $opts{groups_dir} );
	}
	if ( $opts{shipped} ) {
		my $shipped_groups;
		eval { $shipped_groups = File::ShareDir::dist_dir('App-Baphomet') . '/groups'; };
		if ( defined($shipped_groups) && -d $shipped_groups ) {
			push( @groups_dirs, $shipped_groups );
		}
	}

	my $self = {
		rules_dirs  => \@rules_dirs,
		groups_dirs => \@groups_dirs,
		shipped_dir => $shipped_dir,
		cache       => {},
	};
	bless( $self, ref($blank) || $blank );

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
		# a rule first loaded with skip_tests may be cached untested... a
		# caller wanting the tests still gets the must-pass guarantee
		if ( !$opts{skip_tests} && !$self->{tested}{$name} ) {
			$self->_run_load_tests( $name, $self->{cache}{$name} );
			$self->{tested}{$name} = 1;
		}
		return $self->{cache}{$name};
	}

	my ($type) = split( /\//, $name );
	if ( !defined( $types{$type} ) ) {
		die( 'The rule "' . $name . '" is of the unknown type "' . $type . '"' );
	}

	my $path = $self->rule_path($name);
	if ( !defined($path) ) {
		die(      'The rule "'
				. $name
				. '" does not exist under any of the rules dirs... '
				. join( ', ', map { '"' . $_ . '"' } @{ $self->{rules_dirs} } ) );
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

	# stamp the EVE gid from where the file resolved... shipped or override
	$rule->set_gid( $self->_gid_for_path($path) );

	if ( !$opts{skip_tests} ) {
		$self->_run_load_tests( $name, $rule );
		$self->{tested}{$name} = 1;
	}

	$self->{cache}{$name} = $rule;

	return $rule;
} ## end sub load

# runs a rule's embedded tests, dying in the load style when any fail
sub _run_load_tests {
	my ( $self, $name, $rule ) = @_;

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

	return;
} ## end sub _run_load_tests

=head2 rule_path

Returns the path of the file backing the named rule, searching the rules
dirs in order and returning the first that exists, so an override dir shadows
the shipped rule of the same name. Returns undef when the rule is found in
none of them.

    my $path = $rules->rule_path($name);

=cut

sub rule_path {
	my ( $self, $name ) = @_;

	foreach my $dir ( @{ $self->{rules_dirs} } ) {
		my $path = $dir . '/' . $name . '.yaml';
		if ( -f $path ) {
			return $path;
		}
	}

	return undef;
} ## end sub rule_path

=head2 group_path

Returns the path of the file backing the named group, searching the groups
dirs in order and returning the first that exists, so an override groups dir
shadows the shipped group of the same name. Returns undef when the group is
found in none of them. A group name is a C<type/name> relative path like a
rule, but the file carries no extension... C<json/suricata-all> is the file
C<json/suricata-all> backing the reference C<%json/suricata-all%>.

    my $path = $rules->group_path($name);

=cut

sub group_path {
	my ( $self, $name ) = @_;

	foreach my $dir ( @{ $self->{groups_dirs} } ) {
		my $path = $dir . '/' . $name;
		if ( -f $path ) {
			return $path;
		}
	}

	return undef;
} ## end sub group_path

=head2 group_members

Reads the named group and returns its member rule names in file order. A
group file is newline delimited... a line whose first non-whitespace
character is C<#> is a comment, a whitespace-only line is ignored, leading
and trailing whitespace on a line is trimmed, and every surviving line is one
rule name to include. Dies on a group that resolves to no file, a member not
in C<type/name> form, or a group with no members at all.

    my @names = $rules->group_members('json/suricata-all');

=cut

sub group_members {
	my ( $self, $name ) = @_;

	if ( !defined($name) || $name !~ /^[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+$/ ) {
		die( 'The group name, "' . ( defined($name) ? $name : 'undef' ) . '", is not in the form "type/name"' );
	}

	my $path = $self->group_path($name);
	if ( !defined($path) ) {
		die(      'The group "'
				. $name
				. '" does not exist under any of the groups dirs... '
				. ( @{ $self->{groups_dirs} }
				? join( ', ', map { '"' . $_ . '"' } @{ $self->{groups_dirs} } )
				: 'none are configured or shipped' ) );
	}

	open( my $fh, '<', $path ) || die( 'Failed to open the group "' . $name . '", "' . $path . '"... ' . $! );
	my @members;
	while ( my $line = <$fh> ) {
		$line =~ s/^\s+//;
		$line =~ s/\s+$//;
		next if ( $line eq '' || $line =~ /^#/ );
		if ( $line !~ /^[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+$/ ) {
			close($fh);
			die(      'The group "'
					. $name . '", "'
					. $path
					. '", has the invalid rule "'
					. $line
					. '"... should be like "syslog/sshd"' );
		} ## end if ( $line !~ /^[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+$/)
		push( @members, $line );
	} ## end while ( my $line = <$fh> )
	close($fh);

	if ( !@members ) {
		die( 'The group "' . $name . '", "' . $path . '", has no members' );
	}

	return @members;
} ## end sub group_members

=head2 expand_rules

Expands a watcher's rule list, replacing every group reference with its
members and passing bare rule names through untouched. A entry wrapped in
percent signs, C<%json/suricata-all%>, is a group reference resolved via
L</group_members>; anything else is a rule name kept as is. The result keeps
order and is deduplicated to the first occurrence... under the default
first-match overlap a repeat is inert anyway, and under a overlap of all the
dedup keeps a twice-named rule from counting twice. Dies through
group_members on a unresolvable group or a bad member.

    my @names = $rules->expand_rules(@entries);

=cut

sub expand_rules {
	my ( $self, @entries ) = @_;

	my @expanded;
	my %seen;
	foreach my $entry (@entries) {
		my @names;
		if ( defined($entry) && $entry =~ /^%(.+)%$/ ) {
			@names = $self->group_members($1);
		} else {
			@names = ($entry);
		}
		foreach my $name (@names) {
			next if ( defined($name) && $seen{$name} );
			$seen{$name} = 1 if defined($name);
			push( @expanded, $name );
		}
	} ## end foreach my $entry (@entries)

	return @expanded;
} ## end sub expand_rules

# the EVE gid for a resolved rule path... 0 when the file came from the
# shipped rules dir, 1 from the site override dir. A rule resolved with no
# shipped dir in play (a caller looking at one dir in isolation) is treated
# as an override
sub _gid_for_path {
	my ( $self, $path ) = @_;

	if ( defined( $self->{shipped_dir} ) && index( $path, $self->{shipped_dir} . '/' ) == 0 ) {
		return 0;
	}

	return 1;
}

=head2 rule_names

Returns the sorted, unique list of rule names available across the rules
dirs, each a C<type/name> relative path with out the C<.yaml>. A name present
in more than one dir is listed once, the override dir shadowing the shipped
copy. For walking the whole shipped-plus-override set, as the check_rules
command does.

    my @names = $rules->rule_names;

=cut

sub rule_names {
	my ($self) = @_;

	my %seen;
	foreach my $dir ( @{ $self->{rules_dirs} } ) {
		next if !-d $dir;
		File::Find::find(
			{
				wanted => sub {
					if ( $File::Find::name =~ /^\Q$dir\E\/(.+)\.yaml$/ ) {
						$seen{$1} = 1;
					}
				},
				no_chdir => 1,
			},
			$dir
		);
	} ## end foreach my $dir ( @{ $self->{rules_dirs} } )

	my @names = sort( keys(%seen) );
	return @names;
} ## end sub rule_names

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
