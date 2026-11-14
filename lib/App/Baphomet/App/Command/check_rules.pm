package App::Baphomet::App::Command::check_rules;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util qw( is_plain_arrayref is_plain_hashref );
use App::Baphomet::App -command;
use App::Baphomet::Config qw( load_config );
use App::Baphomet::Rules  ();

=head1 NAME

App::Baphomet::App::Command::check_rules - Check that rules load and pass their own tests.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet check_rules
    baphomet check_rules syslog/sshd
    baphomet check_rules --rules-dir ./share/rules syslog/sshd
    baphomet check_rules --file ./share/rules/syslog/sshd.yaml
    baphomet check_rules -v syslog/sshd

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'check that rules load and pass their own tests' }

sub description {
	return
		  'Loads the specified rules, or every rule available if none are '
		. 'specified, compiling each and running the tests embedded in it, and reports '
		. 'the results. Exits non-zero if any failed. With out --rules-dir the rules are '
		. 'resolved as at run time... the override dir from the config first, then the '
		. 'shipped rules, which in a source checkout is the INSTALLED copy and not the '
		. 'tree; the dir every rule came from is named in the summary, and per rule under '
		. '--verbose. Use --file to check a path outright and leave resolving out of it.';
} ## end sub description

sub usage_desc { return '%c check_rules %o [rule ...]'; }

sub opt_spec {
	return (
		[ 'config=s',    'path of the config file', { default => '/usr/local/etc/baphomet/config.toml' } ],
		[ 'rules-dir=s', 'a single rules dir to check in isolation, instead of the resolved set' ],
		[ 'file|f=s@',   'check the rule at this path, resolving nothing... repeatable' ],
		[ 'verbose|v',   'name the file each rule loaded from, where it ranks, and its tests by section' ],
	);
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	# --file names a path outright, so each gets its own resolver rooted above
	# its type dir and nothing is searched for... which is the way to be certain
	# WHICH copy of a rule is under test, the resolved shipped dir in a source
	# checkout being the installed one rather than the tree
	my @todo;
	foreach my $path ( @{ $opt->file || [] } ) {
		my ( $dir, $name ) = App::Baphomet::Rules::rule_from_path($path);
		if ( !defined($name) ) {
			die( 'The rule file "' . $path . "\" is not a file\n" );
		}
		push(
			@todo,
			{
				'name'     => $name,
				'rules'    => App::Baphomet::Rules->new( 'rules_dir' => $dir, 'shipped' => 0 ),
				'isolated' => 1,
			}
		);
	} ## end foreach my $path ( @{ $opt->file || [] } )

	# Named rules, or no --file at all, need the ordinary resolver. It is only
	# built then, since building it needs a usable rules dir and a run that
	# names nothing but --file paths has no use for one... with no rules dir on
	# the host, the config's nor an installed share dir, --file still works.
	#
	# An explicit --rules-dir means "check exactly this dir", so the shipped
	# rules are left out; with out it the config's override dir is searched
	# ahead of the shipped rules, just as at run time.
	#
	# A named arg may be a %group%, which expands to its members... with no
	# args, and no --file to stand in for them, the whole shipped-plus-override
	# rule set is walked.
	my @names = @{$args};
	if ( @names || !@todo ) {
		my $rules;
		my $isolated = 0;
		if ( defined( $opt->rules_dir ) ) {
			$rules    = App::Baphomet::Rules->new( 'rules_dir' => $opt->rules_dir, 'shipped' => 0 );
			$isolated = 1;
		} else {
			my $config = load_config( $opt->config );
			$rules
				= App::Baphomet::Rules->new( 'rules_dir' => $config->{rules_dir},
					'groups_dir' => $config->{groups_dir} );
		}
		@names = @names ? $rules->expand_rules(@names) : $rules->rule_names;
		push( @todo, map { { 'name' => $_, 'rules' => $rules, 'isolated' => $isolated } } @names );
	} ## end if ( @names || !@todo )

	if ( !@todo ) {
		die("No rules found to check\n");
	}

	my $failed = 0;
	my $warned = 0;
	my %from;
	foreach my $item (@todo) {
		my ( $name, $resolver ) = ( $item->{name}, $item->{rules} );

		# where this one actually came from, which is the question a green run
		# in a source checkout otherwise leaves open
		my $path = $resolver->rule_path($name);
		$from{ defined($path) ? _dir_of( $path, $name ) : 'unresolved' }++;

		my $rule;
		try {
			$rule = $resolver->load( $name, skip_tests => 1 );
		} catch ($caught) {
			print $name . ' ... failed to load... ' . $caught;
			$failed++;
			next;
		}

		if ( $opt->verbose ) {
			print $name . "\n";
			print '    file      ' . ( $path // 'unresolved' ) . "\n";
			my $gid_label = ' (shipped)';
			if ( $item->{isolated} ) {
				$gid_label = ' (one dir checked in isolation, so nothing to rank it against)';
			} elsif ( $rule->gid ) {
				$gid_label = ' (site override dir)';
			}
			print '    gid       ' . $rule->gid . $gid_label . "\n";
			# how many tests each section the rule carries holds
			my $tests = is_plain_hashref( $rule->{def}{tests} ) ? $rule->{def}{tests} : {};
			my @section_counts;
			foreach my $section ( 'positive', 'negative', 'injection' ) {
				if ( is_plain_arrayref( $tests->{$section} ) ) {
					push( @section_counts, $section . ' ' . scalar( @{ $tests->{$section} } ) );
				}
			}
			print '    tests     ' . join( ', ', @section_counts ) . "\n";
			if ( my @mungers = $rule->mungers ) {
				print '    mungers   ' . join( ', ', @mungers ) . "\n";
			}
		} ## end if ( $opt->verbose )

		my $results = $rule->run_tests;
		my $lead    = $opt->verbose ? '    result    ' : $name . ' ... ';

		# a warning is a question about the rule, not a verdict on it... printed
		# whatever the result, and never counted against the exit
		foreach my $warning ( @{ $results->{warnings} || [] } ) {
			print( ( $opt->verbose ? '    warning   ' : $name . ' ... warning: ' ) . $warning . "\n" );
			$warned++;
		}

		if ( $results->{fail} ) {
			print $lead
				. $results->{fail} . ' of '
				. ( $results->{pass} + $results->{fail} )
				. " tests failed...\n    "
				. join( "\n    ", @{ $results->{failures} } ) . "\n";
			$failed++;
		} else {
			print $lead . 'ok, ' . $results->{pass} . " tests passed\n";
		}
	} ## end foreach my $item (@todo)

	# Always say what was checked and where it was read from. Without this a
	# green run in a source checkout is indistinguishable from a green run
	# against a stale install, which is the same rule count and a different file
	print scalar(@todo)
		. ' rules checked, read from '
		. join( ', ', map { $_ . ' (' . $from{$_} . ')' } sort( keys(%from) ) )
		. ( $warned ? ', ' . $warned . ' warned' : '' ) . "\n";

	if ($failed) {
		die( $failed . ' of ' . scalar(@todo) . " rules failed\n" );
	}

	return;
} ## end sub execute

# the dir a resolved rule path sits under, the path with the rule's own
# type/name tail taken back off... so the summary names the dir that was
# searched rather than repeating the file
sub _dir_of {
	my ( $path, $name ) = @_;

	my $tail = '/' . $name . '.yaml';
	if ( substr( $path, -length($tail) ) eq $tail ) {
		return substr( $path, 0, length($path) - length($tail) );
	}

	return $path;
} ## end sub _dir_of

1;
