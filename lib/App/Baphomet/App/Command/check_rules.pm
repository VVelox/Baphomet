package App::Baphomet::App::Command::check_rules;

use 5.006;
use strict;
use warnings;
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
		. 'shipped rules. With --rules-dir only that dir is looked at.';
}

sub usage_desc { return '%c check_rules %o [rule ...]'; }

sub opt_spec {
	return (
		[ 'config=s',    'path of the config file', { default => '/usr/local/etc/baphomet/config.toml' } ],
		[ 'rules-dir=s', 'a single rules dir to check in isolation, instead of the resolved set' ],
	);
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	# an explicit --rules-dir means "check exactly this dir", so the shipped
	# rules are left out; with out it the config's override dir is searched
	# ahead of the shipped rules, just as at run time
	my $rules;
	if ( defined( $opt->rules_dir ) ) {
		$rules = App::Baphomet::Rules->new( 'rules_dir' => $opt->rules_dir, 'shipped' => 0 );
	} else {
		$rules = App::Baphomet::Rules->new( 'rules_dir' => load_config( $opt->config )->{rules_dir} );
	}

	my @names = @{$args};
	if ( !@names ) {
		@names = $rules->rule_names;
	}

	if ( !@names ) {
		die("No rules found to check\n");
	}

	my $failed = 0;
	foreach my $name (@names) {
		my $rule = eval { $rules->load( $name, skip_tests => 1 ); };
		if ($@) {
			print $name . ' ... failed to load... ' . $@;
			$failed++;
			next;
		}

		my $results = $rule->run_tests;
		if ( $results->{fail} ) {
			print $name . ' ... '
				. $results->{fail} . ' of '
				. ( $results->{pass} + $results->{fail} )
				. " tests failed...\n    "
				. join( "\n    ", @{ $results->{failures} } ) . "\n";
			$failed++;
		} else {
			print $name . ' ... ok, ' . $results->{pass} . " tests passed\n";
		}
	} ## end foreach my $name (@names)

	if ($failed) {
		die( $failed . ' of ' . scalar(@names) . " rules failed\n" );
	}

	return;
} ## end sub execute

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
