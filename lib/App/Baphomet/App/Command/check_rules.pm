package App::Baphomet::App::Command::check_rules;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use File::Find            ();
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
    baphomet check_rules --rules-dir ./rules syslog/sshd

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'check that rules load and pass their own tests' }

sub description {
	return
		  'Loads the specified rules, or every rule under the rules dir if none are '
		. 'specified, compiling each and running the tests embedded in it, and reports '
		. 'the results. Exits non-zero if any failed.';
}

sub usage_desc { return '%c check_rules %o [rule ...]'; }

sub opt_spec {
	return (
		[ 'config=s',    'path of the config file', { default => '/usr/local/etc/baphomet/config.toml' } ],
		[ 'rules-dir=s', 'the rules dir, instead of the one from the config' ],
	);
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $rules_dir = $opt->rules_dir;
	if ( !defined($rules_dir) ) {
		$rules_dir = load_config( $opt->config )->{rules_dir};
	}

	my $rules = App::Baphomet::Rules->new( 'rules_dir' => $rules_dir );

	my @names = @{$args};
	if ( !@names ) {
		File::Find::find(
			{
				wanted => sub {
					if ( $File::Find::name =~ /^\Q$rules_dir\E\/(.+)\.yaml$/ ) {
						push( @names, $1 );
					}
				},
				no_chdir => 1,
			},
			$rules_dir
		);
		@names = sort(@names);
	} ## end if ( !@names )

	if ( !@names ) {
		die( 'No rules found under "' . $rules_dir . '"' );
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
