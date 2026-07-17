package App::Baphomet::App::Command::test_line;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use JSON::MaybeXS         ();
use App::Baphomet::Config qw( load_config );
use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();

=head1 NAME

App::Baphomet::App::Command::test_line - Feed a single log line through a parser and a rule.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet test_line --rule syslog/sshd 'Jul 12 08:15:50 vixen42 sshd[1]: Invalid user foo from 1.2.3.4'
    baphomet test_line --rule syslog/sshd --parser ietf_syslog '<38>1 ...'

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'feed a single log line through a parser and a rule' }

sub description {
	return
		  'Parses the passed line via the specified parser, checks it against the '
		. 'specified rule, and prints what came of it as JSON... how the line parsed '
		. 'and, if it matched, which regexp matched and what got captured. Handy when '
		. 'writing rules. The rule is loaded with its embedded tests skipped, so a '
		. 'rule those are failing for can still be poked at.';
}

sub usage_desc { return '%c test_line %o <line>'; }

sub opt_spec {
	return (
		[ 'rule=s',      'the rule to check the line against' ],
		[ 'parser=s',    'the parser to parse the line with', { default => 'syslog' } ],
		[ 'config=s',    'path of the config file',           { default => '/usr/local/etc/baphomet/config.toml' } ],
		[ 'rules-dir=s', 'the rules dir, instead of the one from the config' ],
	);
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->rule ) ) {
		$self->usage_error('--rule must be specified');
	}
	if ( @{$args} != 1 ) {
		$self->usage_error('test_line takes exactly one arg, the line... quote it');
	}
	if ( !App::Baphomet::Parser::is_known( $opt->parser ) ) {
		$self->usage_error( '"'
				. $opt->parser
				. '" is not a known parser... '
				. join( ' ', App::Baphomet::Parser::known_parsers ) );
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $rules_dir = $opt->rules_dir;
	if ( !defined($rules_dir) ) {
		$rules_dir = load_config( $opt->config )->{rules_dir};
	}

	my $rules = App::Baphomet::Rules->new( 'rules_dir' => $rules_dir );
	my $rule  = $rules->load( $opt->rule, skip_tests => 1 );

	my $parsed = App::Baphomet::Parser::parse( $opt->parser, $args->[0] );

	my $result = {
		'parsed' => $parsed,
		'found'  => 0,
	};

	if ( defined($parsed) ) {
		my $found = $rule->check($parsed);
		if ( defined($found) ) {
			$result->{found}  = 1;
			$result->{regexp} = $found->{regexp};
			$result->{data}   = $found->{data};
		}
	}

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	if ( !defined($parsed) ) {
		die("The line did not parse\n");
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
