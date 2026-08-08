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
		[ 'rules-dir=s', 'a single rules dir to look in, instead of the resolved set' ],
		[ 'file|f=s',    'the path of the rule to use, resolving nothing... an alternative to --rule' ],
	);
}

# Turns a path to a rule file into the (rules dir, rule name) pair the resolver
# works in, so --file leans on the ordinary load path rather than a second way of
# reading a rule. A rule's name is its path relative to the rules dir with the
# extension off, so the type is the parent dir and the rules dir the one above:
# ".../share/rules/syslog/sshd.yaml" is "syslog/sshd" under ".../share/rules".
sub _rule_from_path {
	my ( $self, $path ) = @_;

	if ( !-f $path ) {
		return ();
	}

	my @parts = split( m{/}, $path );
	if ( @parts < 2 ) {
		return ();
	}

	my $base = pop(@parts);
	$base =~ s/\.yaml$//;
	my $type = pop(@parts);
	my $dir = @parts ? join( '/', @parts ) : '.';

	return ( $dir, $type . '/' . $base );
} ## end sub _rule_from_path

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !defined( $opt->rule ) && !defined( $opt->file ) ) {
		$self->usage_error('--rule or --file must be specified');
	}
	if ( defined( $opt->rule ) && defined( $opt->file ) ) {
		$self->usage_error('--rule and --file name the same thing two ways... pass one');
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

	# an explicit --rules-dir means "look only in this dir", so the shipped
	# rules are left out; with out it the config's override dir is searched
	# ahead of the shipped rules, just as at run time
	my ( $rules, $name );
	if ( defined( $opt->file ) ) {

		# a path names the file outright, which is the way to be certain WHICH
		# copy is under test... the resolved shipped dir in a source checkout
		# being the installed one and not the tree
		my $dir;
		( $dir, $name ) = $self->_rule_from_path( $opt->file );
		if ( !defined($name) ) {
			die( 'The rule file "' . $opt->file . "\" is not a file\n" );
		}
		$rules = App::Baphomet::Rules->new( 'rules_dir' => $dir, 'shipped' => 0 );
	} elsif ( defined( $opt->rules_dir ) ) {
		$rules = App::Baphomet::Rules->new( 'rules_dir' => $opt->rules_dir, 'shipped' => 0 );
		$name  = $opt->rule;
	} else {
		my $config = load_config( $opt->config );
		$rules = App::Baphomet::Rules->new( 'rules_dir' => $config->{rules_dir}, 'groups_dir' => $config->{groups_dir} );
		$name  = $opt->rule;
	}
	my $rule_file = $rules->rule_path($name);
	my $rule      = $rules->load( $name, skip_tests => 1 );

	my $parsed = App::Baphomet::Parser::parse( $opt->parser, $args->[0] );

	# rule_file rides along so the answer says which copy of the rule gave it...
	# resolved, that is the config's override dir or the INSTALLED share dir, and
	# in a source checkout neither is the tree being edited
	my $result = {
		'parsed'    => $parsed,
		'found'     => 0,
		'rule'      => $name,
		'rule_file' => $rule_file,
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

1;
