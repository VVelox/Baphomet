#!perl
#
# every rule shipped under share/rules/ must load and pass its own embedded
# tests, and must actually carry tests to begin with
#
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Find           ();
use App::Baphomet::Rules ();

my $rules_dir = 'share/rules';
if ( !-d $rules_dir ) {
	plan skip_all => 'no rules dir found... not running from the dist root?';
}

my @names;
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

if ( !@names ) {
	plan skip_all => 'no rules found under ' . $rules_dir;
}

plan tests => scalar(@names) * 3;

# look only at the in-tree share/rules, not any installed copy
my $rules = App::Baphomet::Rules->new( rules_dir => $rules_dir, shipped => 0 );

foreach my $name ( sort(@names) ) {
	my $rule = eval { $rules->load( $name, skip_tests => 1 ); };
	ok( defined($rule), 'rule ' . $name . ' loads' ) || diag($@);

	SKIP: {
		skip( 'did not load', 2 ) if !defined($rule);

		my $results = $rule->run_tests;
		cmp_ok( $results->{pass}, '>', 0, 'rule ' . $name . ' carries tests' );
		is( $results->{fail}, 0, 'rule ' . $name . ' passes its own tests' )
			|| diag( join( "\n", @{ $results->{failures} } ) );
	}
} ## end foreach my $name ( sort(@names) )
