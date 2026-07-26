#!perl
#
# every group shipped under share/groups/ must resolve, expand to at least one
# member, and have every member load as a real rule of a type consistent with
# the group's own dir (so a group is usable in a single-parser watcher)
#
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Find           ();
use App::Baphomet::Rules ();

my $rules_dir  = 'share/rules';
my $groups_dir = 'share/groups';
if ( !-d $rules_dir || !-d $groups_dir ) {
	plan skip_all => 'no rules/groups dir found... not running from the dist root?';
}

# group files are extension-less, so gather every plain file under the tree
my @names;
File::Find::find(
	{
		wanted => sub {
			if ( -f $File::Find::name && $File::Find::name =~ /^\Q$groups_dir\E\/(.+)$/ ) {
				push( @names, $1 );
			}
		},
		no_chdir => 1,
	},
	$groups_dir
);

if ( !@names ) {
	plan skip_all => 'no groups found under ' . $groups_dir;
}

plan tests => scalar(@names) * 3;

# in-tree dirs only, no installed copy
my $rules = App::Baphomet::Rules->new( rules_dir => $rules_dir, groups_dir => $groups_dir, shipped => 0 );

foreach my $name ( sort(@names) ) {
	my @members = eval { $rules->group_members($name) };
	my $err     = $@;

	ok( !$err, $name . ' resolves and parses' ) or diag($err);
	ok( scalar(@members), $name . ' has at least one member' );

	# every member loads, and its type matches the group's dir... a group
	# named under json/ must hold only json rules, else it can not be used in
	# a json watcher without the pairing check rejecting it
	my $group_type = ( split( m{/}, $name ) )[0];
	my @bad;
	foreach my $member (@members) {
		my ($member_type) = split( m{/}, $member );
		if ( $member_type ne $group_type ) {
			push( @bad, $member . ' (type ' . $member_type . ')' );
			next;
		}
		eval { $rules->load( $member, skip_tests => 1 ); };
		if ($@) {
			push( @bad, $member . ' (load failed)' );
		}
	} ## end foreach my $member (@members)

	ok( !@bad, $name . ' members all load and match the group type "' . $group_type . '"' )
		or diag( 'offending members... ' . join( ', ', @bad ) );
} ## end foreach my $name ( sort(@names) )
