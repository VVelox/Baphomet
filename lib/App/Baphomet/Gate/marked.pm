package App::Baphomet::Gate::marked;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape qw( check_hash );
use App::Baphomet::Marks qw( mark_key live_mark mark_hosts value_verdict );

=head1 NAME

App::Baphomet::Gate::marked - The marked gate, counting only what already has a brand.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - marked: { name: failed_login, var: USER }
      - ban_var: [ SRC ]
      - marked: { names: [ brute_force, scanner ] }

=head1 DESCRIPTION

Holds when the key checked has a live brand of the name, or of any of the
names, and that brand's value compares as asked. A key with nothing to look
up fails, and a value compare with either side missing can not be proven, so
the gate does not hold on it.

A entry is told...

    - name / names :: Exactly one. The brand to look for, or a array of them
          to hold on any of.

    - var / vars :: Optional, and never both. The found var the key is the
          value of, or the vars whose values joined are the key. With out
          either the key is the offender.

    - value_is / value_not :: Optional, and never both. The found var the
          brand's stored value has to equal, or has to differ from.

    - older_than / newer_than :: Optional. Seconds the brand has to have
          been set for at least, or for less than. A brand is as old as
          when it was first set, however often it has been set since. One
          with no saying when it was set does not hold.

    - hosts :: Optional. How many hosts of the fleet have to have set the
          brand, this one among them when it has. With out a tablet that
          shares brands there is only ever this one.

It needs the C<marks> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

# a entry may hold on any of a list of names in place of its one
my $SHAPE = {
	'optional' => {
		'name'       => 'name',
		'names'      => 'names',
		'var'        => 'string',
		'vars'       => 'strings',
		'value_is'   => 'string',
		'value_not'  => 'string',
		'older_than' => 'seconds',
		'newer_than' => 'seconds',
		'hosts'      => 'positive_int',
	},
	'one_of'   => [ [ 'name', 'names' ] ],
	'not_both' => [ [ 'var',  'vars' ], [ 'value_is', 'value_not' ] ],
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it as written.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	foreach my $key ( keys( %{$args} ) ) {
		$self->{$key} = $args->{$key};
	}

	return;
} ## end sub compile

=head2 needs

Returns C<marks>.

=cut

sub needs {
	return ('marks');
}

=head2 holds

Returns 1 when the key has a live brand the gate holds on, else 0. A names
gate holds on any of its listed brands, each judged with the value compare,
so a any-of never rides a value it did not prove.

    if ( $gate->holds( $data, $ip, $now ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip, $now ) = @_;

	my $key = mark_key( $self, $data, $ip );
	if ( !defined($key) ) {
		return 0;
	}

	my $store = $self->{context}{marks}->();
	my @names = defined( $self->{names} ) ? @{ $self->{names} } : ( $self->{name} );
	foreach my $name (@names) {
		my $mark = live_mark( $store, $name, $key, $now );
		if ( !defined($mark) || value_verdict( $self, $mark, $data ) ne 'holds' ) {
			next;
		}

		# how long ago it was first set, which a brand may have no saying of
		my $asks_age = defined( $self->{older_than} ) || defined( $self->{newer_than} );
		if ( $asks_age && !defined( $mark->{set} ) ) {
			next;
		}
		my $age = $asks_age ? $now - $mark->{set} : 0;
		if ( defined( $self->{older_than} ) && $age < $self->{older_than} ) {
			next;
		}
		if ( defined( $self->{newer_than} ) && $age >= $self->{newer_than} ) {
			next;
		}

		if ( defined( $self->{hosts} ) && mark_hosts($mark) < $self->{hosts} ) {
			next;
		}

		return 1;
	} ## end foreach my $name (@names)

	return 0;
} ## end sub holds

1;
