package App::Baphomet::Gate::Marked;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util           qw( any );
use App::Baphomet::Shape qw( check_hash );
use App::Baphomet::Marks qw( mark_key live_mark value_verdict );

=head1 NAME

App::Baphomet::Gate::Marked - The marked gate, counting only what already has a brand.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - marked: { name: failed_login, var: USER }
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

It needs the C<marks> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

# a entry may hold on any of a list of names in place of its one
my $SHAPE = {
	'optional' => {
		'name'      => 'name',
		'names'     => 'names',
		'var'       => 'string',
		'vars'      => 'strings',
		'value_is'  => 'string',
		'value_not' => 'string',
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
	my $held  = any {
		my $mark = live_mark( $store, $_, $key, $now );
		defined($mark) && value_verdict( $self, $mark, $data ) eq 'holds';
	} @names;

	return $held ? 1 : 0;
} ## end sub holds

1;
