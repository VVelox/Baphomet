package App::Baphomet::Gate::NotMarked;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape qw( check_hash );
use App::Baphomet::Marks qw( mark_key live_mark value_verdict );

=head1 NAME

App::Baphomet::Gate::NotMarked - The not_marked gate, sparing what already has a brand.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - not_marked: { name: cleared, vars: [ SRC, USER ] }
      - not_marked: { name: known_good }

=head1 DESCRIPTION

Holds unless the key checked has a live brand of the name. A key with
nothing to look up holds, there being no brand to veto on. With a value
compare the veto narrows to a brand of that value... one whose stored value
provably differs for C<value_is>, or agrees for C<value_not>, is spared,
while a compare with either side missing still vetoes.

A entry is told...

    - name :: The brand that vetoes.

    - var / vars :: Optional, and never both. The found var the key is the
          value of, or the vars whose values joined are the key. With out
          either the key is the offender.

    - value_is / value_not :: Optional, and never both. The found var the
          brand's stored value has to equal, or has to differ from, for the
          brand to veto.

It needs the C<marks> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

my $SHAPE = {
	'required' => { 'name' => 'name' },
	'optional' => { 'var'  => 'string', 'vars' => 'strings', 'value_is' => 'string', 'value_not' => 'string' },
	'not_both' => [ [ 'var', 'vars' ], [ 'value_is', 'value_not' ] ],
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

Returns 0 when the key has a live brand that vetoes, else 1.

    if ( $gate->holds( $data, $ip, $now ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip, $now ) = @_;

	my $key = mark_key( $self, $data, $ip );
	if ( !defined($key) ) {
		return 1;
	}

	my $mark = live_mark( $self->{context}{marks}->(), $self->{name}, $key, $now );
	if ( defined($mark) && value_verdict( $self, $mark, $data ) ne 'fails' ) {
		return 0;
	}

	return 1;
} ## end sub holds

1;
