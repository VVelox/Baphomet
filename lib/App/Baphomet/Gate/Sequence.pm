package App::Baphomet::Gate::Sequence;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Shape qw( check_hash );
use App::Baphomet::Marks qw( mark_key live_mark );

=head1 NAME

App::Baphomet::Gate::Sequence - The sequence gate, counting only what was branded in a order.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - sequence: { marks: [ recon, exploit, exfil ], var: SRC }

=head1 DESCRIPTION

Ordered temporal correlation. Holds when every named brand is live for the
key checked and their first-seen times do not decrease in the order listed,
so "a then b then c" only holds when a was set no later than b and b no
later than c. A key with nothing to look up fails.

A entry is told...

    - marks :: A array of at least two brands, in the order they have to
          have been set.

    - var / vars :: Optional, and never both. The found var the key is the
          value of, or the vars whose values joined are the key. With out
          either the key is the offender.

It needs the C<marks> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

my $SHAPE = {
	'required' => {
		'marks' => { 'each' => 'name', 'min' => 2, 'says' => 'a array of at least two mark names' },
	},
	'optional' => { 'var' => 'string', 'vars' => 'strings' },
	'not_both' => [ [ 'var', 'vars' ] ],
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

Returns 1 when every brand of the gate is live for the key and they were set
in the order listed, else 0.

    if ( $gate->holds( $data, $ip, $now ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip, $now ) = @_;

	my $key = mark_key( $self, $data, $ip );
	if ( !defined($key) ) {
		return 0;
	}

	my $store = $self->{context}{marks}->();
	my $prev_set;
	foreach my $mark_name ( @{ $self->{marks} } ) {
		my $mark = live_mark( $store, $mark_name, $key, $now );
		if ( !defined($mark) ) {
			return 0;
		}
		my $set = $mark->{set};
		# order only enforced between marks that both have a set time... a
		# mark from before set times existed simply is not ordered against
		if ( defined($set) && defined($prev_set) && $set < $prev_set ) {
			return 0;
		}
		if ( defined($set) ) {
			$prev_set = $set;
		}
	} ## end foreach my $mark_name ( @{ $self->{marks} } )

	return 1;
} ## end sub holds

1;
