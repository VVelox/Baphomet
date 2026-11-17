package App::Baphomet::Gate::network;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Config qw( ip_family ip_network );
use App::Baphomet::Shape  qw( check_hash );

=head1 NAME

App::Baphomet::Gate::network - The network gate, lifting the network a address is in into a found var.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - network: { var: SRC, into: NET }
      - after: { by: NET, count: 30, seconds: 600 }
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Lifts the network a address is in, as a C<address/prefix> CIDR, into a
found var, for what is below the gate and the counting to read. It judges
nothing and vetoes nothing. A attack that comes from a address after
another out of the one provider stays under every count kept by address,
and is one key once it is counted by its network.

A value that is not a address lifts nothing, and what reads the var then
fails closed on its own. It is never lifted over a value the offense
already has.

A entry is told...

    - var :: The found var holding the address.

    - into :: The found var the network is lifted into.

    - v4 :: Optional. The prefix length a IPv4 address is cut to.
        Default :: 24

    - v6 :: Optional. The prefix length a IPv6 address is cut to.
        Default :: 64

=cut

# a prefix length within what the family has bits for
my $V4_PREFIX = {
	'test' => sub { return ( $_[0] // '' ) =~ /^[0-9]+$/ && $_[0] >= 1 && $_[0] <= 32; },
	'says' => 'a prefix length of 1 to 32'
};
my $V6_PREFIX = {
	'test' => sub { return ( $_[0] // '' ) =~ /^[0-9]+$/ && $_[0] >= 1 && $_[0] <= 128; },
	'says' => 'a prefix length of 1 to 128'
};

my $SHAPE = {
	'required' => { 'var' => 'string',   'into' => 'string' },
	'optional' => { 'v4'  => $V4_PREFIX, 'v6'   => $V6_PREFIX },
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it with the defaults filled in.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{var}    = $args->{var};
	$self->{into}   = $args->{into};
	$self->{prefix} = { 'v4' => $args->{v4} // 24, 'v6' => $args->{v6} // 64 };

	return;
} ## end sub compile

=head2 holds

Writes the network of the address in the gate's var into its C<into> of the
passed data, unless the data already has one or the value is no address.
Always returns 1.

    $gate->holds($data);

=cut

sub holds {
	my ( $self, $data ) = @_;

	my $address = $data->{ $self->{var} };
	my $family  = defined($address) ? ip_family($address) : undef;
	if ( defined($family) && !exists( $data->{ $self->{into} } ) ) {
		my $network = ip_network( $address, $self->{prefix}{$family} );
		if ( defined($network) ) {
			$data->{ $self->{into} } = $network;
		}
	}

	return 1;
} ## end sub holds

1;
