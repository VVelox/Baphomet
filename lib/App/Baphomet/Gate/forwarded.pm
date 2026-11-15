package App::Baphomet::Gate::forwarded;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util             qw( is_plain_arrayref );
use App::Baphomet::Config qw( compile_ignore_ips ip_family ip_ignored );
use App::Baphomet::Shape  qw( check_hash );

=head1 NAME

App::Baphomet::Gate::forwarded - The forwarded gate, naming the real client of a proxied request.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - forwarded: { var: xff, peer: host, trusted: [ 10.0.0.0/8 ], into: CLIENT }
      - ban_var: [ CLIENT ]

=head1 DESCRIPTION

Lifts the address of the real client of a request that came through
proxies into a found var, for the C<ban_var> below it to name. Behind a
load balancer every line has the balancer's address, and banning that bans
everyone, while taking the header at its word lets whoever sent the request
write in any address they like to have banished.

So the header is only believed as far as the proxies are trusted. When the
C<peer>, the address the request came to this host from, is not a trusted
proxy, the header is ignored and the peer is the client. When it is, the
header is read from the right, each address a hop nearer the client, and
the first that is not a trusted proxy is the client. Everything to the left
of it was written by that client or before it and is never read.

The header may be a C<X-Forwarded-For> list, addresses a comma apart, or a
C<Forwarded> one, the address of each hop after a C<for=>. A address may
have a port after it, or be a IPv6 one in brackets.

It lifts nothing when it can not say... a peer that is no address, a hop
that is not one, more hops than C<max_hops>, or a chain of nothing but
trusted proxies. What reads the var then fails closed on its own, so a
C<ban_var> names nobody. It never lifts over a value the offense already
has. It judges nothing and vetoes nothing.

A entry is told...

    - var :: The found var holding the forwarding header.

    - peer :: The found var holding the address the request came from.

    - trusted :: A CIDR, or a array of them, of the proxies whose word is
          taken.

    - into :: The found var the client's address is lifted into.

    - max_hops :: Optional. The most hops read before it gives up.
        Default :: 10

=cut

my $SHAPE = {
	'required' => {
		'var'     => 'string',
		'peer'    => 'string',
		'trusted' => 'string_or_strings',
		'into'    => 'string',
	},
	'optional' => { 'max_hops' => 'positive_int' },
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it with the proxies compiled. Dies on
a C<trusted> entry that is not a address or a CIDR.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{var}      = $args->{var};
	$self->{peer}     = $args->{peer};
	$self->{into}     = $args->{into};
	$self->{max_hops} = $args->{max_hops} // 10;

	my $trusted = is_plain_arrayref( $args->{trusted} ) ? $args->{trusted} : [ $args->{trusted} ];
	$self->{trusted} = compile_ignore_ips( $trusted, $where . ' trusted' );

	return;
} ## end sub compile

=head2 pass

Returns C<result>. It reads found vars and never the offenders.

=cut

sub pass {
	return 'result';
}

=head2 holds

Writes the address of the client into the gate's C<into> of the passed data
when it can say what it is. Always returns 1.

    $gate->holds($data);

=cut

sub holds {
	my ( $self, $data ) = @_;

	if ( exists( $data->{ $self->{into} } ) ) {
		return 1;
	}
	my $client = $self->_client_of( $data->{ $self->{peer} }, $data->{ $self->{var} } );
	if ( defined($client) ) {
		$data->{ $self->{into} } = $client;
	}

	return 1;
} ## end sub holds

# the address of the real client of a request, believing the forwarding
# header only as far back as the hops in it are trusted proxies.
#
# args:
#   $peer   :: the address the request came to this host from
#   $header :: the forwarding header, a X-Forwarded-For or a Forwarded
#              list, or undef for none
#
# returns the client's address, or undef when it can not be said.
#
#   my $client = $self->_client_of( '10.0.0.5', '198.51.100.7, 10.0.0.9' );    # '198.51.100.7'
sub _client_of {
	my ( $self, $peer, $header ) = @_;

	$peer = _bare_address($peer);
	if ( !defined($peer) ) {
		return undef;
	}
	if ( !ip_ignored( $self->{trusted}, $peer ) ) {
		return $peer;
	}
	if ( !defined($header) || ref($header) ne '' ) {
		return undef;
	}

	# each hop, nearest first... a Forwarded element is ;-joined pairs, of
	# which the address is the for one
	my @hops = reverse( split( /\s*,\s*/, $header ) );
	my $read = 0;
	foreach my $hop (@hops) {
		$read++;
		if ( $read > $self->{max_hops} ) {
			return undef;
		}
		if ( $hop =~ /(?:^|;)\s*for\s*=\s*("?)([^;"]*)\1/i ) {
			$hop = $2;
		}
		my $address = _bare_address($hop);
		if ( !defined($address) ) {
			return undef;
		}
		if ( !ip_ignored( $self->{trusted}, $address ) ) {
			return $address;
		}
	} ## end foreach my $hop (@hops)

	# nothing but trusted proxies, and none of them is a client to banish
	return undef;
} ## end sub _client_of

# a address as a hop of a header may write it, with the port and the
# brackets of a IPv6 one taken off.
#
# args:
#   $written :: the address as it was written, '198.51.100.7:4711' or
#               '[2001:db8::7]:4711' say
#
# returns the address, or undef for anything that is not one.
#
#   my $address = _bare_address('[2001:db8::7]:4711');    # '2001:db8::7'
sub _bare_address {
	my ($written) = @_;

	if ( !defined($written) || ref($written) ne '' ) {
		return undef;
	}
	my $address = $written =~ s/^\s+|\s+$//gr;
	if ( $address =~ /^\[([^\]]+)\](?::[0-9]+)?$/ ) {
		$address = $1;
	} elsif ( $address =~ /^([0-9.]+):[0-9]+$/ ) {
		$address = $1;
	}

	return defined( ip_family($address) ) ? $address : undef;
} ## end sub _bare_address

1;
