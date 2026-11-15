package App::Baphomet::Gate::address;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util            qw( any );
use Ref::Util             qw( is_plain_arrayref );
use App::Baphomet::Config qw( compile_ignore_ips ip_family ip_ignored );
use App::Baphomet::Shape  qw( check_hash );

=head1 NAME

App::Baphomet::Gate::address - The address gate, judging a address by what kind it is.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - address: { var: SRC, is: bogon }
      - ban_var: [ SRC ]
      - address: { isnot: [ private, cgnat, loopback ] }

=head1 DESCRIPTION

Holds when the address checked is of one of the kinds listed, for C<is>,
or of none of them, for C<isnot>. The kinds are the ones the address space
sets aside, which no list of the operator's has to name... a source of one
that should never appear on the internet is spoofed traffic, and one of a
network the host can not see past is no attacker it can banish.

A value that is not a address fails closed whichever way the gate asks.

The kinds...

    - private :: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and fc00::/7.

    - loopback :: 127.0.0.0/8 and ::1.

    - link_local :: 169.254.0.0/16 and fe80::/10.

    - cgnat :: 100.64.0.0/10, a carrier's shared space.

    - documentation :: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, and
          2001:db8::/32.

    - multicast :: 224.0.0.0/4 and ff00::/8.

    - bogon :: Any address no one on the internet can have... all of the
          above, and 0.0.0.0/8, 192.0.0.0/24, 198.18.0.0/15, 240.0.0.0/4,
          and ::/128.

A entry is told...

    - is / isnot :: Exactly one. A kind, or a array of them.

    - var :: Optional. The found var holding the address. With out it the
          offender is checked.

=cut

# the networks each kind is, as the IANA special purpose registries have them
my %KIND_NETWORKS = (
	'private'       => [ '10.0.0.0/8',     '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7' ],
	'loopback'      => [ '127.0.0.0/8',    '::1/128' ],
	'link_local'    => [ '169.254.0.0/16', 'fe80::/10' ],
	'cgnat'         => ['100.64.0.0/10'],
	'documentation' => [ '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32' ],
	'multicast'     => [ '224.0.0.0/4',  'ff00::/8' ],
);
$KIND_NETWORKS{bogon} = [
	( map { @{ $KIND_NETWORKS{$_} } } sort( keys(%KIND_NETWORKS) ) ),
	'0.0.0.0/8', '192.0.0.0/24', '198.18.0.0/15', '240.0.0.0/4', '::/128',
];

# each kind compiled once, for every gate to share
my %KIND_SETS = map { $_ => compile_ignore_ips( $KIND_NETWORKS{$_}, 'the ' . $_ . ' kind' ) } keys(%KIND_NETWORKS);

my $KINDS = {
	'each'   => { 'in' => [ sort( keys(%KIND_NETWORKS) ) ] },
	'min'    => 1,
	'or_one' => 1,
	'says'   => 'one of ' . join( ', ', sort( keys(%KIND_NETWORKS) ) ) . ', or a non-empty array of them',
};

my $SHAPE = {
	'optional' => { 'is' => $KINDS, 'isnot' => $KINDS, 'var' => 'string' },
	'one_of'   => [ [ 'is', 'isnot' ] ],
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps the mode, the kinds as a list however
they were written, and the var.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{mode} = defined( $args->{is} ) ? 'is' : 'isnot';
	my $kinds = $args->{ $self->{mode} };
	$self->{kinds} = is_plain_arrayref($kinds) ? [ @{$kinds} ] : [$kinds];
	$self->{var}   = $args->{var};

	return;
} ## end sub compile

=head2 holds

Returns 1 when the address checked is of a listed kind for C<is>, or of none
of them for C<isnot>, else 0. The address is the value of the gate's var, or
the offender with out one.

    if ( $gate->holds( $data, $ip ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip ) = @_;

	my $address = defined( $self->{var} ) ? $data->{ $self->{var} } : $ip;
	if ( !defined($address) || !defined( ip_family($address) ) ) {
		return 0;
	}

	my $of_a_kind = any { ip_ignored( $KIND_SETS{$_}, $address ) } @{ $self->{kinds} };

	return ( $of_a_kind ? 1 : 0 ) == ( $self->{mode} eq 'is' ? 1 : 0 ) ? 1 : 0;
} ## end sub holds

1;
