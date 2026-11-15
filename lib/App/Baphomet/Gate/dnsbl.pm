package App::Baphomet::Gate::dnsbl;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util            qw( any );
use Ref::Util             qw( is_plain_arrayref );
use Socket                qw( AF_INET AF_INET6 inet_pton );
use App::Baphomet::Config qw( ip_family );
use App::Baphomet::Shape  qw( check_hash );

our @EXPORT_OK = qw( dnsbl_query_name );

=head1 NAME

App::Baphomet::Gate::dnsbl - The dnsbl gate, asking a DNS blocklist of a address.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - dnsbl: { zones: bl.example.org, var: PEER }
      - ban_var: [ SRC ]
      - dnsbl: { zones: [ bl.example.org, dnsbl.example.net ], codes: [ 127.0.0.2, 127.0.0.4 ] }

=head1 DESCRIPTION

Holds when any of the zones lists the address checked. A zone lists a
address by answering the lookup of it with a address of its own out of
C<127.0.0.0/8>, which of them saying why.

A zone that could not be asked can not clear anyone, so with no zone
listing the address a failed lookup settles the gate by C<on_servfail>,
whether or not C<negate> is set. Two kinds of answer are taken as a failed
lookup and never as a listing... one out of C<127.255.255.0/24>, which is
how a zone says it refused the query, and one that is not out of
C<127.0.0.0/8> at all, which is what a zone that has been parked or
hijacked gives.

It fails closed with nothing to ask with and on a value that is not a
address. A address the context says is one of the operator's own is never
asked about, and is taken as on no list.

Every lookup tells whoever runs the zone which address was seen, so the
galla only asks with the operator's consent.

A entry is told...

    - zones :: The zone to ask, or a array of them.

    - var :: Optional. The found var holding the address to check. With out
          it the offender is checked.

    - codes :: Optional. The answer, or a array of them, that counts as a
          listing. With out it any answer a zone lists with does.

    - negate :: Optional. True to hold when no zone lists the address.

    - on_servfail :: Optional. What a lookup that failed does when no zone
          lists the address, C<pass> or C<fail>.
        Default :: fail

It needs the C<dnsbl> of the L<context|App::Baphomet::Gate/THE CONTEXT>, and
uses its C<internal> when it is there.

=cut

# a zone is a host name, and a code one of the addresses a zone answers with
my $ZONES = {
	'each' => {
		'match' =>
			qr/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+$/
	},
	'min'    => 1,
	'or_one' => 1,
	'says'   => 'a zone name or a non-empty array of them',
};
my $CODES = {
	'each'   => { 'match' => qr/^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/ },
	'min'    => 1,
	'or_one' => 1,
	'says'   => 'a address out of 127.0.0.0/8 or a non-empty array of them',
};

my $SHAPE = {
	'required' => { 'zones' => $ZONES },
	'optional' => {
		'var'         => 'string',
		'codes'       => $CODES,
		'negate'      => 'any',
		'on_servfail' => { 'in' => [qw( pass fail )], 'says' => 'one of pass or fail' },
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it with the defaults filled in, the
zones as a list however they were written and the codes as a set.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{zones}       = is_plain_arrayref( $args->{zones} ) ? [ @{ $args->{zones} } ] : [ $args->{zones} ];
	$self->{var}         = $args->{var};
	$self->{negate}      = $args->{negate} ? 1 : 0;
	$self->{on_servfail} = $args->{on_servfail} // 'fail';
	if ( defined( $args->{codes} ) ) {
		my @codes = is_plain_arrayref( $args->{codes} ) ? @{ $args->{codes} } : ( $args->{codes} );
		$self->{codes} = { map { $_ => 1 } @codes };
	}

	return;
} ## end sub compile

=head2 needs

Returns C<dnsbl>.

=cut

sub needs {
	return ('dnsbl');
}

=head2 wants

Returns C<internal>.

=cut

sub wants {
	return ('internal');
}

=head2 holds

Returns 1 when the address checked passes the gate, else 0. The address is
the value of the gate's var, or the offender with out one.

    if ( $gate->holds( $data, $ip ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip ) = @_;

	my $address = defined( $self->{var} ) ? $data->{ $self->{var} } : $ip;
	my $asker   = $self->{context}{dnsbl}->();
	if ( !defined($address) || !defined($asker) || !defined( ip_family($address) ) ) {
		return 0;
	}

	# one of the operator's own is nobody else's to be told of
	my $internal = $self->{context}{internal};
	my @zones    = ( defined($internal) && $internal->($address) ) ? () : @{ $self->{zones} };

	my $listed = 0;
	my $failed = 0;
	foreach my $zone (@zones) {
		my $answers = $asker->( $zone, $address );

		# a refusal, or a answer no blocklist gives, is a zone that could not
		# be asked
		if ( !defined($answers) || any { $_ !~ /^127\./ || $_ =~ /^127\.255\.255\./ } @{$answers} ) {
			$failed = 1;
			next;
		}

		my @counted = defined( $self->{codes} ) ? ( grep { $self->{codes}{$_} } @{$answers} ) : @{$answers};
		if (@counted) {
			$listed = 1;
			last;
		}
	} ## end foreach my $zone (@zones)

	# a listing stands whatever else failed, and with out one a zone that
	# could not be asked leaves the address uncleared
	if ( !$listed && $failed ) {
		return $self->{on_servfail} eq 'pass' ? 1 : 0;
	}

	return $listed == $self->{negate} ? 0 : 1;
} ## end sub holds

=head1 FUNCTIONS

=head2 dnsbl_query_name

Returns the name a zone is asked about a address by... the address's octets
reversed for IPv4, its 32 nibbles reversed for IPv6, each a label ahead of
the zone. Returns undef for a value that is not a address.

    my $name = dnsbl_query_name( '192.0.2.7', 'bl.example.org' );      # 7.2.0.192.bl.example.org
    my $name = dnsbl_query_name( '2001:db8::1', 'bl.example.org' );    # 1.0.0.0. ... .8.b.d.0.1.0.0.2.bl.example.org

=cut

sub dnsbl_query_name {
	my ( $address, $zone ) = @_;

	my $packed = inet_pton( AF_INET, $address );
	if ( defined($packed) ) {
		return join( '.', reverse( unpack( 'C4', $packed ) ), $zone );
	}

	$packed = inet_pton( AF_INET6, $address );
	if ( defined($packed) ) {
		return join( '.', reverse( split( //, unpack( 'H32', $packed ) ) ), $zone );
	}

	return undef;
} ## end sub dnsbl_query_name

1;
