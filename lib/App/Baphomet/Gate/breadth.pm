package App::Baphomet::Gate::breadth;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::breadth - The breadth gate, holding on a address many rules have counted.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - ban_var: [ SRC ]
      - breadth: { rules: 3, seconds: 3600 }

=head1 DESCRIPTION

Holds when at least C<rules> different rules have live hits against the
address checked with in the last C<seconds>, the rule this gate is of
counted among them. A scanner that tries ssh, ftp, and the web panel once
each stays under every count a rule keeps, and has been counted by three.

What it reads is the hits the galla is counting, so a hit a ban already
cleared, or one older than its rule's C<find_time>, is not there to be
read. A hit counted in observe mode is read with the rest. A hit restored
from a tablet written before the counts said which rule made them is not
any rule's. With C<of>, only the rules named are counted.

A entry is told...

    - rules :: How many different rules it takes, two or more.

    - seconds :: How far back a hit is read.

    - of :: Optional. A rule, or a array of them, the only ones whose hits
          are counted. The rule this gate is of is counted whether or not
          it is named.

    - var :: Optional. The found var holding the address. With out it the
          offender is checked.

It needs the C<rules_hit> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

my $SHAPE = {
	'required' => {
		'rules' => {
			'test' =>
				sub { return ( defined( $_[0] ) && ref( $_[0] ) eq '' && $_[0] =~ /^[0-9]+$/ && $_[0] >= 2 ) ? 1 : 0; },
			'says' => 'a int of two or more',
		},
		'seconds' => 'seconds',
	},
	'optional' => {
		'var' => 'string',
		'of'  => {
			# spelled as App::Baphomet::Rules::is_rule_name has a rule name, said
			# again here as that module is built on the gates and can not be
			# loaded by one
			'each'   => { 'match' => qr/^[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+\z/ },
			'min'    => 1,
			'or_one' => 1,
			'says'   => 'a rule name or a non-empty array of them',
		},
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, the C<of> as a set however it was
written, with the name of the rule it is of.

    $gate->compile( $args, $where, $rule );

=cut

sub compile {
	my ( $self, $args, $where, $rule ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{rules}     = $args->{rules};
	$self->{seconds}   = $args->{seconds};
	$self->{var}       = $args->{var};
	$self->{rule_name} = defined($rule) ? $rule->{name} : undef;
	if ( defined( $args->{of} ) ) {
		my @of = is_plain_arrayref( $args->{of} ) ? @{ $args->{of} } : ( $args->{of} );
		$self->{of} = { map { $_ => 1 } @of };
	}

	return;
} ## end sub compile

=head2 needs

Returns C<rules_hit>.

=cut

sub needs {
	return ('rules_hit');
}

=head2 holds

Returns 1 when enough different rules have counted the address checked, else
0. The address is the value of the gate's var, or the offender with out one.

    if ( $gate->holds( $data, $ip, $now ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip, $now ) = @_;

	my $address = defined( $self->{var} ) ? $data->{ $self->{var} } : $ip;
	if ( !defined($address) ) {
		return 0;
	}

	my %rules = map { $_ => 1 }
		grep { !defined( $self->{of} ) || $self->{of}{$_} }
		@{ $self->{context}{rules_hit}->( $address, $now - $self->{seconds} ) };

	# the hit this offense is about to be has not been counted yet
	if ( defined( $self->{rule_name} ) ) {
		$rules{ $self->{rule_name} } = 1;
	}

	return keys(%rules) >= $self->{rules} ? 1 : 0;
} ## end sub holds

1;
