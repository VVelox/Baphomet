package App::Baphomet::Gate::forgive;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Gate  qw( settle_offenders );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::forgive - The forgive gate, clearing what other rules have counted against a address.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - forgive: { rules: syslog/sshd, var: PEER }
      - ban_var: [ SRC ]
      - forgive: { rules: [ syslog/sshd, syslog/sshd-ddos ], same: USER }

=head1 DESCRIPTION

Takes back the hits the named rules have counted against a address, so a
login that worked clears the failures before it and its owner is not one
typo from a ban for the rest of the C<find_time>. It vetoes nothing.

With a C<same> only the hits that were about the same account are taken
back, so one login that worked does not wash the guesses a address made at
every other account. What a hit was about is the value of the C<user_var>
of the rule that counted it, and a hit of a rule with none is about nobody
and is left.

Only the running counts are touched. A ban already made stands, as do the
subnet counts and what a C<distinct> rule has seen.

A entry is told...

    - rules :: The rule whose hits are taken back, or a array of them,
          named as a watcher names them.

    - var :: Optional. The found var holding the address to forgive. With
          out it each offender is forgiven.

    - same :: Optional. The found var holding the account the hits have to
          have been about. A offense lacking it forgives nothing.

It needs the C<forgive> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

my $SHAPE = {
	'required' => {
		'rules' => {
			# spelled as App::Baphomet::Rules::is_rule_name has a rule name, said
			# again here as that module is built on the gates and can not be
			# loaded by one
			'each'   => { 'match' => qr/^[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+)+\z/ },
			'min'    => 1,
			'or_one' => 1,
			'says'   => 'a rule name or a non-empty array of them',
		},
	},
	'optional' => { 'var' => 'string', 'same' => 'string' },
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, the rules as a set however they
were written.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	my @rules = is_plain_arrayref( $args->{rules} ) ? @{ $args->{rules} } : ( $args->{rules} );
	$self->{rules} = { map { $_ => 1 } @rules };
	$self->{var}   = $args->{var};
	$self->{same}  = $args->{same};

	return;
} ## end sub compile

=head2 needs

Returns C<forgive>.

=cut

sub needs {
	return ('forgive');
}

=head2 ask

Has the hits of the gate's rules taken back for the address in its var, or
with out one for each offender. Always returns 1.

    $gate->ask($offense);

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $data = $offense->{data};

	# a account that can not be named can not be said to be the same one
	my $account;
	if ( defined( $self->{same} ) ) {
		$account = $data->{ $self->{same} };
		if ( !defined($account) || $account eq '' ) {
			return 1;
		}
	}

	my @addresses = defined( $self->{var} ) ? ( $data->{ $self->{var} } ) : @{ settle_offenders($offense) };
	foreach my $address ( grep { defined($_) } @addresses ) {
		$self->{context}{forgive}->( $address, $self->{rules}, $account );
	}

	return 1;
} ## end sub ask

1;
