package App::Baphomet::Gate::account;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util            qw( is_plain_arrayref is_plain_hashref );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::account - The account gate, telling a real account from a name that is nobody's.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - account: { var: USER, exists: false }
      - account: { var: USER, shell: nologin }
      - account: { var: USER, group: [ wheel, operator ] }
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Holds when the name checked is, or is not, a account of the host the galla
runs on, and when told to ask more of it, when the account is of the kind
asked for. A failed login for a name that is nobody's is a guess, and one
for a real account may be its owner's typo, which most daemons log the same.
One for a account that can not log in at all is a guess as sure as the
first, and one for a administrator's is worth more than another's.

The accounts are the galla's own host's, so the gate only means something
over logs that host wrote. A name the offense lacks fails closed whichever
way the gate asks, and so does a account of which what is asked is not
known.

A entry is told...

    - var :: The found var holding the name to check.

    - exists :: Optional. False to hold on a name that is no account, which
          nothing more can then be asked of. With out it, or true, the gate
          holds on one that is.

    - shell :: Optional. C<nologin> to hold on a account that can not log
          in, its shell being C<nologin> or C<false>, or C<login> to hold
          on one that can.

    - system :: Optional. True to hold on a account the system has for
          itself, its uid being below C<system_below>, or false to hold on
          one a person was given. The uid of root is below any, so it is
          one of the system's.

    - system_below :: Optional. The uid the accounts of people start at.
        Default :: 1000

    - group :: Optional. A group, or a array of them, the account has to be
          in one of, as its own group or as one listing it.

    - near :: Optional, and only beside a C<exists> of false. How many
          letters a name that is no account may be off from one that is,
          a letter added, dropped, or changed each being one, for the gate
          to hold on it... the owner of C<neti> typing C<netti>, where
          C<oracle> is a guess.

Everything asked has to be so for the gate to hold.

It needs the C<accounts> of the L<context|App::Baphomet::Gate/THE CONTEXT>,
with a C<group> the C<groups> of it too, and with a C<near> its
C<account_names>.

=cut

my $SHAPE = {
	'required' => { 'var' => 'string' },
	'optional' => {
		'exists'       => 'any',
		'shell'        => { 'in' => [qw( nologin login )], 'says' => 'one of nologin or login' },
		'system'       => 'any',
		'system_below' => 'positive_int',
		'group'        => 'string_or_strings',
		'near'         => 'positive_int',
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, the groups as a list however they
were written. Dies on one told to hold on the lack of a account and to ask
something of it as well.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{var} = $args->{var};

	# it holds on a real account unless told outright to hold on the lack of
	# one
	$self->{exists} = ( defined( $args->{exists} ) && !$args->{exists} ) ? 0 : 1;

	$self->{shell}        = $args->{shell};
	$self->{system_below} = $args->{system_below} // 1000;
	if ( defined( $args->{system} ) ) {
		$self->{system} = $args->{system} ? 1 : 0;
	}
	if ( defined( $args->{group} ) ) {
		$self->{groups} = is_plain_arrayref( $args->{group} ) ? [ @{ $args->{group} } ] : [ $args->{group} ];
	}

	$self->{near} = $args->{near};
	if ( defined( $self->{near} ) && $self->{exists} ) {
		die( $where . ' has a near with out a exists of false, a name near a account being one that is none' );
	}

	my @asked = grep { defined( $args->{$_} ) } qw( shell system group );
	if ( !$self->{exists} && @asked ) {
		die(      $where
				. ' has a exists of false and a '
				. $asked[0]
				. ', and nothing can be asked of a account that is none' );
	}

	return;
} ## end sub compile

=head2 needs

Returns C<accounts>, and C<groups> as well for a gate told a group and
C<account_names> for one told a near.

=cut

sub needs {
	my ($self) = @_;

	return (
		'accounts',
		defined( $self->{groups} ) ? ('groups')        : (),
		defined( $self->{near} )   ? ('account_names') : (),
	);
}

=head2 holds

Returns 1 when the name in the gate's var is a account or not, as the gate
asks, and the account is all else it asks, else 0. Returns 0 on a name the
data lacks or holds empty.

    if ( $gate->holds($data) ) { ... }

=cut

sub holds {
	my ( $self, $data ) = @_;

	my $name = $data->{ $self->{var} };
	if ( !defined($name) || $name eq '' ) {
		return 0;
	}

	my $account = $self->{context}{accounts}->($name);
	if ( !$self->{exists} ) {
		if ($account) {
			return 0;
		}
		if ( !defined( $self->{near} ) ) {
			return 1;
		}
		foreach my $account_name ( @{ $self->{context}{account_names}->() } ) {
			if ( _within_edits( $name, $account_name, $self->{near} ) ) {
				return 1;
			}
		}
		return 0;
	} ## end if ( !$self->{exists} )
	if ( !$account ) {
		return 0;
	}

	# a answer that only says there is one has nothing more to be asked of
	my $known = is_plain_hashref($account) ? $account : {};

	if ( defined( $self->{shell} ) ) {
		if ( !defined( $known->{shell} ) ) {
			return 0;
		}

		# no shell at all is the system's default one, which is a login
		my $can_login = $known->{shell} =~ m{(?:^|/)(?:nologin|false)$} ? 0 : 1;
		if ( $can_login != ( $self->{shell} eq 'login' ? 1 : 0 ) ) {
			return 0;
		}
	} ## end if ( defined( $self->{shell} ) )

	if ( defined( $self->{system} ) ) {
		if ( !defined( $known->{uid} ) ) {
			return 0;
		}
		my $is_system = $known->{uid} < $self->{system_below} ? 1 : 0;
		if ( $is_system != $self->{system} ) {
			return 0;
		}
	}

	my $in_a_group = defined( $self->{groups} ) ? 0 : 1;
	foreach my $group_name ( @{ $self->{groups} // [] } ) {
		my $group = $self->{context}{groups}->($group_name);
		if ( !defined($group) ) {
			next;
		}

		# a account is in the group that is its own with out being listed
		my $its_own = defined( $group->{gid} ) && defined( $known->{gid} ) && $group->{gid} == $known->{gid};
		if ( $group->{members}{$name} || $its_own ) {
			$in_a_group = 1;
			last;
		}
	} ## end foreach my $group_name ( @{ $self->{groups} // ...})

	return $in_a_group;
} ## end sub holds

# whether one name can be made of another by at most so many letters added,
# dropped, or changed. a name that is the other exactly is not with in any,
# as it is no typo of it.
#
# args:
#   $typed :: the name that was typed
#   $real  :: the account name it is measured against
#   $edits :: the most letters it may be off by, one or more
#
# returns 1 when it is with in that many, else 0.
#
#   _within_edits( 'netti', 'neti', 1 );    # 1
#   _within_edits( 'oracle', 'neti', 2 );   # 0
sub _within_edits {
	my ( $typed, $real, $edits ) = @_;

	if ( $typed eq $real || abs( length($typed) - length($real) ) > $edits ) {
		return 0;
	}

	# the edit distance, a row at a time, given up on once the least of a row
	# is past what is allowed, as the rest can only be further
	my @typed = split( //, $typed );
	my @row   = ( 0 .. scalar(@typed) );
	foreach my $real_int ( 1 .. length($real) ) {
		my $real_letter = substr( $real, $real_int - 1, 1 );
		my @next        = ($real_int);
		foreach my $typed_int ( 1 .. scalar(@typed) ) {
			my $changed = $row[ $typed_int - 1 ] + ( $typed[ $typed_int - 1 ] eq $real_letter ? 0 : 1 );
			my $dropped = $row[$typed_int] + 1;
			my $added   = $next[ $typed_int - 1 ] + 1;
			my $least   = $changed < $dropped ? $changed : $dropped;
			push( @next, $least < $added ? $least : $added );
		}
		@row = @next;
		my $row_least = ( sort { $a <=> $b } @row )[0];
		if ( $row_least > $edits ) {
			return 0;
		}
	} ## end foreach my $real_int ( 1 .. length($real) )

	return $row[-1] <= $edits ? 1 : 0;
} ## end sub _within_edits

1;

