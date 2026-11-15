package App::Baphomet::Gate::mark;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Gate  qw( settle_offenders );
use App::Baphomet::Shape qw( check_hash );
use App::Baphomet::Marks qw( mark_key mark_set );

=head1 NAME

App::Baphomet::Gate::mark - The mark gate, branding what a offense names.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - ban_var: [ SRC ]
      - mark: { name: brute_force, ttl: 21600 }
      - mark: { name: sshd-account-src, ttl: 3600, var: USER, value_var: SRC }

=head1 DESCRIPTION

Sets a named, expiring brand that a later rule can gate on. It vetoes
nothing. A offense a gate above it vetoed never reaches it, so only a
offense that stood is branded.

A entry is told...

    - name :: The brand to set.

    - ttl :: Its life in seconds.

    - var / vars :: Optional, and never both. The found var the key is the
          value of, or the vars whose values joined are the key. With out
          either each offender is branded, less any the context says may not
          be, and a offense with no offender brands nobody.

    - value_var :: Optional. The found var whose value is stored on the
          brand.

It needs the C<marks> of the L<context|App::Baphomet::Gate/THE CONTEXT>, and
uses its C<brandable> and C<on_set> when they are there.

=cut

# a mark name is constrained like a rule name so it rides tablets and
# commands cleanly, and vars is a compound key, several captures joined into
# one, and never beside the single var
my $SHAPE = {
	'required' => { 'name' => 'name',   'ttl'  => 'seconds' },
	'optional' => { 'var'  => 'string', 'vars' => 'strings', 'value_var' => 'string' },
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

=head2 settle

Dies when the gate names no var and nothing above it in the list names who a
offense counts against. It would be asked of a offense that has no offenders
yet, and so brand nobody.

=cut

sub settle {
	my ( $self, $gates ) = @_;

	if ( defined( $self->{var} ) || defined( $self->{vars} ) ) {
		return;
	}
	foreach my $gate ( @{$gates} ) {
		if ( $gate == $self ) {
			last;
		}
		if ( $gate->{type} eq 'ban_var' || $gate->{type} eq 'detection_var' ) {
			return;
		}
	}

	die( $self->{where} . ' keys on the offender, and no ban_var above it names one' );
} ## end sub settle

=head2 reads_offenders

Returns 0. One naming no var brands the offenders, but a offense with none
is simply not branded, so it is not refused where there are none.

=cut

sub reads_offenders {
	return 0;
}

=head2 needs

Returns C<marks>.

=cut

sub needs {
	return ('marks');
}

=head2 wants

Returns C<brandable> and C<on_set>.

=cut

sub wants {
	return ( 'brandable', 'on_set' );
}

=head2 ask

Sets the brand on each key the offense gives it, noting each on the
offense's C<set>. Always returns 1.

    $gate->ask($offense);

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $context = $self->{context};
	my $data    = $offense->{data};

	my @keys;
	if ( defined( $self->{var} ) || defined( $self->{vars} ) ) {
		my $key = mark_key( $self, $data, undef );
		if ( defined($key) ) {
			@keys = ($key);
		}
	} else {
		@keys = @{ settle_offenders($offense) };
		if ( defined( $context->{brandable} ) ) {
			@keys = grep { $context->{brandable}->($_) } @keys;
		}
	}

	my $value = defined( $self->{value_var} ) ? $data->{ $self->{value_var} } : undef;
	foreach my $key (@keys) {
		mark_set( $context->{marks}->(),
			$self->{name}, $key, $value, $self->{ttl}, $offense->{now}, $context->{on_set} );
		push( @{ $offense->{set} }, { 'name' => $self->{name}, 'key' => $key } );
	}

	return 1;
} ## end sub ask

1;
