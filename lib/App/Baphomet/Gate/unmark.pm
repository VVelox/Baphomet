package App::Baphomet::Gate::unmark;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Gate  qw( settle_offenders );
use App::Baphomet::Shape qw( check_hash );
use App::Baphomet::Marks qw( mark_key mark_unset );

=head1 NAME

App::Baphomet::Gate::unmark - The unmark gate, lifting a brand from what a offense names.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - ban_var: [ SRC ]
      - unmark: { name: suspect }
      - unmark: { name: sshd-account-src, var: USER }

=head1 DESCRIPTION

Lifts a named brand, a successful login lifting a suspicion, say. It vetoes
nothing, and a key that has no such brand lifts nothing.

A entry is told...

    - name :: The brand to lift.

    - var / vars :: Optional, and never both. The found var the key is the
          value of, or the vars whose values joined are the key. With out
          either the brand is lifted from each offender, less any the context
          says may not be branded.

It needs the C<marks> of the L<context|App::Baphomet::Gate/THE CONTEXT>, and
uses its C<brandable> and C<on_unset> when they are there.

=cut

my $SHAPE = {
	'required' => { 'name' => 'name' },
	'optional' => { 'var'  => 'string', 'vars' => 'strings' },
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
yet, and so lift nothing.

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

Returns 0. One naming no var lifts from the offenders, but a offense with
none simply lifts nothing, so it is not refused where there are none.

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

Returns C<brandable> and C<on_unset>.

=cut

sub wants {
	return ( 'brandable', 'on_unset' );
}

=head2 ask

Lifts the brand from each key the offense gives it, noting each lift on the
offense's C<lifted>. Always returns 1.

    $gate->ask($offense);

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $context = $self->{context};

	my @keys;
	if ( defined( $self->{var} ) || defined( $self->{vars} ) ) {
		my $key = mark_key( $self, $offense->{data}, undef );
		if ( defined($key) ) {
			@keys = ($key);
		}
	} else {
		@keys = @{ settle_offenders($offense) };
		if ( defined( $context->{brandable} ) ) {
			@keys = grep { $context->{brandable}->($_) } @keys;
		}
	}

	foreach my $key (@keys) {
		if ( mark_unset( $context->{marks}->(), $self->{name}, $key, $context->{on_unset} ) ) {
			push( @{ $offense->{lifted} }, { 'name' => $self->{name}, 'key' => $key } );
		}
	}

	return 1;
} ## end sub ask

1;
