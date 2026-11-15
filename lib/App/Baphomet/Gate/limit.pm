package App::Baphomet::Gate::limit;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Marks qw( bound_expiring_store );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::limit - The limit gate, letting only so many offenses of a key by in a window.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - detection_var: [ SRC ]
      - limit: { by: [ SRC, USER ], count: 3, seconds: 300 }

=head1 DESCRIPTION

Lets the first C<count> offenses of a key by and vetoes the rest, until
C<seconds> have passed since the first of them. It is for a rule that
sights more than it needs to say, one noisy source filling the EVE log
with the same event.

A offense it vetoes is vetoed as by any gate, so the line is not consumed
and goes on to the rules after this one. Gates above it have had their
turn by then, so a C<mark> above it brands every offense and one below it
only what was let by.

The windows are kept by the scope the offense is of, a watcher, and are
forgotten at a restart. A offense lacking one of the C<by> vars has
nothing to be held to and is let by.

A entry is told...

    - by :: The found var, or a array of them, whose values joined are the
          key.

    - seconds :: The length of the window.

    - count :: Optional. How many offenses of a key a window lets by.
        Default :: 1

=cut

my $SHAPE = {
	'required' => { 'by'    => 'string_or_strings', 'seconds' => 'seconds' },
	'optional' => { 'count' => 'positive_int' },
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, the C<by> as a list however it
was written, with a empty store of windows.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{by}      = is_plain_arrayref( $args->{by} ) ? [ @{ $args->{by} } ] : [ $args->{by} ];
	$self->{seconds} = $args->{seconds};
	$self->{count}   = $args->{count} // 1;

	# the windows open, by scope and then by key, each a hash of the count
	# let by so far and when it expires
	$self->{windows} = {};

	return;
} ## end sub compile

=head2 reads_offenders

Returns 0. It keys on the found vars it names and never on the offenders.

=cut

sub reads_offenders {
	return 0;
}

=head2 sweep_state

Drops the windows that have run out as of the passed time.

    $gate->sweep_state($now);

=cut

sub sweep_state {
	my ( $self, $now ) = @_;

	my $windows = $self->{windows};
	foreach my $scope ( keys( %{$windows} ) ) {
		foreach my $key ( keys( %{ $windows->{$scope} } ) ) {
			if ( $windows->{$scope}{$key}{expires} <= $now ) {
				delete( $windows->{$scope}{$key} );
			}
		}
		if ( !%{ $windows->{$scope} } ) {
			delete( $windows->{$scope} );
		}
	} ## end foreach my $scope ( keys( %{$windows} ) )

	return;
} ## end sub sweep_state

=head2 ask

Counts the offense into the window of its key, opening one when there is
none or the last has run out. Returns 0 for a offense past what the window
lets by, else 1.

    if ( !$gate->ask($offense) ) { ... }

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $key = $self->_key_of($offense);
	if ( !defined($key) ) {
		return 1;
	}
	my $now = $offense->{now};

	my $store  = $self->{windows}{ $offense->{scope} // '' } //= {};
	my $window = $store->{$key};
	if ( !defined($window) || $window->{expires} <= $now ) {
		# bounded the way the mark store is, so a flood of keys can not grow
		# it with out limit
		bound_expiring_store( $store, $key, $now );
		$store->{$key} = { 'count' => 1, 'expires' => $now + $self->{seconds} };
		return 1;
	}
	if ( $window->{count} < $self->{count} ) {
		$window->{count}++;
		return 1;
	}

	return 0;
} ## end sub ask

# the key a offense is held to, the values of the gate's by vars joined on
# the unit separator, as a mark's vars are. the after gate, which is kept by
# the same key, asks it too.
#
# args:
#   $offense :: the offense, of which the found data is read
#
# returns the key, or undef when the offense lacks one of the vars, a part
# missing being no key at all and never a partial one.
#
#   my $key = $self->_key_of($offense);    # "203.0.113.9\x1fneti"
sub _key_of {
	my ( $self, $offense ) = @_;

	my @parts;
	foreach my $var ( @{ $self->{by} } ) {
		my $value = $offense->{data}{$var};
		if ( !defined($value) ) {
			return undef;
		}
		push( @parts, $value );
	}

	return join( "\x1f", @parts );
} ## end sub _key_of

1;
