package App::Baphomet::Gate::travel;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Math::Trig           qw( deg2rad great_circle_distance pip2 );
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Marks qw( live_mark mark_key mark_set );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::travel - The travel gate, holding on a key seen further away than it could have gone.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - travel: { name: last-login, by: USER, var: SRC, faster_than_kmh: 900 }
      - detection_var: [ SRC ]

=head1 DESCRIPTION

Holds when the address a key is seen at is too far from the one it was last
seen at for the time between the two. A account that logs in from one
continent and a hour later from another did not fly there.

Every offense that reaches the gate is a sighting. The place of its address
is kept as the key's last, in a brand of the gate's C<name> whose value is
the latitude, longitude, accuracy radius in kilometres, and time, so it is
kept and shared as any brand is... across the watchers of a galla, a
restart, and a fleet. The next sighting of the key is measured against it
and then takes its place, whether or not the gate held.

The distance is the great circle one, less the accuracy radius the locator
gives each of the two places, so a address placed only roughly is not held
to a point. It holds when what is left is C<min_km> or more and was covered
faster than C<faster_than_kmh>.

It does not hold on a key's first sighting, on a address the locator can
not place, which is not kept as a sighting either, or on a offense lacking
the address or part of the key.

What it is fed is the rule's to get right... a failed login from anywhere
would move where a account was last seen, so it belongs on a rule that
matches what only the owner of the key can do.

A entry is told...

    - name :: The brand the sightings are kept in.

    - by :: The found var, or a array of them, whose values joined are the
          key.

    - var :: The found var holding the address.

    - faster_than_kmh :: The speed, in kilometres a hour, it has to have
          taken more than.

    - min_km :: Optional. The least distance worth asking the speed of.
        Default :: 100

    - ttl :: Optional. Seconds a sighting is kept.
        Default :: 2592000

    - km_into / kmh_into :: Optional. The found vars the distance and the
          speed are lifted into, whole numbers both, once there is a last
          sighting to measure against. Neither is lifted over a value the
          offense already has.

It needs the C<marks> and the C<city_locator> of the
L<context|App::Baphomet::Gate/THE CONTEXT>, and uses its C<on_set> when it
is there.

=cut

# the mean radius of the earth, in kilometres
my $EARTH_KM = 6371;

my $SHAPE = {
	'required' => {
		'name'            => 'name',
		'by'              => 'string_or_strings',
		'var'             => 'string',
		'faster_than_kmh' => 'positive_number',
	},
	'optional' => {
		'min_km'   => 'positive_number',
		'ttl'      => 'seconds',
		'km_into'  => 'string',
		'kmh_into' => 'string',
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it with the defaults filled in, the
C<by> as a list however it was written.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{name}            = $args->{name};
	$self->{by}              = is_plain_arrayref( $args->{by} ) ? [ @{ $args->{by} } ] : [ $args->{by} ];
	$self->{var}             = $args->{var};
	$self->{faster_than_kmh} = $args->{faster_than_kmh};
	$self->{min_km}          = $args->{min_km} // 100;
	$self->{ttl}             = $args->{ttl}    // 2592000;
	$self->{km_into}         = $args->{km_into};
	$self->{kmh_into}        = $args->{kmh_into};

	return;
} ## end sub compile

=head2 needs

Returns C<marks> and C<city_locator>.

=cut

sub needs {
	return ( 'marks', 'city_locator' );
}

=head2 wants

Returns C<on_set>.

=cut

sub wants {
	return ('on_set');
}

=head2 holds

Keeps the place of the offense's address as its key's last sighting, and
returns 1 when the one it took the place of was too far off for the time
between them, else 0.

    if ( $gate->holds( $data, undef, $now ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip, $now ) = @_;

	my $context = $self->{context};
	my $address = $data->{ $self->{var} };
	my $key     = mark_key( { 'vars' => $self->{by} }, $data );
	my $place   = defined($address) ? $context->{city_locator}->($address) : undef;
	if ( !defined($key) || !defined($place) ) {
		return 0;
	}

	my $store = $context->{marks}->();
	my $last  = live_mark( $store, $self->{name}, $key, $now );
	mark_set( $store, $self->{name}, $key,
		sprintf( '%.4f %.4f %d %d', $place->{lat}, $place->{lon}, $place->{radius}, $now ),
		$self->{ttl}, $now, $context->{on_set} );

	# a first sighting has nothing to be measured against, and neither has a
	# brand of the name some other rule set with a value that is no sighting
	my $number = qr/-?[0-9]+(?:\.[0-9]+)?/;
	if ( !defined($last) || ( $last->{value} // '' ) !~ /^($number) ($number) ($number) ($number)$/ ) {
		return 0;
	}
	my ( $last_lat, $last_lon, $last_radius, $last_seen ) = ( $1, $2, $3, $4 );

	# great_circle_distance takes a longitude and a angle down from the pole,
	# both in radians... what is left once each place's radius is off is the
	# least the two can be apart
	my $km = great_circle_distance(
		deg2rad($last_lon),
		pip2 - deg2rad($last_lat),
		deg2rad( $place->{lon} ),
		pip2 - deg2rad( $place->{lat} ), $EARTH_KM
		)
		- $last_radius
		- $place->{radius};
	if ( $km < 0 ) {
		$km = 0;
	}

	# two sightings in the one second are a second apart, and one that came
	# in ahead of a earlier one, as lines of two logs may, is as far off
	my $seconds = abs( $now - $last_seen ) || 1;
	my $kmh     = $km / ( $seconds / 3600 );

	foreach my ( $into, $measure ) ( $self->{km_into}, $km, $self->{kmh_into}, $kmh ) {
		if ( defined($into) && !exists( $data->{$into} ) ) {
			$data->{$into} = sprintf( '%.0f', $measure );
		}
	}

	return ( $km >= $self->{min_km} && $kmh > $self->{faster_than_kmh} ) ? 1 : 0;
} ## end sub holds

1;
