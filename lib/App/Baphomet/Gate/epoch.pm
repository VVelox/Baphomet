package App::Baphomet::Gate::epoch;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Time::Local          qw( timegm timelocal );
use Time::Piece          ();
use App::Baphomet::Gate  qw( own_fields passage_fields );
use App::Baphomet::Shape qw( check_hash );

our @EXPORT_OK = qw( timestamp_epoch );

=head1 NAME

App::Baphomet::Gate::epoch - The epoch gate, making a number of seconds of a timestamp.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - epoch: { into: WHEN }
      - epoch: { var: started, format: '%Y-%m-%d %H:%M:%S', zone: utc }
      - epoch: { var: time, format: '%d/%b/%Y:%H:%M:%S %z', into: WHEN }
      - epoch: { into: WHEN, hour_into: HOUR, weekday_into: DAY, zone: '-05:00' }

=head1 DESCRIPTION

Reads a timestamp and makes the seconds since the epoch of it, for a gate
below it to read as a number. It judges nothing and turns no line away.

The timestamp is the value of the C<var>, a field of the line, or with out
one the line's own, as the parser found it. With out a C<into> the C<var>
is converted where it is. With one the seconds go into that field and the
C<var> is left as it was, which the line's own timestamp, not being a
field, always needs.

A timestamp that can not be read leaves the field it would have gone into
as it was, unset when it is a C<into>, and what reads it then judges that
for itself.

A entry is told...

    - var :: Optional. The field holding the timestamp. With out it the
          line's own is read.

    - into :: Optional. The field the seconds go into. With out it the
          C<var> is converted where it is.

    - format :: Optional. How the timestamp is written... a C<strptime>
          format, or one of the names below.
        Default :: auto

    - zone :: Optional. The zone of a timestamp that names none... C<local>
          for the host's own, C<utc>, or a offset as C<+02:00>. It is also
          the zone the hour and the day of the week are told in.
        Default :: local

    - hour_into / weekday_into :: Optional. The fields the hour, 0 to 23,
          and the day of the week, 0 for Sunday to 6 for Saturday as
          C<active_time> counts them, are lifted into, both in the C<zone>.
          Given either, a gate reading the line's own timestamp needs no
          C<into>.

The formats that are names...

    - auto :: Whichever of the others below reads it, then the ways the
          parsers write one... a syslog C<Jul 12 08:15:50>, a access log
          C<12/Jul/2026:08:15:50 -0500>, and the two error logs.

    - epoch / epoch_ms / epoch_us :: Seconds, milliseconds, or microseconds
          since the epoch already.

    - iso8601 :: C<2026-07-12T08:15:50>, a fraction of a second and a zone
          after it or not.

A timestamp with no year is taken as this year's, or as last year's when
that would put it more than a day ahead of the line.

=cut

my $SHAPE = {
	'optional' => {
		'var'          => 'string',
		'into'         => 'string',
		'format'       => 'string',
		'hour_into'    => 'string',
		'weekday_into' => 'string',
		'zone'         =>
			{ 'match' => qr/^(?:local|utc|[+-][0-9]{2}:?[0-9]{2})$/, 'says' => 'local, utc, or a offset as +02:00' },
	},
};

# the strptime formats auto tries, each as a parser may write a timestamp
my @AUTO_FORMATS = ( '%d/%b/%Y:%H:%M:%S %z', '%b %d %H:%M:%S', '%a %b %d %H:%M:%S %Y', '%Y/%m/%d %H:%M:%S' );

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it with the defaults filled in. Dies
on one with neither a C<var> nor a C<into>, which has nothing to convert
and nowhere to put it.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{var}    = $args->{var};
	$self->{into}   = $args->{into}   // $args->{var};
	$self->{format} = $args->{format} // 'auto';
	$self->{zone}   = $args->{zone}   // 'local';

	$self->{hour_into}    = $args->{hour_into};
	$self->{weekday_into} = $args->{weekday_into};

	my $lifts = defined( $self->{hour_into} ) || defined( $self->{weekday_into} );
	if ( !defined( $self->{into} ) && !$lifts ) {
		die( $where
				. ' has neither a var nor a into, and the line\'s own timestamp is no field to convert where it is' );
	}

	return;
} ## end sub compile

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 ask

Writes the seconds the timestamp comes to into the gate's field of the
line, and the hour and the day of the week into theirs, making the line a
field space of the rule's own when it has none. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	my $timestamp
		= defined( $self->{var} )
		? ( passage_fields($passage) // {} )->{ $self->{var} }
		: $passage->{parsed}{time};
	my $epoch = timestamp_epoch( $timestamp, $self->{format}, $self->{zone}, $passage->{now} );
	if ( !defined($epoch) ) {
		return 1;
	}

	my $fields = own_fields($passage);
	if ( !defined($fields) ) {
		$fields                  = {};
		$passage->{fields}       = $fields;
		$passage->{fields_owned} = 1;
	}
	if ( defined( $self->{into} ) ) {
		$fields->{ $self->{into} } = $epoch;
	}

	if ( defined( $self->{hour_into} ) || defined( $self->{weekday_into} ) ) {
		# the parts of the time as the zone tells it... a offset is that many
		# seconds ahead of utc
		my @parts;
		if ( $self->{zone} eq 'local' ) {
			@parts = localtime($epoch);
		} elsif ( $self->{zone} eq 'utc' ) {
			@parts = gmtime($epoch);
		} else {
			my ( $sign, $hours, $minutes ) = $self->{zone} =~ /^([+-])([0-9]{2}):?([0-9]{2})$/;
			my $offset = ( $hours * 3600 ) + ( $minutes * 60 );
			@parts = gmtime( $sign eq '+' ? $epoch + $offset : $epoch - $offset );
		}
		if ( defined( $self->{hour_into} ) ) {
			$fields->{ $self->{hour_into} } = $parts[2];
		}
		if ( defined( $self->{weekday_into} ) ) {
			$fields->{ $self->{weekday_into} } = $parts[6];
		}
	} ## end if ( defined( $self->{hour_into} ) || defined...)

	return 1;
} ## end sub ask

=head1 FUNCTIONS

=head2 timestamp_epoch

Returns the seconds since the epoch a timestamp comes to, or undef for one
that can not be read as the format has it.

    - timestamp :: The timestamp, as it was written.

    - format :: A C<strptime> format, or C<auto>, C<epoch>, C<epoch_ms>,
          C<epoch_us>, or C<iso8601>.

    - zone :: The zone of a timestamp that names none, C<local>, C<utc>, or
          a offset as C<+02:00>.

    - now :: The time a timestamp with no year is placed by.

    my $epoch = timestamp_epoch( '12/Jul/2026:08:15:50 -0500', 'auto', 'local', time );    # 1783862150

=cut

sub timestamp_epoch {
	my ( $timestamp, $format, $zone, $now ) = @_;

	if ( !defined($timestamp) || ref($timestamp) ne '' || $timestamp eq '' ) {
		return undef;
	}

	# seconds since the epoch already, in one unit or another... auto tells
	# them apart by how many digits there are
	my %unit_digits = ( 'epoch' => 1, 'epoch_ms' => 1000, 'epoch_us' => 1_000_000 );
	if ( defined( $unit_digits{$format} ) ) {
		return $timestamp =~ /^[0-9]+(?:\.[0-9]+)?$/ ? int( $timestamp / $unit_digits{$format} ) : undef;
	}
	if ( $format eq 'auto' && $timestamp =~ /^([0-9]{9,17})(?:\.[0-9]+)?$/ ) {
		# seconds are ten digits until the year 2286, milliseconds thirteen,
		# and microseconds sixteen
		my $whole_digits = length($1);
		my $unit         = 1;
		if ( $whole_digits >= 15 ) {
			$unit = 1_000_000;
		} elsif ( $whole_digits >= 12 ) {
			$unit = 1000;
		}
		return int( $timestamp / $unit );
	} ## end if ( $format eq 'auto' && $timestamp =~ /^([0-9]{9,17})(?:\.[0-9]+)?$/)

	if ( $format eq 'iso8601' || $format eq 'auto' ) {
		if ( $timestamp
			=~ /^([0-9]{4})-([0-9]{2})-([0-9]{2})[T ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:[.,][0-9]+)?\s*(Z|[+-][0-9]{2}:?[0-9]{2})?$/
			)
		{
			my $named_zone = defined($7) ? ( $7 eq 'Z' ? 'utc' : $7 ) : $zone;
			return _zoned_epoch( [ $6, $5, $4, $3, $2 - 1, $1 ], $named_zone );
		}
		if ( $format eq 'iso8601' ) {
			return undef;
		}
	} ## end if ( $format eq 'iso8601' || $format eq 'auto')

	# runs of blanks as one, as a syslog day under ten is padded with a second,
	# and any fraction of a second off, which strptime has no way to read
	my $written = $timestamp =~ s/\s+/ /gr =~ s/(:[0-9]{2})[.,][0-9]+/$1/r;

	foreach my $try ( $format eq 'auto' ? @AUTO_FORMATS : ($format) ) {
		# a timestamp that is not as the format has it dies or warns
		my $parsed = eval {
			local $SIG{__WARN__} = sub { die( $_[0] ); };
			Time::Piece->strptime( $written, $try );
		};
		if ( !defined($parsed) ) {
			next;
		}

		# a format with its own zone has said which instant it is
		if ( $try =~ /%[zZs]/ ) {
			return $parsed->epoch;
		}

		my @broken = ( $parsed->sec, $parsed->min, $parsed->hour, $parsed->mday, $parsed->_mon, $parsed->year );
		if ( $try =~ /%[YyGgCcDFx]/ ) {
			return _zoned_epoch( \@broken, $zone );
		}

		# no year, so this one's, or the last when that is still to come
		my $this_year = ( gmtime($now) )[5] + 1900;
		foreach my $year ( $this_year, $this_year - 1 ) {
			my $epoch = _zoned_epoch( [ @broken[ 0 .. 4 ], $year ], $zone );
			if ( defined($epoch) && $epoch <= $now + 86400 ) {
				return $epoch;
			}
		}
		return undef;
	} ## end foreach my $try ( $format eq 'auto' ? @AUTO_FORMATS...)

	return undef;
} ## end sub timestamp_epoch

# the seconds since the epoch of a time broken into its parts, read in a
# zone.
#
# args:
#   $broken :: array ref of the second, minute, hour, day of the month, month
#              counted from 0, and the year whole, as timegm takes them
#   $zone   :: the zone the parts are in, 'local', 'utc', or a offset as
#              '+02:00' or '+0200'
#
# returns the seconds, or undef for parts that are no time, the 31st of
# February say.
#
#   my $epoch = _zoned_epoch( [ 50, 15, 8, 12, 6, 2026 ], '-05:00' );    # 1783862150
sub _zoned_epoch {
	my ( $broken, $zone ) = @_;

	if ( $zone eq 'local' ) {
		return eval { timelocal( @{$broken} ) };
	}

	my $epoch = eval { timegm( @{$broken} ) };
	if ( !defined($epoch) || $zone eq 'utc' ) {
		return $epoch;
	}

	# a time written a offset ahead of utc is that much earlier in it
	my ( $sign, $hours, $minutes ) = $zone =~ /^([+-])([0-9]{2}):?([0-9]{2})$/;
	my $offset = ( $hours * 3600 ) + ( $minutes * 60 );

	return $sign eq '+' ? $epoch - $offset : $epoch + $offset;
} ## end sub _zoned_epoch

1;
