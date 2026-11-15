package App::Baphomet::Gate::active_time;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::active_time - The active_time gate, counting only in, or out of, certain hours.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - active_time: { isnot: [ business ] }
      - active_time: { is: overnight, vars: [ timestamp ] }

=head1 DESCRIPTION

Holds when each time checked satisfies the gate... in one of the named
windows for C<is>, in none of them for C<isnot>. A time that is missing or
does not parse fails closed.

A entry is told...

    - is / isnot :: Exactly one. The name of a time window, or a array of
          them, out of the watcher's C<active_time>.

    - vars :: Optional. The found var or vars holding the times to check.
          With out it the time of the line is checked.

Time is a property of the line and not of a offender, so the gate is always
of the result pass, whether it names vars or not.

A time is read as a day of the week, 0 for Sunday through 6, and a HHMM, the
hour times a hundred plus the minute. One that is all digits is a epoch read
in local time, a journal's micro or milliseconds scaled down to seconds, and
anything else is a ISO 8601 datetime taken at its face-value components, the
zone it names being dropped and not converted.

It needs the C<active_time> of the
L<context|App::Baphomet::Gate/THE CONTEXT>. A window the context does not
define is fatal when the gate is bound.

=cut

my $SHAPE = {
	'optional' => { 'is' => 'name_or_names', 'isnot' => 'name_or_names', 'vars' => 'string_or_strings' },
	'one_of'   => [ [ 'is', 'isnot' ] ],
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps the mode, the window names as a list
however they were written, and the vars as a list when there are any. The
names are left unresolved, the windows they name being a watcher's.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	# a lone window or var is a list of one, so each lands as a list
	$self->{mode} = defined( $args->{is} ) ? 'is' : 'isnot';
	my $windows = $args->{ $self->{mode} };
	$self->{windows} = is_plain_arrayref($windows) ? [ @{$windows} ] : [$windows];
	if ( defined( $args->{vars} ) ) {
		$self->{vars} = is_plain_arrayref( $args->{vars} ) ? [ @{ $args->{vars} } ] : [ $args->{vars} ];
	}

	return;
} ## end sub compile

=head2 pass

Returns C<result>, always.

=cut

sub pass {
	return 'result';
}

=head2 needs

Returns C<active_time>.

=cut

sub needs {
	return ('active_time');
}

=head2 bound

Returns a copy of the gate bound over a context, its window names resolved
to the compiled specs of every window named. Dies on a window the context's
C<active_time> does not define. Windows are pure config, so the specs are
frozen once resolved.

    my $bound = $gate->bound( \%context, $where );

=cut

sub bound {
	my ( $self, $context, $where ) = @_;

	my @specs;
	foreach my $name ( @{ $self->{windows} } ) {
		my $window = $context->{active_time}{$name};
		if ( !is_plain_arrayref($window) ) {
			die( $where . ' references active_time{' . $name . '}, which is not a defined window for it' );
		}
		foreach my $spec ( @{$window} ) {
			my $days;
			if ( defined( $spec->{days} ) ) {
				$days = {};
				foreach my $day ( @{ $spec->{days} } ) {
					$days->{$day} = 1;
				}
			}
			my $ranges;
			if ( defined( $spec->{hours} ) ) {
				$ranges = [];
				my @hours = is_plain_arrayref( $spec->{hours} ) ? @{ $spec->{hours} } : ( $spec->{hours} );
				foreach my $range (@hours) {
					my ( $start, $end ) = split( /-/, $range );
					push( @{$ranges}, [ $start + 0, $end + 0 ] );
				}
			}
			push( @specs, { 'days' => $days, 'ranges' => $ranges } );
		} ## end foreach my $spec ( @{$window} )
	} ## end foreach my $name ( @{ $self->{windows} } )

	my $bound = $self->SUPER::bound( $context, $where );
	$bound->{specs} = \@specs;

	return $bound;
} ## end sub bound

# turns a time value into the day of the week and HHMM the windows are checked
# against.
#
# args:
#   $value :: the time, a all-digits epoch in seconds, milliseconds, or
#             microseconds, or a ISO 8601 datetime
#
# returns the list ( $wday, $hhmm ), or a empty list when the value does not
# parse.
#
#   my ( $wday, $hhmm ) = _time_fields('2021-01-04T10:30:00Z');    # ( 1, 1030 )
sub _time_fields {
	my ($value) = @_;

	if ( $value =~ /^[0-9]+$/ ) {
		my $epoch = $value + 0;
		while ( $epoch > 99_999_999_999 ) {
			$epoch = int( $epoch / 1000 );
		}
		my @local_time = localtime($epoch);
		return ( $local_time[6], $local_time[2] * 100 + $local_time[1] );
	}

	my $time_piece;
	eval {
		require Time::Piece;
		my $iso = $value;
		# the fraction of a second, then the zone, then the T between the
		# date and the time
		$iso =~ s/[.,][0-9]+//;
		$iso =~ s/(?:Z|[+-][0-9]{2}:?[0-9]{2})$//;
		$iso =~ s/T/ /;
		$time_piece = Time::Piece->strptime( $iso, '%Y-%m-%d %H:%M:%S' );
	};
	if ( !$@ && defined($time_piece) ) {
		return ( $time_piece->day_of_week, $time_piece->hour * 100 + $time_piece->minute );
	}

	return ();
} ## end sub _time_fields

# whether a day of the week and HHMM fall in any of a gate's compiled specs...
# a spec holds when the day is in its days set, if it has one, and the time is
# in one of its ranges, if it has any.
#
# args:
#   $specs :: arrayref of the compiled specs, each a hash of days, a hash of
#             the days of the week it holds on or undef for every day, and
#             ranges, a arrayref of [ start, end ] HHMM pairs or undef for
#             the whole day
#   $wday  :: the day of the week, 0 for Sunday through 6
#   $hhmm  :: the time of day, the hour times a hundred plus the minute
#
# returns 1 when a spec holds, else 0.
#
#   if ( _in_windows( $self->{specs}, 1, 1030 ) ) { ... }
sub _in_windows {
	my ( $specs, $wday, $hhmm ) = @_;

	foreach my $spec ( @{$specs} ) {
		if ( defined( $spec->{days} ) && !$spec->{days}{$wday} ) {
			next;
		}
		if ( defined( $spec->{ranges} ) ) {
			my $in_a_range = 0;
			foreach my $range ( @{ $spec->{ranges} } ) {
				my ( $start, $end ) = @{$range};
				# a range whose start is after its end wraps midnight, holding
				# from start to the end of the day and from midnight to end
				my $in_range;
				if ( $start <= $end ) {
					$in_range = $hhmm >= $start && $hhmm <= $end;
				} else {
					$in_range = $hhmm >= $start || $hhmm <= $end;
				}
				if ($in_range) {
					$in_a_range = 1;
					last;
				}
			} ## end foreach my $range ( @{ $spec->{ranges} } )
			if ( !$in_a_range ) {
				next;
			}
		} ## end if ( defined( $spec->{ranges} ) )
		return 1;
	} ## end foreach my $spec ( @{$specs} )

	return 0;
} ## end sub _in_windows

=head2 holds

Returns 1 when every time checked satisfies the gate, else 0. The times are
the values of the gate's vars, or the passed C<$now> with out any. The
offender is not looked at.

    if ( $gate->holds( $data, undef, $now ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip, $now ) = @_;

	my @times = defined( $self->{vars} ) ? ( map { $data->{$_} } @{ $self->{vars} } ) : ($now);

	foreach my $time (@times) {
		my @fields = defined($time) ? _time_fields($time) : ();
		if ( !@fields ) {
			return 0;
		}
		# is passes only a time in a window, isnot only one out of them all
		my $in_window = _in_windows( $self->{specs}, $fields[0], $fields[1] );
		if ( $self->{mode} eq 'is' && !$in_window ) {
			return 0;
		}
		if ( $self->{mode} ne 'is' && $in_window ) {
			return 0;
		}
	} ## end foreach my $time (@times)

	return 1;
} ## end sub holds

1;
