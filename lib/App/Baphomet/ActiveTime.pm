package App::Baphomet::ActiveTime;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util qw( is_plain_arrayref );
use Exporter  qw( import );

our @EXPORT_OK = qw( resolve_active_time_gate active_time_pass );

=head1 NAME

App::Baphomet::ActiveTime - The active_time gate's pure core, drivable over any clock.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::ActiveTime qw( resolve_active_time_gate active_time_pass );

    my $gate = resolve_active_time_gate( $rule->active_time, \%named_windows, $where );
    if ( active_time_pass( $gate, $data, $ip, time ) ) { ... }

=head1 DESCRIPTION

The active_time gate's judgment, lifted out of the galla so it runs over any
clock... the galla passes the wall clock, while a test passes whatever epoch
it wants judged. Nothing here knows of config or of the time it is called at.

A time is read as a day of the week, 0 for Sunday through 6, and a HHMM, the
hour times a hundred plus the minute. One that is all digits is a epoch read
in local time, a journal's micro or milliseconds scaled down to seconds, and
anything else is a ISO 8601 datetime taken at its face-value components, the
zone it names being dropped and not converted.

=head1 FUNCTIONS

=head2 resolve_active_time_gate

Resolves a rule's active_time gate (the C<active_time> accessor's
C<{mode, windows, vars}>) against a set of named windows into a concrete
gate... the mode, the compiled specs of every window named, and the vars.
Returns undef when the rule has no gate. A reference to a window the set does
not define is fatal, C<$where> naming the offender in the die. Windows are
pure config, so the gate is frozen once resolved.

    my $gate = resolve_active_time_gate( $rule->active_time, \%named_windows, $where );

=cut

sub resolve_active_time_gate {
	my ( $active_time, $windows, $where ) = @_;

	if ( !defined($active_time) ) {
		return undef;
	}

	my @specs;
	foreach my $name ( @{ $active_time->{windows} } ) {
		my $window = $windows->{$name};
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
	} ## end foreach my $name ( @{ $active_time->{windows} })

	return { 'mode' => $active_time->{mode}, 'specs' => \@specs, 'vars' => $active_time->{vars} };
} ## end sub resolve_active_time_gate

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
#   if ( _in_windows( $gate->{specs}, 1, 1030 ) ) { ... }
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

=head2 active_time_pass

Evaluates a resolved active_time gate against the passed epoch, or against
the found vars when it names them. Time is a property of the line and not of
a offender, so the gate is judged once per found result, in the data pass (ip
undef), and lets every offender of the offender pass (ip set) by. Every time
checked must satisfy the gate, and a value that is missing or does not parse
fails closed. A undef gate passes.

    if ( active_time_pass( $gate, $data, $ip, $now ) ) { ... }

=cut

sub active_time_pass {
	my ( $gate, $data, $ip, $now ) = @_;

	if ( !defined($gate) || defined($ip) ) {
		return 1;
	}

	my @times = defined( $gate->{vars} ) ? ( map { $data->{$_} } @{ $gate->{vars} } ) : ($now);

	foreach my $time (@times) {
		my @fields = defined($time) ? _time_fields($time) : ();
		if ( !@fields ) {
			return 0;
		}
		# is passes only a time in a window, isnot only one out of them all
		my $in_window = _in_windows( $gate->{specs}, $fields[0], $fields[1] );
		if ( $gate->{mode} eq 'is' && !$in_window ) {
			return 0;
		}
		if ( $gate->{mode} ne 'is' && $in_window ) {
			return 0;
		}
	} ## end foreach my $time (@times)

	return 1;
} ## end sub active_time_pass

1;
