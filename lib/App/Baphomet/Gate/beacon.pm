package App::Baphomet::Gate::beacon;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
# kept by the same key and in the same store as the limit gate, as the after
# gate is
use parent 'App::Baphomet::Gate::limit';
use List::Util           qw( sum0 );
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Marks qw( bound_expiring_store );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::beacon - The beacon gate, holding on a key whose offenses come like clockwork.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - beacon: { by: [ SRC, dest ], count: 10, jitter: 0.1 }
      - detection_var: [ SRC ]

=head1 DESCRIPTION

Holds when the last C<count> gaps between a key's offenses are all much the
same length. A host calling home every five minutes, or a slow brute force
on a timer, stays under every count, and is far too even to be a person.

How even is the spread of the gaps over their mean, their standard
deviation over their average, which has to be C<jitter> or less. Gaps of
300, 302, and 298 seconds are a spread of under one percent. Gaps shorter on
average than C<min_interval> are a burst and not a beacon, and a gap longer
than C<max_interval> starts the key over, a beacon that stopped and started
again being two.

A offense it vetoes is vetoed as by any gate, so the line is not consumed
and goes on to the rules after this one. What is seen of a key is kept by
the scope the offense is of, a watcher, and is forgotten at a restart. A
offense lacking one of the C<by> vars is vetoed.

A entry is told...

    - by :: The found var, or a array of them, whose values joined are the
          key.

    - count :: How many gaps it takes, two or more.

    - jitter :: Optional. How uneven the gaps may be, as a share of their
          average.
        Default :: 0.1

    - min_interval :: Optional. The shortest average gap that can be a
          beacon, in seconds.
        Default :: 10

    - max_interval :: Optional. The longest gap that does not start the key
          over, in seconds.
        Default :: 86400

=cut

my $SHAPE = {
	'required' => {
		'by'    => 'string_or_strings',
		'count' => {
			'test' =>
				sub { return ( defined( $_[0] ) && ref( $_[0] ) eq '' && $_[0] =~ /^[0-9]+$/ && $_[0] >= 2 ) ? 1 : 0; },
			'says' => 'a int of two or more',
		},
	},
	'optional' => {
		'jitter'       => 'positive_number',
		'min_interval' => 'seconds',
		'max_interval' => 'seconds',
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it with the defaults filled in, the
C<by> as a list however it was written, with a empty store of what has been
seen. Dies on a C<min_interval> that is not under the C<max_interval>.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{by}           = is_plain_arrayref( $args->{by} ) ? [ @{ $args->{by} } ] : [ $args->{by} ];
	$self->{count}        = $args->{count};
	$self->{jitter}       = $args->{jitter}       // 0.1;
	$self->{min_interval} = $args->{min_interval} // 10;
	$self->{max_interval} = $args->{max_interval} // 86400;

	if ( $self->{min_interval} >= $self->{max_interval} ) {
		die( $where . ' has a min_interval that is not under its max_interval' );
	}

	# what has been seen, by scope and then by key, each a hash of when the
	# last offense was, the gaps before it, and when the key is forgotten
	$self->{windows} = {};

	return;
} ## end sub compile

=head2 ask

Notes the gap since the key's last offense. Returns 1 when the last
C<count> gaps are even enough and long enough, else 0.

    if ( !$gate->ask($offense) ) { ... }

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $key = $self->_key_of($offense);
	if ( !defined($key) ) {
		return 0;
	}
	my $now = $offense->{now};

	my $store = $self->{windows}{ $offense->{scope} // '' } //= {};
	my $seen  = $store->{$key};
	if ( !defined($seen) || $now - $seen->{last} > $self->{max_interval} ) {
		# bounded the way the mark store is, so a flood of keys can not grow
		# it with out limit
		bound_expiring_store( $store, $key, $now );
		$store->{$key} = { 'last' => $now, 'gaps' => [], 'expires' => $now + $self->{max_interval} };
		return 0;
	}

	# a offense that came in ahead of the last, as lines of two logs may, is
	# no gap to measure
	if ( $now < $seen->{last} ) {
		return 0;
	}

	push( @{ $seen->{gaps} }, $now - $seen->{last} );
	if ( @{ $seen->{gaps} } > $self->{count} ) {
		shift( @{ $seen->{gaps} } );
	}
	$seen->{last}    = $now;
	$seen->{expires} = $now + $self->{max_interval};

	my @gaps = @{ $seen->{gaps} };
	if ( @gaps < $self->{count} ) {
		return 0;
	}

	my $mean = sum0(@gaps) / @gaps;
	if ( $mean < $self->{min_interval} ) {
		return 0;
	}
	my $spread = sqrt( sum0( map { ( $_ - $mean )**2 } @gaps ) / @gaps );

	return ( $spread / $mean ) <= $self->{jitter} ? 1 : 0;
} ## end sub ask

1;
