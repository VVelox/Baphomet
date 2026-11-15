package App::Baphomet::Gate::sum;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
# kept by the same key and in the same store as the limit gate, as the after
# gate is
use parent 'App::Baphomet::Gate::limit';
use List::Util           qw( sum0 );
use POSIX                qw( ceil );
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Marks qw( bound_expiring_store );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::sum - The sum gate, holding once a number has added up to enough for a key.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - sum: { by: host, of: bytes, above: 1000000000, seconds: 3600 }
      - ban_var: [ host ]

=head1 DESCRIPTION

Adds the number in a found var to a running total for a key, and holds
while what the key has added up to with in C<seconds> is above the mark. It
is the after gate for how much in place of how often... the bytes sent to
one client in a hour, say.

The total is kept in sixty spans of the C<seconds>, so what falls out of
it does so a span at a time, and it may run up to one span long and never
short. A offense it vetoes is vetoed as by any gate, so the line is not
consumed and goes on to the rules after this one.

The totals are kept by the scope the offense is of, a watcher, and are
forgotten at a restart. A offense lacking one of the C<by> vars, or whose
C<of> is not a number of zero or more, adds nothing and is vetoed.

A entry is told...

    - by :: The found var, or a array of them, whose values joined are the
          key.

    - of :: The found var holding the number to add.

    - above :: What the total has to be more than.

    - seconds :: How far back it is added up over.

=cut

my $SHAPE = {
	'required' => {
		'by'      => 'string_or_strings',
		'of'      => 'string',
		'above'   => 'positive_number',
		'seconds' => 'seconds',
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, the C<by> as a list however it
was written, with the width of a span and a empty store of totals.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{by}      = is_plain_arrayref( $args->{by} ) ? [ @{ $args->{by} } ] : [ $args->{by} ];
	$self->{of}      = $args->{of};
	$self->{above}   = $args->{above};
	$self->{seconds} = $args->{seconds};

	# sixty spans to the window, each a whole second or more
	$self->{span} = ceil( $args->{seconds} / 60 );

	# the totals, by scope and then by key, each a hash of spans, the start
	# of a span to what was added in it, and when the newest stops counting
	$self->{windows} = {};

	return;
} ## end sub compile

=head2 ask

Adds the offense's number to the total of its key. Returns 1 when the
total with in C<seconds> is above the mark, else 0.

    if ( !$gate->ask($offense) ) { ... }

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $key    = $self->_key_of($offense);
	my $number = $offense->{data}{ $self->{of} };
	if ( !defined($key) || !defined($number) || ref($number) ne '' || $number !~ /^[0-9]+(?:\.[0-9]+)?$/ ) {
		return 0;
	}
	my $now = $offense->{now};

	my $store = $self->{windows}{ $offense->{scope} // '' } //= {};
	if ( !defined( $store->{$key} ) ) {
		# bounded the way the mark store is, so a flood of keys can not grow
		# it with out limit
		bound_expiring_store( $store, $key, $now );
		$store->{$key} = { 'spans' => {} };
	}
	my $total = $store->{$key};
	my $spans = $total->{spans};

	$spans->{ $now - ( $now % $self->{span} ) } += $number;
	$total->{expires} = $now + $self->{seconds};

	# a span counts while any of it is with in the seconds
	delete( @{$spans}{ grep { $_ + $self->{span} <= $now - $self->{seconds} } keys( %{$spans} ) } );

	return sum0( values( %{$spans} ) ) > $self->{above} ? 1 : 0;
} ## end sub ask

1;
