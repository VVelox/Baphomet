package App::Baphomet::Gate::concurrent;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
# kept by the same key and in the same store as the limit gate, as the after
# gate is
use parent 'App::Baphomet::Gate::limit';
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Marks qw( bound_expiring_store );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::concurrent - The concurrent gate, holding on a key seen with too many values at once.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - concurrent: { by: USER, of: SRC, more_than: 2, seconds: 600 }
      - detection_var: [ SRC ]

=head1 DESCRIPTION

Holds when a key has been seen with more than C<more_than> different values
of C<of> with in the last C<seconds>, this offense's among them. One account
logged in from three addresses in the one ten minutes is a account shared,
or one that is not its owner's any more.

A value counts for C<seconds> after it was last seen with the key, so a
value seen again stays one value. It is a gate, so a rule may have it beside
its own counting, where C<distinct> is the way a rule counts.

A offense it vetoes is vetoed as by any gate, so the line is not consumed
and goes on to the rules after this one. What is seen is kept by the scope
the offense is of, a watcher, and is forgotten at a restart. A key holds at
most a thousand values, the longest unseen let go first. A offense lacking
one of the C<by> vars or the C<of> is vetoed.

A entry is told...

    - by :: The found var, or a array of them, whose values joined are the
          key.

    - of :: The found var whose different values are counted.

    - more_than :: How many values a key may have at once and the gate not
          hold.

    - seconds :: How long a value counts after it was last seen.

=cut

# the most values one key holds, so one key fed a flood of them can not grow
# with out limit
my $VALUE_CAP = 1000;

my $SHAPE = {
	'required' => {
		'by'        => 'string_or_strings',
		'of'        => 'string',
		'more_than' => 'positive_int',
		'seconds'   => 'seconds',
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, the C<by> as a list however it
was written, with a empty store of what has been seen.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{by}        = is_plain_arrayref( $args->{by} ) ? [ @{ $args->{by} } ] : [ $args->{by} ];
	$self->{of}        = $args->{of};
	$self->{more_than} = $args->{more_than};
	$self->{seconds}   = $args->{seconds};

	# what has been seen, by scope and then by key, each a hash of the values,
	# each to when it was last seen, and when the key is forgotten
	$self->{windows} = {};

	return;
} ## end sub compile

=head2 ask

Notes the offense's value under its key. Returns 1 when the key then has
more than C<more_than> values with in C<seconds>, else 0.

    if ( !$gate->ask($offense) ) { ... }

=cut

sub ask {
	my ( $self, $offense ) = @_;

	my $key   = $self->_key_of($offense);
	my $value = $offense->{data}{ $self->{of} };
	if ( !defined($key) || !defined($value) || $value eq '' ) {
		return 0;
	}
	my $now = $offense->{now};

	my $store = $self->{windows}{ $offense->{scope} // '' } //= {};
	if ( !defined( $store->{$key} ) ) {
		# bounded the way the mark store is, so a flood of keys can not grow
		# it with out limit
		bound_expiring_store( $store, $key, $now );
		$store->{$key} = { 'values' => {} };
	}
	my $seen   = $store->{$key};
	my $values = $seen->{values};

	# the values no longer counted are let go before this one lands
	delete( @{$values}{ grep { $values->{$_} <= $now - $self->{seconds} } keys( %{$values} ) } );
	if ( !exists( $values->{$value} ) && keys( %{$values} ) >= $VALUE_CAP ) {
		my ($longest_unseen) = sort { $values->{$a} <=> $values->{$b} } keys( %{$values} );
		delete( $values->{$longest_unseen} );
	}
	$values->{$value} = $now;
	$seen->{expires} = $now + $self->{seconds};

	return keys( %{$values} ) > $self->{more_than} ? 1 : 0;
} ## end sub ask

1;
