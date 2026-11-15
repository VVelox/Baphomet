package App::Baphomet::Gate::after;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
# kept by the same key and in the same store as the limit gate, which it is
# the other half of... that one lets the first few of a key by, this one
# everything but them
use parent 'App::Baphomet::Gate::limit';
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Marks qw( bound_expiring_store );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::after - The after gate, holding only once a key has been seen often enough.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - after: { by: USER, count: 20, seconds: 600 }
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Holds from the C<count>th offense of a key with in C<seconds> on, and
vetoes the ones before it. The count a rule keeps is by its offender, and
this one is by anything, so it is how a rule says twenty failures against
one account, whoever they came from.

The window slides... a offense holds when it and the C<count> less one
before it all landed with in C<seconds>, wherever a window might have been
said to start.

A offense it vetoes is vetoed as by any gate, so the line is not consumed
and goes on to the rules after this one.

What is seen of a key is kept by the scope the offense is of, a watcher,
and is forgotten at a restart. A offense lacking one of the C<by> vars has
nothing to be counted under and is vetoed.

A entry is told...

    - by :: The found var, or a array of them, whose values joined are the
          key.

    - count :: How many offenses of a key it takes. Two or more.

    - seconds :: How long they have to land with in.

=cut

my $SHAPE = {
	'required' => {
		'by'      => 'string_or_strings',
		'seconds' => 'seconds',
		'count'   => {
			'test' =>
				sub { return ( defined( $_[0] ) && ref( $_[0] ) eq '' && $_[0] =~ /^[0-9]+$/ && $_[0] >= 2 ) ? 1 : 0; },
			'says' => 'a int of two or more',
		},
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

	$self->{by}      = is_plain_arrayref( $args->{by} ) ? [ @{ $args->{by} } ] : [ $args->{by} ];
	$self->{seconds} = $args->{seconds};
	$self->{count}   = $args->{count};

	# what has been seen, by scope and then by key, each a hash of the times
	# of the last count offenses and when the newest of them stops counting
	$self->{windows} = {};

	return;
} ## end sub compile

=head2 ask

Notes the offense under its key. Returns 1 when it is the C<count>th or
later with in C<seconds>, else 0.

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
	if ( !defined( $store->{$key} ) ) {
		# bounded the way the mark store is, so a flood of keys can not grow
		# it with out limit
		bound_expiring_store( $store, $key, $now );
		$store->{$key} = { 'times' => [] };
	}
	my $seen = $store->{$key};

	# only the last count of them are ever needed... the oldest kept is the
	# one this offense has to be with in seconds of
	push( @{ $seen->{times} }, $now );
	if ( @{ $seen->{times} } > $self->{count} ) {
		shift( @{ $seen->{times} } );
	}
	$seen->{expires} = $now + $self->{seconds};

	if ( @{ $seen->{times} } < $self->{count} ) {
		return 0;
	}

	return ( $now - $seen->{times}[0] ) < $self->{seconds} ? 1 : 0;
} ## end sub ask

1;
