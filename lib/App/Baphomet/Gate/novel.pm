package App::Baphomet::Gate::novel;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Marks qw( live_mark mark_key mark_set );
use App::Baphomet::Shape qw( check_hash );

=head1 NAME

App::Baphomet::Gate::novel - The novel gate, holding on a value a key has not had before.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - novel: { name: login-country, by: USER, of: COUNTRY }
      - detection_var: [ SRC ]

=head1 DESCRIPTION

Holds when a key is seen with a value it has not been seen with before,
once the key has been seen often enough to have a before. A account that
has only ever logged in from one country and now logs in from another, say.

Every offense that reaches the gate is a sighting, and is remembered
whether or not the gate held. What a key has been seen with, and how often
it has been seen at all, are kept as brands of the gate's C<name>, so they
are kept and shared as any brand is... across the watchers of a galla, a
restart, and a fleet. Each value is forgotten C<ttl> after it was last
seen, and is then new again.

It does not hold on a key seen fewer than C<after_seen> times before, a new
key's first values being all of them new, or on a offense lacking the
value or part of the key.

A entry is told...

    - name :: The brand the sightings are kept in.

    - by :: The found var, or a array of them, whose values joined are the
          key.

    - of :: The found var holding the value.

    - ttl :: Optional. Seconds a value is remembered after it was last
          seen.
        Default :: 2592000

    - after_seen :: Optional. How many times a key has to have been seen
          before a value new to it holds.
        Default :: 3

It needs the C<marks> of the L<context|App::Baphomet::Gate/THE CONTEXT>, and
uses its C<on_set> when it is there.

=cut

my $SHAPE = {
	'required' => { 'name' => 'name',    'by' => 'string_or_strings', 'of' => 'string' },
	'optional' => { 'ttl'  => 'seconds', 'after_seen' => 'positive_int' },
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

	$self->{name}       = $args->{name};
	$self->{by}         = is_plain_arrayref( $args->{by} ) ? [ @{ $args->{by} } ] : [ $args->{by} ];
	$self->{of}         = $args->{of};
	$self->{ttl}        = $args->{ttl}        // 2592000;
	$self->{after_seen} = $args->{after_seen} // 3;

	return;
} ## end sub compile

=head2 pass

Returns C<result>. It keys on the found vars it names and never on the
offenders.

=cut

sub pass {
	return 'result';
}

=head2 needs

Returns C<marks>.

=cut

sub needs {
	return ('marks');
}

=head2 wants

Returns C<on_set>.

=cut

sub wants {
	return ('on_set');
}

=head2 holds

Remembers the offense's value for its key, and returns 1 when the key had
not been seen with it and had been seen often enough before, else 0.

    if ( $gate->holds( $data, undef, $now ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip, $now ) = @_;

	my $context = $self->{context};
	my $key     = mark_key( { 'vars' => $self->{by} }, $data );
	my $value   = $data->{ $self->{of} };
	if ( !defined($key) || !defined($value) || $value eq '' ) {
		return 0;
	}

	# two brands of the one name... the key alone, valued with how often it
	# has been seen, and the key with the value after it, for each value it
	# has been seen with. a part of a key never holds the separator, so the
	# two can not be taken for one another
	my $store     = $context->{marks}->();
	my $value_key = $key . "\x1f" . $value;
	my $history   = live_mark( $store, $self->{name}, $key, $now );
	my $seen      = ( defined($history) && ( $history->{value} // '' ) =~ /^[0-9]+$/ ) ? $history->{value} : 0;
	my $known     = defined( live_mark( $store, $self->{name}, $value_key, $now ) )    ? 1                 : 0;

	mark_set( $store, $self->{name}, $key,       $seen + 1, $self->{ttl}, $now, $context->{on_set} );
	mark_set( $store, $self->{name}, $value_key, undef,     $self->{ttl}, $now, $context->{on_set} );

	return ( !$known && $seen >= $self->{after_seen} ) ? 1 : 0;
} ## end sub holds

1;
