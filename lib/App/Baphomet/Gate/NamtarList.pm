package App::Baphomet::Gate::NamtarList;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util             qw( is_plain_arrayref is_plain_hashref );
use App::Baphomet::Shape  qw( check_hash );
use App::Baphomet::Namtar qw( namtar_slots namtar_listed );

=head1 NAME

App::Baphomet::Gate::NamtarList - The namtar_list gate, counting only what is already on a list.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - namtar_list: { list: threatfeed }
      - namtar_list: { lists: [ service_accounts, bait_accounts ], var: USER }

=head1 DESCRIPTION

Holds when the value checked is on any of the lists the entry names. A value
on none of them fails closed, as does one the result lacks and a list whose
file is not loaded.

A entry is told...

    - list / lists :: Exactly one. The name of a list, or a array of them,
          out of the watcher's C<namtar_lists>.

    - var :: Optional. The found var holding the value to check. With out it
          the offender is checked.

One entry may name lists of both kinds, each matched its own way, a C<cidr>
one by network and a C<string> one by equality.

It needs the C<namtar_lists> and the C<namtar_files> of the
L<context|App::Baphomet::Gate/THE CONTEXT>. A list the context does not
define is fatal when the gate is bound.

=cut

my $SHAPE = {
	'optional' => { 'list' => 'name_or_names', 'lists' => 'name_or_names', 'var' => 'string' },
	'one_of'   => [ [ 'list', 'lists' ] ],
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps the list names, as a list whichever of
C<list> or C<lists> was written, and the var. The names are left unresolved,
the lists they name being a watcher's.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	my $lists = $args->{lists} // $args->{list};
	$self->{lists} = is_plain_arrayref($lists) ? [ @{$lists} ] : [$lists];
	$self->{var}   = $args->{var};

	return;
} ## end sub compile

=head2 needs

Returns C<namtar_lists> and C<namtar_files>.

=cut

sub needs {
	return ( 'namtar_lists', 'namtar_files' );
}

=head2 bound

Returns a copy of the gate bound over a context, its list names resolved to
the slots of their files, sorted by key and with a file two of the lists
name appearing once. Dies on a list the context's C<namtar_lists> does not
define.

    my $bound = $gate->bound( \%context, $where );

=cut

sub bound {
	my ( $self, $context, $where ) = @_;

	my %slots;
	foreach my $name ( @{ $self->{lists} } ) {
		my $list = $context->{namtar_lists}{$name};
		if ( !is_plain_hashref($list) ) {
			die( $where . ' references namtar_lists{' . $name . '}, which is not a defined list for it' );
		}
		foreach my $slot ( namtar_slots($list) ) {
			$slots{ $slot->{key} } = $slot;
		}
	}

	my $bound = $self->SUPER::bound( $context, $where );
	$bound->{slots} = [ map { $slots{$_} } sort( keys(%slots) ) ];

	return $bound;
} ## end sub bound

=head2 list_slots

Returns the slots of the list files a bound gate reads.

    foreach my $slot ( $gate->list_slots ) { ... }

=cut

sub list_slots {
	my ($self) = @_;

	return @{ $self->{slots} };
}

=head2 holds

Returns 1 when the value checked is on any of the gate's lists, else 0. The
value is that of the gate's var, or the offender with out one.

    if ( $gate->holds( $data, $ip ) ) { ... }

=cut

sub holds {
	my ( $self, $data, $ip ) = @_;

	my $value = defined( $self->{var} ) ? $data->{ $self->{var} } : $ip;

	return namtar_listed( $self->{context}{namtar_files}, $self->{slots}, $value );
}

1;
