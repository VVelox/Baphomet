package App::Baphomet::Gate;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Exporter  qw( import );
use Ref::Util qw( is_plain_arrayref is_plain_hashref );

our @EXPORT_OK = qw( gate_class compile_rule_gates bind_rule_gates );

=head1 NAME

App::Baphomet::Gate - The gates a rule's matches are vetted by, each type a class of its own.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Gate qw( compile_rule_gates bind_rule_gates );

    # when the rule loads
    my $gates = compile_rule_gates( $def->{rule_gates}, $rule, 'syslog/sshd' );

    # when the rule is bound to a watcher
    my $bound = bind_rule_gates( $gates, \%context, 'The rule "syslog/sshd" of the watcher "auth"' );

    # for a found result, then for each candidate offender of it
    if ( all { $_->holds( $data, undef, $now ) } @{ $bound->{result} } )   { ... }
    if ( all { $_->holds( $data, $ip,   $now ) } @{ $bound->{offender} } ) { ... }

=head1 DESCRIPTION

A rule that matched a line has only said the line looks like a offense. Its
gates say if it really is one, each asking something the line can not answer
for itself... if a address is branded, what country it is in, if it is on a
list, what its reverse DNS says, what time it is.

A rule names its gates under C<rule_gates>, a list, each entry a hash of one
key, the gate type, over what that gate is told. A type may be named more
than once.

    rule_gates:
      - marked: { name: failed_login, var: USER }
      - country: { isnot: [ US ] }

Every gate has to hold for the match to count, and the first that does not
ends the asking. So the order written decides only what a veto spares, and
the gate cheapest to ask, or likeliest to veto, belongs first.

A gate is asked in one of two passes, going by what it keys on. One naming a
C<var> or C<vars> reads the found data, and is asked once for the result,
with no offender. One naming neither keys on the offender, and is asked once
for each candidate. Each pass keeps the order written.

Each type is a class under this namespace, found by its name... C<country>
is L<App::Baphomet::Gate::Country> and C<namtar_list> is
L<App::Baphomet::Gate::NamtarList>. The shipped types are C<marked>,
C<not_marked>, C<sequence>, C<country>, C<namtar_list>, C<reverse_dns>, and
C<active_time>.

A gate has three stages to its life. It is compiled once when its rule
loads, where what it is told is vetted and a rule that can not have it is
refused. It is bound once for each watcher the rule is on, where the names
it uses are resolved against that watcher's lists and it is handed what it
judges over. Then it is asked, per match.

=head1 THE CONTEXT

What a gate is bound over, a hash the caller fills... the galla with its
live stores and lookups, C<run_tests> with a throwaway store and the
fixtures of a rule's own tests.

    - marks :: A sub returning the mark store.

    - locator :: A sub taking a address and returning its ISO 3166 country
          code upcased, or undef for one it can not place.

    - resolver :: A sub returning the resolver, or undef when there is none
          to ask. The resolver is a hash of C<reverse> and C<forward>, each a
          sub answering a array ref of names or addresses, a empty one for
          authoritative absence, or undef for a failure.

    - namtar_files :: The loaded lists, a hash of slot key to a hash holding
          that slot's compiled C<set>.

    - country_codes :: Hash of the named country code lists.

    - namtar_lists :: Hash of the named lists.

    - active_time :: Hash of the named time windows.

C<marks> and C<resolver> hand the thing over when asked so a gate judges
over what is there at the time, not what was there when it was bound.

=head1 WRITING A TYPE

A type is a class under this namespace with this one as its parent, named
for the type with each word capitalized... C<my_gate> is
C<App::Baphomet::Gate::MyGate>. It has to have L</compile> and L</holds>.
The rest have defaults. A gate is a blessed hash, of which the keys C<type>
and C<context> are this class's.

=head1 METHODS

=head2 new

Makes a gate out of one C<rule_gates> entry, at rule load, handing what it
was told to the type's L</compile>. Called by L</compile_rule_gates>.

    - type :: The type name, for the messages.

    - args :: What the entry tells the gate, as the author wrote it.

    - where :: The lead in for the die messages, naming the gate and its
          rule.

    - rule :: The rule object the gate is for. It is still being built, so
          only what its def answers is there to ask.

    my $gate = App::Baphomet::Gate::Country->new(
        'type'  => 'country',
        'args'  => { 'isnot' => ['US'] },
        'where' => 'The country gate of the rule "syslog/sshd" (rule_gates entry 0)',
        'rule'  => $rule,
    );

=cut

sub new {
	my ( $class, %arg ) = @_;

	my $self = bless( { 'type' => $arg{type} }, $class );
	$self->compile( $arg{args}, $arg{where}, $arg{rule} );

	return $self;
}

=head2 compile

A type's own. Vets what the gate was told and keeps what it will judge by on
the object, dying on anything malformed, or on a rule that can not have the
gate, the passed C<$where> leading the message. Returns nothing.

    $gate->compile( $args, $where, $rule );

=head2 holds

A type's own. Judges one match, C<$data> being the found data and C<$now>
the time of the line. C<$ip> is the candidate offender for a gate of the
offender pass, and undef for one of the result pass. Returns 1 when the gate
holds, else 0. What can not be answered has to fail closed.

    if ( $gate->holds( $data, $ip, $now ) ) { ... }

=head2 pass

Returns the pass the gate is asked in, C<result> for one keyed by a C<var>
or C<vars> and C<offender> for one keyed by neither. A type that keys some
other way overrides it.

    my $pass = $gate->pass;

=cut

sub pass {
	my ($self) = @_;

	return ( defined( $self->{var} ) || defined( $self->{vars} ) ) ? 'result' : 'offender';
}

=head2 needs

Returns the list of the L<context|/THE CONTEXT> keys the gate can not judge
with out. A empty list unless the type says otherwise.

    foreach my $need ( $gate->needs ) { ... }

=cut

sub needs {
	return ();
}

=head2 bound

Returns a copy of the gate bound over a context, the context keys it
L</needs> held under its C<context> key. A type that resolves names against
a watcher's lists overrides this to do so, dying on a name the context does
not define, the passed C<$where> leading the message.

    my $bound = $gate->bound( \%context, 'The rule "syslog/sshd" of the watcher "auth"' );

=cut

sub bound {
	my ( $self, $context, $where ) = @_;

	return bless( { %{$self}, 'context' => { map { $_ => $context->{$_} } $self->needs } }, ref($self) );
}

=head2 list_slots

Returns the list file slots a bound gate reads, for the galla to load and
keep fresh, each as L<App::Baphomet::Namtar/namtar_slots> gives one. A empty
list unless the type says otherwise.

    foreach my $slot ( $gate->list_slots ) { ... }

=cut

sub list_slots {
	return ();
}

=head1 FUNCTIONS

=head2 gate_class

Returns the class of a gate type, loading it on first asking. Dies, the
passed C<$where> leading the message, on a name that is not a type name, on
a type there is no class for, and on a class that is not a
C<App::Baphomet::Gate>. The name has to be lower case words joined by
C<_>, so nothing from outside this namespace can be named.

    my $class = gate_class( 'namtar_list', $where );    # App::Baphomet::Gate::NamtarList

=cut

# the classes of the gate types loaded so far, by type name
my %loaded_class;

sub gate_class {
	my ( $type, $where ) = @_;

	if ( defined( $loaded_class{$type} ) ) {
		return $loaded_class{$type};
	}

	if ( $type !~ /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/ ) {
		die( $where . ' names the gate "' . $type . '", which is not a gate type name' );
	}
	my $class = 'App::Baphomet::Gate::' . join( '', map { ucfirst($_) } split( /_/, $type ) );
	my $file  = $class . '.pm';
	$file =~ s{::}{/}g;

	try {
		require $file;
	} catch ($caught) {
		# a class that is not there is a type that does not exist, which reads
		# better said so than as the search of @INC perl reports it as
		if ( $caught =~ /^Can't locate \Q$file\E / ) {
			die( $where . ' names the gate "' . $type . '", which is not a known gate type' );
		}
		die( $where . ' names the gate "' . $type . '", whose class ' . $class . ' did not load... ' . $caught );
	}
	if ( !$class->isa(__PACKAGE__) ) {
		die( $where . ' names the gate "' . $type . '", whose class ' . $class . ' is not a ' . __PACKAGE__ );
	}

	$loaded_class{$type} = $class;
	return $class;
} ## end sub gate_class

=head2 compile_rule_gates

Compiles a rule's C<rule_gates> list into its gates, in the order written,
at rule load. Dies on a list that is not a non-empty array, a entry that is
not a hash of one key, a type that does not load, and whatever the type's
own L</compile> refuses. A gate of the offender pass on a detection rule is
refused here for every type, as such a rule has no offender and the gate
would never be asked.

    - rule_gates :: The list as the author wrote it, or undef for a rule
          with out any.

    - rule :: The rule object, handed on to each gate.

    - rule_name :: The rule's name, for the die messages.

Returns a array ref of the gates, a empty one for a rule with out any.

    my $gates = compile_rule_gates( $def->{rule_gates}, $rule, 'syslog/sshd' );

=cut

sub compile_rule_gates {
	my ( $rule_gates, $rule, $rule_name ) = @_;

	if ( !defined($rule_gates) ) {
		return [];
	}

	my $list_where = 'The rule_gates of the rule "' . $rule_name . '"';
	if ( !is_plain_arrayref($rule_gates) || !@{$rule_gates} ) {
		die( $list_where . ' is not a non-empty array' );
	}

	my @gates;
	foreach my ( $entry_int, $entry ) ( indexed @{$rule_gates} ) {
		my $entry_where = $list_where . ' entry ' . $entry_int;
		if ( !is_plain_hashref($entry) || scalar( keys( %{$entry} ) ) != 1 ) {
			die( $entry_where . ' is not a hash of one key, the gate type' );
		}
		my ($type) = keys( %{$entry} );

		my $where = 'The ' . $type . ' gate of the rule "' . $rule_name . '" (rule_gates entry ' . $entry_int . ')';
		my $gate  = gate_class( $type, $entry_where )->new(
			'type'  => $type,
			'args'  => $entry->{$type},
			'where' => $where,
			'rule'  => $rule,
		);

		# a type with no holds can not be asked, and a pass that is neither
		# would leave the gate in a list nothing asks, so a rule the author
		# gated would count ungated... both are better found now than on the
		# first match
		if ( !$gate->can('holds') ) {
			die( $where . ' is of a type with no holds method, so it can not be asked' );
		}
		my $pass = $gate->pass;
		if ( $pass ne 'result' && $pass ne 'offender' ) {
			die( $where . ' is of the pass "' . $pass . '", which is neither result nor offender' );
		}
		if ( $pass eq 'offender' && $rule->is_detection ) {
			die( $where . ' keys on the offender, which a detection rule does not have... name a var for it to check' );
		}

		push( @gates, $gate );
	} ## end foreach my ( $entry_int, $entry ) ( indexed @{$rule_gates...})

	return \@gates;
} ## end sub compile_rule_gates

=head2 bind_rule_gates

Binds a rule's gates over a context and sorts them by the pass each is asked
in, each pass keeping the order of the list. Dies, the passed C<$where>
leading the message, on a gate that L</needs> something the context does not
have, and on whatever a gate's own L</bound> refuses. Nothing is ever left
out, as a gate left out is a rule counting what its author gated off.

    - gates :: Array ref of the gates, as L</compile_rule_gates> returns.

    - context :: The L<context|/THE CONTEXT>.

    - where :: The lead in for the die messages, naming the rule and what it
          is being bound for.

Returns a hash ref of C<result> and C<offender>, each a array ref of the
bound gates of that pass, either possibly empty.

    my $bound = bind_rule_gates( $gates, \%context, 'The rule "syslog/sshd" of the watcher "auth"' );

=cut

sub bind_rule_gates {
	my ( $gates, $context, $where ) = @_;

	my %bound = ( 'result' => [], 'offender' => [] );
	foreach my $gate ( @{$gates} ) {
		my @unmet = grep { !defined( $context->{$_} ) } $gate->needs;
		if (@unmet) {
			die(      $where
					. ' has a '
					. $gate->{type}
					. ' gate, which can not judge with out '
					. join( ', ', @unmet )
					. ', and there is none here' );
		}
		push( @{ $bound{ $gate->pass } }, $gate->bound( $context, $where ) );
	} ## end foreach my $gate ( @{$gates} )

	return \%bound;
} ## end sub bind_rule_gates

1;
