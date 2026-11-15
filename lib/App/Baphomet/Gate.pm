package App::Baphomet::Gate;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Exporter   qw( import );
use Ref::Util  qw( is_plain_arrayref is_plain_hashref );
use List::Util qw( uniqstr );

our @EXPORT_OK
	= qw( gate_class compile_rule_gates bind_rule_gates line_walk_of walk_offense stand passage_fields own_fields passage_envelope settle_offenders );

=head1 NAME

App::Baphomet::Gate - The gates a line goes down to be a offense, each type a class of its own.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Gate qw( compile_rule_gates bind_rule_gates walk_offense );

    # when the rule loads
    my $gates = compile_rule_gates( $def->{rule_gates}, $rule, 'syslog/sshd' );

    # when the rule is bound to a watcher
    my $bound = bind_rule_gates( $gates, \%context, 'The rule "syslog/sshd" of the watcher "auth"' );

    # for a line, then for each offense the line made
    foreach my $offense ( @{ $rule->walk_line( $bound, $parsed, $scope, $line_ctx ) } ) {
        if ( walk_offense( $bound, $offense ) ) { ... }
    }

=head1 DESCRIPTION

Everything a rule matches with is a gate, and a rule names its gates under
C<rule_gates>, a list, each entry a hash of one key, the gate type, over what
that gate is told. A type may be named more than once.

    rule_gates:
      - daemons: [ sshd ]
      - message_regexp:
          - '^Invalid user .*? from %%%%SRC%%%%'
      - ban_var: [ SRC ]
      - country: { isnot: [ US ] }
      - mark: { name: brute_force, ttl: 21600 }

Each type is a class under this namespace named exactly as the type is
written... C<country> is L<App::Baphomet::Gate::country> and C<namtar_list>
is L<App::Baphomet::Gate::namtar_list>.

A gate is of one of two phases, going by what it reads, and each phase is
asked in the order the rule wrote it.

    - line :: Reads the line. Asked once per line, handed the line's
          L<passage|/THE PASSAGE>. It may turn the line away outright, lay
          fields down, make a offense, or refuse one. C<daemons>,
          C<message_regexp>, and C<gate> are of it.

    - offense :: Reads a offense the line made. Asked once per offense,
          handed the L<offense|/THE OFFENSE>. It may veto it, name its
          offenders, drop some of them, or brand them. C<country>,
          C<ban_var>, and C<mark> are of it.

A gate has three stages to its life. It is compiled once when its rule
loads, where what it is told is vetted and a rule that can not have it is
refused. It is bound once for each watcher the rule is on, where the names
it uses are resolved against that watcher's lists and it is handed what it
judges over. Then it is asked.

=head1 THE PASSAGE

What a gate of the line phase is handed, one per line per rule, made by
L<App::Baphomet::Rule/walk_line>. A hash of...

    - parsed :: The parsed line. The only key there is for a L</early>
          gate asked ahead of the rest.

    - scope :: What walls one watcher's correlation state off from
          another's, the watcher's name.

    - line_ctx :: The line context... C<now>, the line's C<seq> and
          C<source>, and the C<tracked> record store.

    - now :: The time of the line.

    - message :: The line's message, for the types that match on one.

    - fields :: The line's field space, when it has one... the fields of a
          json record, the fields of a access or error log line, or what
          C<message_json> and C<mungers> laid down. It may be shared between
          rules, so L</own_fields> is how a gate that writes to it gets a
          copy of its own.

    - rule :: What the rule is to a line, a hash of C<implicit>, true when
          the rule has no gate that makes the offense, so the line's fields
          are the offense once every gate has let them by, C<harvests>, true
          when it has a C<track> gate, and C<build_fields>, what builds the
          field space of a type whose parser hands none over.

    - own :: The line's own offense, once a gate has made it.

    - refused :: True once the line's own offense has been refused.

    - results :: Array ref of the offenses standing, the line's own first
          and then any a earlier line left waiting on this one.

=head1 THE OFFENSE

What a gate of the offense phase is handed. A hash of...

    - data :: The found data, every field and capture of the offense.

    - regexp :: Which entry of the matcher made it, or undef.

    - now :: The time of the line.

    - subjects :: Once named, array ref of what the offense counts against,
          each a hash of the C<var> that named it and its C<value>.

    - offenders :: Once named, array ref of the values a banning rule may
          banish. Empty for a detection rule.

    - set / lifted :: Array refs of the brands set on and lifted from it,
          each a hash of C<name> and C<key>.

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

    - internal :: A sub taking a value and returning true when it is one of
          the operator's own hosts.

    - brandable :: A sub taking a offender and returning true when it may be
          branded.

    - on_set / on_unset :: Subs told of each brand set and lifted, or undef.

C<marks> and C<resolver> hand the thing over when asked so a gate judges
over what is there at the time, not what was there when it was bound.

=head1 WRITING A TYPE

A type is a class under this namespace with this one as its parent, named
exactly as the type is written in a rule... C<my_gate> is
C<App::Baphomet::Gate::my_gate>. It has to have L</compile> and either
L</ask> or, for a gate of the offense phase that only judges, L</holds>. The
rest have defaults. A gate is a blessed hash, of which the keys C<type>,
C<where>, and C<context> are this class's.

=head1 METHODS

=head2 new

Makes a gate out of one C<rule_gates> entry, at rule load, handing what it
was told to the type's L</compile>. Called by L</compile_rule_gates>.

    - type :: The type name, for the messages.

    - args :: What the entry tells the gate, as the author wrote it.

    - where :: The lead in for the die messages, naming the gate and its
          rule.

    - rule :: The rule object the gate is for. It is still being built, so
          only what its def and its type answer is there to ask.

    my $gate = App::Baphomet::Gate::country->new(
        'type'  => 'country',
        'args'  => { 'isnot' => ['US'] },
        'where' => 'The country gate of the rule "syslog/sshd" (rule_gates entry 0)',
        'rule'  => $rule,
    );

=cut

sub new {
	my ( $class, %arg ) = @_;

	my $self = bless( { 'type' => $arg{type}, 'where' => $arg{where} }, $class );
	$self->compile( $arg{args}, $arg{where}, $arg{rule} );

	return $self;
}

=head2 compile

A type's own. Vets what the gate was told and keeps what it will judge by on
the object, dying on anything malformed, or on a rule that can not have the
gate, the passed C<$where> leading the message. Returns nothing.

    $gate->compile( $args, $where, $rule );

=head2 settle

Called once every gate of the rule is compiled, with the array ref of them
all in the order written, for what a gate can only check or take from the
gates beside it. Dies on a list the gate can not be in. Does nothing unless
the type says otherwise.

    $gate->settle( \@gates, $rule );

=cut

sub settle {
	return;
}

=head2 phase

Returns the phase the gate is of, C<line> or C<offense>. C<offense> unless
the type says otherwise.

    my $phase = $gate->phase;

=cut

sub phase {
	return 'offense';
}

=head2 ask

Asks the gate. One of the line phase is handed the L<passage|/THE PASSAGE>
and returns false to turn the line away outright, nothing below it then
being asked, else true. One of the offense phase is handed the
L<offense|/THE OFFENSE> and returns false to veto it, else true.

A gate of the offense phase that only judges need not have one. This one
asks its L</holds>, once of the offense for a gate of the result L</pass>,
and once of each offender for one of the offender pass, dropping the
offenders it does not hold for and vetoing a offense left with none of the
ones it had.

    if ( !$gate->ask($passage) ) { ... }

=cut

sub ask {
	my ( $self, $offense ) = @_;

	if ( $self->pass eq 'result' ) {
		return $self->holds( $offense->{data}, undef, $offense->{now} );
	}

	my $offenders = settle_offenders($offense);
	if ( !@{$offenders} ) {
		return 1;
	}
	my @survivors = grep { $self->holds( $offense->{data}, $_, $offense->{now} ) } @{$offenders};
	$offense->{offenders} = \@survivors;

	return @survivors ? 1 : 0;
} ## end sub ask

=head2 filter_line

What a gate of the line phase that only judges asks with, the type's own
L</passes> being the judgment. Every offense standing that the rule's own
gates have yet to judge is kept or dropped by it, one a earlier line left
already judged being let by. And while the line's own offense is still only
the fields it would be made of, those are judged, and the offense refused
when they do not pass. Always returns 1, as a gate that judges turns no line
away outright... a harvest below it still has its turn.

    sub ask { my ( $self, $passage ) = @_; return $self->filter_line($passage); }

=cut

sub filter_line {
	my ( $self, $passage ) = @_;

	my $results = $passage->{results};
	if ( defined($results) && @{$results} ) {
		my @kept;
		foreach my $offense ( @{$results} ) {
			if ( $offense->{judged} || $self->passes( $offense->{data}, $passage ) ) {
				push( @kept, $offense );
			} elsif ( defined( $passage->{own} ) && $offense == $passage->{own} ) {
				$passage->{refused} = 1;
			}
		}
		$passage->{results} = \@kept;
	} ## end if ( defined($results) && @{$results} )

	if ( !defined( $passage->{own} ) && !$passage->{refused} ) {
		my $fields = passage_fields($passage);
		if ( defined($fields) && !$self->passes( $fields, $passage ) ) {
			$passage->{refused} = 1;
		}
	}

	return 1;
} ## end sub filter_line

=head2 passes

A type's own, for a gate of the line phase that asks by L</filter_line>.
Judges one data hash, the fields of a offense or of the line, handed the
passage beside it. Returns true when it passes.

    if ( $gate->passes( $data, $passage ) ) { ... }

=head2 of_types

Dies, the passed C<$where> leading the message, unless the rule is of one of
the passed types... how a gate refuses a rule whose lines do not have what
it reads.

    $gate->of_types( $rule, $where, 'syslog', 'raw' );

=cut

sub of_types {
	my ( $self, $rule, $where, @types ) = @_;

	my $rule_type = $rule->type;
	if ( !grep { $_ eq $rule_type } @types ) {
		die( $where . ' is on a ' . $rule_type . ' rule, and only a ' . join( ' or ', @types ) . ' rule can have one' );
	}

	return;
} ## end sub of_types

=head2 holds

A type's own, for a gate of the offense phase that only judges. Judges one
offense, C<$data> being the found data and C<$now> the time of the line.
C<$ip> is the candidate offender for a gate of the offender pass, and undef
for one of the result pass. Returns 1 when the gate holds, else 0. What can
not be answered has to fail closed.

    if ( $gate->holds( $data, $ip, $now ) ) { ... }

=head2 pass

For a gate that judges by L</holds>, returns what it is asked of...
C<result> for one keyed by a C<var> or C<vars>, asked once of the offense,
and C<offender> for one keyed by neither, asked once of each offender. A
type that keys some other way overrides it.

    my $pass = $gate->pass;

=cut

sub pass {
	my ($self) = @_;

	return ( defined( $self->{var} ) || defined( $self->{vars} ) ) ? 'result' : 'offender';
}

=head2 reads_offenders

Returns true when the gate reads the offenders of a offense, and so has to
have a C<ban_var> above it. True for a gate of the offense phase whose
L</pass> is C<offender>, unless the type says otherwise.

    if ( $gate->reads_offenders ) { ... }

=cut

sub reads_offenders {
	my ($self) = @_;

	return ( $self->phase eq 'offense' && $self->pass eq 'offender' ) ? 1 : 0;
}

=head2 idle

Returns true for a gate there is nothing to ask of, one that is only there
for a gate beside it to read, or one told to do nothing. It is then left out
when the rule is bound. False unless the type says otherwise.

    if ( $gate->idle ) { ... }

=cut

sub idle {
	return 0;
}

=head2 once

Returns true for a type a rule can name only once, as its one matcher is.
False unless the type says otherwise.

    if ( $gate->once ) { ... }

=cut

sub once {
	return 0;
}

=head2 early

Returns true for a gate of the line phase that reads nothing of the passage
but the parsed line and does nothing but turn the line away. The ones that
lead a rule's list are asked before the rest of the passage is made, which
most lines a rule is offered then never need. False unless the type says
otherwise.

    if ( $gate->early ) { ... }

=cut

sub early {
	return 0;
}

=head2 always

Returns true for a gate of the line phase that is asked though no offense
stands, as the harvest of a tracked record is. False unless the type says
otherwise.

    if ( $gate->always ) { ... }

=cut

sub always {
	return 0;
}

=head2 needs

Returns the list of the L<context|/THE CONTEXT> keys the gate can not judge
with out. A empty list unless the type says otherwise.

    foreach my $need ( $gate->needs ) { ... }

=cut

sub needs {
	return ();
}

=head2 wants

Returns the list of the L<context|/THE CONTEXT> keys the gate uses when they
are there and does with out when they are not. A empty list unless the type
says otherwise.

    foreach my $want ( $gate->wants ) { ... }

=cut

sub wants {
	return ();
}

=head2 bound

Returns the gate bound over a context... a copy holding the context keys it
L</needs> and L</wants> under its C<context> key, or the gate itself when it
names none. A type that resolves names against a watcher's lists overrides
this to do so, dying on a name the context does not define, the passed
C<$where> leading the message.

    my $bound = $gate->bound( \%context, 'The rule "syslog/sshd" of the watcher "auth"' );

=cut

sub bound {
	my ( $self, $context, $where ) = @_;

	my @held = ( $self->needs, $self->wants );
	if ( !@held ) {
		return $self;
	}

	return bless( { %{$self}, 'context' => { map { $_ => $context->{$_} } @held } }, ref($self) );
} ## end sub bound

=head2 list_slots

Returns the list file slots a bound gate reads, for the galla to load and
keep fresh, each as L<App::Baphomet::Namtar/namtar_slots> gives one. A empty
list unless the type says otherwise.

    foreach my $slot ( $gate->list_slots ) { ... }

=cut

sub list_slots {
	return ();
}

=head2 sweep_state

Drops whatever state the gate holds that has expired as of the passed time.
Called from the rule's own sweep, so expiry does not depend on traffic.
Does nothing unless the type says otherwise.

    $gate->sweep_state($now);

=cut

sub sweep_state {
	return;
}

=head1 FUNCTIONS

=head2 gate_class

Returns the class of a gate type, loading it on first asking. Dies, the
passed C<$where> leading the message, on a name that is not a type name, on
a type there is no class for, and on a class that is not a
C<App::Baphomet::Gate>. The name has to be lower case words joined by
C<_>, so nothing from outside this namespace can be named.

    my $class = gate_class( 'namtar_list', $where );    # App::Baphomet::Gate::namtar_list

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
	my $class = 'App::Baphomet::Gate::' . $type;
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
not a hash of one key, a type that does not load, a type with nothing to be
asked by, whatever a type's own L</compile> or L</settle> refuses, a second
gate of a type a rule can name
L</once>, and a gate that reads the offenders of a offense with nothing
above it to name them.

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
	# the type that has named who a offense counts against by this point in
	# the list, ban_var or detection_var, or undef while nothing has
	my $named_by;
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

		# a phase that is neither would leave the gate in a list nothing
		# asks, so a rule the author gated would count ungated... better
		# found now than never
		my $phase = $gate->phase;
		if ( $phase ne 'line' && $phase ne 'offense' ) {
			die( $where . ' is of the phase "' . $phase . '", which is neither line nor offense' );
		}

		# a gate that is asked has to have something to be asked by... a ask
		# of its own or, for one of the offense phase, the holds this class's
		# ask judges by. found now, as it is otherwise found by the first
		# line to reach the gate
		if ( !$gate->idle && $gate->can('ask') == \&ask && ( $phase ne 'offense' || !$gate->can('holds') ) ) {
			die(      $where
					. ' is of a type with no '
					. ( $phase eq 'offense' ? 'ask or holds' : 'ask' )
					. ' method, so it can not be asked' );
		}

		# a gate that reads the offenders has to have them named above it, and
		# a detection rule names none at all, so such a gate would never be
		# asked of anyone
		if ( $gate->reads_offenders ) {
			if ( defined($named_by) && $named_by eq 'detection_var' ) {
				die( $where
						. ' keys on the offender, which a detection rule does not have... name a var for it to check' );
			}
			if ( !defined($named_by) ) {
				die( $where . ' keys on the offender, and no ban_var above it names one' );
			}
		}
		if ( $type eq 'ban_var' || $type eq 'detection_var' ) {
			if ( defined($named_by) ) {
				die( $where . ' comes after a ' . $named_by . ', and a rule names who it counts against once' );
			}
			$named_by = $type;
		}
		if ( $gate->once && grep { $_->{type} eq $type } @gates ) {
			die( $where . ' is the second ' . $type . ' gate of the rule, which can have the one' );
		}

		push( @gates, $gate );
	} ## end foreach my ( $entry_int, $entry ) ( indexed @{$rule_gates...})

	foreach my $gate (@gates) {
		$gate->settle( \@gates, $rule );
	}

	return \@gates;
} ## end sub compile_rule_gates

=head2 bind_rule_gates

Binds a rule's gates over a context and sorts them by phase, each phase
keeping the order of the list. Dies, the passed C<$where> leading the
message, on a gate that L</needs> something the context does not have, and
on whatever a gate's own L</bound> refuses. A L</idle> gate is left out, and
nothing else ever is, as a gate left out is a rule counting what its author
gated off.

    - gates :: Array ref of the gates, as L</compile_rule_gates> returns.

    - context :: The L<context|/THE CONTEXT>.

    - where :: The lead in for the die messages, naming the rule and what it
          is being bound for.

Returns a hash ref of C<line> and C<offense>, each a array ref of the bound
gates of that phase, either possibly empty, C<early>, how many of the gates
leading C<line> are L</early> ones, and C<last_always>, the place in C<line>
of the last gate that is asked though no offense stands, -1 when there is
none.

    my $bound = bind_rule_gates( $gates, \%context, 'The rule "syslog/sshd" of the watcher "auth"' );

=cut

sub bind_rule_gates {
	my ( $gates, $context, $where ) = @_;

	my %bound = ( 'line' => [], 'offense' => [], 'early' => 0, 'last_always' => -1 );
	foreach my $gate ( @{$gates} ) {
		if ( $gate->idle ) {
			next;
		}
		my @unmet = grep { !defined( $context->{$_} ) } $gate->needs;
		if (@unmet) {
			die(      $where
					. ' has a '
					. $gate->{type}
					. ' gate, which can not judge with out '
					. join( ', ', @unmet )
					. ', and there is none here' );
		}
		my $phase = $gate->phase;
		push( @{ $bound{$phase} }, $gate->bound( $context, $where ) );
		if ( $phase eq 'line' && $gate->always ) {
			$bound{last_always} = $#{ $bound{line} };
		}
		if ( $phase eq 'line' && $gate->early && $bound{early} == $#{ $bound{line} } ) {
			$bound{early}++;
		}
	} ## end foreach my $gate ( @{$gates} )

	return \%bound;
} ## end sub bind_rule_gates

=head2 line_walk_of

Returns what L<App::Baphomet::Rule/walk_line> takes for a rule's
gates as they are, unbound... the gates of the line phase, which need
nothing of a context, in the order of the list, a L</idle> one left out,
with C<early> and C<last_always> as L</bind_rule_gates> gives them. For
checking a line against a rule with no watcher behind it.

    my $line_walk = line_walk_of($gates);
    my $offenses  = $rule->walk_line( $line_walk, $parsed, $scope, $line_ctx );

=cut

sub line_walk_of {
	my ($gates) = @_;

	my %line_walk = ( 'line' => [], 'early' => 0, 'last_always' => -1 );
	foreach my $gate ( @{$gates} ) {
		if ( $gate->idle || $gate->phase ne 'line' ) {
			next;
		}
		push( @{ $line_walk{line} }, $gate );
		if ( $gate->always ) {
			$line_walk{last_always} = $#{ $line_walk{line} };
		}
		if ( $gate->early && $line_walk{early} == $#{ $line_walk{line} } ) {
			$line_walk{early}++;
		}
	} ## end foreach my $gate ( @{$gates} )

	return \%line_walk;
} ## end sub line_walk_of

=head2 walk_offense

Takes one offense down the gates of the offense phase, in order. Returns 1
when it is left standing, 0 when a gate vetoed it, the gates below that one
not being asked.

    if ( walk_offense( $bound, $offense ) ) { ... }

=cut

sub walk_offense {
	my ( $bound, $offense ) = @_;

	foreach my $gate ( @{ $bound->{offense} } ) {
		if ( !$gate->ask($offense) ) {
			return 0;
		}
	}

	return 1;
} ## end sub walk_offense

=head2 stand

Returns the array ref of the offenses standing in a passage, first making
the line's own out of its fields when the rule leaves that to them... a
rule with no gate that makes the offense, whose every gate let the fields
by.

    foreach my $offense ( @{ stand($passage) } ) { ... }

=cut

sub stand {
	my ($passage) = @_;

	if ( $passage->{rule}{implicit} && !defined( $passage->{own} ) && !$passage->{refused} ) {
		my $fields = passage_fields($passage);
		if ( defined($fields) ) {
			$passage->{own} = { 'data' => { %{$fields} }, 'regexp' => undef };
			unshift( @{ $passage->{results} //= [] }, $passage->{own} );
		} else {
			$passage->{refused} = 1;
		}
	}

	return $passage->{results} // [];
} ## end sub stand

=head2 passage_fields

Returns the field space of a passage's line, building it on first asking for
a type whose parser hands none over. undef for a line with none.

    my $fields = passage_fields($passage);

=cut

sub passage_fields {
	my ($passage) = @_;

	if ( !defined( $passage->{fields} ) && defined( $passage->{rule}{build_fields} ) ) {
		$passage->{fields}       = $passage->{rule}{build_fields}->( $passage->{parsed} );
		$passage->{fields_owned} = 1;
	}

	return $passage->{fields};
} ## end sub passage_fields

=head2 own_fields

Returns the field space of a passage's line as a hash the rule alone holds,
copying it first when it is one every rule on the line shares. For a gate
that writes to the fields, as a tracked record lifted into them is. undef
for a line with none.

    my $fields = own_fields($passage);

=cut

sub own_fields {
	my ($passage) = @_;

	my $fields = passage_fields($passage);
	if ( defined($fields) && !$passage->{fields_owned} ) {
		$fields                  = { %{$fields} };
		$passage->{fields}       = $fields;
		$passage->{fields_owned} = 1;
	}

	return $fields;
} ## end sub own_fields

=head2 passage_envelope

Returns the syslog envelope of a passage's line, the reserved C<syslog.*>
fields a correlation key may name beside the captures, building it on first
asking.

    my $envelope = passage_envelope($passage);

=cut

sub passage_envelope {
	my ($passage) = @_;

	my $parsed = $passage->{parsed};
	$passage->{envelope} //= {
		'syslog.daemon' => $parsed->{daemon},
		'syslog.host'   => $parsed->{hostname},
		'syslog.pid'    => $parsed->{pid},
	};

	return $passage->{envelope};
} ## end sub passage_envelope

=head2 settle_offenders

Returns the array ref of a offense's offenders, settling them out of its
subjects on first asking... any hostname among them handled as the offense's
C<usedns> sub has it, when it has one, and each value kept once however many
vars named it. A empty one for a offense with out subjects.

    my $offenders = settle_offenders($offense);

=cut

sub settle_offenders {
	my ($offense) = @_;

	if ( !defined( $offense->{offenders} ) ) {
		my $subjects = $offense->{subjects} // [];
		if ( defined( $offense->{usedns} ) && @{$subjects} ) {
			$subjects = [ $offense->{usedns}->($subjects) ];
			$offense->{subjects} = $subjects;
		}
		$offense->{offenders} = [ uniqstr( map { $_->{value} } @{$subjects} ) ];
	}

	return $offense->{offenders};
} ## end sub settle_offenders

1;
