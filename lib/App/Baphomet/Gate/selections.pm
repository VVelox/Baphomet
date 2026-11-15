package App::Baphomet::Gate::selections;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use List::Util                  qw( any );
use Ref::Util                   qw( is_plain_hashref );
use App::Baphomet::Rules::Gates qw( compile_gates );

=head1 NAME

App::Baphomet::Gate::selections - The selections gate, the named field test lists a condition folds.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - selections:
          login: [ { field: event, values: [ login ] } ]
          admin: [ { field: user, values: [ root, admin ] } ]
      - condition: login and not admin

=head1 DESCRIPTION

Names the field test lists a C<condition> gate folds into one judgment, the
boolean form of what C<gate> says flat. It judges nothing itself and is not
asked... the C<condition> beside it is what is.

It is told a hash of selection name to a list as C<gate> takes. A name is a
plain identifier, and none of the words a condition reads as its own. A rule
with one has to have a C<condition>, and can not have a C<gate>.

=head1 METHODS

=head2 compile

Vets the names and compiles each list, keeping them under C<compiled>.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	if ( !is_plain_hashref($args) || !%{$args} ) {
		die( $where . ' is not a non-empty table' );
	}

	my %compiled;
	foreach my $selection_name ( sort( keys( %{$args} ) ) ) {
		if (   $selection_name !~ /^[A-Za-z_][A-Za-z0-9_]*$/
			|| $selection_name =~ /^(?:and|or|not|of|them|all)$/i )
		{
			die( $where . ' has the selection name "' . $selection_name . '", which is not a plain identifier' );
		}
		$compiled{$selection_name}
			= compile_gates( $args->{$selection_name}, $where . ' selection "' . $selection_name . '"' );
	}
	$self->{compiled} = \%compiled;

	return;
} ## end sub compile

=head2 settle

Dies when the rule has no C<condition> gate to fold the selections.

=cut

sub settle {
	my ( $self, $gates ) = @_;

	if ( !any { $_->{type} eq 'condition' } @{$gates} ) {
		die( $self->{where} . ' has no condition gate beside it to fold the selections' );
	}

	return;
}

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 once

Returns 1, the one condition reading the one table.

=cut

sub once {
	return 1;
}

=head2 idle

Returns 1, there being nothing to ask of it.

=cut

sub idle {
	return 1;
}

1;
