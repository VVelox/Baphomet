package App::Baphomet::Gate::extract;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use App::Baphomet::Gate          qw( own_fields passage_fields );
use App::Baphomet::Rules::Tokens qw( compile_tokened_regexp match_tokened );
use App::Baphomet::Shape         qw( check_hash );

=head1 NAME

App::Baphomet::Gate::extract - The extract gate, capturing out of any field into found vars.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - extract: { var: user, regexp: '@(?<DOMAIN>[^@]+)$' }
      - after: { by: DOMAIN, count: 50, seconds: 600 }
      - ban_var: [ ip ]

=head1 DESCRIPTION

Matches a regexp against a field and lifts what its named captures took
into found vars. C<message_regexp> only ever reads the message, and the
C<re> op of a C<gate> tests a field and keeps nothing of it, so this is how
a rule takes the domain out of a address, or a part of a path out of a
request, to key or count on.

It reads what stands when it is asked... a offense when one has been made
above it, its captures and all, or the line's fields while there is none
yet. Written above the matcher it lifts into the fields, which the offense
is then made of. Written below, into the offense. A capture is never lifted
over a value already there.

A field the regexp does not match, or that is not there, lifts nothing, and
the gate lets the line by unless C<on_miss> says to turn it away.

A entry is told...

    - var :: The field to match against.

    - regexp :: The regexp, with named captures for what to lift. It may use
          the tokens C<message_regexp> does.

    - on_miss :: Optional. What a field it does not match does, C<pass> or
          C<fail>.
        Default :: pass

=cut

my $SHAPE = {
	'required' => { 'var'     => 'string', 'regexp' => 'string' },
	'optional' => { 'on_miss' => { 'in' => [qw( pass fail )], 'says' => 'one of pass or fail' } },
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it with the regexp compiled. Dies on a
regexp that does not compile and on one with no named capture, which would
lift nothing.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{var}     = $args->{var};
	$self->{on_miss} = $args->{on_miss} // 'pass';
	$self->{entry}   = compile_tokened_regexp( $args->{regexp}, $where . ' regexp' );

	# a capture is named (?<NAME>...) or (?'NAME'...), whether written so or
	# made so by a token
	if ( $self->{entry}{regexp} !~ /\(\?(?:<[A-Za-z_]|'[A-Za-z_])/ ) {
		die( $where . ' has a regexp with no named capture, which would lift nothing' );
	}

	return;
} ## end sub compile

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 ask

Lifts the captures of the regexp into each offense standing, or into the
line's fields while there is none. Returns 0 to turn the line away when
nothing matched and C<on_miss> is C<fail>, else 1.

    if ( !$gate->ask($passage) ) { ... }

=cut

sub ask {
	my ( $self, $passage ) = @_;

	# the offenses standing, or the line's fields while there are none, each
	# lifted into by itself
	my @targets = map { $_->{data} } @{ $passage->{results} // [] };
	if ( !@targets && !defined( $passage->{own} ) && !$passage->{refused} ) {
		my $fields = passage_fields($passage);
		if ( defined($fields) && defined( $fields->{ $self->{var} } ) ) {
			# a lift writes to the fields, which every rule on the line may
			# share
			@targets = ( own_fields($passage) );
		}
	}

	my $matched = 0;
	foreach my $data (@targets) {
		my $value = $data->{ $self->{var} };
		if ( !defined($value) || ref($value) ne '' ) {
			next;
		}

		# a token written twice captures under a alias each time, which this
		# folds back to the name
		my $captured = match_tokened( $self->{entry}, $value );
		if ( !defined($captured) ) {
			next;
		}
		$matched = 1;
		foreach my ( $name, $captured_value ) ( %{$captured} ) {
			if ( defined($captured_value) && !exists( $data->{$name} ) ) {
				$data->{$name} = $captured_value;
			}
		}
	} ## end foreach my $data (@targets)

	return ( $matched || $self->{on_miss} eq 'pass' ) ? 1 : 0;
} ## end sub ask

1;
