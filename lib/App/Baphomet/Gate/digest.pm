package App::Baphomet::Gate::digest;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Digest::SHA          qw( hmac_sha256_hex );
use App::Baphomet::Gate  qw( own_fields passage_fields );
use App::Baphomet::Shape qw( check_hash );

our @EXPORT_OK = qw( digest_of );

=head1 NAME

App::Baphomet::Gate::digest - The digest gate, putting a keyed hash of a value in its place.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - digest: { var: USER }
      - after: { by: USER, count: 20, seconds: 600 }
      - ban_var: [ SRC ]

=head1 DESCRIPTION

Puts a keyed hash of a found value in place of it, so a rule can still key
and count on a account or a address of mail while the brands, the tracked
records, the counts, and the tablets they are kept in hold no plaintext. The
one name always comes to the one hash under the one key, so nothing that
keys on it is the worse for it. Without the key, the hash is no way back to
the name.

It reads what stands when it is asked... a offense when one has been made
above it, or the line's fields while there is none yet. Written above the
matcher it hashes the field, which the offense is then made of. Written
below, the offense's value.

Gates of the line phase above it see the value as it was, and those below,
and every gate of the offense phase, the hash. So a gate that has to read
the name, as a C<account> gate does, needs a C<into> to keep the name
beside the hash, and a rule hashing in place what such a gate reads does
not load. Nor does one hashing a var a C<ban_var> names, as a ban has to be
of the address itself.

The hash is the first 16 hex digits of a HMAC-SHA256 under the C<digest_key>
of the config. Every galla of a fleet has to have the one key, for the
brands they share to agree, and a new key is a new hash for every value, so
what the hashes were kept under is then forgotten.

It does not keep the value out of the EVE log, whose events carry the line
it was found in. A rule's C<eve_line> of false leaves the line out of them.

A entry is told...

    - var :: The found var to hash.

    - into :: Optional. The found var the hash goes into, the C<var> being
          left as it was. With out it the C<var> is hashed where it is.

It needs the C<digest_key> of the L<context|App::Baphomet::Gate/THE CONTEXT>.

=cut

my $SHAPE = {
	'required' => { 'var'  => 'string' },
	'optional' => { 'into' => 'string' },
};

# the gates of the offense phase that read a var by name and have to read the
# value itself, the key of their args naming it
my %READS_PLAINTEXT = ( 'account' => 'var', 'namtar_list' => 'var' );

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	$self->{var}  = $args->{var};
	$self->{into} = $args->{into} // $args->{var};

	return;
} ## end sub compile

=head2 settle

Dies on a hash that a C<ban_var> of the rule names, and on a value hashed in
place that a C<account> or C<namtar_list> gate reads, which would only ever
see the hash.

    $gate->settle( \@gates, $rule );

=cut

sub settle {
	my ( $self, $gates ) = @_;

	foreach my $gate ( @{$gates} ) {
		if ( $gate->{type} eq 'ban_var' && grep { $_ eq $self->{into} } @{ $gate->{names} } ) {
			die(      $self->{where}
					. ' hashes '
					. $self->{into}
					. ', which a ban_var names, and a ban has to be of the address itself' );
		}
		my $read_key = $READS_PLAINTEXT{ $gate->{type} };
		if ( $self->{into} eq $self->{var} && defined($read_key) && ( $gate->{$read_key} // '' ) eq $self->{var} ) {
			die(      $self->{where}
					. ' hashes '
					. $self->{var}
					. ' where it is, and the '
					. $gate->{type}
					. ' gate that reads it would only ever see the hash... give it a into' );
		}
	} ## end foreach my $gate ( @{$gates} )

	return;
} ## end sub settle

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 needs

Returns C<digest_key>.

=cut

sub needs {
	return ('digest_key');
}

=head2 ask

Hashes the value in each offense standing, or in the line's fields while
there is none. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	my @targets = map { $_->{data} } @{ $passage->{results} // [] };
	if ( !@targets && !defined( $passage->{own} ) && !$passage->{refused} ) {
		my $fields = passage_fields($passage);
		if ( defined($fields) && defined( $fields->{ $self->{var} } ) ) {
			# writes to the fields, which every rule on the line may share
			@targets = ( own_fields($passage) );
		}
	}

	my $key = $self->{context}{digest_key};
	foreach my $data (@targets) {
		my $value = $data->{ $self->{var} };
		if ( !defined($value) || ref($value) ne '' ) {
			next;
		}
		$data->{ $self->{into} } = digest_of( $value, $key );
	}

	return 1;
} ## end sub ask

=head1 FUNCTIONS

=head2 digest_of

Returns the hash a value comes to under a key, the first 16 hex digits of
its HMAC-SHA256.

    my $hash = digest_of( 'neti', $key );    # '6a1f0c2b9e4d7a35'

=cut

sub digest_of {
	my ( $value, $key ) = @_;

	return substr( hmac_sha256_hex( $value, $key ), 0, 16 );
}

1;
