package App::Baphomet::Gate::normalize;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use parent 'App::Baphomet::Gate';
use Ref::Util            qw( is_plain_arrayref );
use App::Baphomet::Gate  qw( own_fields passage_fields );
use App::Baphomet::Shape qw( check_hash );

our @EXPORT_OK = qw( normalize_path );

=head1 NAME

App::Baphomet::Gate::normalize - The normalize gate, lifting the path a server would make of a request.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    rule_gates:
      - normalize: { var: path, into: PATH, ops: [ url, dot_segment, slashes, lower ] }
      - match:
          - field: PATH
            regexp: '/wp-(?:login|signup|admin)\.php$'
      - ban_var: [ host ]

=head1 DESCRIPTION

Lifts a copy of a request path into a found var, made the way a server
makes it before it looks for the file, so a rule matching on the copy is
not got round by writing the one path another way... C</%77p-login.php>,
C<//wp-login.php>, and C</x/../wp-login.php> are all C</wp-login.php>. The
path it was given is left as it was, so the event still says what was sent.

It reads what stands when it is asked... a offense when one has been made
above it, or the line's fields while there is none yet. Written above a
C<match>, the match reads the copy.

The path is split from its query at the first C<?> or C<#> ahead of
anything else, as a server splits it, and the steps run over the path
alone. Each is only done when it is named, and they are always done in the
order below, whatever order they are named in, as a step done ahead of the
one it depends on would leave what it was for standing. A server that does
less to a path than a rule does to it answers a error where the rule sees a
hit, so name only what the server does.

    - url :: Percent decoding, done again while it changes things, three
          times at the most... C<%2577> is C<%77> once and C<w> twice.

    - overlong :: The overlong UTF-8 forms of a ASCII byte, as C<%c0%af> for
          C</>, and IIS's C<%u002f> form, made the byte they stand for.

    - nul :: Everything from a NUL on cut off, as a backend that reads a
          path as a C string does.

    - backslash :: Each C<\> made a C</>, as IIS takes it.

    - slashes :: Each run of C</> made one.

    - params :: The C<;name=value> parameters of each segment cut off, as
          Tomcat's C</admin;x=1/> is C</admin/>.

    - dot_segment / dot_segment_below :: Never both. The C<.> and C<..>
          segments resolved. C<dot_segment> does it as a server does, a C<..>
          that would climb above C</> being dropped, so C</../../etc/passwd>
          is C</etc/passwd>. C<dot_segment_below> keeps such a C<..>, so it
          is C</../../etc/passwd> still and a rule can see it tried to.

    - lower :: Lower case, for a server that does not tell the cases apart.

    - query :: The query left off. With out it the query is put back after
          the path as it was given.

A value that is not a string lifts nothing, and a lifted copy is never put
over a value already there.

A entry is told...

    - var :: The found var holding the path.

    - into :: The found var the copy is lifted into.

    - ops :: The steps to do, a array of the names above.

=cut

# the steps, in the order they are done in
my @OP_ORDER  = qw( url overlong nul backslash slashes params dot_segment dot_segment_below lower query );
my %KNOWN_OPS = map { $_ => 1 } @OP_ORDER;

my $SHAPE = {
	'required' => {
		'var'  => 'string',
		'into' => 'string',
		'ops'  => {
			'each' => { 'in' => \@OP_ORDER },
			'min'  => 1,
			'says' => 'a non-empty array of ' . join( ', ', @OP_ORDER ),
		},
	},
};

=head1 METHODS

=head2 compile

Vets what the gate was told and keeps it, the steps as a set. Dies on a step
named twice and on both kinds of C<dot_segment>.

    $gate->compile( $args, $where );

=cut

sub compile {
	my ( $self, $args, $where ) = @_;

	check_hash( $args, $SHAPE, $where );

	my %ops;
	foreach my $op ( @{ $args->{ops} } ) {
		if ( $ops{$op}++ ) {
			die( $where . ' names the op ' . $op . ' twice' );
		}
	}
	if ( $ops{dot_segment} && $ops{dot_segment_below} ) {
		die( $where . ' names both dot_segment and dot_segment_below, which resolve a .. above / two ways' );
	}

	$self->{var}  = $args->{var};
	$self->{into} = $args->{into};
	$self->{ops}  = \%ops;

	return;
} ## end sub compile

=head2 phase

Returns C<line>.

=cut

sub phase {
	return 'line';
}

=head2 ask

Lifts the copy into each offense standing, or into the line's fields while
there is none. Always returns 1.

    $gate->ask($passage);

=cut

sub ask {
	my ( $self, $passage ) = @_;

	my @targets = map { $_->{data} } @{ $passage->{results} // [] };
	if ( !@targets && !defined( $passage->{own} ) && !$passage->{refused} ) {
		my $fields = passage_fields($passage);
		if ( defined($fields) && defined( $fields->{ $self->{var} } ) ) {
			# a lift writes to the fields, which every rule on the line may
			# share
			@targets = ( own_fields($passage) );
		}
	}

	foreach my $data (@targets) {
		my $path = $data->{ $self->{var} };
		if ( !defined($path) || ref($path) ne '' || exists( $data->{ $self->{into} } ) ) {
			next;
		}
		$data->{ $self->{into} } = normalize_path( $path, $self->{ops} );
	}

	return 1;
} ## end sub ask

=head1 FUNCTIONS

=head2 normalize_path

Returns a path made over by the steps named, in the order the gate does
them.

    - path :: The path as it was sent, its query and all.

    - ops :: Hash ref whose keys are the names of the steps to do.

    my $path = normalize_path( '/x/..//%77P-login.php?a=1', { 'url' => 1, 'dot_segment' => 1, 'slashes' => 1, 'lower' => 1 } );
    # '/wp-login.php?a=1'

=cut

sub normalize_path {
	my ( $path, $ops ) = @_;

	# the path is split from its query ahead of anything else, as a server
	# splits it, so a %3f in it is never taken for the start of one
	my ( $target, $query ) = $path =~ /^([^?#]*)(.*)\z/s;

	if ( $ops->{url} ) {
		foreach my $round ( 1 .. 3 ) {
			my $decoded = $target =~ s/%([0-9A-Fa-f]{2})/chr( hex($1) )/ger;
			if ( $decoded eq $target ) {
				last;
			}
			$target = $decoded;
		}
	}

	if ( $ops->{overlong} ) {
		# a ASCII byte, written as IIS's %u or as a UTF-8 form longer than it
		# needs, in two bytes or in three
		$target =~ s/%u00([0-7][0-9A-Fa-f])/chr( hex($1) )/ge;
		$target =~ s/([\xc0\xc1])([\x80-\xbf])/chr( ( ( ord($1) & 0x1f ) << 6 ) | ( ord($2) & 0x3f ) )/ge;
		$target =~ s/\xe0\x80([\x80-\xbf])/chr( ord($1) & 0x3f )/ge;
	}

	if ( $ops->{nul} ) {
		$target =~ s/\0.*\z//s;
	}
	if ( $ops->{backslash} ) {
		$target =~ tr{\\}{/};
	}
	if ( $ops->{slashes} ) {
		$target =~ s{/{2,}}{/}g;
	}
	if ( $ops->{params} ) {
		$target =~ s{;[^/]*}{}g;
	}

	if ( $ops->{dot_segment} || $ops->{dot_segment_below} ) {
		my $rooted   = $target =~ m{^/} ? 1 : 0;
		my @segments = split( m{/}, $target, -1 );
		if ($rooted) {
			shift(@segments);
		}

		# a . is nothing, a .. takes back the segment before it, and one with
		# nothing to take back is dropped, or kept to show it was there
		my @kept;
		foreach my $int ( 0 .. $#segments ) {
			my $segment = $segments[$int];
			my $last    = $int == $#segments;
			if ( $segment eq '.' || $segment eq '..' ) {
				if ( $segment eq '..' ) {
					if ( @kept && $kept[-1] ne '..' ) {
						pop(@kept);
					} elsif ( $ops->{dot_segment_below} ) {
						push( @kept, '..' );
					}
				}
				# a path that ends in one of them ends in a /
				if ($last) {
					push( @kept, '' );
				}
				next;
			} ## end if ( $segment eq '.' || $segment eq '..' )
			push( @kept, $segment );
		} ## end foreach my $int ( 0 .. $#segments )
		$target = ( $rooted ? '/' : '' ) . join( '/', @kept );
	} ## end if ( $ops->{dot_segment} || $ops->{dot_segment_below...})

	if ( $ops->{lower} ) {
		$target = lc($target);
	}

	return $ops->{query} ? $target : $target . $query;
} ## end sub normalize_path

1;
