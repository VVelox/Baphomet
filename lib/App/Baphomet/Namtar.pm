package App::Baphomet::Namtar;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Exporter              qw( import );
use App::Baphomet::Config qw( compile_ignore_ips ip_ignored );

our @EXPORT_OK = qw( namtar_slots namtar_set namtar_listed );

=head1 NAME

App::Baphomet::Namtar - The namtar lists' pure core, drivable over any loaded lists.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Namtar qw( namtar_slots namtar_set namtar_listed );

    my @slots = namtar_slots( $named_lists{threatfeed} );

    my %files;
    foreach my $slot (@slots) {
        $files{ $slot->{key} } = { 'set' => namtar_set( $slot, \@lines_of_the_file ) };
    }

    if ( namtar_listed( \%files, \@slots, $value ) ) { ... }

=head1 DESCRIPTION

What a named list comes to and how a value is found on one, apart from the
galla so it runs over any loaded lists... the galla passes the files it
reads and refreshes as they change, while a test passes sets it compiled
from lines of its own. Nothing here reads a file, watches a mtime, or knows
of config. The gate that judges by these is
L<App::Baphomet::Gate::NamtarList>.

A named list comes to one B<slot> per file it names, a hash of...

    - key :: What the loaded lists hold the slot's file under.

    - type :: How the file is read, C<cidr> or C<string>.

    - nocase :: If a C<string> one is matched with out regard to case.

    - path :: The file.

A file read as C<cidr> and the same one read as C<string> are two slots, so
they stay independent. The loaded lists are a hash of slot key to a hash
holding that slot's compiled C<set>, with whatever else the holder keeps
beside it.

=head1 FUNCTIONS

=head2 namtar_slots

Returns the slots of one named list, a slot per file it names in the order
it names them. The list is as
L<App::Baphomet::Config/resolve_namtar_lists> resolves one, a hash of
C<type>, C<nocase>, and C<paths>.

    my @slots = namtar_slots( $named_lists{threatfeed} );

=cut

sub namtar_slots {
	my ($list) = @_;

	my @slots;
	foreach my $path ( @{ $list->{paths} } ) {
		push(
			@slots,
			{
				'key'    => join( "\0", $list->{type}, $list->{nocase}, $path ),
				'type'   => $list->{type},
				'nocase' => $list->{nocase},
				'path'   => $path,
			}
		);
	} ## end foreach my $path ( @{ $list->{paths} } )

	return @slots;
} ## end sub namtar_slots

=head2 namtar_set

Compiles the lines of one list file into the set its slot is matched
against. A line is one entry, with anything from a C<#> on dropped as a
comment, the whitespace around it trimmed, and a line left blank skipped. A
C<string> slot compiles to a hash of its entries, folded to lower case under
C<nocase>, and a C<cidr> slot to what
L<App::Baphomet::Config/compile_ignore_ips> makes of them. Dies on a C<cidr>
entry that is not a address or a CIDR... a feed is not config, so what a bad
one means is the caller's to decide.

    my $set = namtar_set( $slot, \@lines );

=cut

sub namtar_set {
	my ( $slot, $lines ) = @_;

	my @entries;
	foreach my $line ( @{$lines} ) {
		my $entry = $line;
		$entry =~ s/#.*$//;
		$entry =~ s/^\s+|\s+$//g;
		if ( $entry ne '' ) {
			push( @entries, $entry );
		}
	}

	if ( $slot->{type} ne 'string' ) {
		return compile_ignore_ips( \@entries, 'namtar list "' . $slot->{path} . '"' );
	}

	my %set;
	foreach my $entry (@entries) {
		$set{ $slot->{nocase} ? lc($entry) : $entry } = 1;
	}

	return \%set;
} ## end sub namtar_set

=head2 namtar_listed

Whether a value is on the list of any of the passed slots, going by the
loaded lists. Each slot is matched its own way, a C<string> one by a lookup
with its fold and a C<cidr> one by L<App::Baphomet::Config/ip_ignored>. A
undef value is on no list, and neither is anything on a slot that is not
loaded, so a gate over either fails closed. Returns 1 or 0.

    if ( namtar_listed( \%files, \@slots, $value ) ) { ... }

=cut

sub namtar_listed {
	my ( $files, $slots, $value ) = @_;

	if ( !defined($value) ) {
		return 0;
	}

	foreach my $slot ( @{$slots} ) {
		my $file = $files->{ $slot->{key} };
		if ( !defined($file) ) {
			next;
		}
		if ( $slot->{type} eq 'string' ) {
			if ( exists( $file->{set}{ $slot->{nocase} ? lc($value) : $value } ) ) {
				return 1;
			}
		} elsif ( ip_ignored( $file->{set}, $value ) ) {
			return 1;
		}
	} ## end foreach my $slot ( @{$slots} )

	return 0;
} ## end sub namtar_listed

1;
