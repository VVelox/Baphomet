package App::Baphomet::Namtar;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util             qw( is_plain_hashref );
use Exporter              qw( import );
use App::Baphomet::Config qw( compile_ignore_ips ip_ignored );
use App::Baphomet::Marks  qw( entry_in_pass );

our @EXPORT_OK = qw( resolve_namtar_gate namtar_set namtar_listed namtar_gate_pass );

=head1 NAME

App::Baphomet::Namtar - The namtar_list gate's pure core, drivable over any loaded lists.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Namtar qw( resolve_namtar_gate namtar_set namtar_gate_pass );

    my $gate = resolve_namtar_gate( $rule->namtar_list, \%named_lists, $where );

    my %files;
    foreach my $entry ( @{$gate} ) {
        foreach my $slot ( @{ $entry->{slots} } ) {
            $files{ $slot->{key} } = { 'set' => namtar_set( $slot, \@lines_of_the_file ) };
        }
    }

    if ( namtar_gate_pass( \%files, $gate, $data, $ip ) ) { ... }

=head1 DESCRIPTION

The namtar_list gate's judgment, lifted out of the galla so it runs over any
loaded lists... the galla passes the files it reads and refreshes as they
change, while a test passes sets it compiled from lines of its own. Nothing
here reads a file, watches a mtime, or knows of config.

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

=head2 resolve_namtar_gate

Resolves a rule's namtar_list gate (the C<namtar_list> accessor's array of
C<{lists, var}>) against a set of named lists into a concrete gate... a
array of entries, each the C<var> and the C<slots> its lists come to, sorted
by key and with a file two of its lists name appearing once. One entry may
union lists of different flavors, each matched its own way. Returns undef
when the rule has no gate. A reference to a list the set does not define is
fatal, C<$where> naming the offender in the die.

    my $gate = resolve_namtar_gate( $rule->namtar_list, \%named_lists, $where );

=cut

sub resolve_namtar_gate {
	my ( $namtar_list, $lists, $where ) = @_;

	if ( !defined($namtar_list) ) {
		return undef;
	}

	my @entries;
	foreach my $entry ( @{$namtar_list} ) {
		my %slots;
		foreach my $name ( @{ $entry->{lists} } ) {
			my $list = $lists->{$name};
			if ( !is_plain_hashref($list) ) {
				die( $where . ' references namtar_lists{' . $name . '}, which is not a defined list for it' );
			}
			foreach my $path ( @{ $list->{paths} } ) {
				my $key = join( "\0", $list->{type}, $list->{nocase}, $path );
				$slots{$key} = {
					'key'    => $key,
					'type'   => $list->{type},
					'nocase' => $list->{nocase},
					'path'   => $path,
				};
			}
		} ## end foreach my $name ( @{ $entry->{lists} } )
		push( @entries, { 'slots' => [ map { $slots{$_} } sort( keys(%slots) ) ], 'var' => $entry->{var} } );
	} ## end foreach my $entry ( @{$namtar_list} )

	return \@entries;
} ## end sub resolve_namtar_gate

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

    if ( namtar_listed( \%files, $entry->{slots}, $value ) ) { ... }

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

=head2 namtar_gate_pass

Evaluates a resolved namtar_list gate in one of two modes, mirroring the
mark gates... a C<var> entry is data-driven and ran once per found result
(ip undef), a var-less one is offender-keyed and ran per candidate (ip set).
A entry holds when its value is on any of its lists, and every entry judged
must hold... a value on no list fails closed. A undef gate passes.

    if ( namtar_gate_pass( \%files, $gate, $data, $ip ) ) { ... }

=cut

sub namtar_gate_pass {
	my ( $files, $gate, $data, $ip ) = @_;

	if ( !defined($gate) ) {
		return 1;
	}

	# a var entry is judged in the data pass on the var's value, a var-less
	# one in the offender pass on the offender
	foreach my $entry ( grep { entry_in_pass( $_, $ip ) } @{$gate} ) {
		my $value = defined( $entry->{var} ) ? $data->{ $entry->{var} } : $ip;
		if ( !namtar_listed( $files, $entry->{slots}, $value ) ) {
			return 0;
		}
	}

	return 1;
} ## end sub namtar_gate_pass

1;
