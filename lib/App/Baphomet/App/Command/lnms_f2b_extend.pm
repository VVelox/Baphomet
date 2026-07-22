package App::Baphomet::App::Command::lnms_f2b_extend;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use JSON::MaybeXS      ();
use IO::Compress::Gzip qw( gzip $GzipError );
use MIME::Base64       qw( encode_base64 );

=head1 NAME

App::Baphomet::App::Command::lnms_f2b_extend - Emit the LibreNMS fail2ban SNMP extend JSON.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet lnms-f2b-extend
    baphomet lnms-f2b-extend --pretty
    baphomet lnms-f2b-extend -b

    # in snmpd.conf, standing in for the fail2ban extend
    extend fail2ban /usr/local/bin/baphomet lnms-f2b-extend

    # or GZip+Base64 compressed, for a large fleet of jails
    extend fail2ban /usr/local/bin/baphomet lnms-f2b-extend -b

=head1 DESCRIPTION

Speaks the same JSON the fail2ban SNMP extend for LibreNMS emits, so a
Baphomet host drops straight into the LibreNMS fail2ban application without
fail2ban itself being present. Each kur this Baphomet feeds stands in for a
fail2ban jail, and its "currently banned" tally comes from the Baphomet
manager's C<banished> command... the same lists Ereshkigal, the source of
truth for who Kur holds, reports, gathered by the manager rather than
reached for around it.

A kur this Baphomet targets that is a fan_out gate on the Ereshkigal side
has no ban list of it's own... the banishments land on it's members, so
such a jail's tally is the union of it's members holdings.

The recidive kur, when configured, is counted alongside the watched kurs.

The emitted structure mirrors the extend exactly...

    {
       "data" : {
          "total" : 5,
          "jails" : { "sshd" : 4, "smtp" : 1 }
       },
       "error" : 0,
       "errorString" : "",
       "version" : "1"
    }

Should the manager be unreachable, valid JSON is still emitted, with
C<error> set non-zero and C<errorString> naming the fault, as the extend
does... so LibreNMS records the fault rather than choking on a empty reply.

With C<-b> the reply is GZip compressed then Base64 encoded onto one line,
the LibreNMS SNMP extend compression convention, which LibreNMS decodes on
it's own by the GZip magic... worth it once a fleet has enough jails to
strain the SNMP reply size.

=head1 METHODS

Standard L<App::Cmd::Command> methods... command_names, abstract, opt_spec,
validate_args, and execute.

=cut

# hyphens can not live in a package name, so the on-disk module is
# lnms_f2b_extend while the command is spelled with hyphens, matching the
# fail2ban extend's own dashed idiom
sub command_names { return 'lnms-f2b-extend'; }

sub abstract { return 'emit the LibreNMS fail2ban SNMP extend JSON' }

sub description {
	return
		  'Speaks the JSON the fail2ban SNMP extend for LibreNMS emits, each kur '
		. 'this Baphomet feeds standing in for a jail and its banned tally coming '
		. 'from the Baphomet manager, so a Baphomet host drops into the LibreNMS '
		. 'fail2ban application with no fail2ban present. Point an snmpd extend at it.';
}

sub usage_desc { return '%c lnms-f2b-extend %o'; }

sub opt_spec {
	return (
		[ 'pretty|p',   'pretty print the JSON' ],
		[ 'compress|b', 'GZip+Base64 compress the output, the LibreNMS extend convention' ],
	);
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} ) {
		$self->usage_error('lnms-f2b-extend takes no args');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	# the manager gathers the banned lists now, the recidive kur and the
	# fan_out expansions and all... this just tallies its answer. a whole-run
	# failure rides out as a non-zero error with a empty jail set, per the
	# extend, so LibreNMS records the fault rather than choking
	my %tallies;
	my ( $error, $error_string ) = ( 0, '' );
	eval {
		my $banished = $self->app->manager_call('banished');
		%tallies = _tallies_from_banished($banished);
	};
	if ($@) {
		$error        = 1;
		$error_string = 'asking the manager for the banished lists failed... ' . $@;
		$error_string =~ s/\s+\z//;
		%tallies = ();
	}

	my $extend = _extend_structure( \%tallies, $error, $error_string );

	my $json    = JSON::MaybeXS->new( 'canonical' => 1, 'pretty' => $opt->pretty ? 1 : 0 );
	my $encoded = $json->encode($extend);

	# GZip then Base64 onto one line, the LibreNMS extend compression
	# convention it decodes by the GZip magic... the empty Base64 eol keeps
	# it one line, and the JSON is compressed bare, the newline is the line's
	if ( $opt->compress ) {
		my $gzipped;
		gzip( \$encoded => \$gzipped ) || die( 'GZip compressing the output failed... ' . $GzipError );
		print encode_base64( $gzipped, '' ) . "\n";
		return;
	}

	# a pretty encode already trails a newline; a compact one does not, and
	# the extend ends its line, so match either way
	$encoded .= "\n" if $encoded !~ /\n\z/;
	print $encoded;

	return;
} ## end sub execute

# the per-jail tallies from the manager's banished answer... a real kur's own
# banned count, a fan_out gate's the union of it's members holdings since a
# banishment to a gate lands on each member and the gate keeps no list of it's
# own, and a kur the manager could not read (an error entry) an empty jail of
# zero, so every fed kur still shows as a jail
sub _tallies_from_banished {
	my ($banished) = @_;

	my $kurs = ( ref($banished) eq 'HASH' && ref( $banished->{kurs} ) eq 'HASH' ) ? $banished->{kurs} : {};

	my %tallies;
	foreach my $kur ( keys( %{$kurs} ) ) {
		my $entry = $kurs->{$kur};
		if ( ref( $entry->{banned} ) eq 'ARRAY' ) {
			$tallies{$kur} = scalar( @{ $entry->{banned} } );
		} elsif ( ref( $entry->{members} ) eq 'HASH' ) {
			my %union;
			foreach my $member ( keys( %{ $entry->{members} } ) ) {
				my $held = $entry->{members}{$member};
				if ( ref( $held->{banned} ) eq 'ARRAY' ) {
					foreach my $ip ( @{ $held->{banned} } ) {
						$union{$ip} = 1;
					}
				}
			}
			$tallies{$kur} = scalar( keys(%union) );
		} else {
			$tallies{$kur} = 0;
		}
	} ## end foreach my $kur ( keys( %{$kurs...}))

	return %tallies;
} ## end sub _tallies_from_banished

# assembles the extend structure from the per-jail tallies... total is the
# sum of the jail counts, an IP held in two jails counting in each, exactly
# as the fail2ban extend sums its jails
sub _extend_structure {
	my ( $tallies, $error, $error_string ) = @_;

	my $total = 0;
	my %jails;
	foreach my $kur ( keys( %{$tallies} ) ) {
		my $count = $tallies->{$kur} + 0;
		$jails{$kur} = $count;
		$total += $count;
	}

	return {
		'data'        => { 'total' => $total, 'jails' => \%jails },
		'error'       => defined($error)        ? $error + 0    : 0,
		'errorString' => defined($error_string) ? $error_string : '',
		'version'     => '1',
	};
} ## end sub _extend_structure

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991, or (at your
  option) any later version, matching fail2ban, which parts of this
  project, most notably the shipped rules, are derived from.

=cut

1;
