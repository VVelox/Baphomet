package App::Baphomet::App::Command::lnms_f2b_extend;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use App::Baphomet::Config qw( load_config );
use Ereshkigal::Client    ();
use JSON::MaybeXS         ();
use IO::Compress::Gzip    qw( gzip $GzipError );
use MIME::Base64          qw( encode_base64 );

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
fail2ban jail, and its "currently banned" tally is the count Ereshkigal, the
source of truth for who Kur holds, reports for that kur via the C<banned>
command... exactly the source the C<banished> command draws on.

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

Should Ereshkigal be unreachable, valid JSON is still emitted, with C<error>
set non-zero and C<errorString> naming the fault, as the extend does... so
LibreNMS records the fault rather than choking on a empty reply.

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
		. 'from Ereshkigal, so a Baphomet host drops into the LibreNMS fail2ban '
		. 'application with no fail2ban present. Point an snmpd extend at it.';
}

sub usage_desc { return '%c lnms-f2b-extend %o'; }

sub opt_spec {
	return (
		[ 'config=s',   'path of the config file', { default => '/usr/local/etc/baphomet/config.toml' } ],
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

	my $config = load_config( $opt->config );

	# the kurs this Baphomet feeds... the watched ones plus the recidive kur,
	# which banishments are escalated to, matching the banished command's reach
	my @kurs = sort( keys( %{ $config->{kur} } ) );
	if ( defined( $config->{recidive} ) && !grep { $_ eq $config->{recidive}{kur} } @kurs ) {
		push( @kurs, $config->{recidive}{kur} );
	}

	# gather each jail's banned tally from Ereshkigal... a whole-run failure
	# rides out as a non-zero error with a empty jail set, per the extend
	my %tallies;
	my ( $error, $error_string ) = ( 0, '' );
	eval {
		my $ereshkigal = Ereshkigal::Client->new(
			'socket'  => $config->{ereshkigal_socket},
			'timeout' => $config->{timeout},
		);
		my $banned = $ereshkigal->call_ok('banned');
		my $held   = ref( $banned->{kurs} ) eq 'HASH' ? $banned->{kurs} : {};

		foreach my $kur (@kurs) {
			$tallies{$kur} = _kur_tally( $ereshkigal, $held, $kur );
		}
	};
	if ($@) {
		$error        = 1;
		$error_string = 'asking Ereshkigal for the banned lists failed... ' . $@;
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

# one kur's banned tally... its own count when Ereshkigal holds a list for
# it, else the union of it's fan_out members holdings, since a banishment to
# a gate lands on each member and the gate keeps no list of it's own. a kur
# neither held nor a known gate tallies zero, an empty but present jail
sub _kur_tally {
	my ( $ereshkigal, $held, $kur ) = @_;

	if ( defined( $held->{$kur} ) ) {
		return ref( $held->{$kur}{banned} ) eq 'ARRAY' ? scalar( @{ $held->{$kur}{banned} } ) : 0;
	}

	my $kur_status;
	eval { $kur_status = $ereshkigal->call_ok( 'status_kur', { 'name' => $kur } ); };
	if ( $@ || ref( $kur_status->{fan_out} ) ne 'ARRAY' ) {
		return 0;
	}

	my %union;
	foreach my $member ( @{ $kur_status->{fan_out} } ) {
		if ( defined( $held->{$member} ) && ref( $held->{$member}{banned} ) eq 'ARRAY' ) {
			foreach my $ip ( @{ $held->{$member}{banned} } ) {
				$union{$ip} = 1;
			}
		}
	}

	return scalar( keys(%union) );
} ## end sub _kur_tally

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
