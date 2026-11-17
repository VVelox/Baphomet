package App::Baphomet::App::Command::lnms_f2b_extend;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util qw( is_plain_arrayref is_plain_hashref );
use App::Baphomet::App -command;
use JSON::MaybeXS      ();
use IO::Compress::Gzip qw( gzip $GzipError );
use List::Util         qw( sum0 );
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
has no ban list of its own... the banishments land on its members, so
such a jail's tally is the union of its members' holdings.

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
its own by the GZip magic... worth it once a fleet has enough jails to
strain the SNMP reply size.

=head1 METHODS

Standard L<App::Cmd::Command> methods... command_names, abstract,
description, usage_desc, opt_spec, validate_args, and execute.

=cut

# the subs below with out a comment block are App::Cmd::Command hooks the
# framework calls... command_names for the name the command is invoked by,
# abstract and description for the help, usage_desc and opt_spec for the
# usage line and option parsing, validate_args to vet the args ahead of
# execute, and execute for the work itself. their contract is App::Cmd's,
# so they are not documented one by one here

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
	try {
		my $banished = $self->app->manager_call('banished');
		%tallies = _tallies_from_banished($banished);
	} catch ($caught) {
		$error        = 1;
		$error_string = 'asking the manager for the banished lists failed... ' . $caught;
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
# banned count, a fan_out gate's the union of its members' holdings since a
# banishment to a gate lands on each member and the gate keeps no list of its
# own, and a kur the manager could not read (an error entry) an empty jail of
# zero, so every fed kur still shows as a jail
#
# args:
#   $banished :: hashref, the manager's banished answer... kurs is a hash of
#       kur name to entry, each with banned (arrayref of IPs), or members
#       (hashref of member kur name to a hashref with banned), or neither
#       when the kur could not be read. anything not shaped so reads as no
#       kurs at all
#
# returns:
#   a flat list of kur name and int count pairs, meant for a hash
#
# example:
#   my %tallies = _tallies_from_banished(
#       { 'kurs' => { 'sshd' => { 'banned' => [ '192.0.2.7', '192.0.2.8' ] } } } );
#   # ( 'sshd' => 2 )
sub _tallies_from_banished {
	my ($banished) = @_;

	my $kurs = ( is_plain_hashref($banished) && is_plain_hashref( $banished->{kurs} ) ) ? $banished->{kurs} : {};

	my %tallies;
	foreach my $kur ( keys( %{$kurs} ) ) {
		my $entry = $kurs->{$kur};
		if ( is_plain_arrayref( $entry->{banned} ) ) {
			$tallies{$kur} = scalar( @{ $entry->{banned} } );
		} elsif ( is_plain_hashref( $entry->{members} ) ) {
			my %union;
			foreach my $held ( values( %{ $entry->{members} } ) ) {
				if ( is_plain_arrayref( $held->{banned} ) ) {
					foreach my $ip ( @{ $held->{banned} } ) {
						$union{$ip} = 1;
					}
				}
			}
			$tallies{$kur} = scalar( keys(%union) );
		} else {
			$tallies{$kur} = 0;
		}
	} ## end foreach my $kur ( keys( %{$kurs} ) )

	return %tallies;
} ## end sub _tallies_from_banished

# assembles the extend structure from the per-jail tallies... total is the
# sum of the jail counts, an IP held in two jails counting in each, exactly
# as the fail2ban extend sums its jails
#
# args:
#   $tallies :: hashref of jail (kur) name to int count, as
#       _tallies_from_banished gives
#   $error :: the extend's error number, 0 for none, undef read as 0
#   $error_string :: text naming the fault, '' for none, undef read as ''
#
# returns:
#   hashref in the LibreNMS extend shape... data => { total, jails }, error,
#   errorString, and version, which is always '1'
#
# example:
#   _extend_structure( { 'sshd' => 4, 'smtp' => 1 }, 0, '' );
#   # { 'data' => { 'total' => 5, 'jails' => { 'sshd' => 4, 'smtp' => 1 } },
#   #   'error' => 0, 'errorString' => '', 'version' => '1' }
sub _extend_structure {
	my ( $tallies, $error, $error_string ) = @_;

	my %jails = map { $_ => $tallies->{$_} + 0 } keys( %{$tallies} );
	my $total = sum0( values(%jails) );

	return {
		'data'        => { 'total' => $total, 'jails' => \%jails },
		'error'       => defined($error) ? $error + 0 : 0,
		'errorString' => $error_string // '',
		'version'     => '1',
	};
} ## end sub _extend_structure

1;
