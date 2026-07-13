package App::Baphomet::App::Command::ledger;

use 5.006;
use strict;
use warnings;
use App::Baphomet::App -command;
use App::Baphomet::Config qw( load_config );
use JSON::MaybeXS         ();
use POSIX                 qw( strftime );

=head1 NAME

App::Baphomet::App::Command::ledger - Read the shared consignment ledger.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    baphomet ledger
    baphomet ledger sshd
    baphomet ledger --ip 1.2.3.4
    baphomet ledger --since 7d --tail 20

=head1 DESCRIPTION

Reads the shared consignment ledger under the tablet dir, the record every
galla chisels a row into when it consigns a IP... when, which kur, which
IP, and by which rule and watcher. Read straight from the file, so it
works with the manager down. How far back it reaches is bounded by the
C<ledger_keep> setting.

C<--since> takes either a bare epoch or a relative span of digits and a
unit... C<s>econds, C<m>inutes, C<h>ours, C<d>ays, or C<w>eeks, so C<7d>
is the last week.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'read the shared consignment ledger' }

sub description {
	return
		  'Reads the shared consignment ledger... every consignment any galla made, '
		. 'when, which kur, which IP, and by which rule and watcher. With a kur '
		. 'name, just that kur. --ip picks one IP, --since bounds how far back, '
		. 'and --tail keeps only the last N entries.';
}

sub usage_desc { return '%c ledger %o [kur]'; }

sub opt_spec {
	return (
		[ 'config=s', 'path of the config file', { default => '/usr/local/etc/baphomet/config.toml' } ],
		[ 'ip=s',     'only entries for this IP' ],
		[ 'since=s',  'only entries after this... a epoch, or digits and s/m/h/d/w for a relative span' ],
		[ 'tail=i',   'only the last N entries' ],
	);
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} > 1 ) {
		$self->usage_error('ledger takes at most one arg, a kur name');
	}
	if ( defined( $opt->since ) && $opt->since !~ /^[0-9]+[smhdw]?$/ ) {
		$self->usage_error('--since is not a epoch or a relative span such as 7d');
	}
	if ( defined( $opt->tail ) && $opt->tail < 1 ) {
		$self->usage_error('--tail is not a positive int');
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $config = load_config( $opt->config );
	my $path   = $config->{tablet_base_dir} . '/consignments.csv';

	my $since;
	if ( defined( $opt->since ) ) {
		$since = _since_epoch( $opt->since );
	}
	my $kur = @{$args} ? $args->[0] : undef;

	my @entries;
	if ( -f $path ) {
		open( my $fh, '<', $path ) || die( 'opening the ledger "' . $path . '" failed... ' . $! );
		while ( my $line = <$fh> ) {
			chomp($line);
			my $entry = _parse_row($line);
			if ( !defined($entry) ) {
				next;
			}
			if ( defined($since) && $entry->{epoch} < $since ) {
				next;
			}
			if ( defined($kur) && $entry->{kur} ne $kur ) {
				next;
			}
			if ( defined( $opt->ip ) && $entry->{ip} ne $opt->ip ) {
				next;
			}
			push( @entries, $entry );
		} ## end while ( my $line = <$fh> )
		close($fh);
	} ## end if ( -f $path )

	if ( defined( $opt->tail ) && scalar(@entries) > $opt->tail ) {
		@entries = @entries[ -( $opt->tail ) .. -1 ];
	}

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode( { 'entries' => \@entries } );

	return;
} ## end sub execute

# a ledger row into a entry hash... epoch,kur,ip,rule,watcher, the last
# two quoted if they carry a comma, and absent entirely on rows from
# before the ledger carried them. undef for the header or anything mangled
sub _parse_row {
	my ($line) = @_;

	my $quoted = '"(?:[^"]|"")*"|[^,]*';
	if ( $line !~ /^([0-9]+),([^,]*),([^,]+?)(?:,($quoted),($quoted))?$/ ) {
		return undef;
	}
	my ( $epoch, $kur, $ip, $rule, $watcher ) = ( $1, $2, $3, _unquote($4), _unquote($5) );

	return {
		'epoch' => $epoch + 0,
		'date'  => strftime( '%Y-%m-%dT%H:%M:%S%z', localtime($epoch) ),
		'kur'   => $kur,
		'ip'    => $ip,
		defined($rule)    && $rule ne ''    ? ( 'rule'    => $rule )    : (),
		defined($watcher) && $watcher ne '' ? ( 'watcher' => $watcher ) : (),
	};
} ## end sub _parse_row

# undoes the CSV quoting of the galla's ledger writer
sub _unquote {
	my ($value) = @_;

	if ( defined($value) && $value =~ /^"(.*)"$/ ) {
		$value = $1;
		$value =~ s/""/"/g;
	}

	return $value;
}

# a --since spec into a epoch... bare digits are a epoch already, digits
# with a unit are a span back from now
sub _since_epoch {
	my ($spec) = @_;

	if ( $spec =~ /^([0-9]+)([smhdw])$/ ) {
		my %seconds_per = ( 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400, 'w' => 604800 );
		return time - ( $1 * $seconds_per{$2} );
	}

	return $spec + 0;
}

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
