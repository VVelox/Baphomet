#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );

BEGIN {
	eval { require Ereshkigal::Client; };
	if ($@) {
		plan skip_all => 'Ereshkigal::Client not available';
	}
}

use App::Baphomet::Galla ();

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run', $dir . '/cache' );

open( my $fh, '>', $dir . '/rules/syslog/sshd.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
tests:
  positive:
    - message: "Jul 12 08:15:50 vixen42 sshd[1]: bad thing from 1.2.3.4"
      found: 1
      data:
        SRC: "1.2.3.4"
EOR
close($fh);

open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"

[recidive]
kur = "recidive"
max_retrys = 3
find_time = 604800
ban_time = 0

[kur.sshd]
ban_time = 300

[kur.sshd.authlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"
EOC
close($fh);
open( $fh, '>', $dir . '/log' ) || die($!);
close($fh);

my $galla = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );
ok( defined($galla),          'galla with recidive built' );
ok( defined( $galla->{recidive} ), 'recidive settings present' );
is( $galla->{recidive}{kur}, 'recidive', 'recidive kur' );

# capture every consignment, with its target kur
my @sent;
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub {
		my ( $self, $ip, $ban_time, $kur ) = @_;
		push( @sent, { ip => $ip, ban_time => $ban_time, kur => defined($kur) ? $kur : $self->{name} } );
		return;
	};
}

# three consignments of the same IP hits the recidive threshold
$galla->_ban_ip( '9.9.9.9', 300 );
$galla->_ban_ip( '9.9.9.9', 300 );
is( scalar( grep { $_->{kur} eq 'recidive' } @sent ), 0, 'no escalation below threshold' );

$galla->_ban_ip( '9.9.9.9', 300 );
my @escalations = grep { $_->{kur} eq 'recidive' } @sent;
is( scalar(@escalations), 1,          'escalated at the third consignment' );
is( $escalations[0]{ip},  '9.9.9.9',  'the recidivist was escalated' );
is( $escalations[0]{ban_time}, 0,     'with the recidive ban_time' );
is( $galla->{stats}{recidivists}, 1,  'recidivists stat' );

# a different IP is counted separately
$galla->_ban_ip( '8.8.8.8', 300 );
is( scalar( grep { $_->{kur} eq 'recidive' && $_->{ip} eq '8.8.8.8' } @sent ), 0, 'other IP not yet a recidivist' );

# the ledger exists and carries the consignments
ok( -f $dir . '/cache/consignments.csv', 'ledger written' );
open( $fh, '<', $dir . '/cache/consignments.csv' ) || die($!);
my @rows = <$fh>;
close($fh);
is( scalar( grep { /,9\.9\.9\.9,/ } @rows ), 3, 'three ledger rows for the recidivist' );
like( $rows[0], qr/^epoch,kur,ip,rule,watcher$/, 'the ledger carries its header' );

# a second galla sharing the ledger sees the history... one more from it
# tips a would-be recidivist already at 2
my $galla2 = App::Baphomet::Galla->new( config => $dir . '/config.toml', name => 'sshd' );
{
	no warnings 'redefine';
	*App::Baphomet::Galla::_send_ban = sub {
		my ( $self, $ip, $ban_time, $kur ) = @_;
		push( @sent, { ip => $ip, ban_time => $ban_time, kur => defined($kur) ? $kur : $self->{name} } );
		return;
	};
}
$galla->_ban_ip( '7.7.7.7', 300 );
$galla2->_ban_ip( '7.7.7.7', 300 );
$galla2->_ban_ip( '7.7.7.7', 300 );
is( scalar( grep { $_->{kur} eq 'recidive' && $_->{ip} eq '7.7.7.7' } @sent ),
	1, 'the ledger is shared across gallas' );

#
# recidive off still chisels the ledger, but never escalates
#

open( $fh, '>', $dir . '/config-plain.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
tablet_base_dir = "$dir/cache2"
rules_dir = "$dir/rules"
ereshkigal_socket = "$dir/nonexistent.sock"

[kur.sshd]
ban_time = 300

[kur.sshd.authlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"
EOC
close($fh);
make_path( $dir . '/cache2' );

my $plain = App::Baphomet::Galla->new( config => $dir . '/config-plain.toml', name => 'sshd' );
ok( !defined( $plain->{recidive} ), 'recidive off when unconfigured' );
@sent = ();
$plain->_ban_ip( '1.1.1.1', 300 );
$plain->_ban_ip( '1.1.1.1', 300 );
$plain->_ban_ip( '1.1.1.1', 300 );
is( scalar( grep { $_->{kur} eq 'recidive' } @sent ), 0, 'no escalation with recidive off' );
ok( -f $dir . '/cache2/consignments.csv', 'the ledger is chiseled even with recidive off' );
open( $fh, '<', $dir . '/cache2/consignments.csv' ) || die($!);
@rows = <$fh>;
close($fh);
is( scalar( grep { /,1\.1\.1\.1,/ } @rows ), 3, 'three ledger rows with recidive off' );

# a consignment carrying its context chisels rule and watcher into the row
$plain->_ban_ip( '2.2.2.2', 300, { 'watcher' => 'authlog', 'rule_name' => 'syslog/sshd' } );
open( $fh, '<', $dir . '/cache2/consignments.csv' ) || die($!);
@rows = <$fh>;
close($fh);
is( scalar( grep { m{,2\.2\.2\.2,syslog/sshd,authlog$} } @rows ), 1, 'rule and watcher chiseled into the row' );

done_testing;
