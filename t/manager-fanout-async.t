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
	eval { require POE::Component::Server::JSONUnix::Client; };
	if ($@) {
		plan skip_all => 'POE::Component::Server::JSONUnix::Client not available';
	}
}

use POE;
use POE::Component::Server::JSONUnix ();
use App::Baphomet                    ();

# the deferred fan-out... the manager holds the JSONUnix $ctx, asks every
# running galla through its async client, and chisels the reply when the
# last answer lands, never blocking its loop. fake gallas stand in on the
# real galla socket paths. short tempdir, AF_UNIX paths being bound at 104

my $dir = tempdir( 'bphXXXXXX', TMPDIR => 1, CLEANUP => 1 );
make_path( $dir . '/rules/syslog', $dir . '/run' );

open( my $fh, '>', $dir . '/rules/syslog/sshd.yaml' ) || die($!);
print $fh <<'EOR';
---
daemons:
  - sshd
message_regexp:
  - 'bad thing from %%%%SRC%%%%'
ban_var:
  - SRC
EOR
close($fh);

my $group = getgrgid( ( split( /\s+/, $) ) )[0] );
open( $fh, '>', $dir . '/config.toml' ) || die($!);
print $fh <<"EOC";
run_base_dir = "$dir/run"
rules_dir = "$dir/rules"
socket_group = "$group"
timeout = 2

[kur.sshd]
ban_time = 300

[kur.sshd.authlog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"

[kur.web]
ban_time = 300

[kur.web.weblog]
log = "$dir/log"
parser = "bsd_syslog"
rule = "syslog/sshd"
EOC
close($fh);
open( $fh, '>', $dir . '/log' ) || die($!);
close($fh);

my $baphomet = App::Baphomet->new( 'config' => $dir . '/config.toml' );
ok( defined($baphomet), 'manager built' );

# fake gallas listening where the real ones would
foreach my $name ( 'sshd', 'web' ) {
	POE::Component::Server::JSONUnix->spawn(
		'socket_path' => $baphomet->galla_socket_path($name),
		'alias'       => 'fake_galla_' . $name,
		'commands'    => {
			'accused' => sub {
				return { 'accused' => { '9.9.9.9' => { 'galla' => $name } } };
			},
		},
	);
	$baphomet->{gallas}{$name}{pid} = $$;
}

# a stand-in for the JSONUnix context... records the deferred reply
package MockCtx;

sub new { return bless( { 'result' => undef }, $_[0] ); }

sub respond_result {
	my ( $self, $result ) = @_;
	$self->{result} = $result;
	return;
}

package main;

my $ctx_both = MockCtx->new;
my $ctx_half = MockCtx->new;

POE::Session->create(
	'inline_states' => {
		'_start' => sub {
			my $returned = $baphomet->_cmd_accused( {}, $ctx_both );
			is( $returned, undef, 'a deferred fan-out returns undef to the handler' );
			ok( !defined( $ctx_both->{result} ), 'and has not answered yet at initiation' );
			$_[KERNEL]->delay( 'both_landed', 1 );
			return;
		},
		'both_landed' => sub {
			my $gallas = ref( $ctx_both->{result} ) eq 'HASH' ? $ctx_both->{result}{gallas} : {};
			is( $gallas->{sshd}{accused}{'9.9.9.9'}{galla}, 'sshd', 'the sshd galla answered into the reply' );
			is( $gallas->{web}{accused}{'9.9.9.9'}{galla},  'web',  'the web galla answered into the reply' );

			# one galla gone... its entry errors, the other still answers,
			# and the reply is still chiseled
			$_[KERNEL]->post( 'fake_galla_web', 'shutdown' );
			$_[KERNEL]->delay( 'web_gone', 1 );
			return;
		},
		'web_gone' => sub {
			$baphomet->_cmd_accused( {}, $ctx_half );
			$_[KERNEL]->delay( 'half_landed', 1 );
			return;
		},
		'half_landed' => sub {
			my $gallas = ref( $ctx_half->{result} ) eq 'HASH' ? $ctx_half->{result}{gallas} : {};
			is( $gallas->{sshd}{accused}{'9.9.9.9'}{galla}, 'sshd', 'the living galla still answers' );
			ok( defined( $gallas->{web}{error} ), 'the dead galla holds a per-galla error' );

			# a not-running galla never gets asked and keeps its shape... the
			# ctx-less sync path answers in place. the living galla can not
			# actually reply here, as the blocking call_many holds the very
			# loop the in-process fake server answers from — in reality they
			# are separate processes — so only the shape is asserted for it
			$baphomet->{gallas}{web}{pid} = undef;
			my $sync = $baphomet->_cmd_accused( {} );
			is( ref($sync), 'HASH', 'without a ctx the fan-out answers synchronously' );
			is( $sync->{gallas}{web}{error}, 'not running', 'the stopped galla reads not running' );
			ok( defined( $sync->{gallas}{sshd} ), 'the living galla has a per-galla entry either way' );

			foreach my $name ( keys( %{ $baphomet->{galla_clients} } ) ) {
				$baphomet->{galla_clients}{$name}->shutdown;
			}
			$_[KERNEL]->post( 'fake_galla_sshd', 'shutdown' );
			return;
		},
	},
);

POE::Kernel->run;

done_testing;
