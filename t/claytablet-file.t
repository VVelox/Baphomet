#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );

use App::Baphomet::ClayTablet      ();
use App::Baphomet::ClayTablet::File ();

my $dir = tempdir( CLEANUP => 1 );

# the backend on its own
my $backend = App::Baphomet::ClayTablet::File->new(
	'name'            => 'sshd',
	'options'         => {},
	'tablet_base_dir' => $dir,
);
isa_ok( $backend, 'App::Baphomet::ClayTablet::File' );

is( $backend->verify, undef, 'a writable base dir verifies' );

# the csv/jsonl suffix split, and the galla.<name>.<kind> shape
is( $backend->locator('counters'), $dir . '/galla.sshd.counters.csv',  'counters is a csv' );
is( $backend->locator('marks'),    $dir . '/galla.sshd.marks.csv',     'marks is a csv' );
is( $backend->locator('context'),  $dir . '/galla.sshd.context.jsonl', 'context is a jsonl' );
is( $backend->locator('stats'),    $dir . '/galla.sshd.stats.jsonl',   'stats is a jsonl' );

# a never-written tablet reads empty
is_deeply( [ $backend->read('marks') ], [], 'a missing tablet reads empty' );

# write and read back
ok( $backend->write( 'marks', [ 'line one', 'line two' ] ), 'write a tablet' );
is_deeply( [ $backend->read('marks') ], [ 'line one', 'line two' ], 'read the lines back' );

# the on-disk bytes are the old format, one line each with a trailing newline
my $blob = do {
	local $/ = undef;
	open( my $fh, '<', $backend->locator('marks') ) || die($!);
	my $c = <$fh>;
	close($fh);
	$c;
};
is( $blob, "line one\nline two\n", 'the file is byte-for-byte the old whole-tablet format' );

# write is a whole-tablet replace, not an append
ok( $backend->write( 'marks', ['only this now'] ), 'rewrite the tablet' );
is_deeply( [ $backend->read('marks') ], ['only this now'], 'the rewrite replaced, did not append' );

# an empty write leaves an empty tablet
ok( $backend->write( 'marks', [] ), 'write no lines' );
is_deeply( [ $backend->read('marks') ], [], 'an empty tablet reads empty' );

# verify fails on an unusable base dir... a path under a regular file can
# not be made into a directory
open( my $blocker, '>', $dir . '/afile' ) || die($!);
close($blocker);
my $bad = App::Baphomet::ClayTablet::File->new(
	'name'            => 'sshd',
	'options'         => { 'base_dir' => $dir . '/afile/still-nope' },
	'tablet_base_dir' => $dir,
);
ok( defined( $bad->verify ), 'an uncreatable base dir fails verify' );

# options.base_dir overrides tablet_base_dir
my $sub = $dir . '/elsewhere';
mkdir($sub);
my $over = App::Baphomet::ClayTablet::File->new(
	'name'            => 'web',
	'options'         => { 'base_dir' => $sub },
	'tablet_base_dir' => $dir,
);
is( $over->locator('counters'), $sub . '/galla.web.counters.csv', 'options.base_dir wins over tablet_base_dir' );

# the frontend with no config falls to the file backend
my $tablet = App::Baphomet::ClayTablet->new(
	'config'          => undef,
	'name'            => 'sshd',
	'tablet_base_dir' => $dir,
);
is( $tablet->backend_name, 'file', 'no config means the file backend' );
is( $tablet->verify,       undef,  'the frontend verifies through to the backend' );
ok( $tablet->write( 'context', ['{"rule":"x"}'] ), 'frontend write' );
is_deeply( [ $tablet->read('context') ], ['{"rule":"x"}'], 'frontend read' );

# an explicit file backend, same thing
my $explicit = App::Baphomet::ClayTablet->new(
	'config'          => { 'backend' => 'file' },
	'name'            => 'sshd',
	'tablet_base_dir' => $dir,
);
is( $explicit->backend_name, 'file', 'backend = file is the file backend' );

# a bad backend name is fatal
eval {
	App::Baphomet::ClayTablet->new(
		'config'          => { 'backend' => 'no/such' },
		'name'            => 'sshd',
		'tablet_base_dir' => $dir,
	);
};
ok( $@, 'a bad backend name dies' );

# an unloadable backend is fatal
eval {
	App::Baphomet::ClayTablet->new(
		'config'          => { 'backend' => 'nosuchbackend' },
		'name'            => 'sshd',
		'tablet_base_dir' => $dir,
	);
};
ok( $@, 'an unloadable backend dies' );

done_testing;
