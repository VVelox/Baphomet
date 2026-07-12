#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use App::Baphomet::Parser ();

my $parsed = App::Baphomet::Parser::parse( 'raw', "anything at all\n" );
ok( defined($parsed), 'line parsed' );
is( $parsed->{format},  'raw',             'format' );
is( $parsed->{message}, 'anything at all', 'message is the chomped line' );

$parsed = App::Baphomet::Parser::parse( 'raw', '' );
ok( defined($parsed), 'empty line still parses' );
is( $parsed->{message}, '', 'empty message' );

is( App::Baphomet::Parser::parse( 'raw', undef ), undef, 'undef returns undef' );

ok( App::Baphomet::Parser::is_known('raw'), 'raw is a known parser' );

# raw is never picked by the combined syslog parser's sniffing
$parsed = App::Baphomet::Parser::parse( 'syslog', 'not a syslog line at all' );
is( $parsed, undef, 'the combined syslog parser does not fall back to raw' );

done_testing;
