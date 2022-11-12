#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Baphomet' ) || print "Bail out!\n";
}

diag( "Testing Baphomet $Baphomet::VERSION, Perl $], $^X" );
