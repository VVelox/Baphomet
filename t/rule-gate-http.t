#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use File::Path qw( make_path );
use App::Baphomet::Parser ();
use App::Baphomet::Rules  ();

# the generic gate / selections / keywords, now on the http and http_error
# types too, over their parsed request and error fields

my $dir = tempdir( CLEANUP => 1 );
make_path( $dir . '/http', $dir . '/http_error' );

sub write_rule {
	my ( $name, $yaml ) = @_;
	open( my $fh, '>', $dir . '/' . $name . '.yaml' ) || die($!);
	print $fh $yaml;
	close($fh);
	return;
}

my $rules = App::Baphomet::Rules->new( 'rules_dir' => $dir );

sub http_line {
	my ( $request, $status, $ua ) = @_;
	return App::Baphomet::Parser::parse( 'http_access',
		'203.0.113.9 - - [12/Jul/2026:08:15:50 -0500] "' . $request . '" ' . $status . ' 196 "-" "' . $ua . '"' );
}

sub err_line {
	my ( $module, $level, $message ) = @_;
	return App::Baphomet::Parser::parse( 'apache_error',
		'[Thu Jun 27 11:55:44.569531 2013] [' . $module . ':' . $level . '] [pid 1] [client 203.0.113.9:2345] ' . $message );
}

sub matches {
	my ( $name, $parsed ) = @_;
	my $rule = $rules->load($name);
	return defined( $rule->check($parsed) ) ? 1 : 0;
}

#
# http... a generic gate on a parsed field
#
write_rule( 'http/gate', "---\ngate:\n  - { field: path, op: startswith, value: /admin }\n" );
is( matches( 'http/gate', http_line( 'GET /admin/panel HTTP/1.1', 200, 'x' ) ), 1, 'http gate: path startswith matches' );
is( matches( 'http/gate', http_line( 'GET /public HTTP/1.1', 200, 'x' ) ),      0, 'http gate: other path misses' );

#
# http... selections with OR
#
write_rule( 'http/sel', <<'EOR' );
---
selections:
  post:     [ { field: method, op: eq, value: POST } ]
  notfound: [ { field: status, op: eq, value: "404" } ]
condition: "post or notfound"
EOR
is( matches( 'http/sel', http_line( 'POST /x HTTP/1.1', 200, 'x' ) ), 1, 'http selections: POST matches the or' );
is( matches( 'http/sel', http_line( 'GET /x HTTP/1.1',  404, 'x' ) ), 1, 'http selections: 404 matches the or' );
is( matches( 'http/sel', http_line( 'GET /x HTTP/1.1',  200, 'x' ) ), 0, 'http selections: neither, no match' );

#
# http... keywords over all fields, and scoped to the user agent
#
write_rule( 'http/kw',    "---\nkeywords: [ sqlmap, nikto ]\n" );
write_rule( 'http/kwscope', "---\nkeywords:\n  in: user_agent\n  values: [ curl ]\n" );
is( matches( 'http/kw', http_line( 'GET /x HTTP/1.1', 200, 'sqlmap/1.5' ) ), 1, 'http keywords: a scanner UA is found anywhere' );
is( matches( 'http/kw', http_line( 'GET /x HTTP/1.1', 200, 'Mozilla/5' ) ),  0, 'http keywords: a clean UA misses' );
is( matches( 'http/kwscope', http_line( 'GET /x HTTP/1.1', 200, 'curl/7.8' ) ), 1, 'http scoped keywords: curl in the UA matches' );
is( matches( 'http/kwscope', http_line( 'GET /curl HTTP/1.1', 200, 'Mozilla/5' ) ), 0, 'http scoped keywords: curl in the path is ignored' );

#
# http... the generic gate ANDs with the status gate
#
write_rule( 'http/both', "---\nstatus: [ 200 ]\nkeywords: [ sqlmap ]\n" );
is( matches( 'http/both', http_line( 'GET /x HTTP/1.1', 200, 'sqlmap/1' ) ), 1, 'http: status gate and keyword both hold' );
is( matches( 'http/both', http_line( 'GET /x HTTP/1.1', 500, 'sqlmap/1' ) ), 0, 'http: the status gate fails' );

#
# http_error... a generic gate over the message, ANDed with message_regexp
#
write_rule( 'http_error/gate', "---\nmessage_regexp: [ '.' ]\ngate:\n  - { field: message, op: contains, value: shellshock }\n" );
is( matches( 'http_error/gate', err_line( 'core', 'error', 'possible shellshock attempt' ) ), 1, 'http_error gate: message contains matches' );
is( matches( 'http_error/gate', err_line( 'core', 'error', 'ordinary failure' ) ),             0, 'http_error gate: message without it misses' );

#
# http_error... keywords over the parsed fields, and %%%ANY%%% reaching module
#
write_rule( 'http_error/kw',  "---\nmessage_regexp: [ '.' ]\nkeywords: [ exploit ]\n" );
write_rule( 'http_error/any', "---\nmessage_regexp: [ '.' ]\ngate:\n  - { field: '%%%ANY%%%', op: contains, value: modsecurity }\n" );
is( matches( 'http_error/kw',  err_line( 'core', 'error', 'exploit blocked' ) ),   1, 'http_error keywords: found in the message' );
is( matches( 'http_error/kw',  err_line( 'core', 'error', 'nothing here' ) ),      0, 'http_error keywords: absent, no match' );
is( matches( 'http_error/any', err_line( 'modsecurity', 'error', 'clean text' ) ), 1, 'http_error %%%ANY%%%: matches in the module field' );

done_testing;
