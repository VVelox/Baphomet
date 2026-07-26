package App::Baphomet::Geo;

use 5.006;
use strict;
use warnings;
use Exporter qw( import );

our @EXPORT_OK = qw( resolve_country_gate country_gate_pass );

=head1 NAME

App::Baphomet::Geo - The country gate's pure core, drivable over any locator.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Geo qw( resolve_country_gate country_gate_pass );

    my $gate = resolve_country_gate( $rule->country, \%code_lists, $where );
    my $locator = sub { ... };    # address -> ISO code, or undef when unlocatable
    if ( country_gate_pass( $locator, $gate, $data, $ip ) ) { ... }

=head1 DESCRIPTION

The country gate's judgment, lifted out of the galla so it runs over any
locator... the galla passes a closure over its cached GeoIP lookups, while
C<run_tests> passes a fixture map from the rule file's own C<geo:> test
key, so a geography-gated rule proves its gate cold. The locator answers
an upcased ISO 3166 code or undef for a address it can not place... and
unplaceable always fails closed, an unknown country being unclearable.
Nothing here knows of databases, caches, or config.

=head1 FUNCTIONS

=head2 resolve_country_gate

Resolves a rule's country gate (the C<country> accessor's
C<{mode, entries, vars}>) against a set of named code lists into a
concrete gate... a mode, a set of upcased codes, and the vars. Returns
undef when the rule has no gate. A C<%%%country_codes{name}%%%> import of
a list the set does not define is fatal, C<$where> naming the offender in
the die.

    my $gate = resolve_country_gate( $country, \%code_lists, $where );

=cut

sub resolve_country_gate {
	my ( $country, $codes, $where ) = @_;

	if ( !defined($country) ) {
		return undef;
	}

	my %set;
	foreach my $entry ( @{ $country->{entries} } ) {
		if ( $entry =~ /^%%%country_codes\{([a-zA-Z0-9_\-]+)\}%%%$/ ) {
			my $list = $codes->{$1};
			if ( ref($list) ne 'ARRAY' ) {
				die( $where . ' imports country_codes{' . $1 . '}, which is not a defined list for it' );
			}
			foreach my $code ( @{$list} ) {
				$set{ uc($code) } = 1;
			}
		} else {
			$set{ uc($entry) } = 1;
		}
	} ## end foreach my $entry ( @{ $country->{entries} } )

	return {
		'mode'  => $country->{mode},
		'codes' => \%set,
		'vars'  => $country->{vars},
	};
} ## end sub resolve_country_gate

=head2 country_gate_pass

Evaluates a resolved country gate in one of two modes, mirroring the mark
gates... a vars gate is data-driven and ran once per found result (ip
undef), a var-less one is offender-keyed and ran per candidate (ip set).
Every checked value's country must satisfy the gate, and a value that
does not locate fails closed... an unknown country can not be cleared. A
undef gate passes, a undef locator fails closed.

    if ( country_gate_pass( $locator, $gate, $data, $ip ) ) { ... }

=cut

sub country_gate_pass {
	my ( $locator, $gate, $data, $ip ) = @_;

	if ( !defined($gate) ) {
		return 1;
	}

	my @check;
	if ( defined( $gate->{vars} ) ) {
		# a vars gate belongs to the data pass... let the offender pass by
		if ( defined($ip) ) {
			return 1;
		}
		foreach my $var ( @{ $gate->{vars} } ) {
			push( @check, $data->{$var} );
		}
	} else {
		# a var-less gate belongs to the offender pass... let the data pass by
		if ( !defined($ip) ) {
			return 1;
		}
		@check = ($ip);
	}

	if ( !defined($locator) ) {
		return 0;
	}

	foreach my $value (@check) {
		my $country = defined($value) ? $locator->($value) : undef;
		if ( !defined($country) ) {
			return 0;
		}
		my $in = $gate->{codes}{$country} ? 1 : 0;
		if ( $gate->{mode} eq 'is' ? !$in : $in ) {
			return 0;
		}
	} ## end foreach my $value (@check)

	return 1;
} ## end sub country_gate_pass

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
