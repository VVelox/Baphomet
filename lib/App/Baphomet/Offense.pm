package App::Baphomet::Offense;

use 5.006;
use strict;
use warnings;
use Exporter qw( import );
use App::Baphomet::Marks ();

our @EXPORT_OK = qw( resolve_offense data_gate_pass );

=head1 NAME

App::Baphomet::Offense - The one place the per-offender gate order lives.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::Offense qw( resolve_offense );

    my $outcome = resolve_offense(
        store     => \%marks,
        marks     => $rule->marks,
        unmarks   => $rule->unmarks,
        data      => $found->{data},
        offenders => \@offenders,
        now       => $now,
        gate      => sub { my ($ip) = @_; ... every per-offender gate ... },
    );
    next if !$outcome->{fired};
    # brand the survivors already applied; count them
    foreach my $ip ( @{ $outcome->{survivors} } ) { ... }

=head1 DESCRIPTION

One matched result, resolved to the offenders it truly fires against, in
the single order the live galla and the rule self-tester must share. The
per-offender gates (the var-less mark, country, namtar, and reverse_dns
gates) filter the candidate offenders to the survivors; a offender a gate
vetoes is not an offense, so it is neither branded nor counted; and a
result whose every offender is gated out did not fire at all... it brands
nobody and the caller emits nothing for it.

The gate evaluations differ between the callers... the galla runs live
resolvers, C<run_tests> runs the rule file's fixtures... so the gate is
injected as one predicate over an offender. Everything downstream of the
gate, the part that drifted and let a legit crawler be branded, lives here
once: the survivor filter, the gated-out verdict, and the branding of the
survivors (and only the survivors) via L<App::Baphomet::Marks>.

=head1 FUNCTIONS

=head2 data_gate_pass

Runs a result's data-level gates, the ones evaluated once per result (the
var-keyed mark, country, namtar, and reverse_dns gates, and active_time)
rather than per offender. Takes an ordered arrayref of check closures,
each returning true to pass, and returns true only when every one holds...
short-circuiting on the first veto, since these gates do DNS and GeoIP
lookups a earlier veto should spare. A data veto means the whole result
did not fire: the caller brands nobody and emits nothing, exactly as a
per-offender full veto does in L</resolve_offense>. Both the galla and the
rule self-tester run their data pass through here so the "all gates, short
circuit, veto skips the result" shape can not drift between them; the set
of gates differs (the self-tester can not fixture namtar or active_time),
but the shape does not.

    next if !data_gate_pass( [ sub { ... }, sub { ... } ] );

=cut

sub data_gate_pass {
	my ($checks) = @_;

	foreach my $check ( @{$checks} ) {
		if ( !$check->() ) {
			return 0;
		}
	}

	return 1;
} ## end sub data_gate_pass

=head2 resolve_offense

Takes the mark C<store>, the rule's C<marks>/C<unmarks>, the found
C<data>, the C<offenders> arrayref, and C<now>. Optional: C<gate>, a
per-offender predicate; C<brandable>, a predicate narrowing which
survivors may be branded (the galla's C<ignore_ips>); and C<on_set> /
C<on_unset>, the mark-store callbacks (the galla's fleet gossip). Returns
a hashref:

    {
        fired     => 1 or 0,      # 0 when every offender was gated out
        survivors => [ ... ],     # the offenders that cleared the gate
        set       => [ ... ],     # brands set, for the EVE event
        lifted    => [ ... ],     # brands lifted
    }

A result with no offenders (a detection or purely var-keyed rule) fires
so long as it reached here, branding its data-keyed marks.

=cut

sub resolve_offense {
	my (%arg) = @_;

	my $offenders = $arg{offenders} || [];
	my $gate      = $arg{gate};

	# the survivors: every offender the gate clears. no gate means every
	# offender survives
	my @survivors = defined($gate) ? grep { $gate->($_) } @{$offenders} : @{$offenders};

	# a result that had offenders and cleared none is not an offense... it
	# fires nobody, brands nobody, and the caller emits nothing for it
	if ( @{$offenders} && !@survivors ) {
		return { 'fired' => 0, 'survivors' => [], 'set' => [], 'lifted' => [] };
	}

	my $marks   = $arg{marks}   || [];
	my $unmarks = $arg{unmarks} || [];

	# the overwhelmingly common rule brands nothing, so it skips the
	# brandable walk and the mark core entirely
	if ( !@{$marks} && !@{$unmarks} ) {
		return { 'fired' => 1, 'survivors' => \@survivors, 'set' => [], 'lifted' => [] };
	}

	# brand the survivors, less any the caller marks unbrandable (the
	# galla's ignore_ips)... counting still sees every survivor, the
	# caller's own per-hit filter deciding there
	my @brandable = defined( $arg{brandable} ) ? grep { $arg{brandable}->($_) } @survivors : @survivors;

	my ( $set, $lifted ) = App::Baphomet::Marks::apply_marks(
		$arg{store}, $marks, $unmarks, $arg{data}, \@brandable, $arg{now},
		$arg{on_set}, $arg{on_unset}
	);

	return { 'fired' => 1, 'survivors' => \@survivors, 'set' => $set, 'lifted' => $lifted };
} ## end sub resolve_offense

1;
