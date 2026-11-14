package App::Baphomet::App::FanoutCmd;

use v5.40;
# log data is raw bytes of unknown encoding... under unicode_strings \s, \w,
# lc, and /i would read a high byte as a Latin-1 character, so it stays off
no feature 'unicode_strings';
use Ref::Util     qw( is_plain_hashref );
use Exporter      qw( import );
use JSON::MaybeXS ();

our @EXPORT_OK = qw( fanout_validate_args fanout_execute );

=pod

=head1 NAME

App::Baphomet::App::FanoutCmd - The shared body of the per-galla fan-out commands.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Baphomet::App::FanoutCmd qw( fanout_validate_args fanout_execute );

    sub validate_args {
        my ( $self, $opt, $args ) = @_;
        return fanout_validate_args( $self, $args, 'accused' );
    }

    sub execute {
        my ( $self, $opt, $args ) = @_;
        return fanout_execute( $self, $args, 'accused', $opt->ip, 'accused' );
    }

=head1 DESCRIPTION

The accused and marked commands are the same shape... ask the manager,
which fans out to one galla or all, then optionally pare each galla's
answer down to one key of interest. This holds that shape once so the
commands carry only their own names and wording.

=head1 FUNCTIONS

=head2 fanout_validate_args

Dies via usage_error when more than the one optional galla-name arg was
passed. C<$command> names the command in the error.

    fanout_validate_args( $self, $args, $command );

=cut

sub fanout_validate_args {
	my ( $self, $args, $command ) = @_;

	if ( @{$args} > 1 ) {
		$self->usage_error( $command . ' takes at most one arg, a galla name' );
	}

	return;
}

=head2 fanout_execute

Calls the manager's C<$command>, passing the galla name when one was
argued. C<$pare_value>, when defined, pares each galla's C<$pare_key>
hash down to that one entry, dropping gallas not carrying it at all. The
result prints as pretty canonical JSON.

    fanout_execute( $self, $args, $command, $pare_value, $pare_key );

=cut

sub fanout_execute {
	my ( $self, $args, $command, $pare_value, $pare_key ) = @_;

	my $result;
	if ( @{$args} ) {
		$result = $self->app->manager_call( $command, { 'name' => $args->[0] } );
	} else {
		$result = $self->app->manager_call($command);
	}

	if ( defined($pare_value) && is_plain_hashref( $result->{gallas} ) ) {
		foreach my $galla ( keys( %{ $result->{gallas} } ) ) {
			my $held = $result->{gallas}{$galla}{$pare_key};
			if ( !is_plain_hashref($held) || !defined( $held->{$pare_value} ) ) {
				delete( $result->{gallas}{$galla} );
				next;
			}
			$result->{gallas}{$galla}{$pare_key} = { $pare_value => $held->{$pare_value} };
		}
	} ## end if ( defined($pare_value) && is_plain_hashref...)

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	return;
} ## end sub fanout_execute

1;
