use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

my %WriteMakefileArgs = (
	NAME               => 'App::Baphomet',
	AUTHOR             => q{Zane C. Bowers-Hadley <vvelox@vvelox.net>},
	VERSION_FROM       => 'lib/App/Baphomet.pm',
	ABSTRACT_FROM      => 'lib/App/Baphomet.pm',
	LICENSE            => 'gpl_2',
	MIN_PERL_VERSION   => '5.006',
	INST_SCRIPT        => 'bin',
	EXE_FILES          => [ 'src_bin/baphomet', 'src_bin/galla' ],
	CONFIGURE_REQUIRES => {
		'ExtUtils::MakeMaker' => '0',
	},
	TEST_REQUIRES => {
		'Test::More' => '0',
	},
	PREREQ_PM => {
		'App::Cmd'                         => '0',
		'Ereshkigal::Client'               => '0',
		'Error::Helper'                    => '0',
		'JSON::MaybeXS'                    => '0',
		'Net::Server::Daemonize'           => '0',
		'POE'                              => '0',
		'POE::Component::Server::JSONUnix' => '0.1.0',
		'Regexp::IPv4'                     => '0',
		'Regexp::IPv6'                     => '0',
		'TOML::Tiny'                       => '0',
		'YAML::XS'                         => '0',
	},
	dist       => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
	clean      => { FILES    => 'App-Baphomet-*' },
	META_MERGE => {
		"meta-spec" => { version => 2 },
		resources   => {
			repository => {
				type => 'git',
				url  => 'https://github.com/LilithSec/Baphomet.git',
				web  => 'https://github.com/LilithSec/Baphomet',
			},
		},
		# only needed by optional pieces, soft requires at runtime... the
		# country gate's GeoIP, and the ClayTablet redis backend
		prereqs => {
			runtime => {
				recommends => {
					'IP::Geolocation::MMDB' => '0',
					'Redis::Fast'           => '0',
				},
			},
		},
	}
);

# Compatibility with old versions of ExtUtils::MakeMaker
unless ( eval { ExtUtils::MakeMaker->VERSION('6.64'); 1 } ) {
	my $test_requires = delete $WriteMakefileArgs{TEST_REQUIRES} || {};
	@{ $WriteMakefileArgs{PREREQ_PM} }{ keys %$test_requires } = values %$test_requires;
}

unless ( eval { ExtUtils::MakeMaker->VERSION('6.55_03'); 1 } ) {
	my $build_requires = delete $WriteMakefileArgs{BUILD_REQUIRES} || {};
	@{ $WriteMakefileArgs{PREREQ_PM} }{ keys %$build_requires } = values %$build_requires;
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
	unless eval { ExtUtils::MakeMaker->VERSION('6.52'); 1 };
delete $WriteMakefileArgs{MIN_PERL_VERSION}
	unless eval { ExtUtils::MakeMaker->VERSION('6.48'); 1 };
delete $WriteMakefileArgs{LICENSE}
	unless eval { ExtUtils::MakeMaker->VERSION('6.31'); 1 };

WriteMakefile(%WriteMakefileArgs);
