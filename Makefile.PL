use ExtUtils::MakeMaker;

use 5.008;

WriteMakefile(
    dist	   => {
	            PREOP	=> 'pod2text FPing.pm | tee README >$(DISTVNAME)/README; chmod -R u=rwX,go=rX . ;',
	            COMPRESS	=> 'gzip -9v',
	            SUFFIX	=> '.gz',
	           },
    PREREQ_PM      => {
       AnyEvent => 0,
    },
    NAME           => "Net::FPing",
    VERSION_FROM   => "FPing.pm",
    LIBS           => ["-lpthread"],
    EXE_FILES      => ["bin/net-fping"],
);

