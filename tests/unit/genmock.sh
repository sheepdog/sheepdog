#!/bin/sh
set -xue
export LANG=C LC_ALL=C
# logger.h
(
	rm -f /tmp/logger.h
	cp -a ../../include/logger.h /tmp/logger.h
	perl -i -p -e 's/__printf\(.*?\)//g' /tmp/logger.h
	perl -i -e '$/=undef;$_=<>;s/static const char \* const loglevel_table.*?;//s;print' /tmp/logger.h
	ruby cmock/lib/cmock.rb /tmp/logger.h
)
