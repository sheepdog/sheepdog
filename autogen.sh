#!/bin/sh
# Run this to generate all the initial makefiles, etc.

echo Building configuration system...
autoreconf -i -f && echo Now run ./configure and make
