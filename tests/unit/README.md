Required git submodule:

Make empty directories "unity" and "cmock" in "tests/unit" directory.
  e.g. $ mkdir unity  and $ mkdir cmock

Then type the following commands for "unity" and "cmock" submodule
  $ git submodule update --init unity
  $ git submodule update --init cmock

To run unit tests:
When configuring sheepdog in "sheepdog" directory, put --enabel-unittest option.
  e.g. ./configure --enable-unittest 

Then type "make check"

