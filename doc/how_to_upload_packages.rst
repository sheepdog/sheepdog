Introduction
============
This documentation briefly describes how to upload deb/rpm packages to Sheepdog web-page.

Sheepdog web-page: https://sheepdog.github.io/sheepdog/

Procedure
=========
This procedure is just one example.

1. Build Environment
--------------------

Install OS with which you want to make a package.

Then, install the following dependent packages:

Run-time dependencies:
    - The corosync and corosync lib package or zookeeper equivalent
    - QEMU 0.13 or later
    - liburcu

Compile-time dependencies:
    - GNU Autotools
    - corosync devel package (needed for building cluster using corosync)
    - liburcu (userspace rcu) devel package
    - optional:fuse-devel (for sheepfs)
    - optional:libzookeeper-mt-dev (needed for building cluster using zookeeper)
    - optional:curl, fcgi (for http request service)

2. Make Package
-----------------
Here is just an example with sheepdog-1.0.1.tar.gz.

Replace source-code file which answers your purpose.

- deb
 1. Install "build-essential" & "checkinstall"

 ::

     $ sudo apt-get install build-essential checkinstall

 2. Download & extract source-code file

 
 ::

     $ curl -L https://github.com/sheepdog/sheepdog/archive/v1.0.1.tar.gz| tar zx

 3. Set configuration

 ::

     $ cd sheepdog-1.0.1
     $ ./autogen.sh
     $ ./configure

 4. Build

 ::

     $ make

 5. Make deb-package

 ::

     $ sudo checkinstall --install=no

 The deb-package file will be made in the current directory.

- rpm
 1. Install the required packages

 ::

     $ sudo yum install rpm-build
     $ sudo yum install autoconf automake yasm corosynclib-devel userspace-rcu-devel


 2. Download & extract source-code file

 ::

     $ curl -L https://github.com/sheepdog/sheepdog/archive/v1.0.1.tar.gz| tar zx

 3. Set configuration

 ::

     $ cd sheepdog-1.0.1
     $ ./autogen.sh
     $ ./configure

 4. Make rpm-package

 ::

     $ make rpm

 The rpm-package file will be made in `./x86_64/` .

3. Modify gh-pages
------------------
 
 In the brach "gh-pages", put the package, that you made, in data/package/deb for deb-package or data/package/rpm for rpm-package.
 
 Then, modify the following 3 files.
 
 - _sources/index.txt 
 - index.html 
 - src/index.rst 

 like this PR below:

 https://github.com/sheepdog/sheepdog/pull/317/files

 
4. Pull Request
---------------

 Do pull-request to the branch "gh-pages".

