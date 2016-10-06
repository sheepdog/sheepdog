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
Here is just an exmple with sheepdog-sheepdog-v1.0-0-gc949903.tar.gz.

Replace source-code file which answers your purpose.

- deb
 1. Install "build-essential" & "checkinstall"

 ::

     $ sudo apt-get install build-essential checkinstall

 2. Download & extract source-code file

 
 ::

     $ wget https://github.com/sheepdog/sheepdog/tarball/v1.0/sheepdog-sheepdog-v1.0-0-gc949903.tar.gz
     $ tar zxvf sheepdog-sheepdog-v1.0-0-gc949903.tar.gz

 3. Set configuration

 ::

     $ cd sheepdog-sheepdog-v1.0-0-gc949903
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
 1. Install "rpm-build"

 ::

     $ sudo yum install rpm-build


 2. Make "rpmbuild" directory

 ::

     $ cd ~
     $ mkdir -p rpmbuild/BUILD
     $ mkdir -p rpmbuild/BUILDROOT
     $ mkdir -p rpmbuild/RPMS
     $ mkdir -p rpmbuild/SOURCES
     $ mkdir -p rpmbuild/SPECS
     $ mkdir -p rpmbuild/SRPMS

 3. Make spec file
 
 Make spec file like "Example of rpm spec file" at Reference.
 
 Then, save it as "sheepdog.spec" in rpmbuild/SPECS.

 4. Make rpm-package

 ::

     $ cd ~/rpmbuild/SPECS
     $ rpmbuild -ba sheepdog.spec

 The rpm-package file will be made in rpmbuild/RPMS.

3. Modify gh-pages
------------------
 
 In the brach "gh-pages", put the package, that you made, in data/package/deb for deb-package or data/package/rpm for rpm-package.
 
 Then, like this PR below >
 
 https://github.com/sheepdog/sheepdog/pull/317/files
 
 modify the following 3 files.
 
 - _sources/index.txt 
 - index.html 
 - src/index.rst 
 
4. Pull Request
---------------

 Do pull-request to the branch "gh-pages".

Reference
=========

Example of rpm spec file:
 ::

    Name: sheepdog-sheepdog
    Summary: The Sheepdog Distributed Storage System for QEMU
    Version: c949903
    Release: 1%{?dist}
    License: GPLv2 and GPLv2+
    Group: System Environment/Base
    URL: http://www.osrg.net/sheepdog
    Source0: https://github.com/sheepdog/sheepdog/tarball/v1.0/sheepdog-sheepdog-v1.0-0-gc949903.tar.gz
    
    # Runtime bits
    Requires: corosync
    Requires(post): chkconfig
    Requires(preun): chkconfig
    Requires(preun): initscripts
    
    # Build bits
    BuildRequires: autoconf automake
    BuildRequires: corosynclib-devel userspace-rcu-devel
    
    BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
    
    %description
    This package contains the Sheepdog server, and command line tool which offer
    a distributed object storage system for QEMU.
    
    %prep
    %setup -q
    
    %build
    ./autogen.sh
    %{configure} --with-initddir=%{_initrddir} %{_configopts}
    
    make %{_smp_mflags}
    
    %install
    rm -rf %{buildroot}
    
    make install DESTDIR=%{buildroot}
    
    ## tree fixup
    # drop static libs
    rm -f %{buildroot}%{_libdir}/*.a
    
    %clean
    rm -rf %{buildroot}
    
    %post
    /sbin/chkconfig --add sheepdog
    ln -s -f %{_bindir}/dog %{_bindir}/collie
    
    %preun
    if [ $1 -eq 0 ] ; then
    	/sbin/service sheepdog stop >/dev/null 2>&1
    	/sbin/chkconfig --del sheepdog
    fi
    
    %postun
    if [ "$1" -ge "1" ] ; then
    	/sbin/service sheepdog condrestart >/dev/null 2>&1 || :
    else
    	rm -f /usr/sbin/collie
    fi
    
    %files
    %defattr(-,root,root,-)
    %doc COPYING README INSTALL
    %{_sbindir}/sheep
    %{_bindir}/dog
    %{_sbindir}/shepherd
    %attr(755,-,-)%config %{_initddir}/sheepdog
    %dir %{_localstatedir}/lib/sheepdog
    %config %{_sysconfdir}/bash_completion.d/dog
    %{_mandir}/man8/sheep.8*
    %{_mandir}/man8/dog.8*
    %{_prefix}/lib/systemd/system/sheepdog.service
    %dir %{_includedir}/sheepdog
    %{_includedir}/sheepdog/internal.h
    %{_includedir}/sheepdog/list.h
    %{_includedir}/sheepdog/sheepdog.h
    %{_includedir}/sheepdog/sheepdog_proto.h
    %{_includedir}/sheepdog/util.h
    %{_libdir}/libsheepdog.la
    %{_libdir}/libsheepdog.so
    
    %changelog
    * Mon Oct 3 2016 Autotools generated version <sheepdog-users@lists.wpkg.org> - v1.0-1.0.0
    - Autotools generated version
