Sheepdog Project
================

Sheepdog is a distributed storage system for `QEMU <http://www.qemu.org/>`__.
It provides highly available block level storage volumes
that can be attached to QEMU virtual machines. Sheepdog scales to several
hundreds nodes, and supports
advanced volume management features such as snapshot, cloning, and
thin provisioning.

.. figure:: overview.png
   :alt: figure of sheepdog overview
   :align: center
   :scale: 80

Documentations
--------------

.. toctree::
   :maxdepth: 1

* Wiki

  + https://github.com/sheepdog/sheepdog/wiki

+ Presentations

  + Sheepdog: Yet Another All-In-One Storage For Openstack, Openstack Hong Kong Summit, Nov 2013. (`Slides <_static/sheepdog-openstack.pdf>`__)
  + Sheepdog: Distributed Storage System for QEMU, KVM Forum 2010, Aug 2010. (`Slides <_static/kvmforum2010.pdf>`__)
  + Sheepdog: Distributed Storage System for QEMU/KVM, LCA 2010 DS&R miniconf, Jan 2010. (`Slides <_static/lca2010_miniconf.pdf>`__)

Source Code
-----------
Sheepdog is an Open Source software, released under the terms of the
`GPL2 <./_static/LICENSE.txt>`__.

+ The latest version is `0.7.4 <https://github.com/sheepdog/sheepdog/tarball/v0.7.4>`__
+ The latest developent code is available on the git tree

  + server: git://github.com/sheepdog/sheepdog.git
    [`browse <https://github.com/sheepdog/sheepdog>`__]
  + client: git://git.qemu.org/qemu.git
    [`browse <http://git.qemu.org/qemu.git>`__]

Mailing list and IRC
--------------------

+ Developers Mailing list

  + Subscribe: `http://lists.wpkg.org/mailman/listinfo/sheepdog
    <http://lists.wpkg.org/mailman/listinfo/sheepdog>`__
  + Archive:  `http://lists.wpkg.org/pipermail/sheepdog/
    <http://lists.wpkg.org/pipermail/sheepdog/>`__

+ Users Mailing list

  + Subscribe: `http://lists.wpkg.org/mailman/listinfo/sheepdog-users
    <http://lists.wpkg.org/mailman/listinfo/sheepdog-users>`__
  + Archive:  `http://lists.wpkg.org/pipermail/sheepdog-users/
    <http://lists.wpkg.org/pipermail/sheepdog-users/>`__

+ IRC

  + #sheepdog on `freenode <http://webchat.freenode.net/>`__
