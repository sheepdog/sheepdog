
SHEEPDOG ADMINISTRATOR GUIDE
============================

Sheepdog is a distributed storage system for QEMU.
It provides highly available block level storage volumes that can be attached to
QEMU virtualmachines.
Sheepdog scales to several hundreds nodes, and supports advanced volume
management features such as snapshot, cloning, and thin provisioning.



Introduction
============

.. toctree::
    :maxdepth: 2
    

    about_this_guide.rst
    author_and_licensing.rst
    project_history.rst
    project_status.rst
    main_futures.rst
    goals.rst


    
Sheepdog Basic
==============

.. toctree::
    :maxdepth: 2
    
    concepts.rst
    installation.rst
    configuration.rst
    start_the_cluster.rst
    dog_intro.rst
    create_new_disk.rst
    monitor_cluster.rst
    fail_over.rst
    verify_vdi.rst
    stop_and_restart_cluster.rst
    backup.rst



Sheepdog Advanced
=================

.. toctree::
    :maxdepth: 2
    
    more_concepts.rst
    multidevice.rst
    cache.rst
    journal.rst
    more_network_cards.rst
    snapshot.rst
    vdi_read_and_write.rst
    more_about_backup.rst
    misc.rst



Suggestions And Special Cases
=============================

.. toctree::
    :maxdepth: 2
    
    optimization.rst
    