Goals
=====

Common Problems Related To Virtual Server Management:
*****************************************************

Host Dependence:
    A virtualized environment allows several operation systems to run on a 
    single physical server.
    This results in better resource utilization but it implies more services
    going down if the host has problems.
    Eventually we'll have to do some maintenance on our servers or they may
    simply stop working.
    When we stop a host, it would be a good thing to be able to run its guests
    on another server.
    
Downtime:
    We may copy the guests files to a second server or even move the physical
    hard disks on it.
    This requires time, effort and probably the physical access to the servers.
    
Single Point of Failure:
    Another common solution is to have a shared storage.
    That simply means to have a nfs folder on a nas like server, where our
    guests disks are stored.
    This way, if the server running the virtual machines
    (name it front-end server) needs maintenance, we may simply start the
    guests on the second server.
    But what do we do if the nas breaks down?

Resource waste:
    The disadvantage of this approach is that we need more hardware for the 
    back-end (the shared storage) but we still have to worry about the back-end
    failover.
    Furthermore, the hard disks on the front-end hosts are almost useless.
    
Raid complexity:
    It's common practice to use RAID (1,5,6,10) to avoid down time due to disk
    failure.
    This implies to buy hardware controllers or to use software RAID.

Sheepdog Benefits
*****************

Host Independence:
    We can run any guest on any host of the cluster, as with a common shared
    storage.
    
Less Downtime:
    Because of the host independence, we do not need to fix the broken host
    before running its guests.
    
No Single Point of Failure:
    There's not a single shared storage.
    Multiple hosts failure can be easily handled.
    
Less Resource Waste:
    Each node is, at the same time, a virtualization and storage server.
    
No Raid Necessary:
    Sheepdog is not limited to a single device per host, but as many as we wish.
    You don't need to configure a RAID Software or buy a RAID Controller.
    It will manage (on a single node) as much as unlimited disks in 
    a RAID0 like way.
