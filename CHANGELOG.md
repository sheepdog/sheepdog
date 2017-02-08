## 1.0.2 (release candidate)

IMPORTANT CHANGES:
 - Unlimited workqueue is now removed and changed to dynamic one.
   This is for sheep not to consume a huge amount of memory by
   creating new threads infinitely under heavy load, and to avoid
   being shot by OOM-killer.
 - zk\_control now can purge znodes within 24 hours. It purges znodes
   created before the given threshold. This is useful if tens of
   thousands of znodes are created in a day.

SHEEP COMMAND INTERFACE:
 - New option "-x" to set the maximum number of threads for dynamic
   workqueue. (default: decided by "max(#nodes,#cores,16)\*2" formula)

ZK\_CONTROL COMMAND INTERFACE:
 - The "purge" subcommand can take a non-negative interger as a
   threshold in seconds. (default: 86400 (24 hours))

LOGGING:
 - Print object IDs in 16-digit zero-padded hexadecimal to sheep.log.

## 1.0.1

IMPORTANT BUG FIX:
 - handle a case of snapshot then failover properly on iSCSI multipath
   use case (please use tgt 1.0.68 or later together)
 - disable asynchronous update of ledger objects if VID recycling is
   enabled for avoiding data object loss
 - do not make non-ledger and non-inode objects moving between disks
   when "dog node md plug" be sparse

NEW FEATURE:
 - fixed work queue: Sets and limits the number of threads in a sheep
   process. You can get stable performance with this if tuned properly.

SHEEP COMMAND INTERFACE
 - new option "-w" to set fixed work queue (default: disabled i.e. the
   number of threads increases and decreases automatically and unlimitedly)
   **(note that "-w" was object cache option before v1.0)**

DOG COMMAND INTERFACE:
 - refine output of "dog vdi lock list"
 - enhance "dog vdi lock unlock" to unlock not only working VDI but
   also snapshot

TESTING:
 - Travis CI: Tests a new pull request automatically

## 1.0

NEW FEATURE:
 - VDI over 4TiB: Now we can create a VDI larger than 4 tebibytes in
   size. This is realized by enlarging the size of data objects in a
   VDI. When you let it 8MiB (=2\*\*23 bytes), the size of VDI is 8TiB
   (=8MiB\*1024\*1024). Note that this can degrade I/O performance. So
   you should use this only if nesessary.
 - multi-cluster in one ZooKeeper: Now we can manage one or more
   Sheepdog clusters in one ZooKeeper ensemble. You should give the
   cluster driver a "cluster ID" to which cluster the sheep process
   is to join when it is launched.
 - fixed vnodes: Gives vnodes to each sheep process in a cluster not
   automatically but manually. This is useful for reducing temporal
   disk space during recovery. Note that vnodes should be given to
   each sheep process in proportion to the capacity of disk(s). So
   you should use this carefully.
 - recycleing VID: Lets a cluster garbage-collect VDI IDs when all
   the members in a VDI family are deleted then reuse them when a
   new VDI is being created. This is useful for a cluster that VDIs
   are created, snapshotted and deleted many times.
 - avoiding diskfull caused by recovery: Lets each sheep process in
   a cluster not start recovery if total capacity of objects placed
   on it in the next epoch is larger than that of disk(s).

SHEEP COMMAND INTERFACE:
 - new option "-V" to set the number of fixed vnodes manually
   (default: disabled i.e. vnodes calculated automatically)
 - a "cluster ID" can be given to the ZooKeeper cluster driver in
   the form of "host:port[,..]**/clusterID**" (default: "/sheepdog")

DOG COMMAND INTERFACE:
 - new command "dog benchmark":
 - new option "-z" to "dog cluster format" to set default data object
   size and VDI size in a cluster
   (default: 22 i.e. 4MiB = 2\*\*22 bytes per data object and
                     4TiB = 4MiB\*1024\*1024 per VDI)
 - new option "-V" to "dog cluster format" to enable fixed vnodes
   (default: disabled i.e. vnodes calculated automatically)
 - new option "-R" to "dog cluster format" to enable recycling VID
   (default: disabled)
 - new option "-F" to "dog cluster format" to enable avoiding diskfull
   caused by recovery (default: disabled i.e. try to recover always)
 - new option "-z" to "dog vdi create" to set data object size and VDI
   size being created individually with cluster's default
 - new option "-R" to "dog vdi snapshot" not to create a new snapshot
   if a working VDI does not have its own objects (default: disabled)

TESTING:
 - operation test: Useful for testing SD\_OP\_\*.

OTHER IMPORTANT NOTE:
 - **object cache feature and related interfaces are removed**

## 0.9.4

NEW FEATURE:
 - updating ledger object asynchronously: Now each sheep in a cluster
   updates an inode object and related ledger objects in an asynchronous
   manner. This improves performance of copy-on-write and dereferencing,
   especially deleting VDIs.

## 0.9.3

NEW FEATURE:
 - store driver "tree": Puts data objects into separate subdirectories
   based on their object ID, and meta objects into different directory
   from data objects. This is useful for massive cluster.
 - recovery speed throttling: Limits the number of objects being
   transferred from one sheep process to another when recovery.
   This will increase the recovery time but reduce the impact on the
   application.
 - wildcard recovery: Lets a sheep process search all objects from
   all nodes when it is launched. This enables us to upgrade a cluster
   even if object placement strategy is changed.

SHEEP COMMAND INTERFACE:
 - new option "-R" to set recovery speed throttling
   (default: no throttle)
 - new option "-W" to enable wildcard recovery (default: disabled)

DOG COMMAND INTERFACE:
 - new command "dog upgrade" to upgrade inode, epoch and config files
   and object location from old version
 - new subcommand "dog node format" to set store driver
 - new subsubcommand "get-throttle" and "set-throttle" to "dog node
   recovery" to get/set recovery speed throttling

## 0.9.2

DOG COMMAND INTERFACE:
 - new option "-l" to "dog cluster format" to enable VDI lock
   (default: disabled)

## 0.9.1

DOG COMMAND INTERFACE:
 - enhance "dog vdi lock unlock" to unlock shared-locked VDI by tgtd

## 0.9.0

NEW FEATURE:
 - new object reclaim scheme: Sheep uses new garbage collection algorithm for reclaiming objects. Disk consumption of deleted VDIs are reduced dramatically.
 -- In addition, the limitation of maximum number of children (snapshots and clones) is resolved. Creating more than 1024 snapshots or clones from single virtual disk is allowed.
 - iSCSI multipath: now tgtd isn't a single point of failure
 - VDI locking: opening single VDI by multiple QEMU process is not allowed

DOG COMMAND INTERFACE:
 - output format of "dog vdi snapshot" with -v option is changed
 - remove "dog vdi object"
  - instead, "dog vdi object location" is the new name of the previous "dog vdi object"
 - new subcommand "dog vdi object map" for printing map of inode objects
 - new option "-l" to "dog node kill" for killing sheep daemon on localhost without specifying ID
 - allow snapshot tags which start with decimal number (e.g. "123abc")
 - enhance "dog cluster snapshot' to restore previous default format redundancy.
  - add a version control to cluster snapshot.
  - 'cluster snapshot' layout is changed and DO NOT keep backward compatibility.

## 0.8.0

NEW FEATURE:
 - hyper volume: use B-tree structure to replace index-array in sd_inode so the max size of vdi could extent from 4TB to 16PB.
 - Erasure Code: a new redundancy scheme that uses error correction algorithm to achieves high available of data with much less storage overhead compared to complete replication
 - HTTP simple storage: a new interface to retrieve any amount of data with a simple web services interface.

DOG COMMAND INTERFACE:
 - new subcommand "vdi cache purge" for cleaning stale object cache
  - "vdi cache purge" cleans stale cache of all images
  - "vdi cache purge <image>" cleans stale cache of the specified image
 - new subcommand "node stat" for showing I/O status of the node
 - new subcommand "node log level" for changing log level at runtime
  - "node log level set" sets loglevel of running sheep process
  - "node log level get" gets loglevel from running sheep process
  - "node log level list" lists avialable loglevels
 - new option "-o" of "vdi track", for tracking objects with their oids
 - new option "-y" of "vdi create", for create hyper-volume vdi
 - new option "-s" of "cluster info", show backend store information
 - new option "-t" of "cluster format", choose not serve write request if number of nodes is not sufficient
 - modify option "-c" of "vdi create", we can specify "x:y" for erasure code
 - new subcommand "node stat" for node request satistics
  - "node stat -w" set watch mode for this command

SHEEP COMMAND INTERFACE:
 - improvements of help messages
 - change format of the size format in -j (journaling) and -w (object cache) options. The new format is: n[TtGgMmKkb]. e.g. "-j size=1024M".
 - rotate log when sheep process catches SIGHUP signal
 - remove "-o" option for choosing stdout as an output of log
 - remove "-f" option for executing sheep as a foreground process
  - "-o" and "-f" is a same thing to "-l dst=stdout"
 - unified "-l" option
  - "-l format=..." for log format
  - "-l level=..." for log level
  - "-l dst=..." for log destination
 - new option '-r' to enable http service
 - modify option "-c" of "cluster format", we can specify "x:y" for erasure code
