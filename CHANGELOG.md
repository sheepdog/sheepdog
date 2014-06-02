## 0.9.0 (not released yet)

NEW FEATURE:
 - new object reclaim scheme: Sheep uses new garbage collection algorithm for reclaiming objects. Disk consumption of deleted VDIs are reduced dramatically.

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
