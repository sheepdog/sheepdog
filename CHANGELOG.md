
## 0.8.0 (not released yet)

DOG COMMAND INTERFACE:
 - new subcommand "vdi cache purge" for cleaning stale object cache
  - "vdi cache purge" cleans stale cache of all images
  - "vdi cache purge <image>" cleans stale cache of the specified image
 - new subcommand "node stat" for showing I/O status of the node
 - new subcommand "node loglevel" for changing log level at runtime
  - "node log level set" sets loglevel of running sheep process
  - "node log level get" gets loglevel from running sheep process
  - "node log level list" lists avialable loglevels
 - new option "-o" of "vdi track", for tracking objects with their oids

SHEEP COMMAND INTERFACE:
 - improvements of help messages
 - change format of the size format in -j (journaling) and -w (object cache) options. The new format is: n[TtGgMmKkb]. e.g. "-j size=1024M".
 - rotate log when sheep process catches SIGHUP signal
