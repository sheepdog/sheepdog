
## 0.8.0 (not released yet)

DOG COMMAND INTERFACE:
 - new subcommand "vdi cache purge" for cleaning stale object cache
 -- "vdi cache purge" cleans stale cache of all images
 -- "vdi cache purge <image>" cleans stale cache of the specified image
 - new subcommand "node stat" for showing I/O status of the node

SHEEP COMMAND INTERFACE:
 - improvements of help messages
 - change format of the size format in -j (journaling) and -w (object cache) options. The new format is: n[TtGgMmKkb]. e.g. "-j size=1024M".
