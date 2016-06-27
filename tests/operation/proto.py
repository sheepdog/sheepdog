SD_PROTO_VER = 0x02
SD_SHEEP_PROTO_VER = 0x0a

SD_EC_MAX_STRIP = 16
SD_MAX_COPIES = SD_EC_MAX_STRIP * 2 - 1

SD_OP_CREATE_AND_WRITE_OBJ  = 0x01
SD_OP_READ_OBJ       = 0x02
SD_OP_WRITE_OBJ      = 0x03
SD_OP_REMOVE_OBJ     = 0x04
SD_OP_DISCARD_OBJ    = 0x05

SD_OP_NEW_VDI        = 0x11
SD_OP_LOCK_VDI       = 0x12
SD_OP_RELEASE_VDI    = 0x13
SD_OP_GET_VDI_INFO   = 0x14
SD_OP_READ_VDIS      = 0x15
SD_OP_FLUSH_VDI      = 0x16
SD_OP_DEL_VDI        = 0x17
SD_OP_GET_CLUSTER_DEFAULT   = 0x18

SD_OP_GET_OBJ_LIST   = 0xA1
SD_OP_GET_EPOCH      = 0xA2
SD_OP_CREATE_AND_WRITE_PEER  = 0xA3
SD_OP_READ_PEER      = 0xA4
SD_OP_WRITE_PEER     = 0xA5
SD_OP_REMOVE_PEER    = 0xA6

SD_OP_GET_VDI_COPIES = 0xAB
SD_OP_READ_DEL_VDIS  = 0xC9

# macros in the SD_FLAG_CMD_XXX group are mutually exclusive
SD_FLAG_CMD_WRITE    = 0x01
SD_FLAG_CMD_COW      = 0x02
SD_FLAG_CMD_CACHE    = 0x04
SD_FLAG_CMD_DIRECT   = 0x08 # don't use object cache
# return something back while sending something to sheep
SD_FLAG_CMD_PIGGYBACK   = 0x10
SD_FLAG_CMD_TGT   = 0x20

SD_RES_SUCCESS       = 0x00 # Success
SD_RES_UNKNOWN       = 0x01 # Unknown error
SD_RES_NO_OBJ        = 0x02 # No object found
SD_RES_EIO           = 0x03 # I/O error
SD_RES_VDI_EXIST     = 0x04 # VDI exists already
SD_RES_INVALID_PARMS = 0x05 # Invalid parameters
SD_RES_SYSTEM_ERROR  = 0x06 # System error
SD_RES_VDI_LOCKED    = 0x07 # VDI is locked
SD_RES_NO_VDI        = 0x08 # No VDI found
SD_RES_NO_BASE_VDI   = 0x09 # No base VDI found
SD_RES_VDI_READ      = 0x0A # Cannot read requested VDI
SD_RES_VDI_WRITE     = 0x0B # Cannot write requested VDI
SD_RES_BASE_VDI_READ = 0x0C # Cannot read base VDI
SD_RES_BASE_VDI_WRITE   = 0x0D # Cannot write base VDI
SD_RES_NO_TAG        = 0x0E # Requested tag is not found
SD_RES_STARTUP       = 0x0F # Sheepdog is on starting up
SD_RES_VDI_NOT_LOCKED   = 0x10 # VDI is not locked
SD_RES_SHUTDOWN      = 0x11 # Sheepdog is shutting down
SD_RES_NO_MEM        = 0x12 # Cannot allocate memory
SD_RES_FULL_VDI      = 0x13 # we already have the maximum VDIs
SD_RES_VER_MISMATCH  = 0x14 # Protocol version mismatch
SD_RES_NO_SPACE      = 0x15 # Server has no room for new objects
SD_RES_WAIT_FOR_FORMAT  = 0x16 # Sheepdog is waiting for a format operation
SD_RES_WAIT_FOR_JOIN = 0x17 # Sheepdog is waiting for other nodes joining
SD_RES_JOIN_FAILED   = 0x18 # Target node had failed to join sheepdog
SD_RES_HALT          = 0x19 # Sheepdog is stopped doing IO
SD_RES_READONLY      = 0x1A # Object is read-only
# inode object in client is invalidated, refreshing is required
SD_RES_INODE_INVALIDATED = 0x1D

# Object ID rules
#
#  0 - 31 (32 bits): data object space
# 32 - 55 (24 bits): VDI object space
# 56 - 59 ( 4 bits): reserved VDI object space
# 60 - 63 ( 4 bits): object type identifier space
VDI_SPACE_SHIFT = 32
SD_VDI_MASK = 0x00FFFFFF00000000
VDI_BIT = 1 << 63
VMSTATE_BIT = 1 << 62
VDI_ATTR_BIT = 1 << 61
VDI_BTREE_BIT = 1 << 60
LEDGER_BIT = 1 << 59
OLD_MAX_DATA_OBJS = 1 << 20
MAX_DATA_OBJS = 1 << 32
SD_MAX_VDI_LEN = 256
SD_MAX_VDI_TAG_LEN = 256
SD_MAX_VDI_ATTR_KEY_LEN = 256
SD_MAX_VDI_ATTR_VALUE_LEN = 65536
SD_MAX_SNAPSHOT_TAG_LEN = 256
SD_NR_VDIS = 1 << 24
SD_DATA_OBJ_SIZE = 1 << 22
SD_OLD_MAX_VDI_SIZE = (SD_DATA_OBJ_SIZE * OLD_MAX_DATA_OBJS)
SD_MAX_VDI_SIZE = (SD_DATA_OBJ_SIZE * MAX_DATA_OBJS)
SD_DEFAULT_BLOCK_SIZE_SHIFT = 22

SD_LEDGER_OBJ_SIZE = 1 << 22
CURRENT_VDI_ID = 0

STORE_LEN = 16

SD_REQ_SIZE = 48
SD_RSP_SIZE = 48

LOCK_TYPE_NORMAL = 0
LOCK_TYPE_SHARED = 1  # for iSCSI multipath


def vid_to_vdi_oid(vid):
    return VDI_BIT | vid << VDI_SPACE_SHIFT
