#ifndef SHEEPFS_H
#define SHEEPFS_H

#include <fuse.h>

enum sheepfs_opcode {
	OP_NULL = 0,
	OP_CLUSTER_INFO,
	OP_VDI_LIST,
	OP_VDI_MOUNT,
	OP_VDI_UNMOUNT,
	OP_NODE_INFO,
	OP_NODE_LIST,
	OP_CONFIG_PCACHE,
	OP_CONFIG_OCACHE,
	OP_CONFIG_SHEEP,
	OP_VOLUME,
};

#define COMMAND_LEN  512

extern char sheepfs_shadow[];
extern int sheepfs_page_cache;
extern int sheepfs_object_cache;
extern char sdhost[];
extern int sdport;

struct strbuf *sheepfs_run_cmd(const char *command);
int sheepfs_set_op(const char *path, unsigned opcode);

typedef void (*printf_fn)(const char *func, int line, const char *, ...)
	__printf(3, 4);

extern printf_fn fs_printf;

#define sheepfs_pr(fmt, args...)			\
({							\
	fs_printf(__func__, __LINE__, fmt, ##args);	\
})

/* shadow_file.c */
size_t shadow_file_write(const char *path, char *buf, size_t size);
int shadow_file_read(const char *, char *buf, size_t size, off_t);
int shadow_dir_create(const char *path);
int shadow_file_create(const char *path);
int shadow_file_setxattr(const char *path, const char *name,
				const void *value, size_t size);
int shadow_file_getxattr(const char *path, const char *name,
				void *value, size_t size);
int shadow_file_delete(const char *path);
bool shadow_file_exsit(const char *path);

/* volume.c */
int create_volume_layout(void);
int volume_read(const char *path, char *buf, size_t size, off_t offset);
int volume_write(const char *, const char *buf, size_t size, off_t);
size_t volume_get_size(const char *);
int volume_create_entry(const char *entry);
int volume_remove_entry(const char *entry);
int volume_sync(const char *path);
int volume_open(const char *path, struct fuse_file_info *);
int reset_socket_pool(void);

/* cluster.c */
int cluster_info_read(const char *path, char *buf, size_t size, off_t);
size_t cluster_info_get_size(const char *path);
int create_cluster_layout(void);

/* vdi.c */
int create_vdi_layout(void);
int vdi_list_read(const char *path, char *buf, size_t size, off_t);
size_t vdi_list_get_size(const char *path);

int vdi_mount_write(const char *, const char *buf, size_t size, off_t);
int vdi_unmount_write(const char *, const char *buf, size_t, off_t);

/* node.c */
int node_list_read(const char *path, char *buf, size_t size, off_t);
size_t node_list_get_size(const char *path);
int node_info_read(const char *path, char *buf, size_t size, off_t);
size_t node_info_get_size(const char *path);
int create_node_layout(void);

/* config.c */
int create_config_layout(void);

int config_pcache_read(const char *path, char *buf, size_t size, off_t);
int config_pcache_write(const char *path, const char *, size_t, off_t);
size_t config_pcache_get_size(const char *path);

int config_ocache_read(const char *path, char *buf, size_t size, off_t);
int config_ocache_write(const char *path, const char *, size_t, off_t);
size_t config_ocache_get_size(const char *path);

int config_sheep_info_read(const char *path, char *, size_t size, off_t);
int config_sheep_info_write(const char *, const char *, size_t, off_t);
size_t config_sheep_info_get_size(const char *path);

#endif
