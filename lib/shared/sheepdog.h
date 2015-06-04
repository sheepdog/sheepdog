/*
 * Copyright (C) 2015 China Mobile Inc.
 *
 * Liu Yuan <liuyuan@cmss.chinamobile.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SHEEPDOG_H_
#define SHEEPDOG_H_

#ifndef NO_SHEEPDOG_LOGGER
# define NO_SHEEPDOG_LOGGER
#endif

#include "sheepdog_proto.h"
#include "list.h"
#include "util.h"

#include <arpa/inet.h>
#include <sys/eventfd.h>

struct sd_cluster {
	int sockfd;
	uint8_t addr[INET_ADDRSTRLEN];
	unsigned int port;
	uint32_t seq_num;
	pthread_t request_thread;
	pthread_t reply_thread;
	int request_fd, reply_fd;
	struct list_head request_list;
	struct list_head inflight_list;
	struct list_head blocking_list;
	uatomic_bool stop_request_handler;
	uatomic_bool stop_reply_handler;
	struct sd_rw_lock request_lock;
	struct sd_rw_lock inflight_lock;
	struct sd_rw_lock blocking_lock;
	struct sd_mutex submit_mutex;
};

struct sd_vdi {
	struct sd_cluster *cluster;
	struct sd_inode *inode;
	uint32_t vid;
	struct sd_rw_lock lock;
	char *name;
};

/*
 * Connect to the specified Sheepdog cluster.
 *
 * @host: string in the form of IP:PORT that identify a valid Sheepdog cluster.
 *
 * Return a cluster descriptor on success. Otherwise, return NULL in case of
 * error and set errno as error code defined in sheepdog_proto.h.
 */
struct sd_cluster *sd_connect(char *host);

/*
 * Disconnect to the specified sheepdog cluster.
 *
 * @c: pointer to the cluster descriptor.
 *
 * Return error code defined in sheepdog_proto.h.
 */
int sd_disconnect(struct sd_cluster *c);

/*
 * Run the Sheepdog request on the specified cluster synchronously.
 *
 * @c: pointer to the cluster descriptor.
 * @hdr: pointer to the sheepdog request header descriptor.
 * @data: pointer to the data for hdr.
 *
 * Return error code defined in sheepdog_proto.h.
 */
int sd_run_sdreq(struct sd_cluster *c, struct sd_req *hdr, void *data);

/*
 * Open the named vdi from the specified cluster.
 *
 * @c: pointer to the cluster descriptor.
 * @name: the name of the vdi to be opened.
 *
 * Return a vdi descriptor on success. Otherwise, return NULL in case of
 * error and set errno as error code defined in sheepdog_proto.h.
 */
struct sd_vdi *sd_vdi_open(struct sd_cluster *c, char *name);

/*
 * Read from a vdi descriptor at a given offset.
 *
 * @vdi: pointer to the vdi descriptor.
 * @buf: the buffer to hold the data.
 * @count: how many bytes we read up to.
 * @offset: the start of the vdi we try to read.
 *
 * Return error code defined in sheepdog_proto.h.
 */
int sd_vdi_read(struct sd_vdi *vdi, void *buf, size_t count, off_t offset);

/*
 * Write to a vdi descriptor at a given offset.
 *
 * @vdi: pointer to the vdi descriptor.
 * @buf: the buffer to hold the data.
 * @count: how many bytes we write up to.
 * @offset: the start of the vdi we try to write.
 *
 * Return error code defined in sheepdog_proto.h.
 */
int sd_vdi_write(struct sd_vdi *vdi, void *buf, size_t count, off_t offset);

/*
 * Close a vdi descriptor.
 *
 * @vdi: pointer to the vdi descriptor.
 *
 * Return error code defined in sheepdog_proto.h.
 */
int sd_vdi_close(struct sd_vdi *vdi);

/*
 * Create a snapshot of a VDI
 *
 * @c: pointer to the cluster descriptor
 * @name: the name of the VDI to snapshot
 * @tag: the tag of the snapshot
 *
 * Return error code defined in sheepdog_proto.h.
 */
int sd_vdi_snapshot(struct sd_cluster *c, char *name, char *tag);

/*
 * Create a VDI in the specified cluster
 *
 * @c: pointer to the cluster descriptor
 * @name: the name of the VDI to be created
 * @size: the size(Byte) of the VDI to be created
 *
 * Return error code defined in sheepdog_proto.h.
 */
int sd_vdi_create(struct sd_cluster *c, char *name, uint64_t size);

/*
 * Clone a new VDI from a snapshot
 *
 * @c: pointer to the cluster descriptor
 * @srcname: the source VDI name
 * @srctag: the source VDI tag
 * @dstname: the destination VDI name
 *
 * Return error code defined in sheepdog_proto.h.
 * Only snapshot VDI can be cloned.
 */
int sd_vdi_clone(struct sd_cluster *c, char *srcname,
		 char *srctag, char *dstname);

/*
 * Delete a VDI in the cluster
 *
 * @c: pointer to the cluster descriptor
 * @name: the name of the VDI to be deleted
 * @tag: the snapshot tag of the VDI
 *
 * Return error code defined in sheepdog_proto.h
 */
int sd_vdi_delete(struct sd_cluster *c, char *name, char *tag);

/*
 * Rollback a VDI from it's early snapshot
 *
 * @c: pointer to the cluster descriptor
 * @name: the name of the VDI to be deleted
 * @tag: the snapshot tag of the VDI
 *
 * Return error code defined in sheepdog_proto.h
 */
int sd_vdi_rollback(struct sd_cluster *c, char *name, char *tag);

#endif
