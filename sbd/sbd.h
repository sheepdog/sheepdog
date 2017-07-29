#ifndef _SBD_H_
#define _SBD_H_

#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/gfp.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "sheepdog_proto.h"

#define DRV_NAME "sbd"
#define DEV_NAME_LEN 32
#define SBD_MINORS_SHIFT 5 /* at most 31 partitions for a single device */
#define SECTOR_SIZE 512

/* __GFP_MEMALLOC was introduced since v3.6, if not defined, nullify it */
#ifndef __GFP_MEMALLOC
# define __GFP_MEMALLOC GFP_NOIO
#endif

/*
 * Try our best to handle low memory situation, when dirty pages should be
 * written out over network, not local disks.
 */
#define SBD_GFP_FLAGS (GFP_NOIO | __GFP_MEMALLOC)

struct sheep_vdi {
	struct sd_inode *inode;
	u32 vid;
	char ip[16];
	unsigned int port;
	char name[SD_MAX_VDI_LEN];
};

struct sbd_device {
	struct socket *sock;
	int id;		/* blkdev unique id */
	atomic_t seq_num;

	int major;
	int minor;
	struct gendisk *disk;
	struct request_queue *rq;
	spinlock_t queue_lock;   /* request queue lock */

	struct sheep_vdi vdi;		/* Associated sheep image */
	spinlock_t vdi_lock;

	struct list_head request_head; /* protected by queue lock */
	struct list_head inflight_head; /* for inflight sheep requests */
	struct list_head blocking_head; /* for blocking sheep requests */
	rwlock_t inflight_lock;
	rwlock_t blocking_lock;

	struct list_head list;
	struct task_struct *reaper;
	struct task_struct *submiter;
	wait_queue_head_t reaper_wq;
	wait_queue_head_t submiter_wq;
};

struct sheep_aiocb {
	struct request *request;
	u64 offset;
	u64 length;
	int ret;
	atomic_t nr_requests;
	char *buf;
	int buf_iter;
	void (*aio_done_func)(struct sheep_aiocb *);
};

enum sheep_request_type {
	SHEEP_READ,
	SHEEP_WRITE,
	SHEEP_CREATE,
};

struct sheep_request {
	struct list_head list;
	struct sheep_aiocb *aiocb;
	u64 oid;
	u64 cow_oid;
	u32 seq_num;
	int type;
	int offset;
	int length;
	char *buf;
};

void socket_shutdown(struct socket *sock);
int sheep_setup_vdi(struct sbd_device *dev);
struct sheep_aiocb *sheep_aiocb_setup(struct request *req);
int sheep_aiocb_submit(struct sheep_aiocb *aiocb);
int sheep_handle_reply(struct sbd_device *dev);
int sheep_slab_create(void);
void sheep_slab_destroy(void);

static inline int sbd_dev_id_to_minor(int id)
{
	return id << SBD_MINORS_SHIFT;
}

#define sbd_debug(fmt, ...) \
	pr_debug("%s:%s:%u " fmt, KBUILD_MODNAME,  __func__, \
		 __LINE__, ##__VA_ARGS__)

#endif /* _SBD_H_ */
