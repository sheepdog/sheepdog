/*
 * Copyright (C) 2014 Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * SBD - Sheepdog Block Device
 *
 * This file implements the glue functions to export sheep vdi as Linux block
 * device.
 *
 */

#include "sbd.h"

static LIST_HEAD(sbd_dev_list);

static const struct block_device_operations sbd_bd_ops = {
	.owner		= THIS_MODULE,
};

static int sbd_submit_request(struct request *req)
{
	struct sheep_aiocb *aiocb = sheep_aiocb_setup(req);

	if (IS_ERR(aiocb))
		return PTR_ERR(aiocb);

	return sheep_aiocb_submit(aiocb);
}

static void sbd_request_fn(struct request_queue *q)
__releases(q->queue_lock) __acquires(q->queue_lock)
{
	struct request *req;
	struct sbd_device *dev = q->queuedata;

	while ((req = blk_fetch_request(q)) != NULL) {

		/* filter out block requests we don't understand */
		if (unlikely(req->cmd_type != REQ_TYPE_FS)) {
			__blk_end_request_all(req, 0);
			continue;
		}

		list_add_tail(&req->queuelist, &dev->request_head);
		spin_unlock_irq(q->queue_lock);

		wake_up(&dev->submiter_wq);

		spin_lock_irq(q->queue_lock);
	}
}

static int sbd_add_disk(struct sbd_device *dev)
{
	struct gendisk *disk;
	struct request_queue *rq;

	disk = alloc_disk(SBD_MINORS_PER_MAJOR);
	if (!disk)
		return -ENOMEM;

	snprintf(disk->disk_name, DEV_NAME_LEN, DRV_NAME "%d", dev->id);
	disk->major = dev->major;
	disk->first_minor = 0;
	disk->fops = &sbd_bd_ops;
	disk->private_data = dev;

	rq = blk_init_queue(sbd_request_fn, &dev->queue_lock);
	if (!rq) {
		put_disk(disk);
		return -ENOMEM;
	}

	blk_queue_max_hw_sectors(rq, SD_DATA_OBJ_SIZE / SECTOR_SIZE);
	blk_queue_max_segments(rq, SD_DATA_OBJ_SIZE / SECTOR_SIZE);
	blk_queue_max_segment_size(rq, SD_DATA_OBJ_SIZE);
	blk_queue_io_opt(rq, SD_DATA_OBJ_SIZE);

	disk->queue = rq;
	rq->queuedata = dev;
	dev->disk = disk;
	dev->rq = rq;

	set_capacity(disk, dev->vdi.inode->vdi_size / SECTOR_SIZE);
	add_disk(disk);

	return 0;
}

static int sbd_request_reaper(void *data)
{
	struct sbd_device *dev = data;
	int ret;

	while (!kthread_should_stop() || !list_empty(&dev->inflight_head)) {
		bool empty;

		wait_event_interruptible(dev->reaper_wq,
					 kthread_should_stop() ||
					 !list_empty(&dev->inflight_head));

		read_lock(&dev->inflight_lock);
		empty = list_empty(&dev->inflight_head);
		read_unlock(&dev->inflight_lock);

		if (unlikely(empty))
			continue;

		ret = sheep_handle_reply(dev);
		if (unlikely(ret < 0))
			pr_err("reaper: failed to handle reply\n");
	}
	return 0;
}

static int sbd_request_submiter(void *data)
{
	struct sbd_device *dev = data;
	int ret;

	while (!kthread_should_stop() || !list_empty(&dev->request_head)) {
		struct request *req;

		wait_event_interruptible(dev->submiter_wq,
					 kthread_should_stop() ||
					 !list_empty(&dev->request_head));

		spin_lock_irq(&dev->queue_lock);
		if (unlikely(list_empty(&dev->request_head))) {
			spin_unlock_irq(&dev->queue_lock);
			continue;
		}
		req = list_entry_rq(dev->request_head.next);
		list_del_init(&req->queuelist);
		spin_unlock_irq(&dev->queue_lock);

		ret = sbd_submit_request(req);
		if (unlikely(ret < 0))
			pr_err("submiter: failed to submit request\n");
	}
	return 0;
}

static inline void free_sbd_device(struct sbd_device *dev)
{
	socket_shutdown(dev->sock);
	vfree(dev->vdi.inode);
	kfree(dev);
}

static ssize_t sbd_add(struct bus_type *bus, const char *buf,
		       size_t count)
{
	struct sbd_device *dev, *tmp;
	ssize_t ret;
	int new_id = 0;
	char name[DEV_NAME_LEN];

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto err_put;
	}

	if (sscanf(buf, "%s %d %s", dev->vdi.ip, &dev->vdi.port,
		   dev->vdi.name) != 3) {
		ret = -EINVAL;
		goto err_put;
	}

	spin_lock_init(&dev->queue_lock);
	spin_lock_init(&dev->vdi_lock);
	INIT_LIST_HEAD(&dev->inflight_head);
	INIT_LIST_HEAD(&dev->blocking_head);
	INIT_LIST_HEAD(&dev->request_head);
	init_waitqueue_head(&dev->reaper_wq);
	init_waitqueue_head(&dev->submiter_wq);
	rwlock_init(&dev->inflight_lock);
	rwlock_init(&dev->blocking_lock);

	list_for_each_entry(tmp, &sbd_dev_list, list) {
		if (tmp->id > new_id)
			new_id = tmp->id + 1;
	}

	ret = sheep_setup_vdi(dev);
	if (ret < 0)
		goto err_free_dev;

	dev->id = new_id;
	snprintf(name, DEV_NAME_LEN, DRV_NAME "%d", dev->id);
	ret = register_blkdev(0, name);
	if (ret < 0)
		goto err_free_dev;
	dev->major = ret;
	dev->minor = 0;
	dev->reaper = kthread_run(sbd_request_reaper, dev, "sbd_reaper");
	if (IS_ERR(dev->reaper))
		goto err_unreg_blkdev;
	dev->submiter = kthread_run(sbd_request_submiter, dev, "sbd_submiter");
	if (IS_ERR(dev->submiter))
		goto err_unreg_blkdev;

	ret = sbd_add_disk(dev);
	if (ret < 0)
		goto err_unreg_blkdev;

	list_add_tail(&dev->list, &sbd_dev_list);

	return count;
err_unreg_blkdev:
	unregister_blkdev(dev->major, name);
err_free_dev:
	free_sbd_device(dev);
err_put:
	module_put(THIS_MODULE);
	pr_err("%s: error adding device %s", DRV_NAME, buf);
	return ret;
}

static void sbd_del_disk(struct sbd_device *dev)
{
	struct gendisk *disk = dev->disk;

	if (!disk)
		return;

	if (disk->flags & GENHD_FL_UP)
		del_gendisk(disk);
	if (disk->queue)
		blk_cleanup_queue(disk->queue);
	put_disk(disk);
}

static ssize_t sbd_remove(struct bus_type *bus, const char *buf,
			  size_t count)
{

	struct list_head *tmp, *n;
	struct sbd_device *dev;
	unsigned long ul;
	int target_id, ret;

	ret = strict_strtoul(buf, 10, &ul);
	if (ret)
		return ret;

	/* convert to int; abort if we lost anything in the conversion */
	target_id = (int)ul;
	if (target_id != ul)
		return -EINVAL;

	list_for_each_safe(tmp, n, &sbd_dev_list) {
		dev = list_entry(tmp, struct sbd_device, list);
		if (dev->id == target_id) {
			list_del(&dev->list);
			break;
		}
		dev = NULL;
	}

	if (!dev)
		return -ENOENT;

	kthread_stop(dev->reaper);
	kthread_stop(dev->submiter);
	wake_up(&dev->reaper_wq);
	wake_up(&dev->submiter_wq);

	sbd_del_disk(dev);
	free_sbd_device(dev);
	module_put(THIS_MODULE);

	return count;
}

static struct bus_attribute sbd_bus_attrs[] = {
	__ATTR(add, S_IWUSR, NULL, sbd_add),
	__ATTR(remove, S_IWUSR, NULL, sbd_remove),
	__ATTR_NULL
};

static struct bus_type sbd_bus_type = {
	.name		= "sbd",
	.bus_attrs	= sbd_bus_attrs,
};

static void sbd_root_dev_release(struct device *dev)
{
}

static struct device sbd_root_dev = {
	.init_name	= "sbd",
	.release	= sbd_root_dev_release,
};

/* Create control files in /sys/bus/sbd/... */
static int sbd_sysfs_init(void)
{
	int ret;

	ret = device_register(&sbd_root_dev);
	if (ret < 0)
		return ret;

	ret = bus_register(&sbd_bus_type);
	if (ret < 0)
		device_unregister(&sbd_root_dev);

	return ret;
}

static void sbd_sysfs_cleanup(void)
{
	bus_unregister(&sbd_bus_type);
	device_unregister(&sbd_root_dev);
}

int __init sbd_init(void)
{
	int ret;

	ret = sbd_sysfs_init();
	if (ret < 0)
		return ret;

	pr_info("%s: Sheepdog block device loaded\n", DRV_NAME);
	return 0;
}

void __exit sbd_exit(void)
{
	sbd_sysfs_cleanup();
	pr_info("%s: Sheepdog block device unloaded\n", DRV_NAME);
}

module_init(sbd_init);
module_exit(sbd_exit);

MODULE_AUTHOR("Liu Yuan <namei.unix@gmail.com>");
MODULE_DESCRIPTION("Sheepdog Block Device");
MODULE_LICENSE("GPL");
