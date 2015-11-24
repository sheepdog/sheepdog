/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "dog.h"
#include "sha1.h"
#include "sockfd_cache.h"
#include "fec.h"

struct timespec get_time_tick(void)
{
	struct timespec ts;
	int ret;

	ts.tv_sec = 0;
	ts.tv_nsec = 0;

	ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret < 0)
		sd_err("clock_gettime failure: %m");

	return ts;
}

double get_time_interval(const struct timespec *start,
						 const struct timespec *end)
{
	assert(start);
	assert(end);

	return ((end->tv_nsec - start->tv_nsec) * 0.000000001)
			+ end->tv_sec - start->tv_sec;
}

char *strnumber_raw(uint64_t _size, bool raw)
{
	const char *units[] = {"MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
	static __thread struct size_str {
		char str[UINT64_DECIMAL_SIZE];
	} s[1024]; /* Is this big enough ? */
	static int j;
	int i = 0;
	double size;
	char *ret;

	if (raw) {
		snprintf(s[j].str, UINT64_DECIMAL_SIZE, "%" PRIu64, _size);
		goto out;
	}

	size = (double)_size;
	size /= 1024 * 1024;
	while (i < ARRAY_SIZE(units) - 1 && size >= 1024) {
		i++;
		size /= 1024;
	}

	if (size >= 10)
		snprintf(s[j].str, UINT64_DECIMAL_SIZE, "%.0lf %s",
			 size, units[i]);
	else
		snprintf(s[j].str, UINT64_DECIMAL_SIZE, "%.1lf %s",
			 size, units[i]);
out:
	ret = s[j++].str;
	if (j == 1024)
		j = 0;
	return ret;
}

char *strnumber(uint64_t size)
{
	return strnumber_raw(size, raw_output);
}

int dog_read_object(uint64_t oid, void *data, unsigned int datalen,
		    uint64_t offset, bool direct)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;

	sd_init_req(&hdr, SD_OP_READ_OBJ);
	hdr.data_length = datalen;

	hdr.obj.oid = oid;
	hdr.obj.offset = offset;
	if (direct)
		hdr.flags |= SD_FLAG_CMD_DIRECT;

	ret = dog_exec_req(&sd_nid, &hdr, data);
	if (ret < 0) {
		sd_err("Failed to read object %" PRIx64, oid);
		return SD_RES_EIO;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to read object %" PRIx64 " %s", oid,
		       sd_strerror(rsp->result));
		return rsp->result;
	}

	return SD_RES_SUCCESS;
}

int dog_write_object(uint64_t oid, uint64_t cow_oid, void *data,
		     unsigned int datalen, uint64_t offset, uint32_t flags,
		     uint8_t copies, uint8_t copy_policy, bool create,
		     bool direct)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;

	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
	else
		sd_init_req(&hdr, SD_OP_WRITE_OBJ);

	hdr.data_length = datalen;
	hdr.flags = flags | SD_FLAG_CMD_WRITE;
	if (cow_oid)
		hdr.flags |= SD_FLAG_CMD_COW;
	if (direct)
		hdr.flags |= SD_FLAG_CMD_DIRECT;

	hdr.obj.copies = copies;
	hdr.obj.copy_policy = copy_policy;
	hdr.obj.oid = oid;
	hdr.obj.cow_oid = cow_oid;
	hdr.obj.offset = offset;

	ret = dog_exec_req(&sd_nid, &hdr, data);
	if (ret < 0) {
		sd_err("Failed to write object %" PRIx64, oid);
		return SD_RES_EIO;
	}
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to write object %" PRIx64 ": %s", oid,
		       sd_strerror(rsp->result));
		return rsp->result;
	}

	return SD_RES_SUCCESS;
}

#define FOR_EACH_VDI(nr, vdis) FOR_EACH_BIT(nr, vdis, SD_NR_VDIS)

int parse_vdi(vdi_parser_func_t func, size_t size, void *data,
		bool no_deleted)
{
	int ret;
	unsigned long nr;
	struct sd_inode *i = xmalloc(sizeof(*i));
	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;
	static DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	static DECLARE_BITMAP(vdi_deleted, SD_NR_VDIS);
	uint32_t rlen;

	sd_init_req(&req, SD_OP_READ_VDIS);
	req.data_length = sizeof(vdi_inuse);

	ret = dog_exec_req(&sd_nid, &req, vdi_inuse);
	if (ret < 0)
		goto out;
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		goto out;
	}

	sd_init_req(&req, SD_OP_READ_DEL_VDIS);
	req.data_length = sizeof(vdi_deleted);

	ret = dog_exec_req(&sd_nid, &req, vdi_deleted);
	if (ret < 0)
		goto out;
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		goto out;
	}

	FOR_EACH_VDI(nr, vdi_inuse) {
		uint64_t oid;
		uint32_t snapid;

		if (test_bit(nr, vdi_deleted))
			continue;

		oid = vid_to_vdi_oid(nr);

		/* for B-tree inode, we also need sd_index_header */
		ret = dog_read_object(oid, i, SD_INODE_HEADER_SIZE +
				      sizeof(struct sd_index_header), 0, true);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read inode header");
			continue;
		}

		/* this VDI has been deleted, and no need to handle it */
		if (no_deleted && i->name[0] == '\0')
			continue;

		if (size > SD_INODE_HEADER_SIZE) {
			rlen = sd_inode_get_meta_size(i, size);
			ret = dog_read_object(oid,
					((char *)i) + SD_INODE_HEADER_SIZE,
					      rlen, SD_INODE_HEADER_SIZE, true);

			if (ret != SD_RES_SUCCESS) {
				sd_err("Failed to read inode");
				continue;
			}
		}

		snapid = vdi_is_snapshot(i) ? i->snap_id : 0;
		func(i->vdi_id, i->name, i->tag, snapid, 0, i, data);
	}

out:
	free(i);
	return ret;
}

int dog_exec_req(const struct node_id *nid, struct sd_req *hdr, void *buf)
{
	struct sockfd *sfd;
	int ret;

	sfd = sockfd_cache_get(nid);
	if (!sfd)
		return -1;

	/*
	 * Retry forever for dog because
	 * 1. We can't get the newest epoch
	 * 2. Some operations might take unexpected long time
	 */
	ret = exec_req(sfd->fd, hdr, buf, NULL, 0, UINT32_MAX);

	sockfd_cache_put(nid, sfd);

	return ret ? -1 : 0;
}

/* Light request only contains header, without body content. */
int send_light_req(const struct node_id *nid, struct sd_req *hdr)
{
	int ret = dog_exec_req(nid, hdr, NULL);
	struct sd_rsp *rsp = (struct sd_rsp *)hdr;

	if (ret == -1)
		return -1;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Response's result: %s", sd_strerror(rsp->result));
		return -1;
	}

	return 0;
}

int subcmd_depth = -1;
struct subcommand *subcmd_stack[MAX_SUBCMD_DEPTH];

int do_generic_subcommand(struct subcommand *sub, int argc, char **argv)
{
	int i, ret;

	if (subcmd_depth + 1 == MAX_SUBCMD_DEPTH) {
		sd_err("Too deep netsted subcommands, "
		       "please expand MAX_SUBCMD_DEPTH");
		exit(EXIT_USAGE);
	}

	for (i = 0; sub[i].name; i++) {
		unsigned long flags;

		if (strcmp(sub[i].name, argv[optind]))
			continue;

		subcmd_stack[++subcmd_depth] = &sub[i];
		flags = sub[i].flags;

		if (flags & CMD_NEED_ROOT) {
			if (!is_root()) {
				sd_err("Need run under root");
				exit(EXIT_SYSFAIL);
			}
		}

		if (flags & CMD_NEED_NODELIST) {
			ret = update_node_list(SD_MAX_NODES);
			if (ret < 0) {
				sd_err("Failed to get node list");
				exit(EXIT_SYSFAIL);
			}
		}

		optind++;
		if ((flags & CMD_NEED_ARG) &&
				(argc == optind || argv[optind][0] == '\0'))
			subcommand_usage(argv[1], argv[2], EXIT_USAGE);
		ret = sub[i].fn(argc, argv);
		if (ret == EXIT_USAGE)
			subcommand_usage(argv[1], argv[2], EXIT_USAGE);
		return ret;
	}

	subcommand_usage(argv[1], argv[2], EXIT_FAILURE);
	subcmd_depth--;

	return EXIT_FAILURE;
}

void confirm(const char *message)
{
	char input[8] = "";
	char *ret;

	printf("%s", message);
	ret = fgets(input, sizeof(input), stdin);
	if (ret == NULL || strncasecmp(input, "yes", 3) != 0)
		exit(EXIT_SUCCESS);
}

void work_queue_wait(struct work_queue *q)
{
	while (!work_queue_empty_all(q))
		event_loop(-1);
}

#define DEFAULT_SCREEN_WIDTH 80

static int get_screen_width(void)
{
	struct winsize wsz;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &wsz) < 0)
		return DEFAULT_SCREEN_WIDTH;

	return wsz.ws_col;
}

/*
 * Show progress bar as follows.
 *
 *  45.0 % [===============>                  ] 180 MB / 400 MB
 */
void show_progress(uint64_t done, uint64_t total, bool raw)
{
	int screen_width = get_screen_width();
	int bar_length = screen_width - 30;
	char *buf;

	if (!is_stdout_console())
		return;
	if (screen_width <= 0)
		return;

	printf("\r"); /* move to the beginning of the line */

	buf = xmalloc(screen_width + 1);
	snprintf(buf, screen_width, "%5.1lf %% [", (double)done / total * 100);

	for (int i = 0; i < bar_length; i++) {
		if (total * (i + 1) / bar_length <= done)
			strcat(buf, "=");
		else if (total * i / bar_length <= done &&
			 done < total * (i + 1) / bar_length)
			strcat(buf, ">");
		else
			strcat(buf, " ");
	}
	snprintf(buf + strlen(buf), screen_width - strlen(buf),
		 "] %s / %s", strnumber_raw(done, raw),
		 strnumber_raw(total, raw));

	/* fill the rest of buffer with blank characters */
	memset(buf + strlen(buf), ' ', screen_width - strlen(buf));
	buf[screen_width] = '\0';
	printf("%s", buf);

	if (done == total)
		printf("\n");

	fflush(stdout);

	free(buf);
}

size_t get_store_objsize(uint8_t copy_policy, uint8_t block_size_shift,
			 uint64_t oid)
{
	uint32_t object_size;
	if (is_vdi_obj(oid))
		return SD_INODE_SIZE;
	if (is_vdi_btree_obj(oid))
		return SD_INODE_DATA_INDEX_SIZE;

	object_size = (UINT32_C(1) << block_size_shift);
	if (copy_policy != 0) {
		int d;

		ec_policy_to_dp(copy_policy, &d, NULL);
		return object_size / d;
	}
	return get_objsize(oid, object_size);
}

bool is_erasure_oid(uint64_t oid, uint8_t policy)
{
	if (is_vdi_obj(oid))
		return false;
	if (is_vdi_btree_obj(oid))
		return false;
	if (policy == 0)
		return false;
	return true;
}

static const char * const loglevel_table[] = {
	"emerg",
	"alert",
	"crit",
	"err",
	"warning",
	"notice",
	"info",
	"debug",
};				/* index is log level */

int do_loglevel_set(const struct node_id *nid, const char *loglevel_str)
{
	int32_t loglevel = loglevel_str2num(loglevel_str);
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	if (loglevel == -1)
		return EXIT_USAGE;

	sd_init_req(&hdr, SD_OP_SET_LOGLEVEL);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(loglevel);

	ret = dog_exec_req(nid, &hdr, &loglevel);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

int do_loglevel_get(const struct node_id *nid, int32_t *ret_loglevel)
{
	int32_t loglevel = -1;
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	sd_init_req(&hdr, SD_OP_GET_LOGLEVEL);
	hdr.data_length = sizeof(loglevel);

	ret = dog_exec_req(nid, &hdr, &loglevel);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS)
		return EXIT_FAILURE;

	*ret_loglevel = loglevel;

	return EXIT_SUCCESS;
}

const char *loglevel_to_str(int loglevel)
{
	for (int i = 0; i < ARRAY_SIZE(loglevel_table); i++) {
		if (i == loglevel)
			return loglevel_table[i];
	}

	return "unknown loglevel";
}

void dump_loglevels(bool err)
{
	for (int i = 0; i < ARRAY_SIZE(loglevel_table); i++) {
		if (err)
			sd_err("%s\t(%d)", loglevel_table[i], i);
		else
			sd_info("%s\t(%d)", loglevel_table[i], i);
	}
}

/* Return 0 to indicate ill str */
uint8_t parse_copy(const char *str, uint8_t *copy_policy)
{
	char *n1, *n2;
	uint8_t copy, parity;
	char p[10];

	strcpy(p, str);
	n1 = strtok(p, ":");
	n2 = strtok(NULL, ":");

	if ((!n1 || !is_numeric(n1)) || (n2 && !is_numeric(n2)))
		return 0;

	copy = strtol(n1, NULL, 10);
	if (copy > SD_MAX_COPIES)
		return 0;
	if (!n2) {
		*copy_policy = 0;
		return copy;
	}

	if (copy != 2 && copy != 4 && copy != 8 && copy != 16)
		return 0;

	parity = strtol(n2, NULL, 10);
	if (parity >= SD_EC_MAX_STRIP || parity == 0)
		return 0;

	/*
	 * 4 bits for parity and 4 bits for data.
	 * We have to compress upper data bits because it can't represent 16
	 */
	*copy_policy = ((copy / 2) << 4) + parity;
	copy = copy + parity;
	return copy;
}

bool is_root(void)
{
	if (geteuid() != 0)
		return false;

	return true;
}
