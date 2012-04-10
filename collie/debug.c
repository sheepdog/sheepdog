#include <ctype.h>

#include "collie.h"

static void print_trace_item(struct trace_graph_item *item)
{
	int i;

	if (item->type == TRACE_GRAPH_ENTRY) {
		printf("             |  ");
		for (i = 0; i < item->depth; i++)
			printf("   ");
		printf("%s() {\n", item->fname);
	} else {
		unsigned duration = item->return_time - item->entry_time;
		unsigned quot = duration / 1000, rem = duration % 1000;
		printf("%8u.%-3u |  ", quot, rem);
		for (i = 0; i < item->depth; i++)
			printf("   ");
		printf("}\n");
	}
}

static void parse_trace_buffer(char *buf, int size)
{
	struct trace_graph_item *item = (struct trace_graph_item *)buf;
	int sz = size / sizeof(struct trace_graph_item), i;

	printf("   Time(us)  |  Function Graph\n");
	printf("-------------------------------\n");
	for (i = 0; i < sz; i++)
		print_trace_item(item++);
	return;
}

static int do_trace_cat(void)
{
	int fd, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned rlen, wlen;
	char *buf = xzalloc(TRACE_BUF_LEN * 12);

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_TRACE_CAT;
	hdr.data_length = rlen = TRACE_BUF_LEN;
	hdr.epoch = node_list_version;

	wlen = 0;
	ret = exec_req(fd, &hdr, buf, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to connect\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Trace failed: %s\n",
				sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	parse_trace_buffer(buf, rlen);

	free(buf);
	return EXIT_SUCCESS;
}

static int debug_trace(int argc, char **argv)
{
	int fd, ret, i, l;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned rlen, wlen;
	char *cmd = argv[optind];
	int enabled;

	l = strlen(cmd);
	for (i = 0; i < l; i++)
		cmd[i] = tolower(cmd[i]);

	if (strcmp(cmd, "start") == 0) {
		enabled = 1;
		printf("start the tracing\n");
	} else if (strcmp(cmd, "stop") == 0) {
		enabled = 0;
		printf("stop the tracing\n");
	} else if (strcmp(cmd, "cat") == 0) {
		printf("cat the tracing\n\n");
		return do_trace_cat();
	} else {
		printf("unsupported operation\n");
		return EXIT_FAILURE;
	}

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_TRACE;
	hdr.epoch = node_list_version;
	hdr.data_length = enabled;

	rlen = 0;
	wlen = 0;
	ret = exec_req(fd, &hdr, NULL, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to connect\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Trace failed: %s\n",
				sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int debug_parser(int ch, char *opt)
{
	return 0;
}

static struct subcommand debug_cmd[] = {
	{"trace", "{start, stop, cat}", "aph", "trace the node",
		0, debug_trace},
	{NULL,},
};

struct command debug_command = {
	"debug",
	debug_cmd,
	debug_parser
};
