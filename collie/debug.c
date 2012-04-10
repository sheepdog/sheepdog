#include <ctype.h>

#include "collie.h"

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
