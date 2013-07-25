#ifndef SHEPHERD_H
#define SHEPHERD_H

enum sph_cli_msg_type {
	/* messages sent by a cluster driver, received by shepherd */
	SPH_CLI_MSG_JOIN = 0,
	SPH_CLI_MSG_ACCEPT,
	SPH_CLI_MSG_NOTIFY,
	SPH_CLI_MSG_BLOCK,
	SPH_CLI_MSG_LEAVE,
};

enum sph_srv_msg_type {
	/* messages sent by shepherd, received by a cluster driver */
	SPH_SRV_MSG_JOIN_REPLY = 0,
	SPH_SRV_MSG_JOIN_RETRY,

	SPH_SRV_MSG_NEW_NODE,
	SPH_SRV_MSG_NEW_NODE_FINISH,

	SPH_SRV_MSG_NOTIFY_FORWARD,
	SPH_SRV_MSG_BLOCK_FORWARD,
	SPH_SRV_MSG_LEAVE_FORWARD,

	SPH_SRV_MSG_REMOVE,
};

struct sph_msg {
	/*
	 * original type of uint32_t type:
	 * enum sph_cli_msg_type or enum sph_srv_msg_type
	 */
	uint32_t type;
	uint32_t body_len;
};

#include "internal_proto.h"

struct sph_msg_join {
	struct sd_node new_node;

	struct sd_node nodes[SD_MAX_NODES];
	uint32_t nr_nodes;
	uint8_t opaque[0];
};

struct sph_msg_join_reply {
	struct sd_node nodes[SD_MAX_NODES];
	uint32_t nr_nodes;
	uint8_t opaque[0];
};

struct sph_msg_join_node_finish {
	struct sd_node new_node;

	struct sd_node nodes[SD_MAX_NODES];
	uint32_t nr_nodes;
	uint8_t opaque[0];
};

struct sph_msg_notify {
	uint8_t unblock;
	uint8_t notify_msg[0];
};

struct sph_msg_notify_forward {
	struct sd_node from_node;
	uint8_t unblock;
	uint8_t notify_msg[0];
};

#define SHEPHERD_PORT 2501

static inline const char *sph_cli_msg_to_str(enum sph_cli_msg_type msg)
/* CAUTION: non reentrant */
{
	int i;
	static char unknown[64];

	static const struct {
		enum sph_cli_msg_type msg;
		const char *desc;
	} msgs[] = {
		{ SPH_CLI_MSG_JOIN, "SPH_CLI_MSG_JOIN" },
		{ SPH_CLI_MSG_ACCEPT, "SPH_CLI_MSG_ACCEPT" },
		{ SPH_CLI_MSG_NOTIFY, "SPH_CLI_MSG_NOTIFY" },
		{ SPH_CLI_MSG_BLOCK, "SPH_CLI_MSG_BLOCK" },
		{ SPH_CLI_MSG_LEAVE, "SPH_CLI_MSG_LEAVE" },
	};

	for (i = 0; i < ARRAY_SIZE(msgs); i++) {
		if (msgs[i].msg == msg)
			return msgs[i].desc;
	}

	memset(unknown, 0, 64);
	snprintf(unknown, 64, "<unknown shepherd client message: %d>", msg);
	return unknown;
}

static inline const char *sph_srv_msg_to_str(enum sph_srv_msg_type msg)
/* CAUTION: non reentrant */
{
	int i;
	static char unknown[64];

	static const struct {
		enum sph_srv_msg_type msg;
		const char *desc;
	} msgs[] = {
		{ SPH_SRV_MSG_JOIN_RETRY, "SPH_SRV_MSG_JOIN_RETRY" },
		{ SPH_SRV_MSG_NEW_NODE, "SPH_SRV_MSG_NEW_NODE" },
		{ SPH_SRV_MSG_NEW_NODE_FINISH, "SPH_SRV_MSG_NEW_NODE_FINISH" },
		{ SPH_SRV_MSG_NOTIFY_FORWARD, "SPH_SRV_MSG_NOTIFY_FORWARD" },
		{ SPH_SRV_MSG_BLOCK_FORWARD, "SPH_SRV_MSG_BLOCK_FORWARD" },
		{ SPH_SRV_MSG_REMOVE, "SPH_SRV_MSG_REMOVE" },
	};

	for (i = 0; i < ARRAY_SIZE(msgs); i++) {
		if (msgs[i].msg == msg)
			return msgs[i].desc;
	}

	memset(unknown, 0, 64);
	snprintf(unknown, 64, "<unknown shepherd server message: %d>", msg);
	return unknown;
}

#endif	/* SHEPHERD_H */
