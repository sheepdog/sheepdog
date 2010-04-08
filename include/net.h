#ifndef __NET_H__
#define __NET_H__

#include <sys/socket.h>

enum conn_state {
	C_IO_HEADER = 0,
	C_IO_DATA_INIT,
	C_IO_DATA,
	C_IO_END,
	C_IO_CLOSED,
};

struct connection {
	int fd;

	enum conn_state c_rx_state;
	int rx_length;
	void *rx_buf;
	struct sd_req rx_hdr;

	enum conn_state c_tx_state;
	int tx_length;
	void *tx_buf;
	struct sd_rsp tx_hdr;
};

void conn_tx_off(struct connection *conn);
void conn_tx_on(struct connection *conn);
int is_conn_dead(struct connection *conn);
int do_read(int sockfd, void *buf, int len);
int rx(struct connection *conn, enum conn_state next_state);
int tx(struct connection *conn, enum conn_state next_state, int flags);
int connect_to(char *name, int port);
int send_req(int sockfd, struct sd_req *hdr, void *data, unsigned int *wlen);
int exec_req(int sockfd, struct sd_req *hdr, void *data,
	     unsigned int *wlen, unsigned int *rlen);
int write_object(struct sheepdog_node_list_entry *e,
		 int nodes, uint32_t node_version,
		 uint64_t oid, char *data, unsigned int datalen,
		 uint64_t offset, int nr, int create);
int read_object(struct sheepdog_node_list_entry *e,
		int nodes, uint32_t node_version,
		uint64_t oid, char *data, unsigned int datalen,
		uint64_t offset, int nr);
int remove_object(struct sheepdog_node_list_entry *e,
		  int nodes, uint32_t node_version,
		  uint64_t oid, int nr);

int exec_reqs(struct sheepdog_node_list_entry *e,
	      int nodes, uint32_t node_version, uint64_t oid, struct sd_req *hdr,
	      char *data, unsigned int wdatalen, unsigned int rdatalen, int nr,
	      int quorum);

int create_listen_ports(int port, int (*callback)(int fd, void *), void *data);

char *addr_to_str(char *str, int size, uint8_t *addr, uint16_t port);

#endif
