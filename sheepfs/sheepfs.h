#ifndef SHEEPFS_H
#define SHEEPFS_H

enum sheepfs_opcode {
	OP_NULL = 0,
};

extern char sheepfs_shadow[];

extern struct strbuf *sheepfs_run_cmd(const char *command);
extern int sheepfs_set_op(const char *path, unsigned opcode);

#endif
