#include <string.h>

#include "sheepdog_proto.h"

uint32_t sd_inode_get_vid(const struct sd_inode *inode, int idx)
{
	return inode->data_vdi_id[idx];
}

void sd_inode_set_vid(struct sd_inode *inode, int idx, uint32_t vdi_id)
{
	inode->data_vdi_id[idx] = vdi_id;
}
