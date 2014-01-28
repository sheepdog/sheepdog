/*
 * Copyright (C) 2014 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <nfs://www.gnu.org/licenses/>.
 */

#include "sheep_priv.h"
#include "nfs.h"
#include <rpc/pmap_clnt.h>

typedef void *(*svc_func)(struct svc_req *, struct nfs_arg *argp);

struct svc_handler {
	svc_func     func;    /* process the request */
	xdrproc_t    decoder; /* XDR decode args */
	xdrproc_t    encoder; /* XDR encode result */
	unsigned int count;	 /* call count */
};

#define NFS_HANDLER(name)			\
{						\
	(svc_func)  nfs3_##name,		\
	(xdrproc_t) xdr_##name##_args,		\
	(xdrproc_t) xdr_##name##_res,		\
	0,					\
}

static struct svc_handler nfs3_handlers[] = {
	NFS_HANDLER(null),
	NFS_HANDLER(getattr),
	NFS_HANDLER(setattr),
	NFS_HANDLER(lookup),
	NFS_HANDLER(access),
	NFS_HANDLER(readlink),
	NFS_HANDLER(read),
	NFS_HANDLER(write),
	NFS_HANDLER(create),
	NFS_HANDLER(mkdir),
	NFS_HANDLER(symlink),
	NFS_HANDLER(mknod),
	NFS_HANDLER(remove),
	NFS_HANDLER(rmdir),
	NFS_HANDLER(rename),
	NFS_HANDLER(link),
	NFS_HANDLER(readdir),
	NFS_HANDLER(readdirplus),
	NFS_HANDLER(fsstat),
	NFS_HANDLER(fsinfo),
	NFS_HANDLER(pathconf),
	NFS_HANDLER(commit),
};

static void nfs3_dispatcher(struct svc_req *reg, SVCXPRT *transp)
{
	struct nfs_arg arg = {};
	int proc = reg->rq_proc;
	void *result;

	sd_debug("%d", proc);

	if (!svc_getargs(transp, nfs3_handlers[proc].decoder, (caddr_t)&arg)) {
		sd_err("svc_getargs failed");
		svcerr_decode(transp);
		return;
	}

	result = nfs3_handlers[proc].func(reg, &arg);
	if (result && !svc_sendreply(transp, nfs3_handlers[proc].encoder,
				     result)) {
		sd_err("svc_sendreply failed");
		svcerr_systemerr(transp);
	}

	if (!svc_freeargs(transp, nfs3_handlers[proc].decoder, (caddr_t)&arg))
		panic("unable to free arguments");

	return;
}

static int nfs_init_transport(void)
{
	SVCXPRT *nfs_trans = NULL;

	pmap_unset(NFS_PROGRAM, NFS_V3);

	nfs_trans = svcudp_create(RPC_ANYSOCK);
	if (!nfs_trans) {
		sd_err("svcudp_create failed");
		return -1;
	}

	if (!svc_register(nfs_trans, NFS_PROGRAM, NFS_V3, nfs3_dispatcher,
			  IPPROTO_UDP)) {
		sd_err("svc_register udp, failed");
		return -1;
	}
	sd_info("nfs service listen at %d, proto udp", nfs_trans->xp_port);

	nfs_trans = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (!nfs_trans) {
		sd_err("svctcp_create failed");
		return -1;
	}

	if (!svc_register(nfs_trans, NFS_PROGRAM, NFS_V3, nfs3_dispatcher,
			  IPPROTO_TCP)) {
		sd_err("svc_register tcp, failed");
		return -1;
	}
	sd_info("nfs service listen at %d, proto tcp", nfs_trans->xp_port);

	return 0;
}

static void *nfsd(void *ignored)
{
	int err;

	if (nfs_init_transport() < 0)
		goto out;

	/* FIXME: glibc doesn't support multi-threaded svc API */
	svc_run();

	sd_err("svc_run exited");
out:
	err = pthread_detach(pthread_self());
	if (err)
		sd_err("%s", strerror(err));
	pthread_exit(NULL);
}

int nfs_init(const char *options)
{
	pthread_t t;
	int err;

	err = pthread_create(&t, NULL, nfsd, NULL);
	if (err) {
		sd_err("%s", strerror(err));
		return -1;
	}

	return 0;
}
