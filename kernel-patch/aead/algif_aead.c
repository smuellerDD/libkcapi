/*
 * algif_aeadr: User-space interface for AEAD algorithms
 *
 * Copyright (C) 2014, Stephan Mueller <smueller@chronox.de>
 *
 * This file provides the user-space API for AEAD ciphers.
 *
 * This file is derived from algif_skcipher.c.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/scatterwalk.h>
#include <crypto/if_alg.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>

struct aead_sg_list {
	unsigned int cur;
	struct scatterlist sg[ALG_MAX_PAGES];
};

struct aead_ctx {
	struct aead_sg_list tsgl;
	struct af_alg_sgl rsgl;

	void *iv;

	struct af_alg_completion completion;

	unsigned long used;

	unsigned int len;
	bool more;
	bool merge;
	bool enc;

	size_t aead_assoclen;
	struct aead_request aead_req;
};

static inline int aead_sndbuf(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct aead_ctx *ctx = ask->private;

	return max_t(int, max_t(int, sk->sk_sndbuf & PAGE_MASK, PAGE_SIZE) -
			  ctx->used, 0);
}

static inline bool aead_writable(struct sock *sk)
{
	return PAGE_SIZE <= aead_sndbuf(sk);
}

static inline bool aead_sufficient_data(struct aead_ctx *ctx)
{
	unsigned as = crypto_aead_authsize(crypto_aead_reqtfm(&ctx->aead_req));

	return (ctx->used >= (ctx->aead_assoclen + (ctx->enc ?: as)));
}
static inline bool aead_readable(struct aead_ctx *ctx)
{
	/*
	 * Ensure that assoc data is present, the plaintext / ciphertext
	 * is non-zero and that the authentication tag is also present
	 * in case of a decryption operation.
	 *
	 * Also, wait until all data is received before processing.
	 */
	return (aead_sufficient_data(ctx) && !ctx->more);
}

static void aead_put_sgl(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct aead_ctx *ctx = ask->private;
	struct aead_sg_list *sgl = &ctx->tsgl;
	struct scatterlist *sg = sgl->sg;
	unsigned int i;

	for (i = 0; i < sgl->cur; i++) {
		if (!sg_page(sg + i))
			continue;

		put_page(sg_page(sg + i));
		sg_assign_page(sg + i, NULL);
	}
	sgl->cur = 0;
	ctx->used = 0;
	ctx->more = 0;
	ctx->merge = 0;
}

static int aead_wait_for_wmem(struct sock *sk, unsigned flags)
{
	long timeout;
	DEFINE_WAIT(wait);
	int err = -ERESTARTSYS;

	if (flags & MSG_DONTWAIT)
		return -EAGAIN;

	set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	for (;;) {
		if (signal_pending(current))
			break;
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		timeout = MAX_SCHEDULE_TIMEOUT;
		if (sk_wait_event(sk, &timeout, aead_writable(sk))) {
			err = 0;
			break;
		}
	}
	finish_wait(sk_sleep(sk), &wait);

	return err;
}

static void aead_wmem_wakeup(struct sock *sk)
{
	struct socket_wq *wq;

	if (!aead_writable(sk))
		return;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, POLLIN |
							   POLLRDNORM |
							   POLLRDBAND);
	sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	rcu_read_unlock();
}

static int aead_wait_for_data(struct sock *sk, unsigned flags)
{
	struct alg_sock *ask = alg_sk(sk);
	struct aead_ctx *ctx = ask->private;
	long timeout;
	DEFINE_WAIT(wait);
	int err = -ERESTARTSYS;

	if (flags & MSG_DONTWAIT) {
		return -EAGAIN;
	}

	set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);

	for (;;) {
		if (signal_pending(current))
			break;
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		timeout = MAX_SCHEDULE_TIMEOUT;
		if (sk_wait_event(sk, &timeout, aead_readable(ctx))) {
			err = 0;
			break;
		}
	}
	finish_wait(sk_sleep(sk), &wait);

	clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);

	return err;
}

static void aead_data_wakeup(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct aead_ctx *ctx = ask->private;
	struct socket_wq *wq;

	if (!aead_readable(ctx))
		return;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, POLLOUT |
							   POLLRDNORM |
							   POLLRDBAND);
	sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
	rcu_read_unlock();
}

static int aead_sendmsg(struct kiocb *unused, struct socket *sock,
		        struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct aead_ctx *ctx = ask->private;
	unsigned ivsize =
		crypto_aead_ivsize(crypto_aead_reqtfm(&ctx->aead_req));
	struct aead_sg_list *sgl = &ctx->tsgl;
	struct af_alg_control con = {};
	long copied = 0;
	bool enc = 0;
	bool init = 0;
	int err = -EINVAL;

	if (msg->msg_controllen) {
		err = af_alg_cmsg_send(msg, &con);
		if (err)
			return err;

		init = 1;
		switch (con.op) {
		case ALG_OP_ENCRYPT:
			enc = 1;
			break;
		case ALG_OP_DECRYPT:
			enc = 0;
			break;
		default:
			return -EINVAL;
		}

		if (con.iv && con.iv->ivlen != ivsize)
			return -EINVAL;

		if (!con.aead_assoclen)
			return -EINVAL;

		/* aead_recvmsg limits the maximum AD size to one page */
		if (con.aead_assoclen > PAGE_SIZE)
			return -E2BIG;
	}

	lock_sock(sk);
	if (!ctx->more && ctx->used)
		goto unlock;

	if (init) {
		ctx->enc = enc;
		if (con.iv)
			memcpy(ctx->iv, con.iv->iv, ivsize);

		ctx->aead_assoclen = con.aead_assoclen;
	}

	while (size) {
		unsigned long len = size;
		struct scatterlist *sg = NULL;

		if (ctx->merge) {
			sg = sgl->sg + sgl->cur - 1;
			len = min_t(unsigned long, len,
				    PAGE_SIZE - sg->offset - sg->length);
			err = memcpy_fromiovec(page_address(sg_page(sg)) +
					       sg->offset + sg->length,
					       msg->msg_iov, len);
			if (err)
				goto unlock;

			sg->length += len;
			ctx->merge = (sg->offset + sg->length) &
				     (PAGE_SIZE - 1);

			ctx->used += len;
			copied += len;
			size -= len;
		}

		if (!aead_writable(sk)) {
			/*
			 * If there is more data to be expected, but we cannot
			 * write more data, forcefully define that we do not
			 * expect more data to invoke the AEAD operation. This
			 * prevents a deadlock in user space.
			 */
			ctx->more = 0;
			err = aead_wait_for_wmem(sk, msg->msg_flags);
			if (err)
				goto unlock;
		}

		len = min_t(unsigned long, size, aead_sndbuf(sk));
		while (len && sgl->cur < ALG_MAX_PAGES) {
			int plen = 0;

			sg = sgl->sg + sgl->cur;
			plen = min_t(int, len, PAGE_SIZE);

			if (sgl->cur >= ALG_MAX_PAGES) {
				err = -E2BIG;
				goto unlock;
			}

			sg_assign_page(sg, alloc_page(GFP_KERNEL));
			err = -ENOMEM;
			if (!sg_page(sg))
				goto unlock;

			err = memcpy_fromiovec(page_address(sg_page(sg)),
					       msg->msg_iov, plen);
			if (err) {
				__free_page(sg_page(sg));
				sg_assign_page(sg, NULL);
				goto unlock;
			}

			sg->length = plen;
			len -= plen;
			ctx->used += plen;
			copied += plen;
			sgl->cur++;
			size -= plen;
			ctx->merge = plen & (PAGE_SIZE - 1);
		}
	}

	err = 0;

	ctx->more = msg->msg_flags & MSG_MORE;

unlock:
	aead_data_wakeup(sk);
	release_sock(sk);

	return copied ?: err;
}

static ssize_t aead_sendpage(struct socket *sock, struct page *page,
			     int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct aead_ctx *ctx = ask->private;
	struct aead_sg_list *sgl = &ctx->tsgl;
	int err = -EINVAL;

	if (flags & MSG_SENDPAGE_NOTLAST)
		flags |= MSG_MORE;

	if (sgl->cur >= ALG_MAX_PAGES)
		return -E2BIG;

	lock_sock(sk);
	if (!ctx->more && ctx->used)
		goto unlock;

	if (!size)
		goto done;

	if (!aead_writable(sk)) {
		/* see aead_sendmsg why more is set to 0 */
		ctx->more = 0;
		err = aead_wait_for_wmem(sk, flags);
		if (err)
			goto unlock;
	}

	ctx->merge = 0;

	get_page(page);
	sg_set_page(sgl->sg + sgl->cur, page, size, offset);
	sgl->cur++;
	ctx->used += size;

	err = 0;

done:
	ctx->more = flags & MSG_MORE;

unlock:
	aead_data_wakeup(sk);
	release_sock(sk);

	return err ?: size;
}

static int aead_recvmsg(struct kiocb *unused, struct socket *sock,
			    struct msghdr *msg, size_t ignored, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct aead_ctx *ctx = ask->private;
	unsigned bs = crypto_aead_blocksize(crypto_aead_reqtfm(&ctx->aead_req));
	unsigned as = crypto_aead_authsize(crypto_aead_reqtfm(&ctx->aead_req));
	struct aead_sg_list *sgl = &ctx->tsgl;
	struct scatterlist *sg = sgl->sg;
	struct scatterlist assoc;
	size_t assoclen = 0;
	unsigned int i = 0;
	int err = -EAGAIN;
	unsigned long used = 0;
	unsigned long outlen = 0;

	/*
	 * Require exactly one IOV block as the AEAD operation is a one shot
	 * due to the authentication tag.
	 */
	if (msg->msg_iovlen != 1)
		return -ENOMSG;

	lock_sock(sk);
	/*
	* AEAD memory structure: For encryption, the tag is appended to the
	* ciphertext which implies that the memory allocated for the ciphertext
	* must be increased by the tag length. For decryption, the tag
	* is expected to be concatenated to the ciphertext. The plaintext
	* therefore has a memory size of the ciphertext minus the tag length.
	*
	* The memory structure for cipher operation has the following
	* structure:
	*	AEAD encryption input:  assoc data || plaintext
	*	AEAD encryption output: cipherntext || auth tag
	*	AEAD decryption input:  assoc data || ciphertext || auth tag
	*	AEAD decryption output: plaintext
	*/

	if (!aead_readable(ctx)) {
		err = aead_wait_for_data(sk, flags);
		if (err)
			goto unlock;
	}

	used = ctx->used;

	err = -ENOMEM;
	if (!aead_sufficient_data(ctx))
		goto unlock;
	/*
	 * The cipher operation input data is reduced by the associated data
	 * length as this data is processed separately later on.
	 */
	used -= ctx->aead_assoclen;

	if (ctx->enc) {
		/* round up output buffer to multiple of block size */
		outlen = ((used + bs - 1) / bs * bs);
		/* add the size needed for the auth tag to be created */
		outlen += as;
	} else {
		/* output data size is input without the authentication tag */
		outlen = used - as;
		/* round up output buffer to multiple of block size */
		outlen = ((outlen + bs - 1) / bs * bs);
	}

	/* ensure output buffer is sufficiently large */
	if (msg->msg_iov->iov_len < outlen)
		goto unlock;

	outlen = af_alg_make_sg(&ctx->rsgl, msg->msg_iov->iov_base, outlen, 1);
	err = outlen;
	if (err < 0)
		goto unlock;

	err = -EINVAL;
	/*
	 * first chunk of input is AD -- one scatterlist entry is one page,
	 * and we process only one scatterlist, the maximum size of AD is
	 * one page
	 */
	sg_init_table(&assoc, 1);
	sg_set_page(&assoc, sg_page(sg), ctx->aead_assoclen, sg->offset);
	aead_request_set_assoc(&ctx->aead_req, &assoc, ctx->aead_assoclen);

	/* point sg to cipher/plaintext start */
	assoclen = ctx->aead_assoclen;
	for(i = 0; i < ctx->tsgl.cur; i++) {
		sg = sgl->sg + i;
		if (sg->length <= assoclen) {
			assoclen -= sg->length;
			if (i >= ctx->tsgl.cur)
				goto unlock;
		} else {
			sg->length -= assoclen;
			sg->offset += assoclen;
			break;
		}
	}

	aead_request_set_crypt(&ctx->aead_req, sg, ctx->rsgl.sg, used, ctx->iv);

	err = af_alg_wait_for_completion(ctx->enc ?
					 crypto_aead_encrypt(&ctx->aead_req) :
					 crypto_aead_decrypt(&ctx->aead_req),
					 &ctx->completion);

	af_alg_free_sg(&ctx->rsgl);

	if (err)
		goto unlock;

	aead_put_sgl(sk);

	err = 0;

unlock:
	aead_wmem_wakeup(sk);
	release_sock(sk);

	return err ? err : outlen;
}

static unsigned int aead_poll(struct file *file, struct socket *sock,
				  poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct aead_ctx *ctx = ask->private;
	unsigned int mask;

	sock_poll_wait(file, sk_sleep(sk), wait);
	mask = 0;

	if (aead_readable(ctx))
		mask |= POLLIN | POLLRDNORM;

	if (aead_writable(sk))
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;

	return mask;
}

static struct proto_ops algif_aead_ops = {
	.family		=	PF_ALG,

	.connect	=	sock_no_connect,
	.socketpair	=	sock_no_socketpair,
	.getname	=	sock_no_getname,
	.ioctl		=	sock_no_ioctl,
	.listen		=	sock_no_listen,
	.shutdown	=	sock_no_shutdown,
	.getsockopt	=	sock_no_getsockopt,
	.mmap		=	sock_no_mmap,
	.bind		=	sock_no_bind,
	.accept		=	sock_no_accept,
	.setsockopt	=	sock_no_setsockopt,

	.release	=	af_alg_release,
	.sendmsg	=	aead_sendmsg,
	.sendpage	=	aead_sendpage,
	.recvmsg	=	aead_recvmsg,
	.poll		=	aead_poll,
};

static void *aead_bind(const char *name, u32 type, u32 mask)
{
	return crypto_alloc_aead(name, type, mask);
}

static void aead_release(void *private)
{
	crypto_free_aead(private);
}

static int aead_setauthsize(void *private, unsigned int authsize)
{
	return crypto_aead_setauthsize(private, authsize);
}

static int aead_setkey(void *private, const u8 *key, unsigned int keylen)
{
	return crypto_aead_setkey(private, key, keylen);
}

static void aead_sock_destruct(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct aead_ctx *ctx = ask->private;
	unsigned int ivlen = crypto_aead_ivsize(
				crypto_aead_reqtfm(&ctx->aead_req));

	aead_put_sgl(sk);
	sock_kzfree_s(sk, ctx->iv, ivlen);
	sock_kfree_s(sk, ctx, ctx->len);
	af_alg_release_parent(sk);
}

static int aead_accept_parent(void *private, struct sock *sk)
{
	struct aead_ctx *ctx;
	struct alg_sock *ask = alg_sk(sk);
	unsigned int len = sizeof(*ctx) + crypto_aead_reqsize(private);
	unsigned int ivlen = crypto_aead_ivsize(private);

	ctx = sock_kmalloc(sk, len, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	memset(ctx, 0, len);

	ctx->iv = sock_kmalloc(sk, ivlen, GFP_KERNEL);
	if (!ctx->iv) {
		sock_kfree_s(sk, ctx, len);
		return -ENOMEM;
	}
	memset(ctx->iv, 0, ivlen);

	ctx->len = len;
	ctx->used = 0;
	ctx->more = 0;
	ctx->merge = 0;
	ctx->enc = 0;
	ctx->tsgl.cur = 0;
	ctx->aead_assoclen = 0;
	af_alg_init_completion(&ctx->completion);
	sg_init_table(ctx->tsgl.sg, ALG_MAX_PAGES);

	ask->private = ctx;

	aead_request_set_tfm(&ctx->aead_req, private);
	aead_request_set_callback(&ctx->aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  af_alg_complete, &ctx->completion);

	sk->sk_destruct = aead_sock_destruct;

	return 0;
}

static const struct af_alg_type algif_type_aead = {
	.bind		=	aead_bind,
	.release	=	aead_release,
	.setkey		=	aead_setkey,
	.setauthsize	=	aead_setauthsize,
	.accept		=	aead_accept_parent,
	.ops		=	&algif_aead_ops,
	.name		=	"aead",
	.owner		=	THIS_MODULE
};

static int __init algif_aead_init(void)
{
	return af_alg_register_type(&algif_type_aead);
}

static void __exit algif_aead_exit(void)
{
	int err = af_alg_unregister_type(&algif_type_aead);
	BUG_ON(err);
}

module_init(algif_aead_init);
module_exit(algif_aead_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("AEAD kernel crypto API user space interface");
