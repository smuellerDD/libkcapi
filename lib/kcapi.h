/*
 * Copyright (C) 2015 - 2020, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef KCAPI_H
#define KCAPI_H

#include <stdint.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define DSO_DEPRECATED(x) \
	__attribute__ ((deprecated ("API deprecated with library version " x)))

/*
 * Flags for the encrypt / decrypt operations
 * 
 * @KCAPI_ACCESS_HEURISTIC Allow the libkcapi heuristic to determine the
 * optimal kernel access type
 * @KCAPI_ACCESS_VMSPLICE Require libkcapi to always use the vmsplice zero
 * copy kernel interface
 * @KCAPI_ACCESS_SENDMSG Require libkcapi to always use the sendmsg kernel
 * interface
 */
#define KCAPI_ACCESS_HEURISTIC 	0x0
#define KCAPI_ACCESS_VMSPLICE  	0x1
#define KCAPI_ACCESS_SENDMSG   	0x2

/*
 * Flags for initializing a cipher handle
 * 
 * @KCAPI_INIT_AIO Handle uses AIO kernel interface if available
 */
#define KCAPI_INIT_AIO		(1<<0)

/*
 * Opaque cipher handle
 */
struct kcapi_handle;

/**
 * DOC: Symmetric Cipher API
 *
 * API function calls used to invoke symmetric ciphers.
 */

/**
 * kcapi_handle_reinit() - re-initialize a new kernel interface
 *
 * @newhandle: [out] cipher handle filled during the call
 * @existing: [in] existing cipher handle from which a new handle shall be
 *	      re-initialized
 * @flags: [in] flags specifying the type of cipher handle
 *
 * The kernel crypto API interface operates with two types of file descriptors,
 * the TFM file descriptor and the OP file descriptor.
 *
 * The TFM file descriptor receives the cipher-operation static information:
 * the key, and the AEAD tag size.
 *
 * The OP file descriptor receives the volatile data, such as the plaintext /
 * ciphertext, the IV, or the AEAD AD size.
 *
 * The kernel crypto API AF_ALG interface supports the concept that one TFM
 * file descriptor can operate with multiple OP file descriptors. The different
 * OP file descriptors can perform completely separate cipher operations
 * using the same key which can execute in parallel. The parallel execution
 * can be performed in the same or different process threads.
 *
 * kcapi_handle_reinit() function allows the allocation of a new cipher handle
 * with a new OP file descriptor but using the same TFM file descriptor. To
 * obtain a reference to the TFM file descriptor, an @existing cipher handle
 * is used as source. kcapi_handle_reinit() can be invoked multiple times.
 * Each resulting cipher handle must be deallocated with kcapi_cipher_destroy().
 * The deallocation ensures that the TFM resource is only released if the
 * last handle using this TFM resource is released.
 *
 * @return 0 upon success;
 *	   -EINVAL - accept syscall failed
 *	   -ENOMEM - cipher handle cannot be allocated
 */
int kcapi_handle_reinit(struct kcapi_handle **newhandle,
			struct kcapi_handle *existing, uint32_t flags);

/**
 * kcapi_cipher_init() - initialize cipher handle
 *
 * @handle: [out] cipher handle filled during the call
 * @ciphername: [in] kernel crypto API cipher name as specified in
 *	       /proc/crypto
 * @flags: [in] flags specifying the type of cipher handle
 *
 * This function provides the initialization of a symmetric cipher handle and
 * establishes the connection to the kernel.
 *
 * On success, a pointer to kcapi_handle object is returned in *handle.
 * Function kcapi_cipher_destroy() should be called afterwards to free
 * resources.
 *
 * @return 0 upon success;
 *	   -ENOENT - algorithm not available;
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed
 *	   -ENOMEM - cipher handle cannot be allocated
 */
int kcapi_cipher_init(struct kcapi_handle **handle, const char *ciphername,
		      uint32_t flags);

/**
 * kcapi_cipher_destroy() - close the cipher handle and release resources
 *
 * @handle: [in] cipher handle to release
 */
void kcapi_cipher_destroy(struct kcapi_handle *handle);

/**
 * kcapi_cipher_setkey() - set the key for the cipher handle
 *
 * @handle: [in] cipher handle
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 *
 * With this function, the caller sets the key for subsequent encryption or
 * decryption operations.
 *
 * After the caller provided the key, the caller may securely destroy the key
 * as it is now maintained by the kernel.
 *
 * @return 0 upon success (in case of an akcipher handle, a positive integer
 *	   is returned that denominates the maximum output size of the
 *	   cryptographic operation -- this value must be used as the size
 *	   of the output buffer for one cryptographic operation);
 *	   a negative errno-style error code if an error occurred
 */
int kcapi_cipher_setkey(struct kcapi_handle *handle,
			const uint8_t *key, uint32_t keylen);

/**
 * kcapi_cipher_encrypt() - encrypt data (synchronous one shot)
 *
 * @handle: [in] cipher handle
 * @in: [in] plaintext data buffer
 * @inlen: [in] length of in buffer
 * @iv: [in] IV to be used for cipher operation
 * @out: [out] ciphertext data buffer
 * @outlen: [in] length of out buffer
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	    heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	    vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the plaintext is overwritten with the ciphertext.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * @return number of bytes encrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_encrypt(struct kcapi_handle *handle,
			     const uint8_t *in, uint32_t inlen,
			     const uint8_t *iv,
			     uint8_t *out, uint32_t outlen, int access);

/**
 * kcapi_cipher_encrypt_aio() - encrypt data (asynchronous one shot)
 *
 * @handle: [in] cipher handle
 * @iniov: [in] head of scatter-gather list array holding the plaintext
 * @outiov: [out] head of scatter-gather list of the destination buffers filled
 *	with ciphertext
 * @iovlen: [in] number of scatter-gather list entries
 * @iv: [in] IV to be used for cipher operation
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The individual scatter-gather list entries are processed with
 * separate invocations of the the given cipher.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * @return number of bytes encrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_encrypt_aio(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 uint32_t iovlen, const uint8_t *iv,
				 int access);

/**
 * kcapi_cipher_decrypt() - decrypt data (synchronous one shot)
 *
 * @handle: [in] cipher handle
 * @in: [in] ciphertext data buffer
 * @inlen: [in] length of in buffer
 * @iv: [in] IV to be used for cipher operation
 * @out: [out] plaintext data buffer
 * @outlen: [in] length of out bufferS
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the ciphertext is overwritten with the plaintext.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * @return number of bytes decrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_decrypt(struct kcapi_handle *handle,
			     const uint8_t *in, uint32_t inlen,
			     const uint8_t *iv,
			     uint8_t *out, uint32_t outlen, int access);

/**
 * kcapi_cipher_decrypt_aio() - decrypt data (asynchronous one shot)
 *
 * @handle: [in] cipher handle
 * @iniov: [in] head of scatter-gather list array holding the ciphertext
 * @outiov: [out] head of scatter-gather list with the destination buffers for
 *	the plaintext
 * @iovlen: [in] number of scatter-gather list entries
 * @iv: [in] IV to be used for cipher operation
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The individual scatter-gather list entries are processed with
 * separate invocations of the the given cipher.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * @return number of bytes decrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_decrypt_aio(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 uint32_t iovlen, const uint8_t *iv,
				 int access);

/**
 * kcapi_cipher_stream_init_enc() - start an encryption operation (stream)
 *
 * @handle: [in] cipher handle
 * @iv: [in] IV to be used for cipher operation
 * @iov: [in] scatter/gather list with data to be encrypted. This is
 *	the pointer to the first iov entry if an array of iov
 *	entries is supplied. See sendmsg(2) for details on how iov is
 *	to be used. This pointer may be NULL if no data to be encrypted
 *	is available at the point of the call.
 * @iovlen: [in] number of scatter/gather list elements. If iov
 *	is NULL, this value must be zero.
 *
 * A stream encryption operation is started with this call. Multiple
 * successive kcapi_cipher_stream_update() function calls can be invoked to
 * send more plaintext data to be encrypted. The kernel buffers the input
 * until kcapi_cipher_stream_op() picks up the encrypted data. Once plaintext
 * is encrypted during the kcapi_cipher_stream_op() it is removed from the
 * kernel buffer.
 *
 * The function calls of kcapi_cipher_stream_update() and
 * kcapi_cipher_stream_op() can be mixed, even by multiple threads of an
 * application.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_stream_init_enc(struct kcapi_handle *handle,
				     const uint8_t *iv,
				     struct iovec *iov, uint32_t iovlen);
/**
 * kcapi_cipher_stream_init_dec() - start a decryption operation (stream)
 *
 * @handle: [in] cipher handle
 * @iv: [in] IV to be used for cipher operation
 * @iov: [in] scatter/gather list with data to be encrypted. This is
 *	the pointer to the first iov entry if an array of iov
 *	entries is supplied. See sendmsg(2) for details on how iov is
 *	to be used. This pointer may be NULL if no data to be encrypted
 *	is available at the point of the call.
 * @iovlen: [in] number of scatter/gather list elements. If iov
 *	is NULL, this value must be zero.
 *
 * A stream decryption operation is started with this call. Multiple
 * successive kcapi_cipher_stream_update() function calls can be invoked to
 * send more ciphertext data to be decrypted. The kernel buffers the input
 * until kcapi_cipher_stream_op() picks up the decrypted data. Once ciphertext
 * is decrypted during the kcapi_cipher_stream_op() it is removed from the
 * kernel buffer.
 *
 * The function calls of kcapi_cipher_stream_update() and
 * kcapi_cipher_stream_op() can be mixed, even by multiple threads of an
 * application.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_stream_init_dec(struct kcapi_handle *handle,
				     const uint8_t *iv,
				     struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_cipher_stream_update() - send more data for processing (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [in] scatter/gather list with data to be processed by the
 *	cipher operation.
 * @iovlen: [in] number of scatter/gather list elements.
 *
 * Using this function call, more plaintext for encryption or ciphertext for
 * decryption can be submitted to the kernel.
 *
 * This function may cause the caller to sleep if the kernel buffer holding
 * the data is getting full. The process will be woken up once more buffer
 * space becomes available by calling kcapi_cipher_stream_op().
 *
 * Note: with the separate API calls of kcapi_cipher_stream_update() and
 * kcapi_cipher_stream_op() a multi-threaded application can be implemented
 * where one thread sends data to be processed and one thread picks up data
 * processed by the cipher operation.
 *
 * IMPORTANT NOTE: The kernel will only process
 * sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES at one time. If your input data is
 * larger than this threshold, you MUST segment it into chunks of at most
 * sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES and invoke the
 * kcapi_cipher_stream_update() on that segment followed by
 * kcapi_cipher_stream_op() before the next chunk is processed. If this
 * rule is not obeyed, the thread invoking kcapi_cipher_stream_update()
 * will be put to sleep until another thread invokes kcapi_cipher_stream_op().
 *
 * WARNING: The memory referenced by @iov is not accessed by the kernel
 * during this call. The memory is first accessed when kcapi_cipher_stream_op()
 * is called. Thus, you MUST make sure that the referenced memory is still
 * present at the time kcapi_cipher_stream_op() is called.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_stream_update(struct kcapi_handle *handle,
				   struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_cipher_stream_update_last() - send last data for processing (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [in] scatter/gather list with data to be processed by the cipher
 *	 operation.
 * @iovlen: [in] number of scatter/gather list elements.
 *
 * Using this function call, more plaintext for encryption or ciphertext for
 * decryption can be submitted to the kernel.
 *
 * This call is identical to the kcapi_cipher_stream_update() call with the
 * exception that it marks the last data buffer before the cipher operation
 * is triggered. This is call is important for stream ciphers like CTR or CTS
 * mode when providing the last block. It is permissible to provide a zero
 * buffer if all data including the last block is already provided by
 * kcapi_cipher_stream_update.
 *
 * WARNING: If this call is not made for stream ciphers with input data
 * that is not a multiple of the block size of the block cipher, the kernel
 * will not return the last block that contains less data than the block
 * size of the block cipher. For example, sending 257 bytes of data to be
 * encrypted with ctr(aes), the kernel will return only 256 bytes without
 * this call.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_stream_update_last(struct kcapi_handle *handle,
					struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_cipher_stream_op() - obtain processed data (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [out] scatter/gather list pointing to buffers to be filled with
 *	the resulting data from a cipher operation.
 * @iovlen: [in] number of scatter/gather list elements.
 *
 * This call can be called interleaved with kcapi_cipher_stream_update() to
 * fetch the processed data.
 *
 * This function may cause the caller to sleep if the kernel buffer holding
 * the data is empty. The process will be woken up once more data is sent
 * by calling kcapi_cipher_stream_update().
 *
 * Note, when supplying buffers that are not multiple of block size, the buffers
 * will only be filled up to the maximum number of full block sizes that fit
 * into the buffer.
 *
 * The kernel supports multithreaded applications where one or more threads
 * send data via the kcapi_cipher_stream_update() function and another thread
 * collects the processed data via kcapi_cipher_stream_op. The kernel, however,
 * will return data via kcapi_cipher_stream_op() as soon as it has some data
 * available. For example, one thread sends 1000 bytes to be encrypted and
 * another thread already waits for the ciphertext. The kernel may send only,
 * say, 500 bytes back to the waiting process during one
 * kcapi_cipher_stream_op() call. In a subsequent calls to
 * kcapi_cipher_stream_op() more ciphertext is returned. This implies that when
 * the receiving thread shall collect all data there is,
 * kcapi_cipher_stream_op() must be called in a loop until all data is received.
 *
 * @return number of bytes obtained from the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_stream_op(struct kcapi_handle *handle,
			       struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_cipher_enc_aes_cbc - Convenience function for AES CBC encryption
 *
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 * @in: [in] plaintext data buffer
 * @inlen: [in] length of in buffer
 * @iv: [in] IV to be used for cipher operation
 * @out: [out] ciphertext data buffer
 * @outlen: [in] length of out buffer
 *
 * The convenience function performs an AES CBC encryption operation
 * using the provided key, the given input buffer and the given IV.
 * The output is stored in the out buffer.
 *
 * Note, AES CBC requires an input data that is a multiple of 16 bytes.
 * If you have data that is not guaranteed to be multiples of 16 bytes, either
 * add zero bytes at the end of the buffer to pad it up to a multiple of 16
 * bytes. Otherwise, the CTR mode encryption operation may be usable.
 *
 * The output buffer must be at least as large as the input buffer.
 *
 * The IV must be exactly 16 bytes in size.
 *
 * The AES type (AES-128, AES-192 or AES-256) is determined by the size
 * of the given key. If the key is 16 bytes long, AES-128 is used. A 24 byte
 * key implies AES-192 and a 32 byte key implies AES-256.
 *
 * @return number of bytes generated upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_enc_aes_cbc(const uint8_t *key, uint32_t keylen,
				 const uint8_t *in, uint32_t inlen,
				 const uint8_t *iv,
				 uint8_t *out, uint32_t outlen);

/**
 * kcapi_cipher_dec_aes_cbc - Convenience function for AES CBC decryption
 *
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 * @in: [in] ciphertext data buffer
 * @inlen: [in] length of in buffer
 * @iv: [in] IV to be used for cipher operation
 * @out: [out] plaintext data buffer
 * @outlen: [in] length of out buffer
 *
 * The convenience function performs an AES CBC decryption operation
 * using the provided key, the given input buffer and the given IV.
 * The output is stored in the out buffer.
 *
 * Note, AES CBC requires an input data that is a multiple of 16 bytes.
 * If you have data that is not guaranteed to be multiples of 16 bytes, either
 * add zero bytes at the end of the buffer to pad it up to a multiple of 16
 * bytes. Otherwise, the CTR mode encryption operation may be usable.
 *
 * The output buffer must be at least as large as the input buffer.
 *
 * The IV must be exactly 16 bytes in size.
 *
 * The AES type (AES-128, AES-192 or AES-256) is determined by the size
 * of the given key. If the key is 16 bytes long, AES-128 is used. A 24 byte
 * key implies AES-192 and a 32 byte key implies AES-256.
 *
 * @return number of bytes generated upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_dec_aes_cbc(const uint8_t *key, uint32_t keylen,
				 const uint8_t *in, uint32_t inlen,
				 const uint8_t *iv,
				 uint8_t *out, uint32_t outlen);

/**
 * kcapi_cipher_enc_aes_ctr - Convenience function for AES CTR encryption
 *
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 * @in: [in] plaintext data buffer
 * @inlen: [in] length of in buffer
 * @ctr: [in] start counter value to be used for cipher operation
 * @out: [out] ciphertext data buffer
 * @outlen: [in] length of out buffer
 *
 * The convenience function performs an AES counter mode encryption operation
 * using the provided key, the given input buffer and the given IV.
 * The output is stored in the out buffer.
 *
 * The input buffer can be of arbitrary length.
 *
 * The output buffer must be at least as large as the input buffer.
 *
 * The start counter can contain all zeros (not a NULL buffer!) and must be
 * exactly 16 bytes in size.
 *
 * The AES type (AES-128, AES-192 or AES-256) is determined by the size
 * of the given key. If the key is 16 bytes long, AES-128 is used. A 24 byte
 * key implies AES-192 and a 32 byte key implies AES-256.
 *
 * @return number of bytes generated upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_enc_aes_ctr(const uint8_t *key, uint32_t keylen,
				 const uint8_t *in, uint32_t inlen,
				 const uint8_t *ctr,
				 uint8_t *out, uint32_t outlen);

/**
 * kcapi_cipher_dec_aes_ctr - Convenience function for AES CTR decryption
 *
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 * @in: [in] ciphertext data buffer
 * @inlen: [in] length of in buffer
 * @ctr: [in] start counter value to be used for cipher operation
 * @out: [out] plaintext data buffer
 * @outlen: [in] length of out buffer
 *
 * The convenience function performs an AES counter mode encryption operation
 * using the provided key, the given input buffer and the given IV.
 * The output is stored in the out buffer.
 *
 * The input buffer can be of arbitrary length.
 *
 * The output buffer must be at least as large as the input buffer.
 *
 * The start counter can contain all zeros (not a NULL buffer!) and must be
 * exactly 16 bytes in size.
 *
 * The AES type (AES-128, AES-192 or AES-256) is determined by the size
 * of the given key. If the key is 16 bytes long, AES-128 is used. A 24 byte
 * key implies AES-192 and a 32 byte key implies AES-256.
 *
 * @return number of bytes generated upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_dec_aes_ctr(const uint8_t *key, uint32_t keylen,
				 const uint8_t *in, uint32_t inlen,
				 const uint8_t *ctr,
				 uint8_t *out, uint32_t outlen);

/**
 * kcapi_cipher_ivsize() - return size of IV required for cipher
 *
 * @handle: [in] cipher handle
 *
 * @return > 0 specifying the IV size;
 *	   0 on error
 */
uint32_t kcapi_cipher_ivsize(struct kcapi_handle *handle);

/**
 * kcapi_cipher_blocksize() - return size of one block of the cipher
 *
 * @handle: [in] cipher handle
 *
 * @return > 0 specifying the block size;
 *	   0 on error
 */
uint32_t kcapi_cipher_blocksize(struct kcapi_handle *handle);


/**
 * DOC: AEAD Cipher API
 *
 * The following API calls allow using the Authenticated Encryption with
 * Associated Data.
 */

/**
 * kcapi_aead_init() - initialization of cipher handle
 *
 * @handle: [out] cipher handle filled during the call
 * @ciphername: [in] kernel crypto API cipher name as specified in
 *	/proc/crypto
 * @flags: [in] flags specifying the type of cipher handle
 *
 * This function initializes an AEAD cipher handle and establishes the
 * connection to the kernel.
 *
 * On success, a pointer to kcapi_handle object is returned in *handle.
 * Function kcapi_aead_destroy should be called afterwards to free resources.
 *
 * @return 0 upon success;
 *	   -ENOENT - algorithm not available;
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed
 *	   -ENOMEM - cipher handle cannot be allocated
 */
int kcapi_aead_init(struct kcapi_handle **handle, const char *ciphername,
		    uint32_t flags);

/**
 * kcapi_aead_destroy() - close the AEAD handle and release resources
 *
 * @handle: [in] cipher handle to release
 */
void kcapi_aead_destroy(struct kcapi_handle *handle);

/**
 * kcapi_aead_setkey() - set the key for the AEAD handle
 *
 * @handle: [in] cipher handle
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 *
 * With this function, the caller sets the key for subsequent encryption or
 * decryption operations.
 *
 * After the caller provided the key, the caller may securely destroy the key
 * as it is now maintained by the kernel.
 *
 * @return 0 upon success;
 *	   a negative errno-style error code if an error occurred
 */
int kcapi_aead_setkey(struct kcapi_handle *handle,
		      const uint8_t *key, uint32_t keylen);

/**
 * kcapi_aead_settaglen() - set authentication tag size
 *
 * @handle: [in] cipher handle
 * @taglen: [in] length of authentication tag
 *
 * Set the authentication tag size needed for encryption operation. The tag is
 * created during encryption operation with the size provided with this call.
 *
 * @return 0 upon success;
 *	   a negative errno-style error code if an error occurred
 */
int kcapi_aead_settaglen(struct kcapi_handle *handle, uint32_t taglen);

/**
 * kcapi_aead_setassoclen() - set authentication data size
 *
 * @handle: [in] cipher handle
 * @assoclen: [in] length of associated data length
 *
 * The associated data is retained in the cipher handle. During initialization
 * of a cipher handle, it is sent to the kernel. The kernel cipher
 * implementations may verify the appropriateness of the authentication
 * data size and may return an error during initialization if the
 * authentication size is not considered appropriate.
 */
void kcapi_aead_setassoclen(struct kcapi_handle *handle, uint32_t assoclen);

/**
 * kcapi_aead_encrypt() - synchronously encrypt AEAD data (one shot)
 *
 * @handle: [in] cipher handle
 * @in: [in] plaintext data buffer
 * @inlen: [in] length of plaintext buffer
 * @iv: [in] IV to be used for cipher operation
 * @out: [out] data buffer holding cipher text and authentication tag
 * @outlen: [in] length of out buffer
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The AEAD cipher operation requires the furnishing of the associated
 * authentication data. In case such data is not required, it can be set to
 * NULL and length value must be set to zero.
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the plaintext is overwritten with the ciphertext.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * After invoking this function the caller should use
 * kcapi_aead_getdata_output() to obtain the resulting ciphertext and
 * authentication tag references.
 *
 * IMPORTANT NOTE: The kernel will only process
 * sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES at one time. Longer input data cannot
 * be handled by the kernel.
 *
 * @return number of bytes encrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_aead_encrypt(struct kcapi_handle *handle,
			   const uint8_t *in, uint32_t inlen,
			   const uint8_t *iv,
			   uint8_t *out, uint32_t outlen,
			   int access);

/**
 * kcapi_aead_encrypt_aio() - asynchronously encrypt AEAD data (one shot)
 *
 * @handle: [in] cipher handle
 * @iniov: [in] array of scatter-gather list with input buffers
 * @outiov: [out] array of scatter-gather list with output buffers
 * @iovlen: [in] number of IOVECs in array
 * @iv: [in] IV to be used for cipher operation
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The AEAD cipher operation requires the furnishing of the associated
 * authentication data. In case such data is not required, it can be set to
 * NULL and length value must be set to zero.
 *
 * Each IOVEC is processed with its individual AEAD cipher operation. The
 * memory holding the input data will receive the processed data.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * After invoking this function the caller should use
 * kcapi_aead_getdata_output() to obtain the resulting ciphertext and
 * authentication tag references.
 *
 * IMPORTANT NOTE: The kernel will only process
 * sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES at one time. Longer input data cannot
 * be handled by the kernel.
 *
 * @return number of bytes encrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_aead_encrypt_aio(struct kcapi_handle *handle, struct iovec *iniov,
			       struct iovec *outiov, uint32_t iovlen,
			       const uint8_t *iv, int access);

/**
 * kcapi_aead_getdata_input() - get the pointers into input buffer
 *
 * @handle: [in] cipher handle
 * @encdata: [in] data buffer returned by the encryption operation
 * @encdatalen: [in] size of the encryption data buffer
 * @enc: [in] does output buffer hold encryption or decryption result?
 * @aad: [out] AD buffer pointer;  when set to NULL, no data pointer is
 *	returned
 * @aadlen: [out] length of AD; when aad was set to NULL, no information is
 *	returned
 * @data: [out] pointer to output buffer from AEAD encryption operation
 *	when set to NULL, no data pointer is returned
 * @datalen: [out] length of data buffer; when data was set to NULL, no
 *	information is returned
 * @tag: [out] tag buffer pointer;  when set to NULL, no data pointer is
 *	returned
 * @taglen: [out] length of tag; when tag was set to NULL, no information
 *	is returned
 *
 * This function is a service function to the consumer to locate the right
 * ciphertext buffer offset holding the authentication tag. In addition, it
 * provides the consumer with the length of the tag and the length of the
 * ciphertext.
 */
void kcapi_aead_getdata_input(struct kcapi_handle *handle,
			      uint8_t *encdata, uint32_t encdatalen, int enc,
			      uint8_t **aad, uint32_t *aadlen,
			      uint8_t **data, uint32_t *datalen,
			      uint8_t **tag, uint32_t *taglen);

/**
 * kcapi_aead_getdata_output() - get the pointers into output buffer
 *
 * @handle: [in] cipher handle
 * @encdata: [in] data buffer returned by the encryption operation
 * @encdatalen: [in] size of the encryption data buffer
 * @enc: [in] does output buffer hold encryption or decryption result?
 * @aad: [out] AD buffer pointer;  when set to NULL, no data pointer is
 *	returned; returned pointer may also be NULL
 * @aadlen: [out] length of AD; when aad was set to NULL, no information is
 *	returned
 * @data: [out] pointer to output buffer from AEAD encryption operation
 *	when set to NULL, no data pointer is returned
 * @datalen: [out] length of data buffer; when data was set to NULL, no
 *	information is returned
 * @tag: [out] tag buffer pointer;  when set to NULL, no data pointer is
 *	returned; returned pointer may also be NULL
 * @taglen: [out] length of tag; when tag was set to NULL, no information
 *	is returned
 *
 * This function is a service function to the consumer to locate the right
 * ciphertext buffer offset holding the authentication tag. In addition, it
 * provides the consumer with the length of the tag and the length of the
 * ciphertext.
 */
void kcapi_aead_getdata_output(struct kcapi_handle *handle,
			       uint8_t *encdata, uint32_t encdatalen, int enc,
			       uint8_t **aad, uint32_t *aadlen,
			       uint8_t **data, uint32_t *datalen,
			       uint8_t **tag, uint32_t *taglen);

/**
 * kcapi_aead_decrypt() - synchronously decrypt AEAD data (one shot)
 *
 * @handle: [in] cipher handle
 * @in: [in] ciphertext data buffer
 * @inlen: [in] length of in buffer
 * @iv: [in] IV to be used for cipher operation
 * @out: [out] plaintext data buffer
 * @outlen: [in] length of out buffer
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for fastest kernel access; KCAPI_ACCESS_VMSPLICE
 *	use vmsplice access; KCAPI_ACCESS_SENDMSG sendmsg access)
 *
 * The AEAD cipher operation requires the furnishing of the associated
 * authentication data. In case such data is not required, it can be set to
 * NULL and length value must be set to zero.
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the ciphertext is overwritten with the plaintext.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * To catch authentication errors (i.e. integrity violations) during
 * the decryption operation, the return value of this call should be
 * checked. If this function returns -EBADMSG, an authentication error
 * was detected.
 *
 * IMPORTANT NOTE: The kernel will only process
 * sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES at one time. Longer input data cannot
 * be handled by the kernel.
 *
 * @return number of bytes decrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_aead_decrypt(struct kcapi_handle *handle,
			   const uint8_t *in, uint32_t inlen,
			   const uint8_t *iv,
			   uint8_t *out, uint32_t outlen, int access);

/**
 * kcapi_aead_decrypt_aio() - asynchronously decrypt AEAD data (one shot)
 *
 * @handle: [in] cipher handle
 * @iniov: [in] array of scatter-gather list with input buffers
 * @outiov: [out] array of scatter-gather list with output buffers
 * @iovlen: [in] number of IOVECs in array
 * @iv: [in] IV to be used for cipher operation
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The AEAD cipher operation requires the furnishing of the associated
 * authentication data. In case such data is not required, it can be set to
 * NULL and length value must be set to zero.
 *
 * Each IOVEC is processed with its individual AEAD cipher operation. The
 * memory holding the input data will receive the processed data.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * To catch authentication errors (i.e. integrity violations) during
 * the decryption operation, the return value of this call should be
 * checked. If this function returns -EBADMSG, an authentication error
 * was detected.
 *
 * IMPORTANT NOTE: The kernel will only process
 * sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES at one time. Longer input data cannot
 * be handled by the kernel.
 *
 * @return number of bytes encrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_aead_decrypt_aio(struct kcapi_handle *handle, struct iovec *iniov,
			       struct iovec *outiov, uint32_t iovlen,
			       const uint8_t *iv, int access);

/**
 * kcapi_aead_stream_init_enc() - start an encryption operation (stream)
 *
 * @handle: [in] cipher handle
 * @iv: [in] IV to be used for cipher operation
 * @iov: [in] scatter/gather list with data to be encrypted. This is the
 *	pointer to
 *	the first iov entry if an array of iov entries is supplied. See
 *	sendmsg(2) for details on how iov is to be used. This pointer may be
 *	NULL if no data to be encrypted is available at the point of the call.
 * @iovlen: [in] number of scatter/gather list elements. If iov is NULL,
 *	this value must be zero.
 *
 * A stream encryption operation is started with this call. Multiple
 * successive kcapi_aead_stream_update() function calls can be invoked to
 * send more plaintext data to be encrypted. The kernel buffers the input
 * until kcapi_aead_stream_op() picks up the encrypted data. Once plaintext
 * is encrypted during the kcapi_aead_stream_op() it is removed from the
 * kernel buffer.
 *
 * Note, unlike the corresponding symmetric cipher API, the function calls of
 * kcapi_aead_stream_update() and kcapi_aead_stream_op() cannot be mixed! This
 * due to the nature of AEAD where the cipher operation ensures the integrity
 * of the entire data (decryption) or calculates a message digest over the
 * entire data (encryption).
 *
 * When using the stream API, the caller must ensure that data is sent
 * in the correct order (regardless whether data is sent in multiple chunks
 * using kcapi_aead_stream_init_enc() or kcapi_cipher_stream_update()): (i)
 * the complete associated data must be provided, followed by (ii) the
 * plaintext.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_aead_stream_init_enc(struct kcapi_handle *handle,
				   const uint8_t *iv,
				   struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_aead_stream_init_dec() - start a decryption operation (stream)
 *
 * @handle: [in] cipher handle
 * @iv: [in] IV to be used for cipher operation
 * @iov: [in] scatter/gather list with data to be encrypted. This is the
 *	pointer to the first iov entry if an array of iov entries is supplied.
 *	See sendmsg(2) for details on how iov is to be used. This pointer may be
 *	NULL if no data to be encrypted is available at the point of the call.
 * @iovlen: [in] number of scatter/gather list elements. If iov is NULL,
 *	this value must be zero.
 *
 * A stream decryption operation is started with this call. Multiple
 * successive kcapi_aead_stream_update() function calls can be invoked to
 * send more ciphertext data to be encrypted. The kernel buffers the input
 * until kcapi_aead_stream_op() picks up the decrypted data. Once ciphertext
 * is decrypted during the kcapi_aead_stream_op() it is removed from the
 * kernel buffer.
 *
 * Note, unlike the corresponding symmetric cipher API, the function calls of
 * kcapi_aead_stream_update() and kcapi_aead_stream_op() cannot be mixed! This
 * due to the nature of AEAD where the cipher operation ensures the integrity
 * of the entire data (decryption) or calculates a message digest over the
 * entire data (encryption).
 *
 * When using the stream API, the caller must ensure that data is sent
 * in the correct order (regardless whether data is sent in multiple chunks
 * using kcapi_aead_stream_init_enc() or kcapi_cipher_stream_update()): (i)
 * the complete associated data must be provided, followed by (ii) the
 * plaintext. For decryption, also (iii) the tag value must be sent.
 *
 * The IV buffer must be exactly kcapi_cipher_ivsize() bytes in size.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_aead_stream_init_dec(struct kcapi_handle *handle,
				   const uint8_t *iv,
				   struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_aead_stream_update() - send more data for processing (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [in] scatter/gather list with data to be processed by the cipher
 *	operation.
 * @iovlen: [in] number of scatter/gather list elements.
 *
 * Using this function call, more plaintext for encryption or ciphertext for
 * decryption can be submitted to the kernel.
 *
 * Note, see the order of input data as outlined in
 * kcapi_aead_stream_init_dec().
 *
 * This function may cause the caller to sleep if the kernel buffer holding
 * the data is getting full. The process will be woken up once more buffer
 * space becomes available by calling kcapi_aead_stream_op().
 *
 * Note: The last block of input data MUST be provided with
 * kcapi_aead_stream_update_last() as the kernel must be informed about the
 * completion of the input data.
 *
 * With the separate API calls of kcapi_aead_stream_update() and
 * kcapi_aead_stream_op() a multi-threaded application can be implemented
 * where one thread sends data to be processed and one thread picks up data
 * processed by the cipher operation.
 *
 * IMPORTANT NOTE: The kernel will only process
 * sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES at one time. Longer input data cannot
 * be handled by the kernel.
 *
 * WARNING: The memory referenced by @iov is not accessed by the kernel
 * during this call. The memory is first accessed when kcapi_cipher_stream_op()
 * is called. Thus, you MUST make sure that the referenced memory is still
 * present at the time kcapi_cipher_stream_op() is called.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_aead_stream_update(struct kcapi_handle *handle,
				 struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_aead_stream_update_last() - send last data for processing (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [in] scatter/gather list with data to be processed by the cipher
 *	operation.
 * @iovlen: [in] number of scatter/gather list elements.
 *
 * Using this function call, more plaintext for encryption or ciphertext for
 * decryption can be submitted to the kernel.
 *
 * This call is identical to the kcapi_aead_stream_update() call with the
 * exception that it marks the last data buffer before the cipher operation
 * is triggered. Typically, the tag value is provided with this call.
 *
 * WARNING: The memory referenced by @iov is not accessed by the kernel
 * during this call. The memory is first accessed when kcapi_cipher_stream_op()
 * is called. Thus, you MUST make sure that the referenced memory is still
 * present at the time kcapi_cipher_stream_op() is called.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_aead_stream_update_last(struct kcapi_handle *handle,
				      struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_aead_stream_op() - obtain processed data (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [out] scatter/gather list pointing to buffers to be filled with
 *	the resulting data from a cipher operation.
 * @iovlen: [in] number of outiov scatter/gather list elements.
 *
 * This function may cause the caller to sleep if the kernel buffer holding
 * the data is empty. The process will be woken up once more data is sent
 * by calling kcapi_cipher_stream_update().
 *
 * Note, when supplying buffers that are not multiple of block size, the buffers
 * will only be filled up to the maximum number of full block sizes that fit
 * into the buffer.
 *
 * @return number of bytes obtained from the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_aead_stream_op(struct kcapi_handle *handle,
			     struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_aead_ivsize() - return size of IV required for cipher
 *
 * @handle: [in] cipher handle
 *
 * @return > 0 specifying the IV size;
 *	   0 on error
 */
uint32_t kcapi_aead_ivsize(struct kcapi_handle *handle);

/**
 * kcapi_aead_blocksize() - return size of one block of the cipher
 *
 * @handle: [in] cipher handle
 *
 * @return > 0 specifying the block size;
 *	   0 on error
 */
uint32_t kcapi_aead_blocksize(struct kcapi_handle *handle);

/**
 * kcapi_aead_authsize() - return the maximum size of the tag
 *
 * @handle: [in] cipher handle
 *
 * The returned maximum is the largest size of the authenticaation tag that can
 * be produced by the AEAD cipher. Smaller tag sizes may be chosen depending on
 * the AEAD cipher type.
 *
 * @return > 0 specifying the block size;
 *	   0 on error
 */
uint32_t kcapi_aead_authsize(struct kcapi_handle *handle);

/**
 * kcapi_aead_inbuflen_enc() - return minimum encryption input buffer length
 *
 * @handle: [in] cipher handle
 * @inlen: [in] size of plaintext
 * @assoclen: [in] size of associated data (AD)
 * @taglen: [in] size of authentication tag
 *
 * @return minimum size of input data length in bytes
 */
uint32_t kcapi_aead_inbuflen_enc(struct kcapi_handle *handle,
				 uint32_t inlen, uint32_t assoclen,
				 uint32_t taglen);

/**
 * kcapi_aead_inbuflen_dec() - return minimum decryption input buffer length
 *
 * @handle: [in] cipher handle
 * @inlen: [in] size of ciphertext
 * @assoclen: [in] size of associated data (AD)
 * @taglen: [in] size of authentication tag
 *
 * @return minimum size of output data length in bytes
 */
uint32_t kcapi_aead_inbuflen_dec(struct kcapi_handle *handle,
				 uint32_t inlen, uint32_t assoclen,
				 uint32_t taglen);

/**
 * kcapi_aead_outbuflen_enc() - return minimum encryption output buffer length
 *
 * @handle: [in] cipher handle
 * @inlen: [in] size of plaintext
 * @assoclen: [in] size of associated data (AD)
 * @taglen: [in] size of authentication tag
 *
 * @return minimum size of output data length in bytes
 */
uint32_t kcapi_aead_outbuflen_enc(struct kcapi_handle *handle,
				  uint32_t inlen, uint32_t assoclen,
				  uint32_t taglen);

/**
 * kcapi_aead_outbuflen_dec() - return minimum decryption output buffer length
 *
 * @handle: [in] cipher handle
 * @inlen: [in] size of ciphertext
 * @assoclen: [in] size of associated data (AD)
 * @taglen: [in] size of authentication tag
 *
 * @return minimum size of output data length in bytes
 */
uint32_t kcapi_aead_outbuflen_dec(struct kcapi_handle *handle,
				  uint32_t inlen, uint32_t assoclen,
				  uint32_t taglen);

/**
 * kcapi_aead_ccm_nonce_to_iv() - convert CCM nonce into IV
 *
 * @nonce: [in] buffer with nonce
 * @noncelen: [in] length of nonce
 * @iv: [out] newly allocated buffer with IV
 * @ivlen: [out] length of IV
 *
 * This service function converts a CCM nonce value into an IV usable by
 * the kernel crypto API.
 *
 * Caller must free iv.
 *
 * @return 0 upon success;
 *	   < 0 upon failure
 */
int kcapi_aead_ccm_nonce_to_iv(const uint8_t *nonce, uint32_t noncelen,
			       uint8_t **iv, uint32_t *ivlen);


/**
 * DOC: Message Digest Cipher API
 */

/**
 * kcapi_md_init() - initialize cipher handle
 *
 * @handle: [out] cipher handle filled during the call
 * @ciphername: [in] kernel crypto API cipher name as specified in /proc/crypto
 * @flags: [in] flags specifying the type of cipher handle
 *
 * This function provides the initialization of a (keyed) message digest handle
 * and establishes the connection to the kernel.
 *
 * On success, a pointer to kcapi_handle object is returned in *handle.
 * Function kcapi_md_destroy should be called afterwards to free resources.
 *
 * @return 0 upon success;
 *	   -ENOENT - algorithm not available;
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed;
 *	   -ENOMEM - cipher handle cannot be allocated
 */
int kcapi_md_init(struct kcapi_handle **handle, const char *ciphername,
		  uint32_t flags);

/**
 * kcapi_md_destroy() - close the message digest handle and release resources
 *
 * @handle: [in] cipher handle to release
 */
void kcapi_md_destroy(struct kcapi_handle *handle);

/**
 * kcapi_md_setkey() - set the key for the message digest handle
 *
 * @handle: [in] cipher handle
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 *
 * With this function, the caller sets the key for subsequent hashing
 * operations. This call is applicable for keyed message digests.
 *
 * After the caller provided the key, the caller may securely destroy the key
 * as it is now maintained by the kernel.
 *
 * @return 0 upon success;
 *	   a negative errno-style error code if an error occurred
 */
int kcapi_md_setkey(struct kcapi_handle *handle,
		    const uint8_t *key, uint32_t keylen);

/**
 * kcapi_md_update() - message digest update function (stream)
 *
 * @handle: [in] cipher handle
 * @buffer: [in] holding the data to add to the message digest
 * @len: [in] buffer length
 *
 * The input buffer can be at most INT_MAX in size.
 *
 * @return 0 upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_md_update(struct kcapi_handle *handle,
			const uint8_t *buffer, uint32_t len);

/**
 * kcapi_md_final() - message digest finalization function (stream)
 *
 * @handle: [in] cipher handle
 * @buffer: [out] filled with the message digest
 * @len: [in] buffer length
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_final(struct kcapi_handle *handle,
		       uint8_t *buffer, uint32_t len);

/**
 * kcapi_md_digest() - calculate message digest on buffer (one-shot)
 *
 * @handle: [in] cipher handle
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot function, a message digest of the given buffer is
 * generated. The output buffer must be allocated by the caller and have at
 * least the length of the message digest size for the chosen message digest.
 *
 * The message digest handle must have been initialized, potentially by also
 * setting the key using the generic message digest API functions.
 *
 * The input buffer can be at most INT_MAX in size.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_digest(struct kcapi_handle *handle,
		       const uint8_t *in, uint32_t inlen,
		       uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_sha1 - SHA-1 message digest on one buffer
 *
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a message digest of the given buffer
 * is generated. The output buffer must be allocated by the caller and have at
 * least the length of the message digest size for the chosen message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_sha1(const uint8_t *in, uint32_t inlen,
		      uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_sha224 - SHA-224 message digest on one buffer
 *
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a message digest of the given buffer
 * is generated. The output buffer must be allocated by the caller and have at
 * least the length of the message digest size for the chosen message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_sha224(const uint8_t *in, uint32_t inlen,
			uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_sha256 - SHA-256 message digest on one buffer
 *
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a message digest of the given buffer
 * is generated. The output buffer must be allocated by the caller and have at
 * least the length of the message digest size for the chosen message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_sha256(const uint8_t *in, uint32_t inlen,
			uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_sha384 - SHA-384 message digest on one buffer
 *
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a message digest of the given buffer
 * is generated. The output buffer must be allocated by the caller and have at
 * least the length of the message digest size for the chosen message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_sha384(const uint8_t *in, uint32_t inlen,
			uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_sha512 - SHA-512 message digest on one buffer
 *
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a message digest of the given buffer
 * is generated. The output buffer must be allocated by the caller and have at
 * least the length of the message digest size for the chosen message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_sha512(const uint8_t *in, uint32_t inlen,
			uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_hmac_sha1 - HMAC SHA-1 keyed message digest on one buffer
 *
 * @key: [in] buffer with HMAC key
 * @keylen: [in] length of HMAC key buffer
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a keyed message digest of the given
 * buffer is generated. The output buffer must be allocated by the caller and
 * have at least the length of the message digest size for the chosen keyed
 * message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_hmac_sha1(const uint8_t *key, uint32_t keylen,
			   const uint8_t *in, uint32_t inlen,
			   uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_hmac_sha224 - HMAC SHA-224 keyed message digest on one buffer
 *
 * @key: [in] buffer with HMAC key
 * @keylen: [in] length of HMAC key buffer
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a keyed message digest of the given
 * buffer is generated. The output buffer must be allocated by the caller and
 * have at least the length of the message digest size for the chosen keyed
 * message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_hmac_sha224(const uint8_t *key, uint32_t keylen,
			     const uint8_t *in, uint32_t inlen,
			     uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_hmac_sha256 - HMAC SHA-256 keyed message digest on one buffer
 *
 * @key: [in] buffer with HMAC key
 * @keylen: [in] length of HMAC key buffer
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a keyed message digest of the given
 * buffer is generated. The output buffer must be allocated by the caller and
 * have at least the length of the message digest size for the chosen keyed
 * message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_hmac_sha256(const uint8_t *key, uint32_t keylen,
			     const uint8_t *in, uint32_t inlen,
			     uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_hmac_sha384 - HMAC SHA-384 keyed message digest on one buffer
 *
 * @key: [in] buffer with HMAC key
 * @keylen: [in] length of HMAC key buffer
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a keyed message digest of the given
 * buffer is generated. The output buffer must be allocated by the caller and
 * have at least the length of the message digest size for the chosen keyed
 * message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_hmac_sha384(const uint8_t *key, uint32_t keylen,
			     const uint8_t *in, uint32_t inlen,
			     uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_hmac_sha512 - HMAC SHA-512 keyed message digest on one buffer
 *
 * @key: [in] buffer with HMAC key
 * @keylen: [in] length of HMAC key buffer
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a keyed message digest of the given
 * buffer is generated. The output buffer must be allocated by the caller and
 * have at least the length of the message digest size for the chosen keyed
 * message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_hmac_sha512(const uint8_t *key, uint32_t keylen,
			     const uint8_t *in, uint32_t inlen,
			     uint8_t *out, uint32_t outlen);

/**
 * kcapi_md_digestsize() - return the size of the message digest
 *
 * @handle: [in] cipher handle
 *
 * The returned message digest size can be used before the kcapi_md_final
 * function invocation to determine the right memory size to be allocated for
 * this call.
 *
 * @return > 0 specifying the block size;
 *	    0 on error
 */
uint32_t kcapi_md_digestsize(struct kcapi_handle *handle);

/**
 * kcapi_md_blocksize() - return size of one block of the message digest
 *
 * @handle: [in] cipher handle
 *
 * @return > 0 specifying the block size;
 *	   0 on error
 */
uint32_t kcapi_md_blocksize(struct kcapi_handle *handle);


/**
 * DOC: Random Number API
 */

/**
 * kcapi_rng_init() - initialize cipher handle
 *
 * @handle: [out] cipher handle filled during the call
 * @ciphername: [in] kernel crypto API cipher name as specified in
 *	/proc/crypto
 * @flags: [in] flags specifying the type of cipher handle (unused for RNG)
 *
 * This function provides the initialization of a random number generator handle
 * and establishes the connection to the kernel.
 *
 * On success, a pointer to kcapi_handle object is returned in *handle.
 * Function kcapi_rng_destroy should be called afterwards to free resources.
 *
 * @return 0 upon success;
 *	   -ENOENT - algorithm not available;
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed
 *	   -ENOMEM - cipher handle cannot be allocated
 */
int kcapi_rng_init(struct kcapi_handle **handle, const char *ciphername,
		   uint32_t flags);

/**
 * kcapi_rng_destroy() - close the RNG handle and release resources
 *
 * @handle: [in] cipher handle to release
 */
void kcapi_rng_destroy(struct kcapi_handle *handle);

/**
 * kcapi_rng_seed() - seed the RNG
 *
 * @handle: [in] cipher handle
 * @seed: [in] seed data
 * @seedlen: [in] size of seed
 *
 * Note, this call must be called to initialize the selected RNG. When the
 * SP800-90A DRBG is used, this call causes the DRBG to seed itself from the
 * internal noise sources.
 *
 * Note, in case of using the SP800-90A DRBG, the seed buffer may be NULL. If
 * it is not NULL, the DRBG uses the given data either as personalization string
 * in case of the initial seeding or additional data for reseeding.
 *
 * @return 0 upon success;
 * 	   a negative errno-style error code if an error occurred
 */
int kcapi_rng_seed(struct kcapi_handle *handle, uint8_t *seed,
		   uint32_t seedlen);

/**
 * kcapi_rng_generate() - generate a random number
 *
 * @handle: [in] cipher handle
 * @buffer: [out] filled with the random number
 * @len: [in] buffer length
 *
 * @return size of random number generated upon success;
 *	   -EIO - data cannot be obtained
 */
int32_t kcapi_rng_generate(struct kcapi_handle *handle,
			   uint8_t *buffer, uint32_t len);

/**
 * kcapi_rng_get_bytes - Convenience function to generate random bytes
 *
 * @buffer: [out] filled with the random number
 * @outlen: [in] buffer length
 *
 * This convenience function generates random bytes of the size of outlen
 * and stores them into the provided buffer.
 *
 * @return size of random number generated upon success;
 *	   -EIO - data cannot be obtained
 */
int32_t kcapi_rng_get_bytes(uint8_t *buffer, uint32_t outlen);

/**
 * kcapi_rng_seedsize() - return required seed size of DRNG
 *
 * @handle: [in] cipher handle
 *
 * @return > 0 specifying the block size;
 *	   0 on error
 */
uint32_t kcapi_rng_seedsize(struct kcapi_handle *handle);

/**
 * DOC: Common API
 *
 * The following API calls are common to all cipher types.
 */

enum kcapi_verbosity {
	KCAPI_LOG_NONE,
	KCAPI_LOG_ERR,
	KCAPI_LOG_WARN,
	KCAPI_LOG_VERBOSE,
	KCAPI_LOG_DEBUG,
};

/**
 * kcapi_set_verbosity() - set the verbosity level of the library
 *
 * @level: [in] verbosity level:
 *	LOG_ERR: only log error messages (default)
 *	LOG_WARN: log warnings and error messages
 *	LOG_VERBOSE: log verbose messages, warnings and error messages
 *	LOG_DEBUG: log all details of library operation
 */
void kcapi_set_verbosity(enum kcapi_verbosity level);

/**
 * kcapi_versionstring() - obtain version string of kcapi library
 *
 * @buf: [out] buffer to place version string into
 * @buflen: [in] length of buffer
 */
void kcapi_versionstring(char *buf, uint32_t buflen);

/**
 * kcapi_version() - return machine-usable version number of kcapi library
 *
 * The function returns a version number that is monotonic increasing
 * for newer versions. The version numbers are multiples of 100. For example,
 * version 1.2.3 is converted to 1020300 -- the last two digits are reserved
 * for future use.
 *
 * The result of this function can be used in comparing the version number
 * in a calling program if version-specific calls need to be make.
 *
 * @return Version number of kcapi library
 */
uint32_t kcapi_version(void);

/**
 * kcapi_pad_iv() - realign the IV as necessary for cipher
 *
 * @handle: [in] cipher handle
 * @iv: [in] current IV buffer
 * @ivlen: [in] length of IV buffer
 * @newiv: [out] buffer of aligned IV
 * @newivlen: [out] length of newly aligned IV
 *
 * The function pads the least significant bits of the provided IV up to the
 * block size of the cipher with zeros. In case the provided IV is longer than
 * the block size, the least significant bits are truncated to the block size.
 *
 * The function allocates memory for newiv in case the return code indicates
 * success. The consumer must free the memory after use.
 *
 * @return 0 for success;
 *	   a negative errno-style error code if an error occurred
 */
int kcapi_pad_iv(struct kcapi_handle *handle,
		 const uint8_t *iv, uint32_t ivlen,
		 uint8_t **newiv, uint32_t *newivlen);

/**
 * kcapi_memset_secure() - memset() implementation that will not be optimized
 *			   away by the compiler
 *
 * @s: [in] see memset(3)
 * @c: [in] see memset(3)
 * @n: [in] see memset(3)
 *
 * The parameters, he logic and the return code is identical to memset(3).
 */
void kcapi_memset_secure(void *s, int c, uint32_t n);

/**
 * DOC: Asymmetric Cipher API
 *
 * API function calls used to invoke asymmetric ciphers.
 */

/**
 * kcapi_akcipher_init() - initialize cipher handle
 *
 * @handle: [out] cipher handle filled during the call
 * @ciphername: [in] kernel crypto API cipher name as specified in
 *	/proc/crypto
 * @flags: [in] flags specifying the type of cipher handle
 *
 * This function provides the initialization of an asymmetric cipher handle and
 * establishes the connection to the kernel.
 *
 * On success, a pointer to kcapi_handle object is returned in *handle.
 * Function kcapi_akcipher_destroy should be called afterwards to free
 * resources.
 *
 * @return 0 upon success;
 *	   -ENOENT - algorithm not available;
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed
 *	   -ENOMEM - cipher handle cannot be allocated
 */
int kcapi_akcipher_init(struct kcapi_handle **handle, const char *ciphername,
			uint32_t flags);

/**
 * kcapi_akcipher_destroy() - close the cipher handle and release resources
 *
 * @handle: [in] cipher handle to release
 */
void kcapi_akcipher_destroy(struct kcapi_handle *handle);

/**
 * kcapi_akcipher_setkey() - set the private key for the cipher handle
 *
 * @handle: [in] cipher handle
 * @key: [in] key buffer in DER format
 * @keylen: [in] length of key buffer
 *
 * With this function, the caller sets the key for subsequent cipher operations.
 *
 * The key must be in DER format as follows
 *
 * SEQUENCE {
 *        version         INTEGER,
 *        n               INTEGER ({ rsa_get_n }),
 *        e               INTEGER ({ rsa_get_e }),
 *        d               INTEGER ({ rsa_get_d }),
 *        prime1          INTEGER,
 *        prime2          INTEGER,
 *        exponent1       INTEGER,
 *        exponent2       INTEGER,
 *        coefficient     INTEGER
 *}
 *
 * After the caller provided the key, the caller may securely destroy the key
 * as it is now maintained by the kernel.
 *
 * @return upon success the value of the maximum size for the asymmetric
 *	   operation is returned (e.g. the modulus size);
 *	   a negative errno-style error code if an error occurred
 */
int kcapi_akcipher_setkey(struct kcapi_handle *handle,
			  const uint8_t *key, uint32_t keylen);

/**
 * kcapi_akcipher_setpubkey() - set the public key for the cipher handle
 *
 * @handle: [in] cipher handle
 * @key: [in] key buffer in DER format
 * @keylen: [in] length of key buffer
 *
 * With this function, the caller sets the key for subsequent cipher operations.
 *
 * The key must be in DER format as follows
 *
 * SEQUENCE {
 *        n INTEGER ({ rsa_get_n }),
 *        e INTEGER ({ rsa_get_e })
 *}
 *
 * After the caller provided the key, the caller may securely destroy the key
 * as it is now maintained by the kernel.
 *
 * @return upon success the value of the maximum size for the asymmetric
 *	   operation is returned (e.g. the modulus size);
 *	   a negative errno-style error code if an error occurred
 */
int kcapi_akcipher_setpubkey(struct kcapi_handle *handle,
			     const uint8_t *key, uint32_t keylen);

/**
 * kcapi_akcipher_encrypt() - encrypt data
 *
 * @handle: [in] cipher handle
 * @in: [in] plaintext data buffer
 * @inlen: [in] length of in buffer
 * @out: [out] ciphertext data buffer
 * @outlen: [in] length of out buffer
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the plaintext is overwritten with the ciphertext.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * If the output size is insufficiently large, -EINVAL is returned. The
 * output buffer must be at least as large as the modululs of the uses key.
 *
 * @return number of bytes returned by the encryption operation upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_encrypt(struct kcapi_handle *handle,
			       const uint8_t *in, uint32_t inlen,
			       uint8_t *out, uint32_t outlen, int access);

/**
 * kcapi_akcipher_encrypt_aio() - encrypt data (asynchronous one shot)
 *
 * @handle: [in] cipher handle
 * @iniov: [in] head of scatter-gather list array holding the plaintext
 * @outiov: [out] head of scatter-gather list of the destination buffers filled
 *	with ciphertext
 * @iovlen: [in] number of scatter-gather list entries
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The individual scatter-gather list entries are processed with
 * separate invocations of the the given cipher.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * @return number of bytes encrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_encrypt_aio(struct kcapi_handle *handle,
				   struct iovec *iniov, struct iovec *outiov,
				   uint32_t iovlen, int access);

/**
 * kcapi_akcipher_decrypt() - decrypt data
 *
 * @handle: [in] cipher handle
 * @in: [in] ciphertext data buffer
 * @inlen: [in] length of in buffer
 * @out: [out] plaintext data buffer
 * @outlen: [in] length of out buffer
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the decryption operation,
 * the ciphertext is overwritten with the plaintext.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * If the output size is insufficiently large, -EINVAL is returned. The
 * output buffer must be at least as large as the modululs of the uses key.
 *
 * @return number of bytes returned by the decryption operation upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_decrypt(struct kcapi_handle *handle,
			       const uint8_t *in, uint32_t inlen,
			       uint8_t *out, uint32_t outlen, int access);

/**
 * kcapi_akcipher_decrypt_aio() - decrypt data (asynchronous one shot)
 *
 * @handle: [in] cipher handle
 * @iniov: [in] head of scatter-gather list array holding the plaintext
 * @outiov: [out] head of scatter-gather list of the destination buffers filled
 *	with ciphertext
 * @iovlen: [in] number of scatter-gather list entries
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The individual scatter-gather list entries are processed with
 * separate invocations of the the given cipher.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * @return number of bytes decrypted upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_decrypt_aio(struct kcapi_handle *handle,
				   struct iovec *iniov, struct iovec *outiov,
				   uint32_t iovlen, int access);

/**
 * kcapi_akcipher_sign() - signature generation
 *
 * @handle: [in] cipher handle
 * @in: [in] message data buffer
 * @inlen: [in] length of in buffer
 * @out: [out] signature data buffer
 * @outlen: [in] length of out buffer
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * It is perfectly legal to use the same buffer as the message and
 * signature pointers. That would mean that after the signature generation
 * operation, the message is overwritten with the signature.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * If the output size is insufficiently large, -EINVAL is returned. The
 * output buffer must be at least as large as the modululs of the uses key.
 *
 * @return number of bytes returned by the signature gen operation upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_sign(struct kcapi_handle *handle,
			    const uint8_t *in, uint32_t inlen,
			    uint8_t *out, uint32_t outlen, int access);

/**
 * kcapi_akcipher_sign_aio() - sign data (asynchronous one shot)
 *
 * @handle: [in] cipher handle
 * @iniov: [in] head of scatter-gather list array holding the plaintext
 * @outiov: [out] head of scatter-gather list of the destination buffers filled
 *	with ciphertext
 * @iovlen: [in] number of scatter-gather list entries
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The individual scatter-gather list entries are processed with
 * separate invocations of the the given cipher.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * @return number of bytes signed upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_sign_aio(struct kcapi_handle *handle,
				struct iovec *iniov, struct iovec *outiov,
				uint32_t iovlen, int access);

/**
 * kcapi_akcipher_verify() - signature verification
 *
 * @handle: [in] cipher handle
 * @in: [in] message data buffer
 * @inlen: [in] length of in buffer
 * @out: [out] signature data buffer
 * @outlen: [in] length of out buffer
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * It is perfectly legal to use the same buffer as the message and
 * signature pointers. That would mean that after the signature generation
 * operation, the message is overwritten with the signature.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * If the output size is insufficiently large, -EINVAL is returned. The
 * output buffer must be at least as large as the modululs of the uses key.
 *
 * To catch signature verification errors, the return value of this
 * call should be checked. If this function returns -EBADMSG, the
 * verification of the signature failed.
 *
 * @return number of bytes returned by the signature ver operation upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_verify(struct kcapi_handle *handle,
			      const uint8_t *in, uint32_t inlen,
			      uint8_t *out, uint32_t outlen, int access);

/**
 * kcapi_akcipher_verify_aio() - verify data (asynchronous one shot)
 *
 * @handle: [in] cipher handle
 * @iniov: [in] head of scatter-gather list array holding the plaintext
 * @outiov: [out] head of scatter-gather list of the destination buffers filled
 *	with ciphertext
 * @iovlen: [in] number of scatter-gather list entries
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The individual scatter-gather list entries are processed with
 * separate invocations of the the given cipher.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * @return number of bytes verify upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_verify_aio(struct kcapi_handle *handle,
				  struct iovec *iniov, struct iovec *outiov,
				  uint32_t iovlen, int access);

/**
 * kcapi_akcipher_stream_init_enc() - start an encryption operation (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [in] scatter/gather list with data to be encrypted. This is the
 *	pointer to the first iov entry if an array of iov entries is supplied.
 *	See sendmsg(2) for details on how iov is to be used. This pointer may be
 *	NULL if no data to be encrypted is available at the point of the call.
 * @iovlen: [in] number of scatter/gather list elements. If iov is NULL,
 *	this value must be zero.
 *
 * A stream encryption operation is started with this call. Multiple
 * successive kcapi_akcipher_stream_update() function calls can be invoked to
 * send more plaintext data to be encrypted. The last invocation to supply data
 * must be done with kcapi_akcipher_stream_update_last(). The kernel buffers the
 * input until kcapi_akcipher_stream_op() picks up the encrypted data. Once
 * plaintext is encrypted during the kcapi_cipher_stream_op() it is removed
 * from the kernel buffer.
 *
 * The function calls of kcapi_akcipher_stream_update() and
 * kcapi_akcipher_stream_op() can be mixed, even by multiple threads of an
 * application.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_stream_init_enc(struct kcapi_handle *handle,
				       struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_akcipher_stream_init_dec() - start an decryption operation (stream)
 * @handle: [in] cipher handle
 * @iov: [in] scatter/gather list with data to be decrypted. This is the
 *	pointer to the first iov entry if an array of iov entries is supplied.
 *	See sendmsg(2) for details on how iov is to be used. This pointer may be
 *	NULL if no data to be decrypted is available at the point of the call.
 * @iovlen: [in] number of scatter/gather list elements. If iov is NULL,
 *	this value must be zero.
 *
 * A stream decryption operation is started with this call. Multiple
 * successive kcapi_akcipher_stream_update() function calls can be invoked to
 * send more plaintext data to be decrypted. The last invocation to supply data
 * must be done with kcapi_akcipher_stream_update_last(). The kernel buffers the
 * input until kcapi_akcipher_stream_op() picks up the encrypted data. Once
 * plaintext is decrypted during the kcapi_cipher_stream_op() it is removed
 * from the kernel buffer.
 *
 * The function calls of kcapi_akcipher_stream_update() and
 * kcapi_akcipher_stream_op() can be mixed, even by multiple threads of an
 * application.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_stream_init_dec(struct kcapi_handle *handle,
				       struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_akcipher_stream_init_sgn() - start an signing operation (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [in] scatter/gather list with data to be signed. This is the
 *	pointer to the first iov entry if an array of iov entries is supplied.
 *	See sendmsg(2) for details on how iov is to be used. This pointer may be
 *	NULL if no data to be signed is available at the point of the call.
 * @iovlen: [in] number of scatter/gather list elements. If iov is NULL,
 *	this value must be zero.
 *
 * A stream signing operation is started with this call. Multiple
 * successive kcapi_akcipher_stream_update() function calls can be invoked to
 * send more plaintext data to be signed. The last invocation to supply data
 * must be done with kcapi_akcipher_stream_update_last(). The kernel buffers the
 * input until kcapi_akcipher_stream_op() picks up the signed data. Once
 * plaintext is signed during the kcapi_cipher_stream_op() it is removed
 * from the kernel buffer.
 *
 * The function calls of kcapi_akcipher_stream_update() and
 * kcapi_akcipher_stream_op() can be mixed, even by multiple threads of an
 * application.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_stream_init_sgn(struct kcapi_handle *handle,
				       struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_akcipher_stream_init_vfy() - start an signature verification operation
 *				      (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [in] scatter/gather list with data to be verified. This is the
 *	pointer to the first iov entry if an array of iov entries is supplied.
 *	See sendmsg(2) for details on how iov is to be used. This pointer may be
 *	NULL if no data to be verified is available at the point of the call.
 * @iovlen: [in] number of scatter/gather list elements. If iov is NULL,
 *	this value must be zero.
 *
 * A stream signature verification operation is started with this call. Multiple
 * successive kcapi_akcipher_stream_update() function calls can be invoked to
 * send more plaintext data to be verified. The last invocation to supply data
 * must be done with kcapi_akcipher_stream_update_last(). The kernel buffers the
 * input until kcapi_akcipher_stream_op() picks up the verified data. Once
 * plaintext is verified during the kcapi_cipher_stream_op() it is removed
 * from the kernel buffer.
 *
 * The function calls of kcapi_akcipher_stream_update() and
 * kcapi_akcipher_stream_op() can be mixed, even by multiple threads of an
 * application.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_stream_init_vfy(struct kcapi_handle *handle,
				       struct iovec *iov, uint32_t iovlen);


/**
 * kcapi_akcipher_stream_update() - send more data for processing (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [in] scatter/gather list with data to be processed by the cipher
 *	operation.
 * @iovlen: [in] number of scatter/gather list elements.
 *
 * Using this function call, more data can be submitted to the kernel.
 *
 * This function may cause the caller to sleep if the kernel buffer holding
 * the data is getting full. The process will be woken up once more buffer
 * space becomes available by calling kcapi_akcipher_stream_op().
 *
 * Note: with the separate API calls of kcapi_akcipher_stream_update() and
 * kcapi_akcipher_stream_op() a multi-threaded application can be implemented
 * where one thread sends data to be processed and one thread picks up data
 * processed by the cipher operation.
 *
 * WARNING: The memory referenced by @iov is not accessed by the kernel
 * during this call. The memory is first accessed when kcapi_cipher_stream_op()
 * is called. Thus, you MUST make sure that the referenced memory is still
 * present at the time kcapi_cipher_stream_op() is called.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_stream_update(struct kcapi_handle *handle,
				     struct iovec *iov, uint32_t iovlen);

/**
 * kcapi_akcipher_stream_update_last() - send last data for processing (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [in] scatter/gather list with data to be processed by the cipher
 *	operation.
 * @iovlen: [in] number of scatter/gather list elements.
 *
 * Using this function call, more data can be submitted to the kernel.
 *
 * This call is identical to the kcapi_akcipher_stream_update() call with the
 * exception that it marks the last data buffer before the cipher operation
 * is triggered.
 *
 * This call must be used if all data is delivered to the kernel and
 * kcapi_akcipher_stream_op() will be invoked as a next step. This call
 * notifies the kernel that no further data is to be expected.
 *
 * WARNING: The memory referenced by @iov is not accessed by the kernel
 * during this call. The memory is first accessed when kcapi_cipher_stream_op()
 * is called. Thus, you MUST make sure that the referenced memory is still
 * present at the time kcapi_cipher_stream_op() is called.
 *
 * @return number of bytes sent to the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_stream_update_last(struct kcapi_handle *handle,
					  struct iovec *iov, uint32_t iovlen);


/**
 * kcapi_akcipher_stream_op() - obtain processed data (stream)
 *
 * @handle: [in] cipher handle
 * @iov: [in/out] scatter/gather list pointing to buffers to be filled
 *	with the resulting data from a cipher operation.
 * @iovlen: [in] number of scatter/gather list elements.
 *
 * This call can be called interleaved with kcapi_akcipher_stream_update() to
 * fetch the processed data.
 *
 * This function may cause the caller to sleep if the kernel buffer holding
 * the data is empty. The process will be woken up once more data is sent
 * by calling kcapi_cipher_stream_update().
 *
 * Note, when supplying buffers that are not multiple of block size, the buffers
 * will only be filled up to the maximum number of full block sizes that fit
 * into the buffer.
 *
 * @return number of bytes obtained from the kernel upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_akcipher_stream_op(struct kcapi_handle *handle,
			         struct iovec *iov, uint32_t iovlen);

/**
 * DOC: Key-Agreement Protocol Primitives
 *
 * API function calls used to invoke Diffie-Hellmand or EC-Diffie-Hellman
 * operations.
 */

/**
 * kcapi_kpp_init() - initialize cipher handle
 *
 * @handle: [out] cipher handle filled during the call
 * @ciphername: [in] kernel crypto API cipher name as specified in
 *	/proc/crypto
 * @flags: [in] flags specifying the type of cipher handle
 *
 * This function provides the initialization of a KPP cipher handle and
 * establishes the connection to the kernel.
 *
 * On success, a pointer to kcapi_handle object is returned in *handle.
 * Function kcapi_kpp_destroy should be called afterwards to free
 * resources.
 *
 * @return 0 upon success;
 *	   -ENOENT - algorithm not available;
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed
 *	   -ENOMEM - cipher handle cannot be allocated
 */
int kcapi_kpp_init(struct kcapi_handle **handle, const char *ciphername,
		   uint32_t flags);

/**
 * kcapi_kpp_destroy() - close the cipher handle and release resources
 *
 * @handle: [in] cipher handle to release
 */
void kcapi_kpp_destroy(struct kcapi_handle *handle);

/**
 * kcapi_kpp_dh_setparam_pkcs3 - set the PG parameters using PKCS3 format
 *
 * @handle: [in] cipher handle
 * @pkcs3: [in] parameter buffer in DER format
 * @pkcs3len: [in] length of key buffer
 *
 * With this function, the caller sets the PG parameters for subsequent cipher
 * operations.
 *
 * The parameter set must be in DER format as follows
 *
 * SEQUENCE {
 *	prime INTEGER ({ dh_get_p }),
 *	base INTEGER ({ dh_get_g })
 *}
 *
 * The following command generates such parameter set where the output
 * file content is has the correct DER structure:
 *
 * openssl dhparam -outform DER -out dhparam.der 2048
 *
 * Note, this function defines that the subsequent key generation and
 * shared secret operation performs an FFC Diffie-Hellman operation.
 *
 * After the caller provided the key, the caller may destroy the parameter
 * as it is now maintained by the kernel.
 *
 * @return upon success the value of the maximum size for the KPP
 *	   operation is returned (e.g. the prime size);
 *	   a negative errno-style error code if an error occurred
 */
int kcapi_kpp_dh_setparam_pkcs3(struct kcapi_handle *handle,
				const uint8_t *pkcs3, uint32_t pkcs3len);

/* ECC curve IDs */
#define ECC_CURVE_NIST_P192     0x0001
#define ECC_CURVE_NIST_P256     0x0002

/**
 * kcapi_kpp_ecdh_setcurve - set the ECC curve to be used for ECDH
 *
 * @handle: [in] cipher handle
 * @curve_id: [in] ID of the ECC curve
 *
 * With this function, the caller sets the ECC curve for subsequent cipher
 * operations. The curve ID is one of the ECC_CURVE_* identifiers.
 *
 * Note, this function defines that the subsequent key generation and
 * shared secret operation performs an ECC Diffie-Hellman operation.
 *
 * @return 0 upon success;
 *	   a negative errno-style error code if an error occurred
 */
int kcapi_kpp_ecdh_setcurve(struct kcapi_handle *handle,
			    unsigned long curve_id);

/**
 * kcapi_kpp_setkey - set the private key of the DH / ECDH operation
 *
 * @handle: [in] cipher handle
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 *
 * With this function, the caller sets the key for subsequent DH / ECDH
 * public key generation or shared secret generation operations.
 *
 * If the key / keylen is zero, the kernel tries to generate the private key
 * itself and retains it internally. This is useful if the DH / ECDH operation
 * shall be performed on ephemeral keys where the caller is only interested
 * in eventually obtain the shared secret.
 *
 * After the caller provided the key, the caller may securely destroy the key
 * as it is now maintained by the kernel.
 *
 * Note, the key can only be set after the DH parameters or the ECC curve
 * has been set.
 *
 * @return in case of success a positive integer is returned that denominates
 *	   the maximum output size of the cryptographic operation -- this value
 *	   must be used as the size of the output buffer for one cryptographic
 *	   operation);
 *	   a negative errno-style error code if an error occurred -- the error
 *	   -EOPNOTSUPP is returned in case a kernel-triggered private
 *	   key generation is requested, but the underlying cipher implementation
 *	   does not support this operation.
 */
int kcapi_kpp_setkey(struct kcapi_handle *handle,
		     const uint8_t *key, uint32_t keylen);

/**
 * kcapi_kpp_keygen - generate a public key
 *
 * @handle: [in] cipher handle
 * @pubkey: [out] generated public key
 * @pubkeylen: [in] length of key buffer
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	    heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	    vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * @return number of bytes returned by the key generation operation upon
 *	   success; a negative errno-style error code if an error occurred
 */
int32_t kcapi_kpp_keygen(struct kcapi_handle *handle,
			 uint8_t *pubkey, uint32_t pubkeylen, int access);

/**
 * kcapi_kpp_ssgen - generate a shared secret
 *
 * @handle: [in] cipher handle
 * @pubkey: [in] public key of peer that shall be used to generate the shared
 *	    secret with
 * @pubkeylen: [in] length of the public key buffer
 * @ss: [out] generated shared secret
 * @sslen: [in] length of key buffer
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	    heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	    vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * @return number of bytes returned by the shared secret generation operation
 *	   upon success; a negative errno-style error code if an error occurred
 */
int32_t kcapi_kpp_ssgen(struct kcapi_handle *handle,
			const uint8_t *pubkey, uint32_t pubkeylen,
			uint8_t *ss, uint32_t sslen, int access);

/**
 * kcapi_kpp_keygen_aio() - generate a public key (asynchronous one shot)
 *
 * @handle: [in] cipher handle
 * @outiov: [out] head of scatter-gather list of the destination buffers filled
 *	with the generated public key
 * @iovlen: [in] number of scatter-gather list entries
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The individual scatter-gather list entries are processed with
 * separate invocations of the the given cipher.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * @return number of bytes verify upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_kpp_keygen_aio(struct kcapi_handle *handle, struct iovec *outiov,
			     uint32_t iovlen, int access);

/**
 * kcapi_kpp_ssgen_aio() - generate a shared secret (asynchronous one shot)
 *
 * @handle: [in] cipher handle
 * @iniov: [in] head of scatter-gather list of the source buffers with the
 *	public keys of the peer
 * @outiov: [out] head of scatter-gather list of the destination buffers filled
 *	with the generated shared secret
 * @iovlen: [in] number of scatter-gather list entries
 * @access: [in] kernel access type (KCAPI_ACCESS_HEURISTIC - use internal
 *	heuristic for  fastest kernel access; KCAPI_ACCESS_VMSPLICE - use
 *	vmsplice access; KCAPI_ACCESS_SENDMSG - sendmsg access)
 *
 * The individual scatter-gather list entries are processed with
 * separate invocations of the the given cipher.
 *
 * The memory should be aligned at the page boundary using
 * posix_memalign(sysconf(_SC_PAGESIZE)), If it is not aligned at the page
 * boundary, the vmsplice call may not send all data to the kernel.
 *
 * @return number of bytes verify upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_kpp_ssgen_aio(struct kcapi_handle *handle,
			    struct iovec *iniov, struct iovec *outiov,
			    uint32_t iovlen, int access);

/**
 * DOC: Key Derivation Functions
 *
 * API function calls used to invoke a KDF.
 * The KDF functions are based on a message digest or keyed message digest
 * function. The caller must have the handle allocated with kcapi_md_init.
 * If the caller wishes to use a keyed message digest, the caller must invoke
 * kcapi_md_setkey before those functions.
 */

/**
 * kcapi_kdf_dpi() - Double Pipeline Mode Key Derivation Function
 *
 * @handle: [in] cipher handle allocated by caller. This cipher handle
 *	must be allocated with kcapi_md_init(). If the caller is interested in
 *	a KDF using a keyed message digest, the caller should also call
 *	kcapi_md_setkey() before invoking this function.
 * @src: [in] Input data that should be transformed into a key (see below).
 * @slen: [in] Length of the src input data.
 * @dst: [out] Buffer to store the generated key in,
 * @dlen: [in] Length of the dst buffer. This value defines the number of bytes
 *	generated by the KDF.
 *
 * This function is an implementation of the KDF in double pipeline iteration
 * mode according with counter to SP800-108 section 5.3.
 *
 * The caller must provide Label || 0x00 || Context in src. This src pointer
 * may also be NULL if the caller wishes not to provide anything.
 *
 * @return 0 upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_kdf_dpi(struct kcapi_handle *handle,
		      const uint8_t *src, uint32_t slen,
		      uint8_t *dst, uint32_t dlen);

/**
 * kcapi_kdf_fb() - Feedback Mode Key Derivation Function
 *
 * @handle: [in] cipher handle allocated by caller. This cipher handle
 *	must be allocated with kcapi_md_init(). If the caller is interested in
 *	a KDF using a keyed message digest, the caller should also call
 *	kcapi_md_setkey() before invoking this function.
 * @src: [in] Input data that should be transformed into a key (see below).
 * @slen: [in] Length of the src input data.
 * @dst: [out] Buffer to store the generated key in,
 * @dlen: [in] Length of the dst buffer. This value defines the number of bytes
 *	generated by the KDF.
 *
 * This function is an implementation of the KDF in feedback mode with a
 * non-NULL IV and with counter according to SP800-108 section 5.2. The IV is
 * supplied with src and must be equal to the digestsize of the used cipher.
 *
 * In addition, the caller must provide Label || 0x00 || Context in src. This
 * src pointer must not be NULL as the IV is required. The ultimate format of
 * the src pointer is IV || Label || 0x00 || Context where the length of the
 * IV is equal to the block size (i.e. the digest size of the underlying
 * hash) of the PRF.
 *
 * @return 0 upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_kdf_fb(struct kcapi_handle *handle,
		     const uint8_t *src, uint32_t slen,
		     uint8_t *dst, uint32_t dlen);

/**
 * kcapi_kdf_ctr() - Counter Mode Key Derivation Function
 *
 * @handle: [in] cipher handle allocated by caller. This cipher handle
 *	must be allocated with kcapi_md_init(). If the caller is interested in
 *	a KDF using a keyed message digest, the caller should also call
 *	kcapi_md_setkey() before invoking this function.
 * @src: [in] Input data that should be transformed into a key (see below).
 * @slen: [in] Length of the src input data.
 * @dst: [out] Buffer to store the generated key in,
 * @dlen: [in] Length of the dst buffer. This value defines the number of bytes
 *	generated by the KDF.
 *
 * This function is an implementation of the KDF in counter mode according to
 * SP800-108 section 5.1 as well as SP800-56A section 5.8.1 (Single-step KDF).
 *
 * SP800-108:
 * The caller must provide Label || 0x00 || Context in src. This src pointer
 * may also be NULL if the caller wishes not to provide anything.
 *
 * SP800-56A:
 * If a keyed MAC is used, the key shall NOT be the shared secret from the DH
 * operation, but an independently generated key. The src pointer is defined
 * as Z || other info where Z is the shared secret from DH and other info is an
 * arbitrary string (see SP800-56A section 5.8.1.2).
 *
 * @return 0 upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_kdf_ctr(struct kcapi_handle *handle,
		      const uint8_t *src, uint32_t slen,
		      uint8_t *dst, uint32_t dlen);

/**
 * kcapi_pbkdf() - Password-based Key Derivation Function
 *
 * @hashname: [in] kernel crypto API name of a keyed hash (e.g. hmac(sha1))
 * @pw: [in] Password a key shall be derived from
 * @pwlen: [in] Length of password string
 * @salt: [in] Salt as defined in SP800-132
 * @saltlen: [in] Length of salt buffer
 * @count: [in] Numbers of iterations to be performed for the PBKDF
 * @key: [out] Buffer to store the generated key in
 * @keylen: [in] Size of the key to be generated (i.e. length of the key buffer)
 *
 * This function is an implementation of the PBKDF as defined in SP800-132.
 *
 * @return 0 upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_pbkdf(const char *hashname,
		    const uint8_t *pw, uint32_t pwlen,
		    const uint8_t *salt, uint32_t saltlen,
		    uint32_t count,
		    uint8_t *key, uint32_t keylen);

/**
 * kcapi_pbkdf_iteration_count() - Calculate numbers of iterations for a PBKDF
 *
 * @hashname: [in] kernel crypto API name of a keyed hash (e.g. hmac(sha1))
 * @timeshresh: [in] Time duration in nanoseconds that the PBKDF operation
 *	shall at least require. If that value is 0, a default of (1<<27)
 *	nanoseconds is used.
 *
 * The function measures the time the PBKDF operation takes for different
 * round counts for the given keyed message digest type.
 *
 * The result should be taken as the iteration count for a PBKDF operation.
 *
 * If an error occurs with the PBKDF calculation, a value of 1<<18 is returned.
 *
 * @return number of iterations a PBKDF should take on this computer.
 */
uint32_t kcapi_pbkdf_iteration_count(const char *hashname, uint64_t timeshresh);

/**
 * kcapi_hkdf() - Extract-and-Expand HKDF (RFC5869)
 *
 * @hashname: [in] kernel crypto API name of a keyed hash (e.g. hmac(sha1))
 * @ikm: [in] Input Keying Material (IKM) -- must be provided
 * @ikmlen: [in] IKM buffer length -- must be non-zero
 * @salt: [in] salt buffer -- may be NULL
 * @saltlen: [in] salt buffer length -- may be zero
 * @info: [in] info buffer -- may be NULL
 * @infolen: [in] info buffer length -- may be zero
 * @dst: [out] Buffer to store the generated key in,
 * @dlen: [in] Length of the dst buffer. This value defines the number of bytes
 *	generated by the KDF.
 *
 * Perform the key-derivation function according to RFC5869. The input data
 * is defined in sections 2.2 und 2.3 of RFC5869.
 *
 * @return 0 upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_hkdf(const char *hashname,
		   const uint8_t *ikm, uint32_t ikmlen,
		   const uint8_t *salt, uint32_t saltlen,
		   const uint8_t *info, uint32_t infolen,
		   uint8_t *dst, uint32_t dlen);

#ifdef __cplusplus
}
#endif

#endif /* KCAPI_H */
