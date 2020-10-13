LIBKCAPI_0.12.0 {
	global:
	kcapi_cipher_init;
	kcapi_cipher_destroy;
	kcapi_cipher_setkey;
	kcapi_cipher_encrypt;
	kcapi_cipher_encrypt_aio;
	kcapi_cipher_decrypt;
	kcapi_cipher_decrypt_aio;
	kcapi_cipher_stream_init_enc;
	kcapi_cipher_stream_init_dec;
	kcapi_cipher_stream_update;
	kcapi_cipher_stream_op;
	kcapi_cipher_ivsize;
	kcapi_cipher_blocksize;
	kcapi_aead_init;
	kcapi_aead_destroy;
	kcapi_aead_setkey;
	kcapi_aead_settaglen;
	kcapi_aead_setassoclen;
	kcapi_aead_encrypt;
	kcapi_aead_encrypt_aio;
	kcapi_aead_getdata;
	kcapi_aead_decrypt;
	kcapi_aead_decrypt_aio;
	kcapi_aead_stream_init_enc;
	kcapi_aead_stream_init_dec;
	kcapi_aead_stream_update;
	kcapi_aead_stream_update_last;
	kcapi_aead_stream_op;
	kcapi_aead_ivsize;
	kcapi_aead_blocksize;
	kcapi_aead_authsize;
	kcapi_aead_outbuflen;
	kcapi_aead_ccm_nonce_to_iv;
	kcapi_md_init;
	kcapi_md_destroy;
	kcapi_md_setkey;
	kcapi_md_update;
	kcapi_md_final;
	kcapi_md_digest;
	kcapi_md_digestsize;
	kcapi_md_blocksize;
	kcapi_rng_init;
	kcapi_rng_destroy;
	kcapi_rng_seed;
	kcapi_rng_generate;
	kcapi_set_verbosity;
	kcapi_versionstring;
	kcapi_version;
	kcapi_pad_iv;
	kcapi_memset_secure;
	kcapi_akcipher_init;
	kcapi_akcipher_destroy;
	kcapi_akcipher_setkey;
	kcapi_akcipher_setpubkey;
	kcapi_akcipher_encrypt;
	kcapi_akcipher_decrypt;
	kcapi_akcipher_sign;
	kcapi_akcipher_verify;
	kcapi_akcipher_stream_init_enc;
	kcapi_akcipher_stream_init_dec;
	kcapi_akcipher_stream_init_sgn;
	kcapi_akcipher_stream_init_vfy;
	kcapi_akcipher_stream_update;
	kcapi_akcipher_stream_update_last;
	kcapi_akcipher_stream_op;
	kcapi_kdf_dpi;
	kcapi_kdf_fb;
	kcapi_kdf_ctr;
	kcapi_pbkdf;
	kcapi_pbkdf_iteration_count;
	local: *;
};

LIBKCAPI_0.13.0 {
	global:
	kcapi_aead_inbuflen_enc;
	kcapi_aead_inbuflen_dec;
	kcapi_aead_outbuflen_enc;
	kcapi_aead_outbuflen_dec;
	kcapi_aead_getdata_input;
	kcapi_aead_getdata_output;
} LIBKCAPI_0.12.0;

LIBKCAPI_0.14.0 {
	global:
	kcapi_akcipher_encrypt_aio;
	kcapi_akcipher_decrypt_aio;
	kcapi_akcipher_sign_aio;
	kcapi_akcipher_verify_aio;
	kcapi_hkdf;
	kcapi_rng_seedsize;
} LIBKCAPI_0.13.0;

LIBKCAPI_1.0.0 {
	global:
	kcapi_kpp_init;
	kcapi_kpp_destroy;
	kcapi_kpp_dh_setparam_pkcs3;
	kcapi_kpp_ecdh_setcurve;
	kcapi_kpp_setkey;
	kcapi_kpp_keygen;
	kcapi_kpp_ssgen;
	kcapi_kpp_keygen_aio;
	kcapi_kpp_ssgen_aio;
	kcapi_md_sha1;
	kcapi_md_sha224;
	kcapi_md_sha256;
	kcapi_md_sha384;
	kcapi_md_sha512;
	kcapi_md_hmac_sha1;
	kcapi_md_hmac_sha224;
	kcapi_md_hmac_sha256;
	kcapi_md_hmac_sha384;
	kcapi_md_hmac_sha512;
	kcapi_cipher_enc_aes_cbc;
	kcapi_cipher_dec_aes_cbc;
	kcapi_cipher_enc_aes_ctr;
	kcapi_cipher_dec_aes_ctr;
	kcapi_rng_get_bytes;
} LIBKCAPI_0.14.0;

LIBKCAPI_1.0.1 {
} LIBKCAPI_1.0.0;

LIBKCAPI_1.0.2 {
} LIBKCAPI_1.0.1;

LIBKCAPI_1.0.3 {
} LIBKCAPI_1.0.2;

LIBKCAPI_1.1.0 {
	kcapi_handle_reinit;
} LIBKCAPI_1.0.3;

LIBKCAPI_1.1.1 {
} LIBKCAPI_1.1.0;

LIBKCAPI_1.1.2 {
} LIBKCAPI_1.1.1;

LIBKCAPI_1.1.3 {
} LIBKCAPI_1.1.2;

LIBKCAPI_1.1.4 {
} LIBKCAPI_1.1.3;

LIBKCAPI_1.1.5 {
} LIBKCAPI_1.1.4;

LIBKCAPI_1.2.0 {
	kcapi_cipher_stream_update_last;
} LIBKCAPI_1.1.5;

LIBKCAPI_1.2.1 {
} LIBKCAPI_1.2.0;
