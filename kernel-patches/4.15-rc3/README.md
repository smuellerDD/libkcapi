Kernel Patches
==============

The following kernel patches are provided in this directory:

* `asym` contains the patches to integrate algif_akcipher.c for making
the asymmetric ciphers available to user space. These patches are needed
for when using the --enable-lib-asym configure option and the
kcapi_akcipher_* API functions.

* `kpp` contains the patches for making the KPP kernel crypto API
available to user space. This API offers DH and ECDH. The patches are
required when using the --enable-lib-kpp configure option and the
kcapi_kpp_* API calls. The KPP currently will not allow setting the key
due to the sanity checks in crypto_dh_decode_key which verifies the values
pf p and g. As they are not set with the setkey call, these sanity checks
will flag the data as invalid. If you need afalg_kpp to work, please let me
know.

Note, the `kpp` patches go on top of the `asym` patches.
