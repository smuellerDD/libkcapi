ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = subdir-objects
lib_LTLIBRARIES = libkcapi.la

COMMON_CPPFLAGS = -Wextra -Wall -pedantic -fwrapv --param ssp-buffer-size=4 -O2 -Werror -std=gnu99 -fstack-protector-strong
COMMON_LDFLAGS =  -Wl,-z,relro,-z,now

libkcapi_la_SOURCES = lib/cryptouser.h \
		      lib/internal.h \
		      lib/kcapi.h \
		      lib/kcapi-kernel-if.c \
		      lib/kcapi-utils.c

man_MANS =

if DISABLE_LIB_SYM
libkcapi_la_SOURCES +=
else
libkcapi_la_SOURCES += lib/kcapi-sym.c
endif

if DISABLE_LIB_MD
libkcapi_la_SOURCES +=
else
libkcapi_la_SOURCES += lib/kcapi-md.c
if DISABLE_LIB_KDF
libkcapi_la_SOURCES +=
else
libkcapi_la_SOURCES += lib/kcapi-kdf.c
endif
endif

if DISABLE_LIB_AEAD
libkcapi_la_SOURCES +=
else
libkcapi_la_SOURCES += lib/kcapi-aead.c
endif

if DISABLE_LIB_RNG
libkcapi_la_SOURCES +=
else
libkcapi_la_SOURCES += lib/kcapi-rng.c
endif

if ENABLE_LIB_ASYM
libkcapi_la_SOURCES += lib/kcapi-asym.c
else
libkcapi_la_SOURCES +=
endif

if ENABLE_LIB_KPP
libkcapi_la_SOURCES += lib/kcapi-kpp.c
else
libkcapi_la_SOURCES +=
endif

libkcapi_la_CPPFLAGS = $(COMMON_CPPFLAGS) -fPIC -fvisibility=hidden
libkcapi_la_LDFLAGS = $(COMMON_LDFLAGS) -Wl,--version-script,$(top_srcdir)/lib/version.lds -version-number `echo $(VERSION) | sed 's/\./:/g'`

SCAN_FILES = $(libkcapi_la_SOURCES)

include_HEADERS = lib/kcapi.h

bin_PROGRAMS =

if ENABLE_KCAPI_TEST
bin_PROGRAMS += bin/kcapi

bin_kcapi_CPPFLAGS = $(COMMON_CPPFLAGS) -Wno-overlength-strings -pie -fPIE -g -Ilib/
bin_kcapi_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_LDADD = libkcapi.la
bin_kcapi_SOURCES = test/kcapi-main.c

SCAN_FILES += $(bin_kcapi_SOURCES)

bin_PROGRAMS += bin/kcapi-enc-test-large

bin_kcapi_enc_test_large_CPPFLAGS = $(COMMON_CPPFLAGS) -Wno-overlength-strings -pie -fPIE -g -Ilib/
bin_kcapi_enc_test_large_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_enc_test_large_LDADD = libkcapi.la
bin_kcapi_enc_test_large_SOURCES = test/kcapi-enc-test-large.c

SCAN_FILES += $(bin_kcapi_enc_test_large_SOURCES)

bin_PROGRAMS += bin/kcapi-convenience

bin_kcapi_convenience_CPPFLAGS = $(COMMON_CPPFLAGS) -Wno-overlength-strings -pie -fPIE -g -Ilib/
bin_kcapi_convenience_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_convenience_LDADD = libkcapi.la
bin_kcapi_convenience_SOURCES = test/kcapi-convenience.c

SCAN_FILES += $(bin_kcapi_convenience_SOURCES)
endif

if ENABLE_KCAPI_SPEED
bin_PROGRAMS += bin/kcapi-speed

bin_kcapi_speed_CPPFLAGS = $(COMMON_CPPFLAGS) -pie -fPIE -Wno-variadic-macros -Ilib/
bin_kcapi_speed_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_speed_LDADD = libkcapi.la
bin_kcapi_speed_SOURCES = speed-test/cryptoperf.h \
                      speed-test/cryptoperf-aead.c \
		      speed-test/cryptoperf-base.c \
		      speed-test/cryptoperf-hash.c \
		      speed-test/cryptoperf-main.c \
		      speed-test/cryptoperf-rng.c \
		      speed-test/cryptoperf-skcipher.c

SCAN_FILES += $(bin_kcapi_speed_SOURCES)
endif

if ENABLE_KCAPI_HASHER
bin_PROGRAMS += bin/kcapi-hasher

bin_kcapi_hasher_CPPFLAGS = $(COMMON_CPPFLAGS) -fPIC -Ilib/
bin_kcapi_hasher_LDFLAGS = $(COMMON_LDFLAGS) -ldl
bin_kcapi_hasher_LDADD = libkcapi.la
bin_kcapi_hasher_SOURCES = apps/kcapi-hasher.c apps/app-internal.c

SCAN_FILES += $(bin_kcapi_hasher_SOURCES)

kcapi_hasher_links = sha1sum sha224sum sha256sum sha384sum sha512sum \
	             md5sum fipscheck fipshmac \
		     sha1hmac sha224hmac sha256hmac sha384hmac sha512hmac

install-exec-hook:
	(cd $(DESTDIR)$(bindir) && \
	($(foreach link, $(kcapi_hasher_links), ln -f kcapi-hasher $(link);)) && \
	($(foreach link, $(kcapi_hasher_links), openssl sha256 -hmac orboDeJITITejsirpADONivirpUkvarP $(link) > .$(link).hmac;)))
endif

if ENABLE_KCAPI_RNGAPP
bin_PROGRAMS += bin/kcapi-rng

bin_kcapi_rng_CPPFLAGS = $(COMMON_CPPFLAGS) -pie -fPIE -Ilib/
bin_kcapi_rng_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_rng_LDADD = libkcapi.la
bin_kcapi_rng_SOURCES = apps/kcapi-rng.c apps/app-internal.c

SCAN_FILES += $(bin_kcapi_rng_SOURCES)
man_MANS += apps/kcapi-rng.1
endif

if ENABLE_KCAPI_ENCAPP
bin_PROGRAMS += bin/kcapi-enc

bin_kcapi_enc_CPPFLAGS = $(COMMON_CPPFLAGS) -pie -fPIE -Ilib/
bin_kcapi_enc_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_enc_LDADD = libkcapi.la
bin_kcapi_enc_SOURCES = apps/kcapi-enc.c apps/app-internal.c

SCAN_FILES += $(bin_kcapi_enc_SOURCES)
man_MANS += apps/kcapi-enc.1
endif

if ENABLE_KCAPI_DGSTAPP
bin_PROGRAMS += bin/kcapi-dgst

bin_kcapi_dgst_CPPFLAGS = $(COMMON_CPPFLAGS) -pie -fPIE -Ilib/
bin_kcapi_dgst_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_dgst_LDADD = libkcapi.la
bin_kcapi_dgst_SOURCES = apps/kcapi-dgst.c apps/app-internal.c

SCAN_FILES += $(bin_kcapi_dgst_SOURCES)
man_MANS += apps/kcapi-dgst.1
endif

if HAVE_CLANG
analyze_srcs = $(filter %.c, $(SCAN_FILES))
analyze_plists = $(analyze_srcs:%.c=%.plist)

MOSTLYCLEANFILES = $(analyze_plists)

$(analyze_plists): %.plist: %.c
	@echo "  CCSA  " $@
	@clang --analyze $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) -Ilib/	$< -o $@

scan: $(analyze_plists)

.PHONY: scan
endif

if HAVE_CPPCHECK
cppcheck:
	cppcheck --enable=performance,warning,portability $(SCAN_FILES)
endif

if HAVE_MKTEMP
TEMPFILE := $(shell mktemp)

lib/doc/bin/docproc:
	$(MAKE) -C lib/doc

%.xml: %.tmpl lib/doc/bin/docproc
	cp $< $(TEMPFILE)
	$(SED) -i "s/@@LIBVERSION@@/$(VERSION)/" $(TEMPFILE)
	LIBVERSION=$(VERSION) SRCTREE=lib/ ./lib/doc/bin/docproc doc $(TEMPFILE) > $@
	rm $(TEMPFILE)

if HAVE_DB2PDF
pdf: lib/doc/libkcapi.xml
	db2$@ -o doc/ $<
endif

if HAVE_DB2PS
ps: lib/doc/libkcapi.xml
	db2$@ -o doc/ $<
endif

if HAVE_XMLTO
man html: lib/doc/libkcapi.xml
	$(MKDIR_P) lib/doc/$@
	xmlto $@ -m lib/doc/stylesheet.xsl --skip-validation -o lib/doc/$@/ $< 2>/dev/null

devel_manpages = lib/doc/man/*.3
man_MANS += $(devel_manpages)

$(devel_manpages): man
endif
endif

clean-local:
	rm -f lib/doc/*.xml
	rm -f lib/doc/*.pdf
	rm -f lib/doc/*.ps
	rm -rf lib/doc/man/
	rm -rf lib/doc/html/
	rm -rf doc/
	rm -rf bin/

SUBDIRS = lib/doc

