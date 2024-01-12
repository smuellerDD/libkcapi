ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = subdir-objects
lib_LTLIBRARIES = libkcapi.la

COMMON_CPPFLAGS = -Wextra -Wall -pedantic -fwrapv --param ssp-buffer-size=4 -O2 -std=gnu99 -Wconversion
if ENABLE_WERROR
COMMON_CPPFLAGS += -Werror
endif
COMMON_LDFLAGS =  -Wl,-z,relro,-z,now

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

noinst_PROGRAMS = lib/doc/bin/docproc

EXTRA_lib_doc_bin_docproc_DEPENDENCIES = libtool

EXTRA_libkcapi_la_DEPENDENCIES = libtool

libkcapi_la_SOURCES = lib/cryptouser.h \
		      lib/internal.h \
		      lib/kcapi.h \
		      lib/kcapi-kernel-if.c \
		      lib/kcapi-utils.c

man_MANS =

DOC_TARGETS =

pkgconfigdir   = @pkgconfigdir@
pkgconfig_DATA = libkcapi.pc

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

libkcapi_la_CPPFLAGS = $(COMMON_CPPFLAGS)
libkcapi_la_LDFLAGS = $(COMMON_LDFLAGS) -Wl,--version-script,$(top_srcdir)/lib/version.lds -version-number `echo $(VERSION) | sed 's/\./:/g'`

SCAN_FILES = $(libkcapi_la_SOURCES)

include_HEADERS = lib/kcapi.h

bin_PROGRAMS =

if ENABLE_KCAPI_TEST
bin_PROGRAMS += bin/kcapi

bin_kcapi_CPPFLAGS = $(COMMON_CPPFLAGS) -Wno-overlength-strings -g -I$(top_srcdir)/lib/
bin_kcapi_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_LDADD = libkcapi.la
bin_kcapi_SOURCES = test/kcapi-main.c
EXTRA_bin_kcapi_DEPENDENCIES = libtool

SCAN_FILES += $(bin_kcapi_SOURCES)

bin_PROGRAMS += bin/kcapi-enc-test-large

bin_kcapi_enc_test_large_CPPFLAGS = $(COMMON_CPPFLAGS) -Wno-overlength-strings -g -I$(top_srcdir)/lib/
bin_kcapi_enc_test_large_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_enc_test_large_LDADD = libkcapi.la
bin_kcapi_enc_test_large_SOURCES = test/kcapi-enc-test-large.c
EXTRA_bin_kcapi_enc_test_large_DEPENDENCIES = libtool

SCAN_FILES += $(bin_kcapi_enc_test_large_SOURCES)

bin_PROGRAMS += bin/kcapi-convenience

bin_kcapi_convenience_CPPFLAGS = $(COMMON_CPPFLAGS) -Wno-overlength-strings -g -I$(top_srcdir)/lib/
bin_kcapi_convenience_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_convenience_LDADD = libkcapi.la
bin_kcapi_convenience_SOURCES = test/kcapi-convenience.c
EXTRA_bin_kcapi_convenience_DEPENDENCIES = libtool

SCAN_FILES += $(bin_kcapi_convenience_SOURCES)

pkglibexec_PROGRAMS = bin/kcapi bin/kcapi-enc-test-large bin/kcapi-convenience

pkglibexec_SCRIPTS = test/libtest.sh \
                     test/test.sh \
                     test/kcapi-enc-test.sh \
                     test/kcapi-enc-test-large.sh \
                     test/kcapi-dgst-test.sh \
                     test/kcapi-convenience.sh \
                     test/kcapi-fuzz-test.sh \
                     test/hasher-test.sh \
                     test/compile-test.sh \
                     test/virttest.sh \
                     test/test-invocation.sh
endif

if ENABLE_KCAPI_SPEED
bin_PROGRAMS += bin/kcapi-speed

bin_kcapi_speed_CPPFLAGS = $(COMMON_CPPFLAGS) -Wno-variadic-macros -I$(top_srcdir)/lib/
bin_kcapi_speed_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_speed_LDADD = libkcapi.la
bin_kcapi_speed_SOURCES = speed-test/cryptoperf.h \
                      speed-test/cryptoperf-aead.c \
		      speed-test/cryptoperf-base.c \
		      speed-test/cryptoperf-hash.c \
		      speed-test/cryptoperf-main.c \
		      speed-test/cryptoperf-rng.c \
		      speed-test/cryptoperf-skcipher.c
EXTRA_bin_kcapi_speed_DEPENDENCIES = libtool

SCAN_FILES += $(bin_kcapi_speed_SOURCES)
endif

if ENABLE_KCAPI_HASHER
bin_PROGRAMS += bin/kcapi-hasher

bin_kcapi_hasher_CPPFLAGS = $(COMMON_CPPFLAGS) -I$(top_srcdir)/lib/
bin_kcapi_hasher_LDFLAGS = $(COMMON_LDFLAGS) -ldl
bin_kcapi_hasher_LDADD = libkcapi.la
bin_kcapi_hasher_SOURCES = apps/kcapi-hasher.c apps/app-internal.c
EXTRA_bin_kcapi_hasher_DEPENDENCIES = libtool

SCAN_FILES += $(bin_kcapi_hasher_SOURCES)
man_MANS += apps/kcapi-hasher.1

hasher_links = sha1sum sha224sum sha256sum sha384sum sha512sum md5sum	\
	sm3sum fipscheck fipshmac sha3sum sha1hmac sha224hmac		\
	sha256hmac sha384hmac sha512hmac sm3hmac

CHECKSUM_CMD = $(OPENSSL) sha512 -r -hmac FIPS-FTW-RHT2009

CHECK_DIR_LIB = $(if $(CHECK_DIR),$(CHECK_DIR)/hmaccalc,$(libdir))
CHECK_DIR_BIN = $(if $(CHECK_DIR),$(CHECK_DIR)/hmaccalc,$(bindir))

install-exec-hook:
	$(MKDIR_P) -p $(DESTDIR)/$(pkglibexecdir)
	$(foreach link, $(hasher_links), $(LN) -sf $(DESTDIR)/$(bindir)/kcapi-hasher $(DESTDIR)/$(pkglibexecdir)/$(link);)
if HAVE_OPENSSL
	$(MKDIR_P) $(DESTDIR)$(CHECK_DIR_BIN)
	cd $(DESTDIR)$(bindir) && $(CHECKSUM_CMD) kcapi-hasher > $(DESTDIR)$(CHECK_DIR_BIN)/$(CHECK_PREFIX)kcapi-hasher.$(CHECK_SUFFIX)
	$(foreach lib, $(wildcard $(DESTDIR)$(libdir)/libkcapi.so*), \
		$(CHECKSUM_CMD) $(lib)  > $(DESTDIR)$(CHECK_DIR_LIB)/$(CHECK_PREFIX)$(notdir $(lib)).$(CHECK_SUFFIX);)
endif
endif

if ENABLE_KCAPI_RNGAPP
bin_PROGRAMS += bin/kcapi-rng

bin_kcapi_rng_CPPFLAGS = $(COMMON_CPPFLAGS) -I$(top_srcdir)/lib/
bin_kcapi_rng_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_rng_LDADD = libkcapi.la
bin_kcapi_rng_SOURCES = apps/kcapi-rng.c apps/app-internal.c
EXTRA_bin_kcapi_rng_DEPENDENCIES = libtool

SCAN_FILES += $(bin_kcapi_rng_SOURCES)
man_MANS += apps/kcapi-rng.1
endif

if ENABLE_KCAPI_ENCAPP
bin_PROGRAMS += bin/kcapi-enc

bin_kcapi_enc_CPPFLAGS = $(COMMON_CPPFLAGS) -I$(top_srcdir)/lib/
bin_kcapi_enc_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_enc_LDADD = libkcapi.la
bin_kcapi_enc_SOURCES = apps/kcapi-enc.c apps/app-internal.c
EXTRA_bin_kcapi_enc_DEPENDENCIES = libtool

SCAN_FILES += $(bin_kcapi_enc_SOURCES)
man_MANS += apps/kcapi-enc.1
endif

if ENABLE_KCAPI_DGSTAPP
bin_PROGRAMS += bin/kcapi-dgst

bin_kcapi_dgst_CPPFLAGS = $(COMMON_CPPFLAGS) -I$(top_srcdir)/lib/
bin_kcapi_dgst_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_dgst_LDADD = libkcapi.la
bin_kcapi_dgst_SOURCES = apps/kcapi-dgst.c apps/app-internal.c
EXTRA_bin_kcapi_dgst_DEPENDENCIES = libtool

SCAN_FILES += $(bin_kcapi_dgst_SOURCES)
man_MANS += apps/kcapi-dgst.1
endif

if HAVE_CLANG
analyze_srcs = $(filter %.c, $(sort $(SCAN_FILES)))
analyze_plists = $(analyze_srcs:%.c=%.plist)

MOSTLYCLEANFILES = $(analyze_plists)

$(analyze_plists): %.plist: %.c
	@echo "  CCSA  " $@
	@$(CLANG) --analyze $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) -I$(top_srcdir)/lib/	$< -o $@

scan: $(analyze_plists)

.PHONY: scan
endif

if HAVE_CPPCHECK
cppcheck:
	$(CPPCHECK) -U CHECK_DIR --error-exitcode=42 --enable=performance,warning,portability $(sort $(SCAN_FILES))
endif

if HAVE_MKTEMP
DOCPROC_TEMP := $(shell $(MKTEMP))
else
DOCPROC_TEMP := $(abs_top_builddir)/docproc.temp
endif

$(lib_doc_bin_docproc_OBJECTS) : CC = $(CC_FOR_BUILD)
$(lib_doc_bin_docproc_OBJECTS) : CFLAGS = $(CFLAGS_FOR_BUILD)
$(lib_doc_bin_docproc_OBJECTS) : CPPFLAGS = $(COMMON_CPPFLAGS) $(CPPFLAGS_FOR_BUILD)

lib/doc/bin/docproc${EXEEXT}: $(lib_doc_bin_docproc_OBJECTS)
	$(CC_FOR_BUILD) $(COMMON_CPPFLAGS) $(CPPFLAGS_FOR_BUILD) $(CFLAGS_FOR_BUILD) -o $@ $<

%.xml: %.tmpl lib/doc/bin/docproc$(EXEEXT)
	$(SED) "s/@@LIBVERSION@@/$(VERSION)/" < $< > $(DOCPROC_TEMP)
	LIBVERSION=$(VERSION) SRCTREE=$(top_srcdir)/lib/ $(abs_top_builddir)/lib/doc/bin/docproc$(EXEEXT) doc $(DOCPROC_TEMP) > $@
	-rm $(DOCPROC_TEMP)

if HAVE_DB2PDF
DOC_TARGETS += pdf

pdf: pdf-stamp
pdf-stamp: lib/doc/libkcapi.xml
	$(MKDIR_P) doc/pdf
	HOME=$(abs_top_builddir)/doc/pdf $(DB2PDF) -o doc/pdf $<
	$(MV) doc/pdf/*.pdf doc
	-rm -r doc/pdf
	$(TOUCH) $@
endif

if HAVE_DB2PS
DOC_TARGETS += ps

ps: ps-stamp
ps-stamp: lib/doc/libkcapi.xml
	$(MKDIR_P) doc/ps
	HOME=$(abs_top_builddir)/doc/ps $(DB2PS) -o doc/ps $<
	$(MV) doc/ps/*.ps doc
	-rm -r doc/ps
	$(TOUCH) $@
endif

if HAVE_XMLTO
DOC_TARGETS += html

html: html-stamp
html-stamp: lib/doc/libkcapi.xml
	$(MKDIR_P) lib/doc/html
	$(XMLTO) html -m $(top_srcdir)/lib/doc/stylesheet.xsl --skip-validation -o lib/doc/html/ $< 2>/dev/null
	$(TOUCH) $@

DOC_TARGETS += man

man: man-stamp
man-stamp: lib/doc/libkcapi.xml
	$(MKDIR_P) lib/doc/man
	$(XMLTO) man -m $(top_srcdir)/lib/doc/stylesheet.xsl --skip-validation -o lib/doc/man/ $< 2>/dev/null
	$(TOUCH) $@

devel_manpages = lib/doc/man/*.3
man_MANS += $(devel_manpages)

$(devel_manpages): man
endif

doc: $(sort $(DOC_TARGETS))

clean-local:
	-rm -f $(DOCPROC_TEMP)
	-rm -f *-stamp
	-rm -f lib/doc/*.xml
	-rm -f lib/doc/*.pdf
	-rm -f lib/doc/*.ps
	-rm -rf lib/doc/man/
	-rm -rf lib/doc/html/
	-rm -rf doc/
	-rm -rf bin/

distclean-local:
	-rm -f lib/doc/Makefile*
	-rm -rf autom4te.cache/
