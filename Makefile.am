ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = subdir-objects
lib_LTLIBRARIES = libkcapi.la

COMMON_CPPFLAGS = -Wextra -Wall -pedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -O2 -Werror -std=gnu99
COMMON_LDFLAGS =  -Wl,-z,relro,-z,now

libkcapi_la_SOURCES = lib/cryptouser.h \
		      lib/internal.h \
		      lib/kcapi.h \
		      lib/kcapi-kernel-if.c \
		      lib/kcapi-utils.c

if DISABLE_LIB_ASYM
libkcapi_la_SOURCES +=
else
libkcapi_la_SOURCES += lib/kcapi-asym.c
endif

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

libkcapi_la_CPPFLAGS = $(COMMON_CPPFLAGS) -fPIC -fvisibility=hidden
libkcapi_la_LDFLAGS = $(COMMON_LDFLAGS) -Wl,--version-script,lib/version.lds -release $(VERSION)

SCAN_FILES = $(libkcapi_la_SOURCES)

include_HEADERS = lib/kcapi.h

bin_PROGRAMS =

if ENABLE_KCAPI_TEST
bin_PROGRAMS += bin/kcapi

bin_kcapi_CPPFLAGS = $(COMMON_CPPFLAGS) -Wno-overlength-strings -pie -fPIE -g -Ilib/
bin_kcapi_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_LDADD = libkcapi.la
bin_kcapi_SOURCES = test/kcapi-main.c

SCAN_FILES += $(kcapi_SOURCES)
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

SCAN_FILES += $(kcapi_speed_SOURCES)
endif

if ENABLE_KCAPI_HASHER
bin_PROGRAMS += bin/kcapi-hasher

bin_kcapi_hasher_CPPFLAGS = $(COMMON_CPPFLAGS) -fPIC -Ilib/
bin_kcapi_hasher_LDFLAGS = $(COMMON_LDFLAGS)
bin_kcapi_hasher_LDADD = libkcapi.la
bin_kcapi_hasher_SOURCES = apps/kcapi-hasher.c

SCAN_FILES += $(kcapi_hasher_SOURCES)

kcapi_hasher_links = sha1sum sha224sum sha256sum sha384sum sha512sum \
	             md5sum fipscheck fipshmac \
		     sha1hmac sha224hmac sha256hmac sha384hmac sha512hmac

install-exec-hook:
	(cd $(DESTDIR)$(bindir) && \
	($(foreach link, $(kcapi_hasher_links), $(LN_S) -f kcapi_hasher $(link);)))
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

noinst_PROGRAMS = lib/doc/bin/docproc

lib_doc_bin_docproc_SOURCES = lib/doc/bin/docproc.c

if HAVE_MKTEMP
TEMPFILE := $(shell mktemp)

%.xml: %.tmpl lib/doc/bin/docproc
	cp $< $(TEMPFILE)
	$(SED) -i "s/@@LIBVERSION@@/$(VERSION)/" $(TEMPFILE)
	SRCTREE=lib/ ./lib/doc/bin/docproc doc $(TEMPFILE) > $@

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
	xmlto $@ -m lib/doc/stylesheet.xsl --skip-validation -o lib/doc/$@/ $<

install-man:
	$(INSTALL) -m 0644 lib/doc/man/* -D -t $(mandir)/man3/
endif
endif

clean-local:
	rm -f lib/doc/*.xml
	rm -f lib/doc/*.pdf
	rm -f lib/doc/*.ps
	rm -rf lib/doc/man/
	rm -rf lib/doc/html/
	rm -rf bin/
