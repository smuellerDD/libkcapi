#
# Makefile
#

subdirs = lib test speed-test

all: $(subdirs)

.PHONY: $(subdirs)
$(subdirs):
	$(MAKE) -C $@

test: lib

speed-test: lib

clean distclean:
	@for dir in $(subdirs); do		\
		$(MAKE) -C $$dir $@ || exit 1;	\
        done
