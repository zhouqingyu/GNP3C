#
# (C) 2010 - Alfredo Cardigliano <cardigliano@ntop.org>
#

obj-m := vnplug.o

ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif

EXTRA_CFLAGS += -I$(PWD)

HERE=$(PWD)

all: Makefile vnplug.c
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) EXTRA_CFLAGS='$(EXTRA_CFLAGS)' modules

headers_install:
	cp linux/vnplug.h $(DESTDIR)/usr/include/linux

clean:
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) clean
	\rm -f *~ Module.symvers  Module.markers  modules.order *#

