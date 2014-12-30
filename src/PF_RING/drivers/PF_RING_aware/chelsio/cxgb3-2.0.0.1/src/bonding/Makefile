# Makefile for Chelsio T3 bonding driver.
# Copyright (c) 2006-2008 Chelsio Communications, Inc.
SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

# Includes.
EXTRA_CFLAGS += $(FLAGS)
EXTRA_CFLAGS += -I$(srcdir)/include
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I.

CFILES  = bond_3ad.c bond_alb.c bond_main.c
CFILES += $(notdir $(wildcard $(drvdir)/bond_sysfs.c))
ifneq ($(shell $(grep) -c '^\#define[[:space:]]\+CONFIG_IPV6' $(AUTOCONF_H)),0)
  CFILES += $(notdir $(wildcard $(drvdir)/bond_ipv6.c))
endif
TARGET  = bonding.o
CLEAN_FILES := $(CFILES:.c=.o)
CLEAN_FILES += bond_sysfs.o

lib_path     := $(PREFIX)/lib/modules/$(utsrelease)
module_path   = updates/kernel/drivers/net/bonding
install_path := $(lib_path)/$(module_path)

ifeq ($(kseries),2.4)
  $(error offload driver is not supported on 2.4 series kernel)
  driver := $(TARGET)
  $(TARGET): $(filter-out $(TARGET),$(CFILES:.c=.o))
	$(LD) -r $^ -o $@
else
  driver := $(TARGET:.o=.ko)
endif

ifneq ($(modulesymfile),)
  override symverfile = symverfile="$(topdir)/$(modulesymfile) \
                                    -o $(drvdir)/$(modulesymfile)"
else
  override symverfile =
endif

obj-m := $(TARGET)
$(TARGET:.o=)-objs := $(CFILES:.c=.o)

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: default
default: build

.PHONY: build
build:
	@$(MAKE) $(symverfile) -C $(KOBJ) SUBDIRS=$(shell pwd) modules

.PHONY:
install:
	@install -D $(verbose) -m 644 $(driver) $(install_path)/$(driver)

.PHONY: uninstall
uninstall:
	@-if [ -n "$(verbose)" ]; then \
	    echo "Removing $(install_path)/$(driver)";\
	  fi;\
	  /bin/rm -f $(install_path)/$(driver) 2>/dev/null;

.PHONY: clean
clean:
	-/bin/rm -rf $(driver) $(TARGET) $(TARGET:.o=.mod.c) \
	             $(TARGET:.o=.mod.o) $(CLEAN_FILES) \
		     .*cmd .tmp_versions *.symvers
