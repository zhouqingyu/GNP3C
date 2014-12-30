# Makefile for Chelsio T3 cxgb3 driver.
# Copyright (c) 2006-2008 Chelsio Communications, Inc.
SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

# Includes.
EXTRA_CFLAGS += $(FLAGS)
EXTRA_CFLAGS += -I$(srcdir)/include
EXTRA_CFLAGS += -I$(KSRC)/drivers/net/bonding
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I.

CFILES  = ael1002.c cxgb3_main.c cxgb3_offload.c l2t.c mc5.c mv88e1xxx.c sge.c \
          t3_hw.c tn1010.c trace.c vsc8211.c xgmac.c vsc7323.c aq100x.c
ifeq ($(kseries),2.4)
  CFILES += linux_2_4_compat.c
  CFILES += linux_2_4_compat_workqueue.c
  CFLAGS += $(EXTRA_CFLAGS)
endif
TARGET  = cxgb3.o
CLEAN_FILES := $(wildcard *.c)
CLEAN_FILES := $(CLEAN_FILES:.c=.o)

lib_path     := $(PREFIX)/lib/modules/$(utsrelease)
module_path   = updates/kernel/drivers/net/cxgb3
install_path := $(lib_path)/$(module_path)

ifeq ($(kseries),2.4)
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

.PHONY: install
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
