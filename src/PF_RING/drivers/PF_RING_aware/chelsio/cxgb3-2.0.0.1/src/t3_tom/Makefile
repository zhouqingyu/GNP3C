# Makefile for Chelsio T3 t3_tom driver.
# Copyright (c) 2006-2008 Chelsio Communications, Inc.
SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

# Includes.
EXTRA_CFLAGS += $(FLAGS)
EXTRA_CFLAGS += -I$(srcdir)/include
EXTRA_CFLAGS += -I$(srcdir)/cxgb3
EXTRA_CFLAGS += -I$(srcdir)/t3_tom
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I.

CFILES  = cpl_io.c cpl_sock.c listen.c module_support.c t3_ddp.c tom.c \
          tom_sysctl.c
ifneq ($(disable_bonding),1)
  CFILES += failover.c
endif
TARGET  = t3_tom.o
CLEAN_FILES := $(wildcard *.c)
CLEAN_FILES := $(CLEAN_FILES:.c=.o)

lib_path     := $(PREFIX)/lib/modules/$(utsrelease)
module_path   = updates/kernel/drivers/net/offload/t3_tom
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
default: symlink build

.PHONY: symlink
symlink:
	@[ -L module_support.c ] && /bin/rm -f module_support.c; true
	@function error() { echo "*** ERROR: Compiling $(TARGET:.o=)" >&2;\
	                    [ -n "$$1" ] && echo "*** ERROR: $$1" >&2;\
			    exit 1; };\
	 file=`for ver in $(kversions); do\
	         grep -l "\\$$SUPPORTED KERNEL $$ver\\$$\$$" module_support/*.c\
		 2>/dev/null && break;\
	       done`;\
	 if [ -z "$$file" ]; then\
	   error "Kernel version not supported.";\
	 fi;\
	 if ! ln -sf $$file module_support.c; then\
	   error "Failed to create symlink.";\
	 fi;

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
