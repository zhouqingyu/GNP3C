#!/usr/bin/make
# Makefile for building Broadcom libfc parallel stack for SLES11SP1
# $id$
KVER=
ifeq ($(KVER),)
  KVER=$(shell uname -r)
endif

ifeq ($(FC2_INCLUDE),)
  # Obtain the current working directory.  $(PWD) doesn't work because this
  # makefile cannot override the $(PWD) definition of the parent makefile.
  BCMPWD = $(shell pwd)
  ifeq ($(shell test -e $(BCMPWD)/../include > /dev/null 2>&1 || echo notfound),)
    FC2_INCLUDE := $(BCMPWD)/../include
  else
      $(error bnx2/cnic package not found. $(BCMPWD))
  endif
  export FC2_INCLUDE
endif

PREFIX=

# Check distro/kernel compatibility
ifeq ($(INCDIR),)
    INCDIR:=$(CURDIR)/../../bnx2fc/driver
endif

include $(INCDIR)/version.mk
DISTRO_COMPATIBLE="no"

ifeq ($(DISTRO), "RHEL")
    ifeq ($(shell [ "$(MAJVER)" = "6" ] || echo notfound),)
        ifeq ($(shell [ "$(MINVER)" = "0" ] || [ "$(MINVER)" = "1" ] || echo notfound),)
            DISTRO_COMPATIBLE="no"
        endif
    endif
endif

ifeq ($(DISTRO), "SLES")
    ifeq ($(shell [ "$(MAJVER)" = "11" ] || echo notfound),)
        ifeq ($(shell [ "$(MINVER)" = "1" ] || echo notfound),)
          DISTRO_COMPATIBLE="yes"
        endif
    endif
endif

ifeq ($(DISTRO_COMPATIBLE)$(KERNEL_COMPATIBLE), "yes""yes")
    BCM_FCOE_BUILD=fcoe_build
    BCM_FCOE_CLEAN=fcoe_clean
    BCM_FCOE_INSTALL=fcoe_install
endif

default: build

ifneq ($(KERNELRELEASE),)
libfcoe2-objs :=  fcoe_ctlr.o fcoe_transport.o
obj-m += libfcoe2.o
EXTRA_CFLAGS += -ffast-math -mhard-float -I${FC2_INCLUDE} 
else
fcoe_build:
	make -C $(LINUX) SUBDIRS=$(shell pwd) modules INCDIR=$(INCDIR)
endif

fcoe_install: default
	mkdir -p $(PREFIX)/lib/modules/$(KVER)/updates
	install -m 444 libfcoe2.ko $(PREFIX)/lib/modules/$(KVER)/updates
	@if [ "$(PREFIX)" = "" ]; then /sbin/depmod -a $(KVER);\
	else echo " *** Run '/sbin/depmod -a' to update the module database.";\
	fi

.PHONEY: all clean install

fcoe_clean:
	rm -f *.o *.mod.[co] *.ko .*.cmd

build: $(BCM_FCOE_BUILD)
clean: $(BCM_FCOE_CLEAN)
install: build $(BCM_FCOE_INSTALL)

cscope:
	find . -name "*.[ch]" > cscope.files
	cscope -bp3

tags:
	ctags -R
