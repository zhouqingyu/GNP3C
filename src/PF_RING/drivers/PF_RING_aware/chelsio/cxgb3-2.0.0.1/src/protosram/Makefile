# Makefile for Chelsio T3 protocol sram.
# Copyright (c) 2006-2008 Chelsio Communications, Inc.
SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

override suff = .bin
override default_fwdir = /lib/firmware

# Find a directory for the image to be installed.
ifeq ($(KERNELRELEASE),$(utsrelease))
  # If the target is this machine, find the firmware location.
  fwdir := $(strip $(shell sed '/^FIRMWARE_DIR\s*=/!d;s/FIRMWARE_DIR\s*=//' \
                           2>/dev/null < /etc/hotplug/firmware.agent))
  fwdir += /lib/firmware /lib/firmware/$(utsrelease) /usr/lib/hotplug/firmware
  fwdir := $(firstword $(wildcard $(fwdir)))
  ifeq ($(fwdir),)
    fwdir := $(default_fwdir)
  endif
else
  # Otherwise, just use default, there's no way of knowing.
  fwdir := $(default_fwdir)
endif

# The driver is looking for the FW under $FIRMWARE_DIR/cxgb3.
# fixup firmware directory.
fixup_fwdir := $(fwdir)/cxgb3

# Get the latest image in the package.
fwfile := $(firstword $(shell /bin/ls *$(suff) |\
                              sed 's/.*\([0-9]\.[0-9]\.[0-9]\).*/\1/' |\
			      sort -nr))
ifneq ($(fwfile),)
  fwfile := $(wildcard *$(fwfile)$(suff))
endif

.PHONY: default
default: install

.PHONY: install
install:
	@if [ -z "$(fwfile)" ]; then \
	   echo "*** ERROR: No sram image to install." >&2;\
	   exit 0;\
	 fi;\
	 if [ -z "$(fwdir)" ]; then \
	   echo "*** ERROR: No directory to install sram image." >&2;\
	   exit 0;\
	 fi;\
	 for file in $(fwfile); do \
	   install -D $(verbose) -m 644 $$file $(fixup_fwdir)/$$file;\
	 done;

.PHONY: uninstall
uninstall:
	@-for file in $(fwfile); do \
	    if [ -n "$(verbose)" ]; then \
	      echo "Removing $(fixup_fwdir)/$$file";\
	    fi;\
	    /bin/rm -f $(fixup_fwdir)/$$file 2>/dev/null;\
	  done;
