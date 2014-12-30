#!/usr/bin/make

KVER=
ifeq ($(KVER),)
    KVER=$(shell uname -r)
endif

ifeq ($(PKG_SRC_BASE),)
    # Obtain the current working directory.  $(PWD) doesn't work because this
    # makefile cannot override the $(PWD) definition of the parent makefile.
    PKG_SRC_BASE = $(shell pwd | sed -e 's/://')
    export PKG_SRC_BASE
endif

ifeq ($(BNX2_DRIVER),)
    # Obtain the current working directory.  $(PWD) doesn't work because this
    # makefile cannot override the $(PWD) definition of the parent makefile.
    BNX2_DRIVER = $(shell ls * | grep bnx2- | sed -e 's/://')
    export BNX2_DRIVER
endif

ifeq ($(BNX2X_DRIVER),)
    # Obtain the current working directory.  $(PWD) doesn't work because this
    # makefile cannot override the $(PWD) definition of the parent makefile.
    BNX2X_DRIVER = $(shell ls * | grep bnx2x- | sed -e 's/://')
    BNX2X_VERSION = $(shell ls * | grep bnx2x- | sed -e 's/bnx2x-//' | sed -e 's/://')
    export BNX2X_DRIVER
endif

ifeq ($(BNX2I_DRIVER),)
    # Obtain the current working directory.  $(PWD) doesn't work because this
    # makefile cannot override the $(PWD) definition of the parent makefile.
    BNX2I_DRIVER = $(shell ls * | grep bnx2i- | sed -e 's/://')
    export BNX2I_DRIVER
endif

ifeq ($(BNX2FC_DRIVER),)
    # Obtain the current working directory.  $(PWD) doesn't work because this
    # makefile cannot override the $(PWD) definition of the parent makefile.
    BNX2FC_DRIVER = $(shell ls * | grep bnx2fc- | sed -e 's/://')
    BNX2FC_BNX2X_COMPAT = $(shell cat ${BNX2FC_DRIVER}/driver/COMPAT | sed -e 's/bnx2x-//' | sed -e 's/://')
    export BNX2FC_DRIVER
    export BNX2FC_BNX2X_COMPAT
endif

ifeq ($(FCLIB_MODS),)
    # Obtain the current working directory.  $(PWD) doesn't work because this
    # makefile cannot override the $(PWD) definition of the parent makefile.
    FCLIB_MODS = $(shell ls * | grep fclibs- | sed -e 's/://')
    export FCLIB_MODS
endif

PREFIX=

default: build


l2build:
	make -C bnx2/src  KVER=$(KVER) PREFIX=$(PREFIX)
	make -C bnx2x/src KVER=$(KVER) PREFIX=$(PREFIX)

l2install:
	make -C bnx2/src  KVER=$(KVER) PREFIX=$(PREFIX) install
	make -C bnx2x/src KVER=$(KVER) PREFIX=$(PREFIX) install

l2clean:
	make -C bnx2/src  clean
	make -C bnx2x/src clean

iscsibuild:
	[ -e bnx2/src/Module.symvers ] && cp -f bnx2/src/Module.symvers bnx2i/driver || /bin/true
	make -C bnx2i/driver KVER=$(KVER) PREFIX=$(PREFIX)

iscsiinstall:
	make -C bnx2i/driver KVER=$(KVER) PREFIX=$(PREFIX) install

iscsiclean:
	make -C bnx2i/driver clean

fclibsbuild:
	make -C fclibs/libfc KVER=$(KVER) PREFIX=$(PREFIX)
	[ -e fclibs/libfc/Module.symvers ] && cp -f fclibs/libfc/Module.symvers fclibs/fcoe || /bin/true
	make -C fclibs/fcoe KVER=$(KVER) PREFIX=$(PREFIX)
	
fclibsinstall:
	make -C fclibs/libfc KVER=$(KVER) PREFIX=$(PREFIX) install
	make -C fclibs/fcoe KVER=$(KVER) PREFIX=$(PREFIX) install

fclibsclean:
	make -C fclibs/libfc clean
	make -C fclibs/fcoe clean

fcoebuild: 
	[ -e bnx2/src/Module.symvers ] && cp -f bnx2/src/Module.symvers bnx2fc/driver || /bin/true
	[ -e fclibs/libfc/Module.symvers ] && cat fclibs/libfc/Module.symvers >> bnx2fc/driver/Module.symvers || /bin/true
	[ -e fclibs/fcoe/Module.symvers ] && cat fclibs/fcoe/Module.symvers >> bnx2fc/driver/Module.symvers || /bin/true
	make -C bnx2fc/driver KVER=$(KVER) PREFIX=$(PREFIX) pfc

fcoeinstall:
	make -C bnx2fc/driver KVER=$(KVER) PREFIX=$(PREFIX) install

fcoeclean:
	make -C bnx2fc/driver clean

build: l2build iscsibuild fclibsbuild fcoebuild

install: build l2install iscsiinstall fclibsinstall fcoeinstall

clean: l2clean iscsiclean fclibsclean fcoeclean

.PHONEY: all clean install
