# MARCH can be specified from the command line (or another Makefile) in order
# to change the default machine architecture of the build.
MARCH =

CFLAGS = -O2 -Wall

OBJS = cxgbtool.o
PROG = cxgbtool

DEFS = -DCONFIG_T3_REGS 
CFLAGS += ${DEFS} ${MARCH}
LDFLAGS += ${MARCH}

all: ${PROG}

${PROG}: ${OBJS}
cxgbtool.o: reg_defs.c reg_defs_t3.c reg_defs_t3b.c reg_defs_t3c.c

install: ${PROG}
	install -m 755 cxgbtool $(PREFIX)/sbin
	gzip -c cxgbtool.8 > cxgbtool.8.gz
	@if [ -d $(PREFIX)/usr/share/man ];\
		then install -m 444 cxgbtool.8.gz $(PREFIX)/usr/share/man/man8;\
	elif [ -d $(PREFIX)/usr/man ];\
		then install -m 444 cxgbtool.8.gz $(PREFIX)/usr/man/man8;\
	fi
	@/bin/rm -f cxgbtool.8.gz
 
clean:
	rm -f ${PROG} ${OBJS}
