CC     =    gcc
CFLAGS =    -Wall -g -I../
LIBS   =    -lpcre
PTHREADLIB		= -lpthread
%.o:%.c
	@${CC} ${CFLAGS} $(PTHREADLIB) -c $< -o $@

OBJS	= ftp.o pcre_matall.o pcre_repl.o pcre_match.o \
	  pcre_multipatt.o

libftp.a:$(OBJS)
	rm -f ftp.a
	ar -cr $@ $(OBJS) 
	
clean:
	@rm -f *.o *~ libftp.a 
