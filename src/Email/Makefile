# __126.o __163.o  __hotmail.o __yahoo.o __sina.o __sohu.o __tom.o __21cn.o \
#  __139.o
CC		= gcc
CFLAGES		= -Wall -g
OBJS		= __qq.o email_analysis.o email_attachment_match.o
PCRELIB		= -lpcre
XMLLIB		= -L/usr/local/lib/ -lxml2
INCLUDE		= -I../
XMLINCLUDE	= -I/usr/local/include/libxml2/
MYSQLINCLUDE	= -I/usr/include/mysql
LIBS		= -L../
%.o:%.c
	$(CC)  $(CFLAGES) $(MYSQLINCLUDE) $(PCRELIB) $(XMLLIB) $(XMLINCLUDE) -c $<  $(INCLUDE) -o $@

all:libemail.a

libemail.a:$(OBJS)
	@rm -f $@
	ar -cr $@ $(OBJS)

clean:
	rm -f *~ *.o libemail.a

