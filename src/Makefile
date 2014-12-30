CC	= gcc
OBJS	= tcp_data_manage.o packet.o \
	job.o safe_time.o main.o \
	configuration.o database.o tcp_lost_manage.o \
	list.o  checksum.o ip_fragment.o ip_options.o  \
	libnids.o tcp.o util.o hash.o http_analysis.o  \
	msn_analysis.o cookies_analysis.o telnet_analysis.o \
	change_channel.o recover_environment.o \
	ftp_file_manage.o user_password_analysis.o  \
	pop3.o tools.o save_environment.o cJSON.o \
	mime.o web_analysis.o smtp.o imap.o
DEPENDING_LIBS		= ./Email/libemail.a ./FTP/libftp.a
SAFEFILELIB		= -L/user/local/lib/ -lmagic
SAFEFILEINC		= -I/usr/local/include
PTHREADLIB		= -lpthread
PCRELIB			= -lpcre
ZIPLIB			= -lz
MYSQLLIB		= -lmysqlclient
XMLLIBLOCAL		= -L/usr/local/lib/ -lxml2
PFRING_LIB		= ./PF_RING/userland/lib/libpfring.a -lpcap
PFRING_INCLUDE		= -I./PF_RING/userland/lib -I./PF_RING/kernel
MYSQLINCLUDE		= -I/usr/include/mysql
XMLINCLUDE		= -I/usr/local/include/libxml2
GTKLIB			= `pkg-config --cflags --libs gtk+-2.0 gthread-2.0`
CFLAGS			= -g -O2 -D_BSD_SOURCE -W -Wall -DLIBNET_VER=1 -DHAVE_ICMPHDR=1 -DHAVE_TCP_STATES=1 -DHAVE_BSD_UDPHDR=1
GNP3C: $(OBJS) $(DEPENDING_LIBS)
	$(CC) $(OBJS) $(PTHREADLIB) $(MYSQLLIB) $(ZIPLIB) $(PCRELIB) $(GTKLIB)   $(DEPENDING_LIBS) $(XMLLIBLOCAL) $(PFRING_LIB) $(SAFEFILELIB) $(GTKLIB) -o $@
main.o:main.c
	$(CC) -c main.c $(PTHREADLIB) $(MYSQLINCLUDE) $(GTKLIB) -o $@
packet.o:packet.c
	$(CC) -c packet.c $(PFRING_INCLUDE) -o $@
job.o:job.c
	$(CC) -c job.c $(PTHREADLIB) -o $@
safe_time.o:safe_time.c
	$(CC) -c safe_time.c $(PTHREADLIB) -o $@
configuration.o:configuration.c
	$(CC) -c configuration.c -o $@
database.o:database.c
	$(CC) -c database.c $(MYSQLINCLUDE) -o $@
tcp_lost_manage.o:tcp_lost_manage.c
	$(CC) -c tcp_lost_manage.c $(PTHREADLIB) -o $@
list.o:list.c
	$(CC) -c list.c -o $@
tcp_data_manage.o:tcp_data_manage.c
	$(CC) -c tcp_data_manage.c -o $@
http_analysis.o:http_analysis.c
	$(CC) -c http_analysis.c $(ZIPLIB) $(PCRELIB) -o $@
user_password_analysis.o:user_password_analysis.c
	$(CC) -c user_password_analysis.c $(PCRELIB) -o $@	
msn_analysis.o:msn_analysis.c
	$(CC) -c msn_analysis.c  $(PCRELIB) -o  $@
cookies_analysis.o:cookies_analysis.c
	$(CC) -c cookies_analysis.c -o $@
telnet_analysis.o:telnet_analysis.c
	$(CC) -c telnet_analysis.c -o $@
change_channel.o:change_channel.c
	$(CC) -c change_channel.c   -o $@
checksum.o: checksum.c
	$(CC) -fPIC $(CFLAGS) -I.  -c checksum.c -o $@
ip_fragment.o: ip_fragment.c
	$(CC) -fPIC $(CFLAGS) -I.  -c ip_fragment.c -o $@
ip_options.o: ip_options.c
	$(CC) -fPIC $(CFLAGS) -I.  -c ip_options.c -o $@
libnids.o: libnids.c
	$(CC) -fPIC $(CFLAGS) -I. $(MYSQLINCLUDE) $(GTKLIB) -c libnids.c -o $@
tcp.o: tcp.c
	$(CC) -fPIC $(CFLAGS) -I.  -c tcp.c -o $@
util.o: util.c
	$(CC) -fPIC $(CFLAGS) -I. -c util.c -o $@
hash.o: hash.c
	$(CC) -fPIC $(CFLAGS) -I. -c hash.c -o $@
ftp_file_manage.o:ftp_file_manage.c
	$(CC) -c ftp_file_manage.c $(SAFEFILEINC) -o $@
pop3.o:pop3.c
	$(CC) -c pop3.c -o $@
tools.o:tools.c
	$(CC) -c tools.c $(PCRELIB) $(XMLLIB) $(XMLINCLUDE) -o $@
save_environment.o:save_environment.c
	$(CC) -c save_environment.c -o $@
recover_environment.o:recover_environment.c
	$(CC) -c recover_environment.c -o $@
cJSON.o:cJSON.c
	$(CC) -c cJSON.c -o $@ -lm
mime.o:mime.c
	$(CC) -c mime.c -o $@
web_analysis.o:web_analysis.c 
	$(CC) -c web_analysis.c $(MYSQLINCLUDE) -o $@
smtp.o:smtp.c
	$(CC) -c smtp.c -o $@	
imap.o:imap.c
	$(CC) -c imap.c -o $@	
	
clean:
	rm -f *.o *~ GNP3C
