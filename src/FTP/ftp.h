#ifndef _FTP_H
#define _FTP_H

#define OVECCOUNT 300
enum ftp_handle {FH_STOR, FH_RETR};
enum ftp_mode   {FM_PORT, FM_PASV};

typedef struct _ftp_msg
{
   enum ftp_mode mode;
   char user[128];
   char passwd[128];
   enum ftp_handle dh_list[256];
   char *dn_list[256];
   char *d_list[256];
   int dport_list[256];
   int dcount;
} ftp_msg_t;

extern struct FTP_FILE_LIST ftp_file_list;
extern pthread_mutex_t ftp_file_mutex;
#endif
