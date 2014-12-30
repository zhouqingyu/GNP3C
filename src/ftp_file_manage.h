#ifndef FTP_FILE_MANAGE_H

#define FTP_FILE_MANAGE_H
#include "list.h"
#include "job.h"
extern struct FTP_FILE_LIST ftp_file_list;
extern pthread_mutex_t ftp_file_mutex;

struct Ftp_file_manage_information{
    char *user;
    char *password;
    char *file_name;
    char *handle;
    char *data;
    int data_length;
    char *file_type;
};
extern char * safe_file_judge_type(char *data,int data_length);
#endif
