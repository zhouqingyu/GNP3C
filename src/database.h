#ifndef DATABASE_H

#define DATABASE_H

#include <mysql.h>

extern struct Configuration configuration;
extern struct project_prm project_params;
extern pthread_mutex_t database_mutex;
extern MYSQL *database_sock;
extern MYSQL database_hadle;

extern int sql_factory_add_new_tcp(struct TcpInformation *tcpinfo);
extern MYSQL *db_init(MYSQL *mysql);
extern void db_close(MYSQL *mysql);
extern void sql_factory_add_user_password_record(struct  UPInformation *upinfo,int hash_index);
extern void sql_factory_add_msn_record(char *my_account,char *contact_account,char *message,int hash_index,time_t t);
extern void sql_factory_add_cookies_record(struct  CookiesInformation *upinfo,int hash_index);
extern void sql_factory_add_telnet_record(struct TelnetInformation *info,int hash_index);

extern void print_email_detai(struct Email_info *email_info);

#endif
