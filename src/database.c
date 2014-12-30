#include <syslog.h>
#include <mysql.h>
#include <stdio.h>
#include <pthread.h>
#include <syslog.h>
#include<sys/timeb.h>
#include <time.h>
#include <string.h>

#include "project.h"
#include "configuration.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "user_password_analysis.h"
#include "cookies_analysis.h"
#include "telnet_analysis.h"
#include "database.h"
#include "ftp_file_manage.h"

static int getId(char *id);
static void add_user_password_record(struct  UPInformation *upinfo,int hash_index);
static int add_new_tcp(struct TcpInformation *tcpinfo);
static void add_msn_record(char *my_account,char *contact_account,char *message,int hash_index,time_t time);
static void add_cookies_record(struct  CookiesInformation *upinfo,int hash_index);
static void add_telnet_record(struct TelnetInformation *info,int hash_index);
static void add_mail_record(struct Email_info *mail,int hash_index, char *id);
static void add_web_record(struct WebInformation *web,int hash_index );
static void add_ftp_record(struct Ftp_file_manage_information *ftp_file_manange_informationint,int hash_index);
static void add_mail_attachment_record(struct Email_info *mail,int hash_index, char *id);
static void add_mail_content_record(struct Email_info *mail,int hash_index, char *id);

static int add_new_tcp(struct TcpInformation *tcpinfo){
     
     char qbuf[] = "insert into tcp(desmac,srcmac,desip,srcip,desport,srcport,essid)values(?,?,?,?,?,?,?)";
     MYSQL_STMT *stmt;
     MYSQL_BIND bind[7];
     int len_des_mac = strlen(tcpinfo->des_mac);
     int len_src_mac = strlen(tcpinfo->src_mac);
     int len_des_ip = strlen(tcpinfo->des_ip);
     int len_src_ip = strlen(tcpinfo->src_ip);
     int len_essid = strlen(tcpinfo->essid);
   
     int dest = tcpinfo->ip_and_port.dest;
     int source = tcpinfo->ip_and_port.source;

     stmt = mysql_stmt_init(database_sock);
     if(stmt == NULL){
         syslog(project_params.syslog_level,"init stmt failur for %s\n",qbuf);
         return;
     }
     mysql_stmt_prepare(stmt,qbuf,strlen(qbuf));
     
     memset(bind,0,sizeof(bind));

     bind[0].buffer_type = FIELD_TYPE_STRING;
     bind[0].buffer= tcpinfo->des_mac;
     bind[0].buffer_length=2000;
     bind[0].length = &len_des_mac;

     bind[1].buffer_type = FIELD_TYPE_STRING; 
     bind[1].buffer= tcpinfo->src_mac;
     bind[1].buffer_length=2000;
     bind[1].length = &len_src_mac;

     bind[2].buffer_type = FIELD_TYPE_STRING;
     bind[2].buffer= tcpinfo->des_ip;
     bind[2].buffer_length=2000;
     bind[2].length = &len_des_ip;

     bind[3].buffer_type = FIELD_TYPE_STRING;
     bind[3].buffer= tcpinfo->src_ip;
     bind[3].buffer_length=2000;
     bind[3].length = &len_src_ip;

     bind[4].buffer_type= FIELD_TYPE_LONG;
     bind[4].buffer=(char *)&(dest);
     bind[4].length = 0;

     bind[5].buffer_type= FIELD_TYPE_LONG;
     bind[5].buffer=(char *)&(source);
     bind[5].length = 0;

     bind[6].buffer_type = FIELD_TYPE_STRING;
     bind[6].buffer= tcpinfo->essid;
     bind[6].buffer_length=2000;
     bind[6].length = &len_essid;

     if(mysql_stmt_bind_param(stmt,bind)){
           syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
          syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
    mysql_stmt_close(stmt);

    int tcpid = mysql_insert_id(&database_hadle);
    return tcpid;
}


extern MYSQL *db_init(MYSQL *mysql){
     mysql_library_init(0,NULL,NULL);
     mysql_init(mysql);
     MYSQL *  mysql_sock = mysql_real_connect (mysql,configuration.database_ip, \
                     configuration.database_account,configuration.database_password,\
                     configuration.database_name,0,NULL,0);
     if(!mysql_sock){
          syslog(project_params.syslog_level,"Could not connect \n%s\n",mysql_error(mysql));
          return NULL;
       }
     return mysql_sock;
}

extern void db_close(MYSQL *mysql){
     mysql_close(mysql);
     mysql_library_end();
}

extern int sql_factory_add_new_tcp(struct TcpInformation *tcpinfo){
     int tcpid;     
     pthread_mutex_lock(&database_mutex);
     tcpid = add_new_tcp(tcpinfo);
     pthread_mutex_unlock(&database_mutex);
     return tcpid;
}

extern void sql_factory_add_user_password_record(struct  UPInformation *upinfo,int hash_index){   
     pthread_mutex_lock(&database_mutex);
     add_user_password_record(upinfo,hash_index);
     pthread_mutex_unlock(&database_mutex);
}

extern void sql_factory_add_msn_record(char *my_account,char *contact_account,char *message,int hash_index,time_t t){
     pthread_mutex_lock(&database_mutex);
     add_msn_record(my_account,contact_account,message,hash_index,t);
     pthread_mutex_unlock(&database_mutex);
}

extern void sql_factory_add_cookies_record(struct  CookiesInformation *upinfo,int hash_index){
     pthread_mutex_lock(&database_mutex);
     add_cookies_record(upinfo,hash_index);
     pthread_mutex_unlock(&database_mutex);
}

extern void sql_factory_add_telnet_record(struct TelnetInformation *info,int hash_index){
     pthread_mutex_lock(&database_mutex);
     add_telnet_record(info,hash_index);
     pthread_mutex_unlock(&database_mutex);
}

extern void sql_factory_add_email_record(struct Email_info *mail,int hash_index, char *id){
     pthread_mutex_lock(&database_mutex);
     add_mail_record(mail,hash_index, id);
     pthread_mutex_unlock(&database_mutex);
}

extern void sql_factory_add_web_record(struct WebInformation *web,int hash_index ){
     pthread_mutex_lock(&database_mutex);
     add_web_record(web,hash_index);
     pthread_mutex_unlock(&database_mutex);
}

extern void sql_factory_add_ftp_record(struct Ftp_file_manage_information *ftp ,int hash_index ){
     pthread_mutex_lock(&database_mutex);
     add_ftp_record(ftp,hash_index);
     pthread_mutex_unlock(&database_mutex);
}

static void add_ftp_record(struct Ftp_file_manage_information *ftp,int hash_index ){
      MYSQL_RES *res;
      MYSQL_FIELD *fd;
      MYSQL_ROW row;
      MYSQL_STMT *stmt;
      MYSQL_BIND bind[8];
      char qbuf[8000];
      
      char id[30];
      getId(id);
 
      int tcpid = hash_index;
      int type = APPLICATION_TYPE_FTP;

      char insertsqlbuffer[] = "insert into ftp(id,tcpid,filetype,file,filename,handle,ftpuser,ftppassword)values(?,?,?,?,?,?,?,?)";                                
      memset(qbuf,0,sizeof(qbuf));
      memcpy(qbuf,insertsqlbuffer,sizeof(insertsqlbuffer));
      stmt = mysql_stmt_init(database_sock);
      if(stmt == NULL){
          syslog(project_params.syslog_level,"stmt is null\n");
      }
      
      mysql_stmt_prepare(stmt,insertsqlbuffer,strlen(insertsqlbuffer));
      int len1 = strlen(id);
      int len3 = strlen(ftp->file_type);
      int len4 = ftp->data_length;
      int len5 = strlen(ftp->file_name);
      int len6 = strlen(ftp->handle);
      int len7 = strlen(ftp->user);
      int len8 = strlen(ftp->password);
  
      memset(bind,0,sizeof(bind));
      bind[0].buffer_type= FIELD_TYPE_STRING;
      bind[0].buffer= id;
      bind[0].buffer_length=2000;
      bind[0].length = &len1;

      bind[1].buffer_type = FIELD_TYPE_LONG;
      bind[1].buffer=(char *)&tcpid;
      bind[1].length = 0;

      bind[2].buffer_type= FIELD_TYPE_STRING;
      bind[2].buffer=ftp->file_type;
      bind[2].buffer_length=2000;
      bind[2].length = &len3;

      bind[3].buffer_type= FIELD_TYPE_BLOB;
      bind[3].buffer=ftp->data;
      bind[3].buffer_length=640000000;
      bind[3].length = &len4;

      bind[4].buffer_type= FIELD_TYPE_STRING;
      bind[4].buffer=ftp->file_name;
      bind[4].buffer_length=2000;
      bind[4].length = &len5;

      bind[5].buffer_type= FIELD_TYPE_STRING;
      bind[5].buffer=ftp->handle;
      bind[5].buffer_length=2000;
      bind[5].length = &len6;

      bind[6].buffer_type= FIELD_TYPE_STRING;
      bind[6].buffer=ftp->user;
      bind[6].buffer_length=2000;
      bind[6].length = &len7;

      bind[7].buffer_type= FIELD_TYPE_STRING;
      bind[7].buffer=ftp->password;
      bind[7].buffer_length=2000;
      bind[7].length = &len8;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
        syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);
     
     memset(qbuf,0,5000);
     char insertsqlbufferagain[] = "insert into applicationresultset(type,resultid,tcpfromid)values(?,?,?)";
     memcpy(qbuf,insertsqlbufferagain,sizeof(insertsqlbufferagain));
 
     stmt = mysql_stmt_init(database_sock);
     if(stmt == NULL)
       syslog(project_params.syslog_level,"stmt is null\n");
     mysql_stmt_prepare(stmt,insertsqlbufferagain,strlen(insertsqlbufferagain));

     memset(bind,0,sizeof(bind));

     bind[0].buffer_type= FIELD_TYPE_LONG;
     bind[0].buffer= (char *)&type;
     bind[0].length = 0;

     bind[1].buffer_type= FIELD_TYPE_STRING;
     bind[1].buffer=id;
     bind[1].buffer_length=2000;
     bind[1].length = &len1;

     bind[2].buffer_type= FIELD_TYPE_LONG;
     bind[2].buffer=(char *)&tcpid;
     bind[2].length = 0;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);   
}


static void add_web_record(struct WebInformation *web,int hash_index ){

      MYSQL_RES *res;
      MYSQL_FIELD *fd;
      MYSQL_ROW row;
      MYSQL_STMT *stmt;
      MYSQL_BIND bind[9];
      char qbuf[8000];
      
      char id[30];
      getId(id);
 
      int tcpid = hash_index;
      int type = APPLICATION_TYPE_WEB;

      char insertsqlbuffer[] = "insert into web(id,tcpid,host,url,referer,access_time,optype,haspostdata,postdata)values(?,?,?,?,?,?,?,?,?)";                                
      memset(qbuf,0,sizeof(qbuf));
      memcpy(qbuf,insertsqlbuffer,sizeof(insertsqlbuffer));
      stmt = mysql_stmt_init(database_sock);

      if(stmt == NULL){
          syslog(project_params.syslog_level,"stmt is null\n");
          return;
      }
      
      mysql_stmt_prepare(stmt,insertsqlbuffer,strlen(insertsqlbuffer));
      int len1 = strlen(id);  
      int len3 = strlen(web->host); 
      int len4 = strlen(web->url); 
      int len5 = strlen(web->referer); 
      int len7 = strlen(web->request); 
      int len9 = web->data_length;

      int access_time = web->time;
      int haspostdata = 2;
      if(web->data_length > 0)
         haspostdata = 1;
  
      memset(bind,0,sizeof(bind));
      bind[0].buffer_type= FIELD_TYPE_STRING;
      bind[0].buffer= id;
      bind[0].buffer_length=2000;
      bind[0].length = &len1;

      bind[1].buffer_type = FIELD_TYPE_LONG;
      bind[1].buffer=(char *)&tcpid;
      bind[1].length = 0;

      bind[2].buffer_type= FIELD_TYPE_STRING;
      bind[2].buffer=web->host;
      bind[2].buffer_length=2000;
      bind[2].length = &len3;

      bind[3].buffer_type= FIELD_TYPE_STRING;
      bind[3].buffer=web->url;
      bind[3].buffer_length=2000;
      bind[3].length = &len4;

      bind[4].buffer_type= FIELD_TYPE_STRING;
      bind[4].buffer=web->referer;
      bind[4].buffer_length=2000;
      bind[4].length = &len5;

      bind[5].buffer_type = FIELD_TYPE_LONG;
      bind[5].buffer=(char *)&access_time;
      bind[5].length = 0;

      bind[6].buffer_type= FIELD_TYPE_STRING;
      bind[6].buffer=web->request;
      bind[6].buffer_length=2000;
      bind[6].length = &len7;

      bind[7].buffer_type = FIELD_TYPE_LONG;
      bind[7].buffer=(char *)&haspostdata;
      bind[7].length = 0;

      bind[8].buffer_type= FIELD_TYPE_BLOB;
      bind[8].buffer=web->data;
      bind[8].buffer_length=64000000;
      bind[8].length = &len9;


     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
        syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);

     
     memset(qbuf,0,5000);
     char insertsqlbufferagain[] = "insert into applicationresultset(type,resultid,tcpfromid)values(?,?,?)";
     memcpy(qbuf,insertsqlbufferagain,sizeof(insertsqlbufferagain));
 
     stmt = mysql_stmt_init(database_sock);
     if(stmt == NULL)
       syslog(project_params.syslog_level,"stmt is null\n");
     mysql_stmt_prepare(stmt,insertsqlbufferagain,strlen(insertsqlbufferagain));

     memset(bind,0,sizeof(bind));

     bind[0].buffer_type= FIELD_TYPE_LONG;
     bind[0].buffer= (char *)&type;
     bind[0].length = 0;

     bind[1].buffer_type= FIELD_TYPE_STRING;
     bind[1].buffer=id;
     bind[1].buffer_length=2000;
     bind[1].length = &len1;

     bind[2].buffer_type= FIELD_TYPE_LONG;
     bind[2].buffer=(char *)&tcpid;
     bind[2].length = 0;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);   

}


static void add_mail_content_record(struct Email_info *mail,int hash_index, char *email_id){
     MYSQL_RES *res;
     MYSQL_FIELD *fd;
     MYSQL_ROW row;
     MYSQL_STMT *stmt;
     MYSQL_BIND bind[9];
     char qbuf[5000];
      
     char id[30];
     getId(id);
 	 strcpy(email_id, id);	
 		
     int tcpid = hash_index;
     int type = APPLICATION_TYPE_EMAIL;
     
     struct Email_info *pMail = mail;
     //email
     memset(qbuf,0,5000);
     char insertsqlbuffer[] = "insert into email(id,emailfrom,emailto,subject,content,isattachment,optype,role,tcpid)values(?,?,?,?,?,?,?,?,?)";
     memcpy(qbuf,insertsqlbuffer,sizeof(insertsqlbuffer));
 
     stmt = mysql_stmt_init(database_sock);
     
     if(stmt == NULL){
          syslog(project_params.syslog_level,"stmt is null\n");
      }
       
     mysql_stmt_prepare(stmt,insertsqlbuffer,strlen(insertsqlbuffer));

     char *from,*to,*subject,*content;

     if(pMail->from == NULL){
          from = (char*)malloc(2 * sizeof(char));
          memcpy(from,"",2);
     }
     else from = pMail->from;

     if(pMail->to == NULL){
          to = (char*)malloc(2 * sizeof(char));
          memcpy(to,"",2);
     }
     else to = pMail->to;

     if(pMail->subject == NULL){
          subject = (char*)malloc(2 * sizeof(char));
          memcpy(subject,"",2);
     }
     else subject = pMail->subject;

     if(pMail->content == NULL){
          content = (char*)malloc(2 * sizeof(char));
          memcpy(content,"",2);
     }
     else content = pMail->content;


     int len1=strlen(id);
     int len2=strlen(from);
     int len3=strlen(to);
     int len4= strlen(subject);
     int len5=strlen(content);
     int len6 = strlen(pMail->category);

     int isattachment = 3;
     int role = pMail->role;

     memset(bind,0,sizeof(bind));

     bind[0].buffer_type= FIELD_TYPE_STRING;
     bind[0].buffer= id;
     bind[0].buffer_length=2000;
     bind[0].length = &len1;

     bind[1].buffer_type= FIELD_TYPE_STRING;
     bind[1].buffer=from;
     bind[1].buffer_length=2000;
     bind[1].length = &len2;

     bind[2].buffer_type= FIELD_TYPE_STRING;
     bind[2].buffer=to;
     bind[2].buffer_length=2000;
     bind[2].length = &len3;

     bind[3].buffer_type= FIELD_TYPE_STRING;
     bind[3].buffer=subject;
     bind[3].buffer_length=2000;
     bind[3].length = &len4;

     bind[4].buffer_type= FIELD_TYPE_BLOB;
     bind[4].buffer=content;
     bind[4].buffer_length=6400000;
     bind[4].length = &len5;

     bind[5].buffer_type= FIELD_TYPE_LONG;
     bind[5].buffer= (char *)&isattachment;
     
     bind[6].buffer_type= FIELD_TYPE_STRING;
     bind[6].buffer=pMail->category;
     bind[6].buffer_length=2000;
     bind[6].length = &len6;
   
     bind[7].buffer_type= FIELD_TYPE_LONG;
     bind[7].buffer= (char *)&(role);
     
     bind[8].buffer_type = FIELD_TYPE_LONG;
     bind[8].buffer=(char *)&tcpid;
     bind[8].length = 0;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);

     printf("db email B\n");
     //applicationresultset
     memset(qbuf,0,5000);
     char insertsqlbufferagain[] = "insert into applicationresultset(type,resultid,tcpfromid)values(?,?,?)";
     memcpy(qbuf,insertsqlbufferagain,sizeof(insertsqlbufferagain));
 
     stmt = mysql_stmt_init(database_sock);
     if(stmt == NULL){
          syslog(project_params.syslog_level,"stmt is null\n");
      }
     mysql_stmt_prepare(stmt,insertsqlbufferagain,strlen(insertsqlbufferagain));

     memset(bind,0,sizeof(bind));

     bind[0].buffer_type= FIELD_TYPE_LONG;
     bind[0].buffer= (char *)&type;
     bind[0].length = 0;

     bind[1].buffer_type= FIELD_TYPE_STRING;
     bind[1].buffer=id;
     bind[1].buffer_length=2000;
     bind[1].length = &len1;

     bind[2].buffer_type= FIELD_TYPE_LONG;
     bind[2].buffer=(char *)&tcpid;
     bind[2].length = 0;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);
   
     printf("db email C\n");

}

static void add_mail_attachment_record(struct Email_info *mail,int hash_index, char *attachment_id){

     MYSQL_RES *res;
     MYSQL_FIELD *fd;
     MYSQL_ROW row;
     MYSQL_STMT *stmt;
     MYSQL_BIND bind[4];
     char qbuf[5000];
      
     char id[30];
     getId(id);
 
     int tcpid = hash_index;
     int type = APPLICATION_TYPE_EMAI_ATTACHMENT;
     struct Email_info *pMail = mail;

     memset(qbuf,0,5000);
     char insertsqlbufferattachment[] = "insert into attachment(id,tcpid,filename,file)values(?,?,?,?)";
     memcpy(qbuf,insertsqlbufferattachment,sizeof(insertsqlbufferattachment));

     stmt = mysql_stmt_init(database_sock);

     if(stmt == NULL)
       printf(" stmt is null\n");

     mysql_stmt_prepare(stmt,insertsqlbufferattachment,strlen(insertsqlbufferattachment));

     int len1;
     int len2;
     int len3;
     char *filename;

     if(pMail->att_filename == NULL){
         filename = "Miss name";
     }else filename = pMail->att_filename;

     if(pMail->attachment == NULL){
         return;
     }

     len1 = strlen(filename);
     len2 = pMail->att_length<0?0:pMail->att_length;
     len3 = strlen(id);

     memset(bind,0,sizeof(bind));

     bind[0].buffer_type= FIELD_TYPE_STRING;
     bind[0].buffer= id;
     bind[0].buffer_length=2000;
     bind[0].length = &len3;

     bind[1].buffer_type = FIELD_TYPE_LONG;
     bind[1].buffer=(char *)&tcpid;
     bind[1].length = 0;

     bind[2].buffer_type= FIELD_TYPE_STRING;
     bind[2].buffer= filename;
     bind[2].buffer_length=2000;
     bind[2].length = &len1;

     bind[3].buffer_type= FIELD_TYPE_LONG_BLOB;
     bind[3].buffer = pMail->attachment;
     bind[3].buffer_length = 64000000;
     bind[3].length = &len2;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
         printf("%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
         printf("%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);

     //print_email_detai(pMail);
 
     //applicationresultset
     memset(qbuf,0,5000);
     char insertsqlbufferagain[] = "insert into applicationresultset(type,resultid,tcpfromid)values(?,?,?)";
     memcpy(qbuf,insertsqlbufferagain,sizeof(insertsqlbufferagain));
 
     stmt = mysql_stmt_init(database_sock);
     if(stmt == NULL){
          syslog(project_params.syslog_level,"stmt is null\n");
      }
     mysql_stmt_prepare(stmt,insertsqlbufferagain,strlen(insertsqlbufferagain));

     memset(bind,0,sizeof(bind));


     bind[0].buffer_type= FIELD_TYPE_LONG;
     bind[0].buffer= (char *)&type;
     bind[0].length = 0;

     bind[1].buffer_type= FIELD_TYPE_STRING;
     bind[1].buffer=id;
     bind[1].buffer_length=2000;
     bind[1].length = &len3;

     bind[2].buffer_type= FIELD_TYPE_LONG;
     bind[2].buffer=(char *)&tcpid;
     bind[2].length = 0;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);
}

static void add_mail_record(struct Email_info *mail,int hash_index, char *id){

     struct Email_info *point;
     for(point = mail; point; point = point->next){

          if(point->content != NULL && strlen(point->content) > 0){

               printf("AAA-1\n");
               add_mail_content_record(point,hash_index, id);
               printf("AAA-2\n");               
          }

          if(point->attachment != NULL && point->att_length > 0){
               printf("AAA-3\n");
               //print_email_detai(point);
               add_mail_attachment_record(point,hash_index, id);
               printf("AAA-4\n");       
          }
     }
}

static void add_telnet_record(struct TelnetInformation *info,int hash_index){
      MYSQL_RES *res;
      MYSQL_FIELD *fd;
      MYSQL_ROW row;
      MYSQL_STMT *stmt;
      MYSQL_BIND bind[8];
      char qbuf[8000];
      
      char id[30];
      getId(id);
 
      int tcpid = hash_index;
      int type = 8;

      char insertsqlbuffer[] = "insert into telnet(id,tcpid,content,password,command)values(?,?,?,?,?)";                                
      memset(qbuf,0,sizeof(qbuf));
      memcpy(qbuf,insertsqlbuffer,sizeof(insertsqlbuffer));
      stmt = mysql_stmt_init(database_sock);
      if(stmt == NULL){
          syslog(project_params.syslog_level,"stmt is null\n");
      }
      
      mysql_stmt_prepare(stmt,insertsqlbuffer,strlen(insertsqlbuffer));
      int len1 = strlen(id);
      int len3 = strlen(info->content);
      int len4 = strlen(info->password);
      int len5 = strlen(info->command);
   
  
      memset(bind,0,sizeof(bind));
      bind[0].buffer_type= FIELD_TYPE_STRING;
      bind[0].buffer= id;
      bind[0].buffer_length=2000;
      bind[0].length = &len1;

      bind[1].buffer_type = FIELD_TYPE_LONG;
      bind[1].buffer=(char *)&tcpid;
      bind[1].length = 0;

      bind[2].buffer_type= FIELD_TYPE_STRING;
      bind[2].buffer=info->content;
      bind[2].buffer_length=2000;
      bind[2].length = &len3;

      bind[3].buffer_type= FIELD_TYPE_STRING;
      bind[3].buffer=info->password;
      bind[3].buffer_length=2000;
      bind[3].length = &len4;

      bind[4].buffer_type= FIELD_TYPE_STRING;
      bind[4].buffer=info->command;
      bind[4].buffer_length=2000;
      bind[4].length = &len5;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
        syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);
     
     memset(qbuf,0,5000);
     char insertsqlbufferagain[] = "insert into applicationresultset(type,resultid,tcpfromid)values(?,?,?)";
     memcpy(qbuf,insertsqlbufferagain,sizeof(insertsqlbufferagain));
 
     stmt = mysql_stmt_init(database_sock);
     if(stmt == NULL)
       syslog(project_params.syslog_level,"stmt is null\n");
     mysql_stmt_prepare(stmt,insertsqlbufferagain,strlen(insertsqlbufferagain));

     memset(bind,0,sizeof(bind));

     bind[0].buffer_type= FIELD_TYPE_LONG;
     bind[0].buffer= (char *)&type;
     bind[0].length = 0;

     bind[1].buffer_type= FIELD_TYPE_STRING;
     bind[1].buffer=id;
     bind[1].buffer_length=2000;
     bind[1].length = &len1;

     bind[2].buffer_type= FIELD_TYPE_LONG;
     bind[2].buffer=(char *)&tcpid;
     bind[2].length = 0;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);   
}

static void add_cookies_record(struct  CookiesInformation *upinfo,int hash_index){
 
     MYSQL_RES *res;
     MYSQL_FIELD *fd;
     MYSQL_ROW row;
     MYSQL_STMT *stmt;
     MYSQL_BIND bind[8];
     char qbuf[8000];

     char id[30];
     getId(id);
     int type = 6;
     int tcpid = hash_index;

     char insertsqlbuffer[] = "insert into cookies(id,tcpid,url,cookie,type)values(?,?,?,?,?)";                                
     memset(qbuf,0,sizeof(qbuf));
     memcpy(qbuf,insertsqlbuffer,sizeof(insertsqlbuffer));
     stmt = mysql_stmt_init(database_sock);
     if(stmt == NULL){
         syslog(project_params.syslog_level,"init stmt failur for %s\n",qbuf);
         return;
     }
     mysql_stmt_prepare(stmt,insertsqlbuffer,strlen(insertsqlbuffer));

     int len1 = strlen(id);
     int len3 = strlen(upinfo->cookies_url);
     int len4 = strlen(upinfo->cookies);
     int len5 = strlen(upinfo->url);
   
     memset(bind,0,sizeof(bind));
     bind[0].buffer_type= FIELD_TYPE_STRING;
     bind[0].buffer= id;
     bind[0].buffer_length=2000;
     bind[0].length = &len1;

     bind[1].buffer_type = FIELD_TYPE_LONG;
     bind[1].buffer=(char *)&tcpid;
     bind[1].length = 0;

     bind[2].buffer_type= FIELD_TYPE_STRING;
     bind[2].buffer=upinfo->cookies_url;
     bind[2].buffer_length=2000;
     bind[2].length = &len3;

     bind[3].buffer_type= FIELD_TYPE_STRING;
     bind[3].buffer=upinfo->cookies;
     bind[3].buffer_length=2000;
     bind[3].length = &len4;

     bind[4].buffer_type= FIELD_TYPE_STRING;
     bind[4].buffer=upinfo->url;
     bind[4].buffer_length=2000;
     bind[4].length = &len5;

     if(mysql_stmt_bind_param(stmt,bind)){
        syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);
     
     
     memset(qbuf,0,5000);
     char insertsqlbufferagain[] = "insert into applicationresultset(type,resultid,tcpfromid)values(?,?,?)";
     memcpy(qbuf,insertsqlbufferagain,sizeof(insertsqlbufferagain));
 
     stmt = mysql_stmt_init(database_sock);
     
     if(stmt == NULL){
         syslog(project_params.syslog_level,"init stmt failur for %s\n",qbuf);
         return;
     }
       
     mysql_stmt_prepare(stmt,insertsqlbufferagain,strlen(insertsqlbufferagain));

     memset(bind,0,sizeof(bind));

     bind[0].buffer_type= FIELD_TYPE_LONG;
     bind[0].buffer= (char *)&type;
     bind[0].length = 0;

     bind[1].buffer_type= FIELD_TYPE_STRING;
     bind[1].buffer=id;
     bind[1].buffer_length=2000;
     bind[1].length = &len1;

     bind[2].buffer_type= FIELD_TYPE_LONG;
     bind[2].buffer=(char *)&tcpid;
     bind[2].length = 0;

     if(mysql_stmt_bind_param(stmt,bind)){
        syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt); 
}

static void add_msn_record(char *my_account,char *contact_account,char *message,int hash_index,time_t time){

     MYSQL_RES *res;
     MYSQL_FIELD *fd;
     MYSQL_ROW row;
     MYSQL_STMT *stmt;
     MYSQL_BIND bind[8];
     char qbuf[8000];

     char id[30];
     getId(id);
     int type = 4;
     int tcpid = hash_index;
     int time_int = time;

     char insertsqlbuffer[] = "insert into msn(id,send,recieve,content,tcpid,access_time)values(?,?,?,?,?,?)";                                
     memset(qbuf,0,500);
     memcpy(qbuf,insertsqlbuffer,sizeof(insertsqlbuffer));

     stmt = mysql_stmt_init(database_sock);
     if(stmt == NULL){
         syslog(project_params.syslog_level,"init stmt failur for %s\n",qbuf);
         return;
     }
     mysql_stmt_prepare(stmt,insertsqlbuffer,strlen(insertsqlbuffer));
     
     int len1 = strlen(id);
     int len2 = strlen(my_account);
     int len3 = strlen(contact_account);
     int len4 = strlen(message);

     printf("\t\t\t\t\t\t\tsend is %s\n receive is %s\n",my_account,contact_account);

     memset(bind,0,sizeof(bind));

     bind[0].buffer_type= FIELD_TYPE_STRING;
     bind[0].buffer= id;
     bind[0].buffer_length=2000;
     bind[0].length = &len1;

     bind[1].buffer_type = FIELD_TYPE_STRING;
     bind[1].buffer= my_account;
     bind[1].buffer_length=2000;
     bind[1].length = &len2;

     bind[2].buffer_type= FIELD_TYPE_STRING;
     bind[2].buffer=contact_account;
     bind[2].buffer_length=2000;
     bind[2].length = &len3;
     
     bind[3].buffer_type= FIELD_TYPE_STRING;
     bind[3].buffer=message;
     bind[3].buffer_length=2000;
     bind[3].length = &len4;
     
     bind[4].buffer_type= FIELD_TYPE_LONG;
     bind[4].buffer=(char *)&tcpid;
     bind[4].length = 0;

     bind[5].buffer_type= FIELD_TYPE_LONG;
     bind[5].buffer=(char *)&time_int;
     bind[5].length = 0;

     if(mysql_stmt_bind_param(stmt,bind)){
        syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);
     
     memset(qbuf,0,5000);
     char insertsqlbufferagain[] = "insert into applicationresultset(type,resultid,tcpfromid)values(?,?,?)";
     memcpy(qbuf,insertsqlbufferagain,sizeof(insertsqlbufferagain));
 
     stmt = mysql_stmt_init(database_sock);
     
     if(stmt == NULL){
         syslog(project_params.syslog_level,"init stmt failur for %s\n",qbuf);
         return;
     }
       
     mysql_stmt_prepare(stmt,insertsqlbufferagain,strlen(insertsqlbufferagain));

     memset(bind,0,sizeof(bind));

     bind[0].buffer_type= FIELD_TYPE_LONG;
     bind[0].buffer= (char *)&type;
     bind[0].length = 0;

     bind[1].buffer_type= FIELD_TYPE_STRING;
     bind[1].buffer=id;
     bind[1].buffer_length=2000;
     bind[1].length = &len1;

     bind[2].buffer_type= FIELD_TYPE_LONG;
     bind[2].buffer=(char *)&tcpid;
     bind[2].length = 0;


     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
        syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);
}

static void add_user_password_record(struct  UPInformation *upinfo,int hash_index){
      MYSQL_RES *res;
      MYSQL_FIELD *fd;
      MYSQL_ROW row;
      MYSQL_STMT *stmt;
      MYSQL_BIND bind[8];
      char qbuf[8000];
      
      char id[30];
      getId(id);
 
      int tcpid = hash_index;
      int type = 7;

      char insertsqlbuffer[] = "insert into userpassword(id,tcpid,url,user,password)values(?,?,?,?,?)";                                
      memset(qbuf,0,sizeof(qbuf));
      memcpy(qbuf,insertsqlbuffer,sizeof(insertsqlbuffer));
      stmt = mysql_stmt_init(database_sock);
      if(stmt == NULL){
          syslog(project_params.syslog_level,"stmt is null\n");
      }
      
      mysql_stmt_prepare(stmt,insertsqlbuffer,strlen(insertsqlbuffer));
      int len1 = strlen(id);
      int len3 = strlen(upinfo->url);
      int len4 = strlen(upinfo->user);
      int len5 = strlen(upinfo->password);
   
  
      memset(bind,0,sizeof(bind));
      bind[0].buffer_type= FIELD_TYPE_STRING;
      bind[0].buffer= id;
      bind[0].buffer_length=2000;
      bind[0].length = &len1;

      bind[1].buffer_type = FIELD_TYPE_LONG;
      bind[1].buffer=(char *)&tcpid;
      bind[1].length = 0;

      bind[2].buffer_type= FIELD_TYPE_STRING;
      bind[2].buffer=upinfo->url;
      bind[2].buffer_length=2000;
      bind[2].length = &len3;

      bind[3].buffer_type= FIELD_TYPE_STRING;
      bind[3].buffer=upinfo->user;
      bind[3].buffer_length=2000;
      bind[3].length = &len4;

      bind[4].buffer_type= FIELD_TYPE_STRING;
      bind[4].buffer=upinfo->password;
      bind[4].buffer_length=2000;
      bind[4].length = &len5;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
        syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);
     
     memset(qbuf,0,5000);
     char insertsqlbufferagain[] = "insert into applicationresultset(type,resultid,tcpfromid)values(?,?,?)";
     memcpy(qbuf,insertsqlbufferagain,sizeof(insertsqlbufferagain));
 
     stmt = mysql_stmt_init(database_sock);
     if(stmt == NULL)
       syslog(project_params.syslog_level,"stmt is null\n");
     mysql_stmt_prepare(stmt,insertsqlbufferagain,strlen(insertsqlbufferagain));

     memset(bind,0,sizeof(bind));

     bind[0].buffer_type= FIELD_TYPE_LONG;
     bind[0].buffer= (char *)&type;
     bind[0].length = 0;

     bind[1].buffer_type= FIELD_TYPE_STRING;
     bind[1].buffer=id;
     bind[1].buffer_length=2000;
     bind[1].length = &len1;

     bind[2].buffer_type= FIELD_TYPE_LONG;
     bind[2].buffer=(char *)&tcpid;
     bind[2].length = 0;

     if(mysql_stmt_bind_param(stmt,bind)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }

     if(mysql_stmt_execute(stmt)){
         syslog(project_params.syslog_level,"%s\n",mysql_error(&database_hadle));
     }
     mysql_stmt_close(stmt);   
}

static int getId(char *id){
    int i = 0,a,b;
    struct timeb tp;    
    ftime(&tp);
    
    b = tp.millitm;
    
    do
    {
        a = b % 10;
        switch(a)
        {
        case 0: id[i] = '0'; i++; break;
        case 1: id[i] = '1'; i++; break;
        case 2: id[i] = '2'; i++; break;
        case 3: id[i] = '3'; i++; break;
        case 4: id[i] = '4'; i++; break;
        case 5: id[i] = '5'; i++; break;
        case 6: id[i] = '6'; i++; break;
        case 7: id[i] = '7'; i++; break;
        case 8: id[i] = '8'; i++; break;
        case 9: id[i] = '9'; i++; break;
        }
        b /= 10;
    }while(b != 0);
    
    if(tp.millitm < 10)
    {
        id[i++] = '0';
        id[i++] = '0';
    }
    if(tp.millitm < 100 && tp.millitm > 9)
    {
        id[i++] = '0';
    }
    
    a = (long)tp.time % 10;
    b = (long)tp.time;
    while( b != 0 )
    {
        switch(a)
        {
        case 0: id[i] = '0'; i++; break;
        case 1: id[i] = '1'; i++; break;
        case 2: id[i] = '2'; i++; break;
        case 3: id[i] = '3'; i++; break;
        case 4: id[i] = '4'; i++; break;
        case 5: id[i] = '5'; i++; break;
        case 6: id[i] = '6'; i++; break;
        case 7: id[i] = '7'; i++; break;
        case 8: id[i] = '8'; i++; break;
        case 9: id[i] = '9'; i++; break;
        }
        b /= 10;
        a = b % 10;
    }
    id[i] = '\0';
    
    int j, m;
    char temp;
    for(j = 0, m = i; j < m / 2; j++)
    {
        temp      =  id[j];
        id[j]     =  id[m-1-j];
        id[m-1-j] =  temp;
    }
    return 0;
}


















                              

