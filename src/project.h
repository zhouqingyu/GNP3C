#ifndef PROJECT_H

#define PROJECT_H

#include <sys/types.h>
#include <sys/timeb.h>
#include <time.h>

#define APPLICATION_TYPE_EMAIL			1
#define APPLICATION_TYPE_WEB			2
#define APPLICATION_TYPE_FTP			3
#define APPLICATION_TYPE_MSN			4
#define APPLICATION_TYPE_QQ_NUMBER		5
#define APPLICATION_TYPE_COOKIES		6
#define APPLICATION_TYPE_USERPASSWORD		7
#define APPLICATION_TYPE_TELNET			8
#define APPLICATION_TYPE_EMAI_ATTACHMENT 	9

#define DATA_TYPE_SERVER	1
#define DATA_TYPE_CLIENT	2
#define DATA_TYPE_PROMISC	3
#define DATA_TYPE_DEZIP		4

#define CONTENT_MAX 2000

#define PACKET_QUEUE_MAX 100000

#define FIND_MIN 5

#define CONFIGURATION_FILE_PATH "./configuration.file"

#define HTTP_HEAD_TYPE_REQUEST 0
#define HTTP_HEAD_TYPE_RESPONSE 1

#define PATTER_MAX 100
#define PATTERN_RESPOND_HEAD	 0
#define PATTERN_REQUEST_HEAD     1
#define PATTERN_ACCEPT	         2
#define PATTERN_ACCEPT_ENCODING  3
#define PATTERN_ACCEPT_LANGUAGE  4
#define PATTERN_CONTENT_ENCODING 5
#define PATTERN_CONTENT_LANGUAGE 6
#define PATTERN_CONTENT_LENGTH   7
#define PATTERN_CONTENT_TYPE     8
#define PATTERN_TRANSFER_ENCODING 9
#define PATTERN_CONTENT_DISPOSITION 10
#define PATTERN_BOUNDARY	11
#define PATTERN_ENTITY_HEAD     12
#define PATTERN_ENTITY_BODY	13
#define PATTERN_URI_PARAMETER   14
#define PATTERN_USER_AGENT      15
#define PATTERN_HOST            16
#define PATTERN_REFERER  	17
#define PATTERN_ABSOLUTE_URI 	18
#define PATTERN_MAIL_UPLOAD_NAME 19
#define PATTERN_CONTENT_DISPOSITION_TYPE 20
#define PATTERN_CONTENT_DISPOSITION_NAME 21
#define PATTERN_CONTENT_DISPOSITION_FILENAME 22

#define MAX_HTTP_ONE_PROMISC 100
#define HTTP_MATCH_YES 1234
#define HTTP_MATCH_NO  5678

#ifndef TURE
#define TRUE 1
#endif 
#ifndef FALSE
#define FALSE 0
#endif

struct tuple4{
  u_short source;
  u_short dest;
  u_int saddr;
  u_int daddr;
};

struct Configuration{
   int packet_queue_number;
   int tcp_connection_number;
   char database_ip[100];
   char database_account[100];
   char database_password[100];
   char database_name[100];
   int  monitor_card_number;
   char monitor_card_name[100][100];
   char save_environment_path[100];
   char recover_environment_path[100];
   int tcp_data_wait_max;
   int tcp_delay_max_time;
   int time_wait_unit;
};

struct File_data{
  int file_length;
  char *content;
};

struct project_prm{
  int syslog_level;
};

struct Packet{
   u_char content[CONTENT_MAX];
   int length;
};

struct TcpInformation{
   int hash_index;
   char bssid[50];
   char essid[255];
   char src_ip[50];
   char src_mac[50];
   char des_ip[50];
   char des_mac[50];
   struct tuple4 ip_and_port;
   unsigned char ap[6];
};

struct mail_info
{
     int att_length;
     int att_count;
     char *from;
     char *to;
     char *subject;
     char *content; 
     char *attachment;
     char *att_list;
     char *att_filename;
     int role;   /* 0-->recipient 1-->sender */
     
     char category[10];   // web or foxmail
     char ip_add[20];
     char mac_add[40];
};

struct WebInformation{
   char *request;
   char *host;
   char *url;
   char *referer;
   char *data_type;
   int data_length;
   char *data;
   int time;
   char srcip[16];
   char dstip[16];
};

struct List_Node{
   char *data;
   int length;
   struct tuple4 ip_and_port;
   struct List_Node *next;   
};

struct List{
  struct List_Node *head;
  struct List_Node *tail;
};

struct FTP_FILE_NODE{
   char user[100];
   char password[100];
   char file_name[100];
   char handle[100];
   int desport;
   struct FTP_FILE_NODE *next;
};

struct FTP_FILE_LIST{
  struct FTP_FILE_NODE *head;
};

struct Content_Attachment_Match{
    char content_referer[1000];
    char attachment_referer[1000];
 
    struct Content_Attachment_Match *next;
};

struct Content_Attachment_Match_List{
   struct Content_Attachment_Match *head;
};


struct Http_List{
   struct Http *head;
};


struct Content_Disposition{
   char type[100];
   char filename[100];
   char create_date[100];
   char modification_date[100];
   char read_date[100];
   char name[100];
};

struct Entity_List{
   struct Entity *head;
};

struct Entity{
   char entity_type[5000];
   char content_disposition[5000];
   struct Content_Disposition content_disposition_struct;

   char *entity_content;  //add one byte space
   int  entity_length;

   char *entity_all_data;    //used for analysis itself
   int entity_all_data_length; //used for analysis itself

   struct Entity *next;
};

struct Parameter_List{
   struct Parameter *head;
};

struct Parameter{
    char *name;
    int name_length;
    char *value;
    int value_length;

    struct Parameter *next;
};


struct Http{

   int type;  //HTTP_HEAD_TYPE_REQUEST or HTTP_HEAD_TYPE_RESPONSE

   char method[100];
   char uri[5000]; // used for analysis itself
   char absolute_uri[5000];

   char status[100];

   char accept[5000];
   char accept_encoding[5000];
   char accept_language[500]; 
   char content_encoding[500];
   char content_language[5000];
   char content_length[100];
   char content_type[5000];
   char transfer_encoding[100];
   char content_disposition[5000];
   char user_agent[5000];
   char host[5000];
   char referer[5000];
   char mail_upload_name[5000];

   char *http_packet;         //used for analysis itself
   int http_packet_length;    //used for analysis itself

   struct Entity_List *entity_list;
   struct Parameter_List *parameter_list;

   struct Http *matched_http;
   int if_matched_http;
   int start_position;

   char *head_for_match;
   int head_for_match_length;
 
   struct Http *next;
};

struct Http_RR{
   struct Http_List *request_list,*response_list;
};

struct Email_info{
     
     char *from;
     char *to;
     char *subject;
     char *content;
     int content_is_html;
     char *password;
     // this structure support signal attachment only, plesase use list to contain this structure when there are multiple attachments
     int att_length;
     char *attachment;
     char *att_filename;

     struct Email_info *next;
     
     int role;   /* 0-->recipient 1-->sender */
     
     char category[10];   // web or foxmail
     char ip_add[20];
     char mac_add[40];
};

enum ANALYSIS_EMAIL_FUNCTIONS{
   ANALYSIS_EMAIL_FUNCTION_126_SEND_CONTENT = 0,
   ANALYSIS_EMAIL_FUNCTION_126_SEND_ATTACHMENT ,
   ANALYSIS_EMAIL_FUNCTION_126_RECEIVE_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_126_RECEIVE_ATTACHMENT,
   ANALYSIS_EMAIL_FUNCTION_163_SEND_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_163_SEND_ATTACHMENT ,
   ANALYSIS_EMAIL_FUNCTION_163_RECEIVE_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_163_RECEIVE_ATTACHMENT,
   ANALYSIS_EMAIL_FUNCTION_QQ_SEND_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_QQ_SEND_ATTACHMENT ,
   ANALYSIS_EMAIL_FUNCTION_QQ_RECEIVE_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_QQ_RECEIVE_ATTACHMENT,
   ANALYSIS_EMAIL_FUNCTION_HOTMAIL_SEND_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_HOTMAIL_SEND_ATTACHMENT ,
   ANALYSIS_EMAIL_FUNCTION_HOTMAIL_RECEIVE_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_HOTMAIL_RECEIVE_ATTACHMENT,
   ANALYSIS_EMAIL_FUNCTION_YAHOO_SEND_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_YAHOO_SEND_ATTACHMENT ,
   ANALYSIS_EMAIL_FUNCTION_YAHOO_RECEIVE_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_YAHOO_RECEIVE_ATTACHMENT,
   ANALYSIS_EMAIL_FUNCTION_SINA_SEND_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_SINA_SEND_ATTACHMENT ,
   ANALYSIS_EMAIL_FUNCTION_SINA_RECEIVE_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_SINA_RECEIVE_ATTACHMENT,
   ANALYSIS_EMAIL_FUNCTION_SOHU_SEND_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_SOHU_SEND_ATTACHMENT ,
   ANALYSIS_EMAIL_FUNCTION_SOHU_RECEIVE_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_SOHU_RECEIVE_ATTACHMENT,
   ANALYSIS_EMAIL_FUNCTION_TOM_SEND_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_TOM_SEND_ATTACHMENT ,
   ANALYSIS_EMAIL_FUNCTION_TOM_RECEIVE_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_TOM_RECEIVE_ATTACHMENT,
   ANALYSIS_EMAIL_FUNCTION_21CN_SEND_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_21CN_SEND_ATTACHMENT ,
   ANALYSIS_EMAIL_FUNCTION_21CN_RECEIVE_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_21CN_RECEIVE_ATTACHMENT,
   ANALYSIS_EMAIL_FUNCTION_139_SEND_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_139_SEND_ATTACHMENT ,
   ANALYSIS_EMAIL_FUNCTION_139_RECEIVE_CONTENT,
   ANALYSIS_EMAIL_FUNCTION_139_RECEIVE_ATTACHMENT,
   ANALYSIS_EMAIL_FUNCTION_NUMBER
};

struct Order_Http{
   struct Http *http;
   int position;
};

extern struct project_prm project_params;

#endif