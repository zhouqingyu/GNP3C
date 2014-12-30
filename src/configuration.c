#include <syslog.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <malloc.h>

#include "project.h"
#include "configuration.h"
#include "tools.h"

static void read_one_item(char item[]);
static void read_one_sub_item(char *content);
static int read_card_names(char *cards);

int read_configuration(){
   struct File_data file_data;
   if(read_file(CONFIGURATION_FILE_PATH,&file_data) != 0){
      syslog(project_params.syslog_level,"read configuration file (%s) error\n",CONFIGURATION_FILE_PATH);
      printf("b\n");
      return 0;
   }

   memset(&configuration,0,sizeof(struct Configuration));

   char *point = file_data.content;
   int length = file_data.file_length;
   int i;
   char item[100];
   int ilen=0;

   memset(item,0,sizeof(item));
   ilen = 0;

   for(i=0;i<length+1;i++){
     if(*(point+i) != ';'&& *(point+i) != 0){
        if( *(point+i)!='\r' && *(point+i)!=' ' && *(point+i)!='\n' && *(point+i)!='\t')
           item[ilen++] = *(point+i);
        continue;
     }

     read_one_item(item);
     
     memset(item,0,sizeof(item));
     ilen = 0;
   }
   free(file_data.content);
}

static void read_one_item(char content[]){

   char *point = content;
   int length = strlen(content);
   int i;
   char item[100];
   int ilen = 0;
   int item_index = 0;
   char name[100];
   char value[100];

   memset(name,0,sizeof(name));
   memset(value,0,sizeof(value));
   memset(item,0,sizeof(item));
   ilen = 0;


   for(i=0;i<length+1;i++){
     if(*(point+i) != ':'&& *(point+i) != 0){
        item[ilen++] = *(point+i);
        continue;
     }

    if(item_index==0)
       memcpy(name,item,sizeof(item));
    else if(item_index == 1)
       memcpy(value,item,sizeof(item));
    else syslog(project_params.syslog_level,"analysis configuretion error while deal with %s",content);

    item_index++;

    memset(item,0,sizeof(item));
    ilen = 0;
  }

  if(strstr(name,"packet_queue_size")!=NULL)
      configuration.packet_queue_number = atoi(value);
  else if(strstr(name,"tcp_connection_number")!=NULL)
      configuration.tcp_connection_number = atoi(value);
  else if(strstr(name,"database_ip")!=NULL)
      memcpy(configuration.database_ip,value,sizeof(value));
  else if(strstr(name,"database_account")!=NULL)
      memcpy(configuration.database_account,value,sizeof(value));
  else if(strstr(name,"database_password")!=NULL)
      memcpy(configuration.database_password,value,sizeof(value));
  else if(strstr(name,"database_name")!=NULL)
      memcpy(configuration.database_name,value,sizeof(value));
  else if(strstr(name,"monitor_cars")!=NULL)
      read_card_names(value);
  else if(strstr(name,"save_environment_path")!=NULL)
      memcpy(configuration.save_environment_path,value,sizeof(value));
  else if(strstr(name,"recover_environment_path")!=NULL)
      memcpy(configuration.recover_environment_path,value,sizeof(value));
  else if(strstr(name,"tcp_data_wait_max")!=NULL)
      configuration.tcp_data_wait_max = atoi(value);
  else if(strstr(name,"tcp_delay_max_time")!=NULL)
      configuration.tcp_delay_max_time = atoi(value);
  else if(strstr(name,"time_wait_unit")!=NULL)
      configuration.time_wait_unit = atoi(value);
}

static int read_card_names(char *content){

   char *point = content;
   int length = strlen(content);
   int i;
   char item[100];
   int ilen = 0;
   int item_index = 0;
   char cards[100][100];
   int card_number;

   memset(cards,0,sizeof(cards));
   memset(item,0,sizeof(item));
   ilen = 0;


   for(i=0;i<length+1;i++){
     if(*(point+i) != ','&& *(point+i) != 0){
        item[ilen++] = *(point+i);
        continue;
     }

    memcpy(cards[item_index],item,sizeof(item));
    item_index++;

    memset(item,0,sizeof(item));
    ilen = 0;
  }

  configuration.monitor_card_number = item_index;
  memcpy(configuration.monitor_card_name,cards,sizeof(cards));
}
