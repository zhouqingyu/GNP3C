#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include <sys/timeb.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netpacket/packet.h> //reference  struct sockaddr_ll                                                                                   
#include <net/if.h> // reference struct ifreq
#include <linux/if_ether.h> // reference ETH_P_ALL
#include <sys/ioctl.h> // reference SIOCGIFINDEX	
#include <syslog.h>
#include <malloc.h>

#include "project.h"
#include "tools.h"
#include "cJSON.h"

extern int __sina_send_content(struct Http *http,struct Email_info *email_info){
   
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.sina.com.cn") == NULL)
      return 0; 
   if(strstr(http->absolute_uri,"/classic/send.php") == NULL)
       return 0;

   struct Entity_List *entity_list;
   struct Entity *entity;

   entity_list = http->entity_list;

   if(entity_list != NULL){

        entity = entity_list->head;
        while(entity != NULL){

            if(entity->entity_length <= 0 || entity->entity_length > 1024*1024*100){
                  entity = entity->next;
                  continue;
            }

            if( strstr(entity->content_disposition_struct.type,"form-data") == NULL ){
                  entity = entity->next;
                  continue;
            }
           
            if( strstr(entity->content_disposition_struct.name,"from") != NULL){
                  copy_into_email_info_member(&email_info->from, entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }

            if( strstr(entity->content_disposition_struct.name,"to") != NULL){
                  copy_into_email_info_member(&email_info->to, entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }

           if( strstr(entity->content_disposition_struct.name,"subj") != NULL){
                  copy_into_email_info_member(&email_info->subject, entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }
            

           if( strstr(entity->content_disposition_struct.name,"msgtxt") != NULL){
                  copy_into_email_info_member(&email_info->content, entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }

            entity = entity->next;

        }
    }
/*
    printf("__sina_send_content\n");
	printf("from : [%s]\n", email_info->from);
	printf("subject : [%s]\n", email_info->subject);
    printf("to : [%s]\n", email_info->to);
	printf("content length : %d\n", strlen(email_info->content));
    printf("content : [%s]\n",email_info->content);
    printf("\n\n");
*/
    return 1;

}


extern int __sina_send_attachment(struct Http *http,struct Email_info *email_info){
   
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.sina.com.cn") == NULL)
      return 0; 
   if(strstr(http->absolute_uri,"/classic/uploadatt.php") == NULL)
       return 0;

   struct Entity_List *entity_list;
   struct Entity *entity;

   entity_list = http->entity_list;

   if(entity_list != NULL){

        entity = entity_list->head;
        while(entity != NULL){

            if(entity->entity_length <= 0 || entity->entity_length > 1024*1024*100){
                  entity = entity->next;
                  continue;
            }

            if( strstr(entity->content_disposition_struct.type,"form-data") == NULL ){
                  entity = entity->next;
                  continue;
            }
           
            if( strstr(entity->content_disposition_struct.name,"Filename") != NULL){
                  copy_into_email_info_member(&email_info->att_filename,entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }

            if( strstr(entity->content_disposition_struct.name,"Filedata") != NULL){
                  copy_into_email_info_member(&email_info->attachment, entity->entity_content, entity->entity_length);
                  email_info->att_length = entity->entity_length;
                  entity = entity->next;
                  result = 1;
                  continue;
            }

            entity = entity->next;

        }
    }
/*
   if(result == 1){
        printf("__sina_send_attachment\n");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
        printf("\n\n");
   }
*/
   return result;
}

extern int __sina_receive_content(struct Http *http,struct Email_info *email_info){
   
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.sina.com.cn") == NULL)
      return 0; 
   if(strstr(http->absolute_uri,"/classic/readmail.php") == NULL)
       return 0;

   if(http->matched_http != NULL && http->if_matched_http == HTTP_MATCH_YES){

       struct Http *another = http->matched_http;
       struct Entity_List *entity_list;
       struct Entity *entity;

       entity_list = another->entity_list;

       if(entity_list != NULL){
           entity = entity_list->head;
           while(entity != NULL){
              if(entity->entity_length > 0){
                
                cJSON *root = cJSON_Parse(entity->entity_content);
                //analysis content information,attachment information analysis later
                cJSON *data = cJSON_GetObjectItem(root,"data");

                char *content = cJSON_GetObjectItem(data,"body")->valuestring;
                if(content != NULL && strlen(content) > 0)
                     copy_into_email_info_member(&email_info->content, content, strlen(content)); 

                char *from = cJSON_GetObjectItem(data,"from")->valuestring;
                if(from != NULL && strlen(from) > 0)
                     copy_into_email_info_member(&email_info->from, from, strlen(from)); 

                char *to = cJSON_GetObjectItem(data,"to")->valuestring;
                if(to != NULL && strlen(to) > 0)
                     copy_into_email_info_member(&email_info->to, to, strlen(to)); 

                char *subject = cJSON_GetObjectItem(data,"subject")->valuestring;
                if(subject != NULL && strlen(subject) > 0)
                     copy_into_email_info_member(&email_info->subject, subject, strlen(subject)); 
                
                cJSON_Delete(root);

                result = 1;
                break;// find one,then quit circle
              }
              entity = entity->next;
           }
       }

   }
/*
   if(result == 1){
      printf("__sina_receive_content\n");
      if(email_info->from != NULL)  
          printf("[%s]\n", email_info->from);
      if(email_info->subject != NULL) 
          printf("[%s]\n", email_info->subject);
      if(email_info->to != NULL) 
          printf("[%s]\n", email_info->to);
      if(email_info->content != NULL){
          printf("content length: %d\n", strlen(email_info->content));
          printf("content: [%s]\n",email_info->content);
          email_info->content_is_html = FALSE;
      }
      printf("\n\n"); 
   }
*/
   return result;
}

extern int __sina_receive_attachment(struct Http *http,struct Email_info *email_info){
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.sina.com.cn") == NULL)
      return 0; 
   if(strstr(http->absolute_uri,"/classic/base_download_att.php") == NULL)
       return 0;

    char *name;
    struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node));
    value->length = 0;
    value->data = NULL;

    name = "file_name";
    get_first_value_from_name(http,name,value);
    if(value->length > 0 && value->data != NULL){
        copy_into_email_info_member(&email_info->att_filename, value->data, value->length);
    }
    free_list_node(value);
    free(value);    

   if(http->matched_http != NULL && http->if_matched_http == HTTP_MATCH_YES){

       struct Http *another = http->matched_http;
       struct Entity_List *entity_list;
       struct Entity *entity;

       entity_list = another->entity_list;

       if(entity_list != NULL){
           entity = entity_list->head;
           while(entity != NULL){
              if(entity->entity_length > 0){
                copy_into_email_info_member(&email_info->attachment, entity->entity_content, entity->entity_length);
                email_info->att_length = entity->entity_length;
                result = 1;
                break;// find one,then quit circle
              }
              entity = entity->next;
           }
       }

   }
/*
   if(result == 1){
        printf("__sina_receive_attachment");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
        printf("\n\n");
   }
*/

   return result;
}
