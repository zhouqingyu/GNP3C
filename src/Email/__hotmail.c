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
#include<errno.h>
#include<string.h>
#include<sys/socket.h>
#include<netpacket/packet.h> //reference  struct sockaddr_ll                                                                                   
#include<net/if.h> // reference struct ifreq
#include<linux/if_ether.h> // reference ETH_P_ALL
#include<sys/ioctl.h> // reference SIOCGIFINDEX	
#include <syslog.h>
#include <malloc.h>

#include "project.h"
#include "tools.h"

extern int __hotmail_send_content(struct Http *http,struct Email_info *email_info){

    if(strstr(http->host,"mail.live.com") == NULL)
         return 0;
    if(strstr(http->method,"POST") == NULL)
         return 0;
    if(strstr(http->absolute_uri,"/mail/SendMessageLight.aspx") == NULL)
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
           
            if( strstr(entity->content_disposition_struct.name,"fFrom") != NULL){
                  copy_into_email_info_member(&email_info->from, entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }

            if( strstr(entity->content_disposition_struct.name,"fTo") != NULL){
                  copy_into_email_info_member(&email_info->to, entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }

           if( strstr(entity->content_disposition_struct.name,"fSubject") != NULL){
                  copy_into_email_info_member(&email_info->subject, entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }
            

           if( strstr(entity->content_disposition_struct.name,"fMessageBody") != NULL){
                  copy_into_email_info_member(&email_info->content, entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }

            entity = entity->next;

        }
    }
/*
    printf("__hotmail_send_content\n");
	printf("from : [%s]\n", email_info->from);
	printf("subject : [%s]\n", email_info->subject);
    printf("to : [%s]\n", email_info->to);
	printf("content length : %d\n", strlen(email_info->content));
    printf("content : [%s]\n",email_info->content);
    printf("\n\n");
*/
    return 1;
}


extern int __hotmail_send_attachment(struct Http *http,struct Email_info *email_info){

   int result = 0;

   if(strstr(http->host,"mail.live.com") == NULL)
         return 0;
   if(strstr(http->method,"POST") == NULL)
         return 0;
   if(strstr(http->uri,"/mail/SilverlightAttachmentUploader.aspx") == NULL)
         return 0;

   struct Entity_List *entity_list;
   struct Entity *entity;

   entity_list = http->entity_list;

   if(entity_list != NULL){
        entity = entity_list->head;
        while(entity != NULL){
            if(entity->entity_content != NULL && entity->entity_length > 0){
                
                copy_into_email_info_member(&email_info->att_filename, http->mail_upload_name, strlen(http->mail_upload_name));
                copy_into_email_info_member(&email_info->attachment, entity->entity_content, entity->entity_length);
                email_info->att_length = entity->entity_length;
                result = 1;
                break;// find one,then quit circle
            }
            entity = entity->next;
        }
   }

   if(http->matched_http != NULL && http->if_matched_http == HTTP_MATCH_YES){
        struct Http *another = http->matched_http;
        //printf_http_entity_parameter_info_detail(another);
        //add more code to get name of attachment
        //...this need to analysis application/json format data
        //...
   }
/*
   if(result == 1){
        printf("__hotmail_send_attachment\n");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
        printf("\n\n");
    }
*/
   return result;
}


extern int __hotmail_receive_content(struct Http *http,struct Email_info *email_info){
   
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->method,"POST") == NULL)
      return 0;
   if(strstr(http->host,"mail.live.com") == NULL)
      return 0; 
   if(strstr(http->uri,"/mail/mail.fpp") == NULL)
      return 0;

   char *name;
   struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node));
   value->length = 0;
   value->data = NULL; 
   name = "cnmn";
   get_first_value_from_name(http,name,value);
   if(value->length > 0 && value->data != NULL){
        if(strstr(value->data,"GetInboxData") == NULL)
            result = 0;
        else result = 1;
   }
   free_list_node(value);
   free(value);    

   if(result == 0)
      return 0;


   if(http->matched_http != NULL && http->if_matched_http == HTTP_MATCH_YES){

       struct Http *another = http->matched_http;
       struct Entity_List *entity_list;
       struct Entity *entity;

       entity_list = another->entity_list;

       if(entity_list != NULL){
           entity = entity_list->head;
           while(entity != NULL){
              if(entity->entity_content != NULL && entity->entity_length > 0){
                
                struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node)); 
                add_html_head_tail(entity->entity_content, entity->entity_length,value);
                copy_into_email_info_member(&email_info->content, value->data, value->length);
                free_list_node(value);
                free(value); 
                result = 1;
                break;// find one,then quit circle
              }
              entity = entity->next;
           }
       }

   }
/*
   if(result == 1){
      printf("__hotmail_receive_content");
      if(email_info->from != NULL)  
          printf("[%s]\n", email_info->from);
      if(email_info->subject != NULL) 
          printf("[%s]\n", email_info->subject);
      if(email_info->to != NULL) 
          printf("[%s]\n", email_info->to);
      if(email_info->content != NULL){
          printf("content length: %d\n", strlen(email_info->content));
          printf("content: [%s]\n",email_info->content);
      }
      printf("\n\n");

      char file_name[100];
      memset(file_name,0,100);
      sprintf(file_name,"/home/safe/hotmail_receive_content.html_%d",strlen(email_info->content));

      write_data_to_file(file_name,email_info->content,strlen(email_info->content));
   }
*/

   return result;
}


extern int __hotmail_receive_attachment(struct Http *http,struct Email_info *email_info){
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
       return 0;
   if(strstr(http->uri,"/att/GetAttachment.aspx") == NULL)
       return 0;

   if(http->matched_http != NULL && http->if_matched_http == HTTP_MATCH_YES){

       struct Http *another = http->matched_http;
       struct Entity_List *entity_list;
       struct Entity *entity;

       entity_list = another->entity_list;

       if(entity_list != NULL){
           entity = entity_list->head;
           while(entity != NULL){
              if(entity->entity_content != NULL && entity->entity_length > 0){
                 
                if( strlen(entity->content_disposition_struct.filename) > 0)
                     copy_into_email_info_member(&email_info->att_filename, \
                                              entity->content_disposition_struct.filename, \
                                              strlen(entity->content_disposition_struct.filename));
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
        printf("__hotmail_receive_attachment");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
   }
*/
   return result;
}
