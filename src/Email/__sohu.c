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

extern int __sohu_send_content(struct Http *http,struct Email_info *email_info){
   int result = 0;

    if(http->type != PATTERN_REQUEST_HEAD)
       return 0;
    if(strstr(http->host,"mail.sohu.com") == NULL)
       return 0; 
    //if(strstr(http->uri,"/bapp/98/mail") == NULL)
       //return 0;

    if( match_or_not("/bapp/(.*?)/mail",http->uri,strlen(http->uri)) == -1)
        return 0;

    char *name;
    struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node));
    value->length = 0;
    value->data = NULL;    

    name = "to";
    get_first_value_from_name(http,name,value);
    if(value->length > 0 && value->data != NULL){
        copy_into_email_info_member(&email_info->to, value->data, value->length);
    }
    free_list_node(value);
    
    value->length = 0;
    value->data = NULL;
    name = "from";
    get_first_value_from_name(http,name,value);
    if(value->length > 0 && value->data != NULL){
        copy_into_email_info_member(&email_info->from, value->data, value->length);
    }
    free_list_node(value);

    value->length = 0;
    value->data = NULL;
    name = "subject";
    get_first_value_from_name(http,name,value);
    if(value->length > 0 && value->data != NULL){
        copy_into_email_info_member(&email_info->subject, value->data, value->length);
    }
    free_list_node(value);

    value->length = 0;
    value->data = NULL;
    name = "html";
    get_first_value_from_name(http,name,value);
    if(value->length > 0 && value->data != NULL){
        struct List_Node *value_modify = (struct List_Node *)malloc(sizeof(struct List_Node)); 
        add_html_head_tail(value->data, value->length,value_modify);
        copy_into_email_info_member(&email_info->content, value_modify->data, value_modify->length);
        free_list_node(value_modify);
        free(value_modify); 
        result = 1;
    }
    free_list_node(value);

    free(value);
  /*
    if(result == 1){
       printf("__sohu_send_content\n");
	   printf("from : [%s]\n", email_info->from);
	   printf("subject : [%s]\n", email_info->subject);
       printf("to : [%s]\n", email_info->to);
	   printf("content length : %d\n", strlen(email_info->content));
       printf("content : [%s]\n",email_info->content);
       printf("\n\n");
   }
*/
    return result;
}


extern int __sohu_send_attachment(struct Http *http,struct Email_info *email_info){
   
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.sohu.com") == NULL)
      return 0; 
   //if(strstr(http->absolute_uri,"/bapp/98/mail/att") == NULL)
       //return 0;

   if( match_or_not("/bapp/(.*?)/mail/att",http->uri,strlen(http->uri)) == -1)
        return 0;

   struct Entity_List *entity_list;
   struct Entity *entity;

   entity_list = http->entity_list;

   if(entity_list != NULL){

        entity = entity_list->head;
        while(entity != NULL){

            if(entity->entity_length <= 0 || entity->entity_length > 1024*1024*100){
                  printf("entity_length is too long %d\n", entity->entity_length);
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

            if( strstr(entity->content_disposition_struct.name,"upload_file") != NULL){
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
        printf("__sohu_send_attachment\n");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
        printf("\n\n");
   }
*/
   return result;

}


extern int __sohu_receive_content(struct Http *http,struct Email_info *email_info){
   
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.sohu.com") == NULL)
      return 0; 
   //if(strstr(http->uri,"/bapp/128/mail") == NULL)
       //return 0;

   if( match_or_not("/bapp/(.*?)/mail",http->uri,strlen(http->uri)) == -1)
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

                cJSON *content_json,*envelope_json,*from_json,*to_json,*subject_json;
                char *content,*from,*to,*subject;

                content_json  = cJSON_GetObjectItem(root,"display");
                if(content_json != NULL){
                     content = content_json->valuestring;
                     if(content != NULL && strlen(content) > 0)
                         copy_into_email_info_member(&email_info->content, content, strlen(content)); 
                }

                envelope_json = cJSON_GetObjectItem(root,"envelope");
                if(envelope_json != NULL){

                     cJSON *to_array = cJSON_GetObjectItem(envelope_json,"to");
                     cJSON *to_point;
                     char to[1000];
                     memset(to,0,1000*sizeof(char));
                     for(to_point = to_array->child;to_point; to_point = to_point->next){

                         cJSON *one_to_json_point;
                         for(one_to_json_point = to_point->child; one_to_json_point; one_to_json_point = one_to_json_point->next){
                              strcat(to,one_to_json_point->valuestring);
                              strcat(to,";");
                         }
                     }
                     if(to != NULL && strlen(to) > 0)
                     copy_into_email_info_member(&email_info->to, to, strlen(to)); 


                     cJSON *from_array = cJSON_GetObjectItem(envelope_json,"from");
                     cJSON *from_point;
                     char from[1000];
                     memset(from,0,1000*sizeof(char));
                     for(from_point = from_array->child;from_point; from_point = from_point->next){

                         cJSON *one_from_json_point;
                         for(one_from_json_point = from_point->child; one_from_json_point; one_from_json_point = one_from_json_point->next){
                              strcat(from,one_from_json_point->valuestring);
                              strcat(from,";");
                         }
                     }
                     if(from != NULL && strlen(from) > 0)
                           copy_into_email_info_member(&email_info->from, from , strlen(from)); 

                     subject_json = cJSON_GetObjectItem(envelope_json,"subject");
                     if(subject_json != NULL){
                         subject = subject_json->valuestring;
                         if(subject != NULL && strlen(subject) > 0)
                         copy_into_email_info_member(&email_info->subject, subject, strlen(subject)); 
                     }

                }

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
      printf("__sohu_receive_content\n");
      if(email_info->from != NULL)  
          printf("from : [%s]\n", email_info->from);
      if(email_info->subject != NULL) 
          printf("subject : [%s]\n", email_info->subject);
      if(email_info->to != NULL) 
          printf("to : [%s]\n", email_info->to);
      if(email_info->content != NULL){
          printf("content length : %d\n", strlen(email_info->content));
          printf("content : [%s]\n",email_info->content);
          email_info->content_is_html = FALSE;
      }
      printf("\n\n"); 
   }
*/

   return result;
}

extern int __sohu_receive_attachment(struct Http *http,struct Email_info *email_info){
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.sohu.com") == NULL)
      return 0; 
   //if(strstr(http->uri,"/bapp/128/download") == NULL)
       //return 0;

   if( match_or_not("/bapp/(.*?)/download",http->uri,strlen(http->uri)) == -1)
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
        printf("__sohu_receive_attachment");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
   }
*/

   return result;
}
