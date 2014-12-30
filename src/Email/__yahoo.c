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
#include "__yahoo.h"
#include "cJSON.h"

#define YAHOO_CONTENT_ANALYSIS_PATTERN "NeoConfig.prefetchObj=\\s(.*)"

static void analysis_yahoo_receive_content(struct Email_info *email_info, const char *source, int *ovector);
static void analysis_from_one_json(cJSON *point,struct Email_info *email_info);
static void analysis_part_array(cJSON *parts,struct Email_info *email_info);
static void analysis_head(cJSON *point,struct Email_info *email_info);
static void analysis_yahoo_send_content_from_one_json(cJSON *point,struct Email_info *email_info);

extern int __yahoo_send_content(struct Http *http,struct Email_info *email_info){
  
   int result = 0;

   if(strstr(http->host,"mail.yahoo.com") == NULL)
         return 0;
   if(strstr(http->method,"POST") == NULL)
         return 0;

   char *name;
   struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node));
   value->length = 0;
   value->data = NULL;
   name = "m";
   get_first_value_from_name(http,name,value);
   if(value->length > 0 && value->data != NULL){
        if(strstr(value->data,"SendMessage") != NULL)
            result = 1;
   }
   free_list_node(value);
   free(value);

   if(result == 0)
        return 0;

   struct Entity_List *entity_list;
   struct Entity *entity;

   entity_list = http->entity_list;

   if(entity_list != NULL){
        entity = entity_list->head;
        while(entity != NULL){
            if(entity->entity_content != NULL && entity->entity_length > 0){
                cJSON *root = cJSON_Parse(entity->entity_content); 

                //analysis content information,attachment information analysis later
                cJSON *params_array = cJSON_GetObjectItem(root,"params");
                if(params_array == NULL){
                    cJSON_Delete(root);
                    result = 0;
                    break;
                }
                int first = TRUE;
                struct Email_info *email_point,*email_before; 

                cJSON *point;
                if(params_array->type == cJSON_Array){
                      point = params_array->child;
                      while(point != NULL){
                                
                                if(first == TRUE){
                                   email_before = email_info;
                                   email_point = email_info;
                                }else{
                                   email_point = (struct Email_info *)malloc(sizeof(struct Email_info));
                                   email_info_init(email_point);
                                   
                                   email_before->next = email_point;
                                   email_before = email_point;
                                }

                                analysis_yahoo_send_content_from_one_json(point,email_point);
                                first = FALSE;
                                point = point->next;
                        }//while

                 }//if

                if(root != NULL)
                     cJSON_Delete(root);
                result = 1;
                break;
            }
            entity = entity->next;
        }
   }
/*
  if(result == 1){
      struct Email_info *email_point = email_info;
      for(email_point = email_info; email_point; email_point = email_point->next)
      { 
            printf("__yahoo_send_content\n");
            if(email_point->from != NULL)  
                  printf("from : [%s]\n", email_point->from);
            if(email_point->subject != NULL) 
                  printf("subject : [%s]\n", email_point->subject);
            if(email_point->to != NULL) 
                  printf("to : [%s]\n", email_point->to);
            if(email_point->content != NULL){
                  printf("content length : %d\n", strlen(email_point->content));
                  printf("content : [%s]\n",email_point->content);
            }
           printf("\n\n"); 
      }
   }
*/

   return result;
}
extern int __yahoo_send_attachment(struct Http *http,struct Email_info *email_info){
  
   int result = 0;

   if(strstr(http->host,"mail.yahoo.com") == NULL)
         return 0;
   if(strstr(http->method,"POST") == NULL)
         return 0;

   struct Entity_List *entity_list;
   struct Entity *entity;

   entity_list = http->entity_list;

   if(entity_list != NULL){
        entity = entity_list->head;
        while(entity != NULL){
            if(entity->entity_content != NULL && entity->entity_length > 0){


                if(  strstr(entity->content_disposition_struct.type,"form-data") && \
                     strlen(entity->content_disposition_struct.filename) > 0  && \ 
                     strstr(entity->content_disposition_struct.name,"Filedata")  ){
                
                       copy_into_email_info_member(&email_info->att_filename, \
                                              entity->content_disposition_struct.filename, \
                                              strlen(entity->content_disposition_struct.filename));
                       copy_into_email_info_member(&email_info->attachment, entity->entity_content, entity->entity_length);
                       email_info->att_length = entity->entity_length;
                       result = 1;
                       break;// find one,then quit circle
                }
            }
            entity = entity->next;
        }
   }
/*
   if(result == 1){
        printf("__yahoo_send_attachment\n");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
        printf("\n\n");
   }
*/

   return result;
}


extern int __yahoo_receive_content(struct Http *http,struct Email_info *email_info){
   
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.yahoo.com") == NULL)
      return 0; 
   if(strstr(http->absolute_uri,"/neo/launch") == NULL)
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

                char *json_buffer = (char *)malloc((entity->entity_length + 1) * sizeof(char));
                memset(json_buffer,0,(entity->entity_length + 1) * sizeof(char));

                if (match_one_substr(YAHOO_CONTENT_ANALYSIS_PATTERN,entity->entity_content, entity->entity_length,json_buffer) > 0){

                     cJSON *root = cJSON_Parse(json_buffer);               
                     cJSON *result_json = cJSON_GetObjectItem(root,"result");
                     cJSON *message_json = cJSON_GetObjectItem(result_json,"message");
                     int first = TRUE;
                     struct Email_info *email_point,*email_before; 
                     cJSON *point;

                     if(message_json->type == cJSON_Array){
                          point = message_json->child;
                          while(point != NULL){
                                
                                if(first == TRUE){
                                   email_before = email_info;
                                   email_point = email_info;
                                }else{
                                   email_point = (struct Email_info *)malloc(sizeof(struct Email_info));
                                   email_info_init(email_point);
                                   
                                   email_before->next = email_point;
                                   email_before = email_point;
                                }

                                analysis_from_one_json(point,email_point);
                                first = FALSE;
                                point = point->next;
                          }//while

                     }//if

                     if(message_json->type == cJSON_Object){
                          email_point = email_info;
                          point = message_json;
                          analysis_from_one_json(point,email_point);
                          first = FALSE;
                     }

                     result = 1;
                     cJSON_Delete(root);
                     free(json_buffer);
                     break;// find one,then quit circle
                }
                free(json_buffer);

              }
              entity = entity->next;
           }
       }

   }
/*
   if(result == 1){
      struct Email_info *email_point = email_info;
      for(email_point = email_info; email_point; email_point = email_point->next)
      { 
            printf("__yahoo_receive_content\n");
            if(email_point->from != NULL)  
                  printf("from : [%s]\n", email_point->from);
            if(email_point->subject != NULL) 
                  printf("subject : [%s]\n", email_point->subject);
            if(email_point->to != NULL) 
                  printf("to : [%s]\n", email_point->to);
            if(email_point->content != NULL){
                  printf("content length : %d\n", strlen(email_point->content));
                  printf("content : [%s]\n",email_point->content);
            }
           printf("\n\n"); 
      }
   }
*/

   return result;
}


extern int __yahoo_receive_attachment(struct Http *http,struct Email_info *email_info){
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
       return 0;
   if(strstr(http->absolute_uri,"securedownload") == NULL)
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
        printf("__yahoo_receive_attachment");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
   }
*/

   return result;
}

static void analysis_from_one_json(cJSON *point,struct Email_info *email_info){

        cJSON *head = cJSON_GetObjectItem(point,"header");
        cJSON *part_array = cJSON_GetObjectItem(point,"part");

        if(head != NULL){
             analysis_head(head,email_info);
        }
        if(part_array != NULL){
             analysis_part_array(part_array,email_info);
        }         
}

static void analysis_head(cJSON *point,struct Email_info *email_info){

        cJSON *from_json = cJSON_GetObjectItem(point,"from");
        if(from_json){
            char *from = cJSON_GetObjectItem(from_json,"email")->valuestring;
            if(from != NULL && strlen(from) > 0)
                  copy_into_email_info_member(&email_info->from, from, strlen(from)); 
        }

        cJSON *to_array = cJSON_GetObjectItem(point,"to");
        cJSON *to_point;
        char to[1000];
        memset(to,0,1000*sizeof(char));
        for(to_point = to_array->child;to_point; to_point = to_point->next){
            strcat(to,cJSON_GetObjectItem(to_point,"email")->valuestring);
            strcat(to,";");
        }
        if(to != NULL && strlen(to) > 0)
            copy_into_email_info_member(&email_info->to, to, strlen(to)); 

        char *subject = cJSON_GetObjectItem(point,"subject")->valuestring;
        if(subject != NULL && strlen(subject) > 0)
            copy_into_email_info_member(&email_info->subject, subject, strlen(subject)); 

}


static void analysis_part_array(cJSON *parts,struct Email_info *email_info){

     cJSON *point,*temp,*content_json;
     for(point = parts->child; point; point = point->next){
           if(( content_json = cJSON_GetObjectItem(point,"text") )!=NULL){
               char *content = content_json->valuestring;
               if(content != NULL && strlen(content) > 0)
                    copy_into_email_info_member(&email_info->content, content, strlen(content)); 
           }

           //other parts are attchment,analysis later
           //....
     }

}

static void analysis_yahoo_send_content_from_one_json(cJSON *point,struct Email_info *email_info){

     cJSON *message = cJSON_GetObjectItem(point,"message");
     if(message == NULL)
         return;

     analysis_head(message,email_info);

     cJSON *simplebody = cJSON_GetObjectItem(message,"simplebody");
     if(simplebody == NULL)
         return;

     cJSON *content_json = cJSON_GetObjectItem(simplebody,"html");
     if(content_json == NULL)
         return;

     char *content = content_json->valuestring;
     if(content != NULL && strlen(content) > 0)
         copy_into_email_info_member(&email_info->content, content, strlen(content)); 
}












