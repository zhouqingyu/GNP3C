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
#include "email_attachment_match.h"

extern int __qq_send_content(struct Http *http,struct Email_info *email_info, 
							struct Email_reference *email_reference) {
	struct Parameter_List *parameter_list;
    struct Parameter *parameter;
	
    if(strstr(http->host,"mail.qq.com") == NULL)
         return 0;
    if(strstr(http->method,"POST") == NULL)
         return 0;
    if(strstr(http->absolute_uri,"/cgi-bin/compose_send") == NULL)
         return 0;
	
	printf("__qq_send_content\n");
	//printf_http_entity_parameter_info_detail(http);
	
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
    name = "sendmailname";
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
    name = "content__html";
    get_first_value_from_name(http,name,value);
    if(value->length > 0 && value->data != NULL){
        copy_into_email_info_member(&email_info->content, value->data, value->length);
    }
    free_list_node(value);

    free(value);
    
    parameter_list = http->parameter_list;
    name = "upfilelist";
    if(http->type == PATTERN_REQUEST_HEAD && parameter_list != NULL){
        parameter = parameter_list->head;
        while(parameter != NULL) {
        	 if (strcmp(parameter->name, name) == 0) {
        	 	printf("name is [%s]\nvalue is [%d]-[%s]\n\n",parameter->name, strlen(parameter->value), parameter->value);
        	 	email_reference->reference = (char*)malloc( strlen(parameter->value) );
        	 	memcpy(email_reference->reference, parameter->value, strlen(parameter->value));
        	 	email_reference->ref_len = strlen(parameter->value);
        	 	break;
        	 }
             parameter = parameter->next;
        }
    }    
#if 0
    printf("__qq_send_content\n");
	printf("from : [%s]\n", email_info->from);
	printf("subject : [%s]\n", email_info->subject);
    printf("to : [%s]\n", email_info->to);
	printf("content length : %d\n", strlen(email_info->content));
    //printf("content : [%s]\n",email_info->content);
    printf("\n\n");
#endif
    return 1;
}


extern int __qq_send_attachment(struct Http *http,struct Email_info *email_info, 
								struct Email_reference *email_reference){
   

    int result = 0;

    if(strstr(http->method,"POST") == NULL)
         return 0;
    if(strstr(http->absolute_uri,"/cgi-bin/uploadfile") == NULL)
         return 0;

    printf("qq_send_attachment\n");
    //printf_http_entity_parameter_info_detail(http);

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
                  copy_into_email_info_member(&email_info->att_filename, entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }

            if( strstr(entity->content_disposition_struct.name,"UploadFile") != NULL){
                  copy_into_email_info_member(&email_info->attachment, entity->entity_content, entity->entity_length);
                  email_info->att_length = entity->entity_length;
                  entity = entity->next;
                  result = 1;
                  continue;
            }

            entity = entity->next;
        }
    }
  
    if(result == 0){

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
    }//another type format

 
    if(http->matched_http != NULL && http->if_matched_http == HTTP_MATCH_YES){

       struct Http *another = http->matched_http;
       struct Entity_List *entity_list;
       struct Entity *entity;

       entity_list = another->entity_list;

       if(entity_list != NULL){
           entity = entity_list->head;
           while(entity != NULL){
              if(entity->entity_length > 0){
              	char *pattern = "/data/(.*)";
              	char *start_point;
                int len;
                printf("*******client: %.*s\n", entity->entity_length, entity->entity_content);
                len = match_one_substr_no_mem(pattern, entity->entity_content, entity->entity_length, &start_point);
                
      			printf("*******sub str[len=%d]: %.*s\n", len, len, start_point);
      			email_reference->reference = (char*)malloc(len);
      			memcpy(email_reference->reference, start_point, len);
      			email_reference->ref_len = len;
                result = 1;
                break;// find one,then quit circle
              }
              entity = entity->next;
           }
       }

   }
    
/*
    if(result == 1){
        printf("__qq_send_attachment\n");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
        printf("\n\n");
    }
*/
    return result;
}

extern int __qq_receive_content(struct Http *http,struct Email_info *email_info, 
							struct Email_reference *email_reference) {
   
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.qq.com") == NULL)
      return 0; 
   if(strstr(http->absolute_uri,"/cgi-bin/readmail") == NULL)
       return 0;

	printf("qq_receive_content\n");	
	//printf_http_entity_parameter_info_detail(http);
	
   if(http->matched_http != NULL && http->if_matched_http == HTTP_MATCH_YES){

       struct Http *another = http->matched_http;
       struct Entity_List *entity_list;
       struct Entity *entity;

       entity_list = another->entity_list;

       if(entity_list != NULL){
           entity = entity_list->head;
           while(entity != NULL){
              if(entity->entity_length > 0){
                
                copy_into_email_info_member(&email_info->content, entity->entity_content, entity->entity_length);
                result = 1;
                break;// find one,then quit circle
              }
              entity = entity->next;
           }
       }

   }
   printf("email content : %s\n", email_info->content);

   if(result == 1){
      printf("__qq_receive_content");
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
      sprintf(file_name,"/home/safe/qq_receive_content.html_%d",strlen(email_info->content));

      write_data_to_file(file_name,email_info->content,strlen(email_info->content));
   }


   return result;
}

extern int __qq_receive_attachment(struct Http *http,struct Email_info *email_info, 
							struct Email_reference *email_reference) {
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.qq.com") == NULL)
      return 0; 
   if(strstr(http->absolute_uri,"/cgi-bin/download") == NULL)
       return 0;
   
   printf("qq_receive_attachment\n");
   //printf_http_entity_parameter_info_detail(http);
   
    char *name;
    struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node));
    name = "filename";
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
        printf("__qq_receive_attachment");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
        printf("\n\n");
   }
*/
   return result;
}
