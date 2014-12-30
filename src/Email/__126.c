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
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "project.h"
#include "tools.h"

static void analysis_126_send_content_xml(char *data,int data_length,struct Email_info *email_info);
static void analysis_126_send_xml_attrs_object(xmlNodePtr root,struct Email_info *email_info);

static void  analysis_126_send_xml_attrs_object(xmlNodePtr root,struct Email_info *email_info){

    char charset_info[100];
    memset(charset_info,0,sizeof(char) * 100);

    xmlNodePtr curr;
    xmlChar *value;
    for(curr = root->xmlChildrenNode;curr; curr = curr->next){
          value = xmlGetProp(curr,(const xmlChar *)"name");
          if(value == NULL){
                continue;
          }

          if(!xmlStrcmp(value,(const xmlChar *)"account")){
                xmlChar *account_xmlchar = xmlNodeGetContent(curr);                
                if(account_xmlchar == NULL)
                    continue;
                
                char *account = account_xmlchar;
                if(account != NULL && strlen(account) > 0)
                     copy_into_email_info_member(&email_info->from, account, strlen(account));
                xmlFree(account_xmlchar);  
          }

          if(!xmlStrcmp(value,(const xmlChar *)"charset")){
                xmlChar *charset_xmlchar = xmlNodeGetContent(curr);                
                if(charset_xmlchar == NULL)
                    continue;
                
                char *charset = charset_xmlchar;
                if(charset != NULL && strlen(charset) > 0)
                     memcpy(charset_info, charset, strlen(charset));
                xmlFree(charset_xmlchar);
                printf("charset is %s\n",charset_info);
          }

         if(!xmlStrcmp(value,(const xmlChar *)"subject")){
                xmlChar *subject_xmlchar = xmlNodeGetContent(curr);                
                if(subject_xmlchar == NULL)
                    continue;
                
                char *subject = subject_xmlchar;
                if(subject != NULL && strlen(subject) > 0)
                     copy_into_email_info_member(&email_info->subject, subject, strlen(subject));
                xmlFree(subject_xmlchar);  
         }
          

         if(!xmlStrcmp(value,(const xmlChar *)"content")){
                xmlChar *content_xmlchar = xmlNodeGetContent(curr);                
                if(content_xmlchar == NULL)
                    continue;
                
                char *content = content_xmlchar;
                if(content != NULL && strlen(content) > 0){

                  struct List_Node *value_modify = (struct List_Node *)malloc(sizeof(struct List_Node)); 
                  add_html_head_tail( content, strlen(content),value_modify);
                  copy_into_email_info_member(&email_info->content, value_modify->data, value_modify->length);
                  free_list_node(value_modify);
                  free(value_modify); 

               }
                xmlFree(content_xmlchar);  
         }

          if(!xmlStrcmp(value,(const xmlChar *)"to")){

                char tos[1000];
                memset(tos,0,sizeof(char)*100);
                xmlNodePtr to_point;
                for(to_point = curr->xmlChildrenNode; to_point; to_point = to_point->next){
                     xmlChar *to_xmlchar = xmlNodeGetContent(to_point);                
                     if(to_xmlchar == NULL)
                         continue;
                
                     char *to = to_xmlchar;
                     if(to != NULL && strlen(to) > 0){
                            strcat(tos, to);
                            strcat(tos,";");
                     }
                     xmlFree(to_xmlchar);  
                }

                copy_into_email_info_member(&email_info->to, tos, strlen(tos));
          }
            
         xmlFree(value);
      }
}

static void analysis_126_send_content_xml(char *data,int data_length,struct Email_info *email_info){

   xmlDocPtr docptr = xmlParseMemory(data, data_length);
   xmlNodePtr root = xmlDocGetRootElement(docptr);
   xmlNodePtr curr;
   xmlChar *value;

   curr = root;
   if(xmlStrcmp(curr->name,(const xmlChar *)"object"))
         return;   

   for(curr = root->xmlChildrenNode;curr; curr = curr->next){
         value = xmlGetProp(curr,(const xmlChar *)"name");
         if(value == NULL){
               xmlFree(value);
               continue;
         }

         if(!xmlStrcmp(value,(const xmlChar *)"attrs")){
               analysis_126_send_xml_attrs_object(curr,email_info);              
         }            
         xmlFree(value);
    }

}


extern int __126_send_content(struct Http *http,struct Email_info *email_info) {

    if(strstr(http->host,"mail.126.com") == NULL)
         return 0;
    if(strstr(http->method,"POST") == NULL)
         return 0;

    char *name = "action";
    struct List *action_value_list = (struct List *)malloc(sizeof(struct List));
    wireless_list_init(action_value_list);
    int result = get_parameter(http->parameter_list,name,action_value_list);
    if(!result){
         wireless_list_free(action_value_list);
         free(action_value_list);
         return 0;
    }

    char *target_value = "deliver";
    int target_value_length = strlen(target_value);

    if(!if_contain_value(action_value_list,target_value,target_value_length)){
         wireless_list_free(action_value_list);
         free(action_value_list);
         return 0;
    }

    wireless_list_free(action_value_list);
    free(action_value_list);    

	name = "var";
    struct List *var_value_list = (struct List *)malloc(sizeof(struct List));
    wireless_list_init(var_value_list);
    result = get_parameter(http->parameter_list,name,var_value_list);
    if(!result)
         return 0;
	
	struct List_Node *ptr;
	for( ptr = (struct List_Node*)var_value_list->head; ptr; ptr = ptr->next) {


         if(ptr->length > 0 && ptr->data != NULL){
            analysis_126_send_content_xml(ptr->data, ptr->length,email_info);
            break;
         }
	}

    wireless_list_free(var_value_list);
    free(var_value_list);   
/*
	printf("[%s]\n", email_info->from);
	printf("[%s]\n", email_info->subject);
    printf("[%s]\n", email_info->to);
	printf("content length: %d\n", strlen(email_info->content));
    printf("content: [%s]\n",email_info->content);
*/
    return 1;
}

extern int __126_send_attachment(struct Http *http,struct Email_info *email_info){

   int result = 0;

   if(strstr(http->host,"mail.126.com") == NULL)
         return 0;
   if(strstr(http->method,"POST") == NULL)
         return 0;
   if(strlen(http->mail_upload_name) <= 0 && strstr(http->absolute_uri,"upload") == NULL)
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
/*
   if(result == 1){
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
   }
*/
   return result;
}

extern int __126_receive_content(struct Http *http,struct Email_info *email_info){  

   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.126.com") == NULL)
      return 0; 
   if(strstr(http->absolute_uri,"readhtml.jsp") == NULL)
       return 0;

   printf("find one 126 receive email\n");

   //printf_http_entity_parameter_info_detail(http);

   if(http->matched_http != NULL && http->if_matched_http == HTTP_MATCH_YES){

       //printf("find matched http\n");
       //printf_http_entity_parameter_info_detail(http->matched_http);

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

   }else printf("Don't find matched http\n");
/*
   if(result == 1){
      if(email_info->content != NULL){
        
          printf("content length: %d\n", strlen(email_info->content));
          printf("content: [%s]\n",email_info->content);
      }

   } 
*/
   return result;
}

extern int __126_receive_attachment(struct Http *http,struct Email_info *email_info){
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.126.com") == NULL)
      return 0; 
   if(strstr(http->absolute_uri,"readdata.jsp") == NULL)
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
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
   }
*/
   return result;
}
