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
#include <pcre.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>


#include "project.h"
#include "tools.h"
#include "cJSON.h"

static void analysis_xml_attrs_object(xmlNodePtr curr,struct Email_info *email_info);

extern int __139_send_content(struct Http *http,struct Email_info *email_info){
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
       return 0;
   if(strstr(http->host,"mail.10086.cn") == NULL)
       return 0; 
   if(strstr(http->absolute_uri,"/RmWeb/mail") == NULL)
       return 0;
   if(strstr(http->content_type,"xml") == NULL)
       return 0;

   char *name;
   struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node));
   value->length = 0;
   value->data = NULL;
   name = "func";
   get_first_value_from_name(http,name,value);
   if(value->length > 0 && value->data != NULL){
        if(strstr(value->data,"compose") != NULL)
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

            if(entity->entity_length <= 0 || entity->entity_length > 1024*1024*100){
                  break;
            }
          
            xmlDocPtr docptr = xmlParseMemory(entity->entity_content, entity->entity_length);
            xmlNodePtr root = xmlDocGetRootElement(docptr);
            xmlNodePtr curr;
            xmlChar *value;

            curr = root;
            if(xmlStrcmp(curr->name,(const xmlChar *)"object"))
              break;   


            for(curr = root->xmlChildrenNode;curr; curr = curr->next){
                value = xmlGetProp(curr,(const xmlChar *)"name");
                if(value == NULL){
                     xmlFree(value);
                     continue;
                }

                if(!xmlStrcmp(value,(const xmlChar *)"attrs")){
                     analysis_xml_attrs_object(curr,email_info);              
                }

                if(!xmlStrcmp(value,(const xmlChar *)"action")){

                     xmlChar *content = xmlNodeGetContent(curr);
                     if(xmlStrcmp(content,(const xmlChar *)"deliver")){
                         result = 0;
                     }else {
                         result = 1;
                     }
                }
            
                xmlFree(value);
            }
            break;
        }
    }
/*
   if(result == 1){
      printf("__139_send_content\n");

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

extern int __139_send_attachment(struct Http *http,struct Email_info *email_info){
   
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.10086.cn") == NULL)
      return 0; 
   if(strstr(http->uri,"/RmWeb/mail") == NULL)
       return 0;

   char *name;
   struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node));
   value->length = 0;
   value->data = NULL;
   name = "func";
   get_first_value_from_name(http,name,value);
   if(value->length > 0 && value->data != NULL){
        if(strstr(value->data,"attach:upload") != NULL)
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

            if(entity->entity_length <= 0 || entity->entity_length > 1024*1024*100){
                  entity = entity->next;
                  continue;
            }

            if( strstr(entity->content_disposition_struct.type,"form-data") == NULL ){
                  entity = entity->next;
                  continue;
            }
           
            if( strstr(entity->content_disposition_struct.name,"Filename") != NULL){
                  //copy_into_email_info_member(&email_info->att_filename,entity->entity_content, entity->entity_length);
                  entity = entity->next;
                  continue;
            }

            if( strstr(entity->content_disposition_struct.name,"Filedata") != NULL){
                  copy_into_email_info_member(&email_info->attachment, entity->entity_content, entity->entity_length);
                  email_info->att_length = entity->entity_length;
                  
                  if(strlen(entity->content_disposition_struct.filename) > 0)
                       copy_into_email_info_member(&email_info->att_filename,\
                                                   entity->content_disposition_struct.filename,\
                                                   strlen(entity->content_disposition_struct.filename));
                  entity = entity->next;
                  result = 1;
                  continue;
            }

            entity = entity->next;

        }
    }
/*
    if(result == 1){
        printf("__139_send_attachment\n");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
        printf("\n\n");
    }
*/

    return result;
 }
extern int __139_receive_content(struct Http *http,struct Email_info *email_info){
   
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.10086.cn") == NULL)
      return 0; 
   if(strstr(http->absolute_uri,"/RmWeb/mail") == NULL)
       return 0;

   char *name;
   struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node));
   value->length = 0;
   value->data = NULL;
   name = "func";
   get_first_value_from_name(http,name,value);
   if(value->length > 0 && value->data != NULL){
        if(strstr(value->data,"readMessage") != NULL)
            result = 1;
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
              if(entity->entity_length > 0){

                char *buffer = (char *)malloc((entity->entity_length +1) * sizeof(char));
                memset(buffer,0,(entity->entity_length +1) * sizeof(char));
                int i;
                for(i=0;i<entity->entity_length + 1;i++){
                    if(entity->entity_content[i] != '\'')
                       buffer[i] = entity->entity_content[i];
                    else buffer[i] = '\"';
                }
                
                cJSON *root = cJSON_Parse(buffer);
                //analysis content information,attachment information analysis later

                cJSON *var = cJSON_GetObjectItem(root,"var");
                cJSON *html = cJSON_GetObjectItem(var,"html");

                char *from = cJSON_GetObjectItem(var,"account")->valuestring;
                if(from != NULL && strlen(from) > 0)
                     copy_into_email_info_member(&email_info->from, from, strlen(from)); 

                char *to = cJSON_GetObjectItem(var,"to")->valuestring;
                if(to != NULL && strlen(to) > 0)
                     copy_into_email_info_member(&email_info->to, to, strlen(to)); 

                char *subject = cJSON_GetObjectItem(var,"subject")->valuestring;
                if(subject != NULL && strlen(subject) > 0)
                     copy_into_email_info_member(&email_info->subject, subject, strlen(subject)); 

                char *content = cJSON_GetObjectItem(html,"content")->valuestring;
                if(content != NULL && strlen(content) > 0)
                     copy_into_email_info_member(&email_info->content, content, strlen(content)); 

                cJSON_Delete(root);
                free(buffer);
                result = 1;
                break;// find one,then quit circle
              }
              entity = entity->next;
           }
       }

   }
/*

   if(result == 1){
      printf("__139_receive_content\n");
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
extern int __139_receive_attachment(struct Http *http,struct Email_info *email_info){
   int result = 0;

   if(http->type != PATTERN_REQUEST_HEAD)
      return 0;
   if(strstr(http->host,"mail.10086.cn") == NULL)
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
                 
                if( strstr(entity->content_disposition_struct.type,"attachment") && strlen(entity->content_disposition_struct.filename) > 0){
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

   }
/*
   if(result == 1){
        printf("__139_receive_attachment");
   		printf("attachement length: %d\n", email_info->att_length);
   		printf("attachement name: [%s]\n",email_info->att_filename);
   		printf("attachement: [%s]\n",email_info->attachment);
        printf("\n\n");
   }
*/
   return result;
}


static void  analysis_xml_attrs_object(xmlNodePtr root,struct Email_info *email_info){

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

          if(!xmlStrcmp(value,(const xmlChar *)"to")){
                xmlChar *to_xmlchar = xmlNodeGetContent(curr);                
                if(to_xmlchar == NULL)
                    continue;
                
                char *to = to_xmlchar;
                if(to != NULL && strlen(to) > 0)
                     copy_into_email_info_member(&email_info->to, to, strlen(to));
                xmlFree(to_xmlchar);  
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
            
         xmlFree(value);
      }
}

























