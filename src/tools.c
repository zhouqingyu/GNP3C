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
#include <dirent.h>
#include <pcre.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "list.h"
#include "project.h"
#include "tools.h"
#include "cJSON.h"
#include "nids.h"
#include "./Email/email_attachment_match.h"

extern int read_file(char *file_path,struct File_data *file_data){
   struct stat buf;
   if(stat(file_path,&buf) < 0 ) {
       syslog(project_params.syslog_level,"get file (%s) stat error %s\n",file_path,strerror(errno));
       return -1;
   }
 
   int fd;
   fd= open(file_path,O_CREAT, S_IRWXU | S_IROTH | S_IXOTH | S_ISUID);
    if(fd == -1){
       syslog(project_params.syslog_level,"open file (%s) error %s\n",file_path,strerror(errno));
       return -1;
    }
 
    file_data->file_length = buf.st_size;
    file_data->content = (char *)malloc(buf.st_size * sizeof(char));
    memset(file_data->content,0,buf.st_size * sizeof(char));
    int len_actual_read = read(fd,file_data->content,buf.st_size);
    close(fd);

    if(len_actual_read<=0){
       syslog(project_params.syslog_level,"file's length %d <=0\n",len_actual_read);
       return -1;
    }
    return 0;
}

extern int create_dirctionary(char *current_dictionary){

    if(access(current_dictionary,0) == 0)
       remove(current_dictionary);

    int flag;
    DIR *d;
    if((d=opendir(current_dictionary)) == NULL){
       if( (flag = mkdir(current_dictionary,S_IRWXU )) == -1 ){
           syslog(project_params.syslog_level,"mkdir %s error:%s",current_dictionary,strerror(errno));
           return -1;
       }
       return 0;
    }
    else{
        closedir(d);
        return 0;
    }
}


extern int write_data_to_file(char file[],char *data,int data_length){
   int fp;
   if(access(file,0) == 0)
      fp = open(file,O_WRONLY|O_APPEND);
   else fp = open(file,O_WRONLY|O_CREAT);
   
   if(fp == -1){
      printf("open file to write data  failure %s %s\n",file,strerror(errno));
      return -1;
   }

   unsigned int write_number;
   write_number = write(fp,data,data_length);
   if(write_number == -1){
       printf("write data failure %s %s\n",file,strerror(errno));
   }
   close(fp);
   return 0;
}

extern int match_one_substr_no_mem(char *pattern,char *source,int length,char **result){

    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[100];

    regex = pcre_compile( pattern, options, &error, &erroffset, NULL);
    if( regex == NULL ){
        free(regex);
        return -1;
    }
       
    rc = pcre_exec( regex, NULL, source, length, 0, 0,ovector, 100);
    if ( rc != 2 )
         return -1;

    int substrlength = ovector[3] - ovector[2];
    if( substrlength != 0 ){
       *result = source + ovector[2];
    }else{
        free(regex);
        return -1;
    }
    
    free( regex );
    return substrlength;
}



extern int match_one_substr(char *pattern,char *source,int length,char *result){

    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[100];

    regex = pcre_compile( pattern, options, &error, &erroffset, NULL);
    if( regex == NULL ){
        free(regex);
        return -1;
    }
       
    rc = pcre_exec( regex, NULL, source, length, 0, 0,ovector, 100);
    if ( rc != 2 )
         return -1;

    int substrlength = ovector[3] - ovector[2];
    if( substrlength != 0 ){
       memcpy(result,source + ovector[2],substrlength);
    }else{
        free(regex);
        return -1;
    }
    
    free( regex );
    return substrlength;
}

void copy_into_email_info_member(char **mem, char *src, int len)
{
	*mem = (char*) malloc( len+1 );
	memset(*mem, 0, len+1); 
	memcpy(*mem, src, len);
}


extern int get_xml_string(const char *str_name, const char *source, 
								int len, char **ptr) 
{
	int ret_len = -1;
	char pattern[500];
	
	snprintf(pattern, sizeof(pattern), 
				"\\<string\\sname=\"%s\"\\>(.*?)\\</string\\>", str_name);
	ret_len = match_one_substr_no_mem(pattern, source, len, ptr);
	
	return ret_len;
}

extern int get_xml_string_match_to(const char *str_name, const char *source, 
								int len, char **ptr) 
{
	int ret_len = -1;
	char pattern[500];
	
	snprintf(pattern, sizeof(pattern), 
				"\\<array\\sname=\"%s\"\\>\\<string\\>(.*?)\\</string\\>\\</array\\>", str_name);
	ret_len = match_one_substr_no_mem(pattern, source, len, ptr);
	
	return ret_len;
}

extern int match_or_not(char *pattern,char *source,int length){
    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[100];

    regex = pcre_compile( pattern, options, &error, &erroffset, NULL);
    if( regex == NULL ){
        free(regex);
        return -1;
    }
       
    rc = pcre_exec( regex, NULL, source, length, 0, 0,ovector, 100);

    free(regex);
    if ( rc <= 0 )
         return -1;
    else return 0;
}


extern int match_strstr_position(char *pattern,char *source,int length){

    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[100];

    regex = pcre_compile( pattern, options, &error, &erroffset, NULL);
    if( regex == NULL ){
        free(regex);
        return -1;
    }
       
    rc = pcre_exec( regex, NULL, source, length, 0, 0,ovector, 100);

    free(regex);
    if ( rc <= 0 )
         return -1;
    else return ovector[0];
}

extern int min(int a,int b){

  if(a>b)
   return b;
  else return a;
}

extern struct Http_RR *clone_http_rr(struct Http_RR *source){
   if(source == NULL)
       return NULL;
   
   struct Http_RR *rr = (struct Http_RR *)malloc(sizeof(struct Http_RR));
   memset(rr,0,sizeof(struct Http_RR));
   if(rr == NULL)
       return NULL;

   if(source->request_list != NULL)
       rr->request_list = http_list_clone(source->request_list);
   if(source->response_list != NULL)
       rr->response_list = http_list_clone(source->response_list);
   
   return rr;
}

extern void http_init(struct Http *http){
          memset(http,0,sizeof(struct Http));
          http->matched_http = NULL;
          http->if_matched_http = HTTP_MATCH_NO;
          http->entity_list = NULL;
          http->parameter_list = NULL;
}

extern struct Http *clone_http(struct Http *source){
   if(source == NULL)
     return NULL;
  
   struct Http *http = (struct Http *)malloc(sizeof(struct Http));
   if(http == NULL)
     return NULL;

   http_init(http);
   memcpy(http,source,sizeof(struct Http));

   http->entity_list = entity_list_clone(source->entity_list);
   http->parameter_list = parameter_list_clone(source->parameter_list);


   if(source->head_for_match_length > 0 && source->head_for_match != NULL){
      http->head_for_match = (char *)malloc(source->head_for_match_length + 1);
      memset(http->head_for_match,0,source->head_for_match_length + 1);
      http->head_for_match_length = source->head_for_match_length;
      memcpy(http->head_for_match,source->head_for_match,source->head_for_match_length);
   }

   if(source->matched_http != NULL && source->if_matched_http == HTTP_MATCH_YES){
      http->if_matched_http == HTTP_MATCH_YES;
      http->matched_http = clone_http(source->matched_http);
   }

   return http;
}

extern struct Parameter *clone_parameter(struct Parameter *source){
   if(source == NULL)
      return NULL;

   struct Parameter *parameter = (struct Parameter *)malloc(sizeof(struct Parameter));
   if(parameter == NULL)
      return NULL;

   memset(parameter,0,sizeof(struct Parameter));

   parameter->name_length = source->name_length;
   parameter->name = (char *)malloc(parameter->name_length + 1);
   memset(parameter->name,0,parameter->name_length + 1);
   memcpy(parameter->name,source->name,source->name_length);

   parameter->value_length = source->value_length;
   parameter->value = (char *)malloc(parameter->value_length + 1);
   memset(parameter->value,0,parameter->value_length + 1);
   memcpy(parameter->value,source->value,source->value_length);

   return parameter;
}

extern struct Entity *clone_entity(struct Entity *source){
    if(source == NULL)
       return NULL;

    struct Entity *entity = (struct Entity *)malloc(sizeof(struct Entity));
    if(entity == NULL)
       return NULL;

    memset(entity,0,sizeof(struct Entity));
    memcpy(entity,source,sizeof(struct Entity));

    entity->entity_length = source->entity_length;
    entity->entity_content = (char *)malloc(entity->entity_length + 1);
    memset(entity->entity_content,0,entity->entity_length + 1);
    memcpy(entity->entity_content,source->entity_content,source->entity_length);

    return entity;
}

extern void free_http_rr(struct Http_RR *source){
    if(source == NULL)
        return;

    struct Http_List *request_list,*response_list;
    request_list = source->request_list;
    response_list = source->response_list;
       
    if(request_list != NULL){
       http_list_free(request_list);
       free(request_list);
    }

    if(response_list != NULL){
       http_list_free(response_list);
       free(response_list);
    }
}

extern void free_http(struct Http *http){
   if(http == NULL)
       return;
   
   struct Entity_List *entity_list;
   struct Parameter_List *parameter_list;

   entity_list = http->entity_list;
   parameter_list = http->parameter_list;

   if(entity_list != NULL){
      entity_list_free(entity_list);
      free(entity_list);
   }

   if(parameter_list != NULL){
      parameter_list_free(parameter_list);
      free(parameter_list);
   }

   if(http->head_for_match_length > 0 && http->head_for_match != NULL)
      free(http->head_for_match);

   if(http->matched_http != NULL && http->if_matched_http == HTTP_MATCH_YES)
      free_http(http->matched_http);
}

extern void free_entity(struct Entity *entity){
    free(entity->entity_content);
}

extern void free_parameter(struct Parameter * parameter){
    free(parameter->name);
    free(parameter->value);
}


extern void add_html_head_tail(char *data,int length,struct List_Node *value){

   char *head = "<html><body>";
   char *tail = "</body></html>";
   
   int total_length = length + strlen(head) + strlen(tail) + 1;

   value->data = (char *)malloc(total_length);
   memset(value->data,0,total_length);
   memcpy(value->data,head,strlen(head));
   memcpy(value->data+strlen(head),data,length);
   memcpy(value->data+strlen(head)+length,tail,strlen(tail));
   value->length = total_length;
}


extern void printf_http_entity_parameter_info_detail(struct Http *http){

    if(http->type == PATTERN_RESPOND_HEAD)
        printf("Type : RESPONSE\n");
    else if(http->type == PATTERN_REQUEST_HEAD)
        printf("Type : REQUEST\n");
    else{ 
        printf("Type : Unknown\n");
        return;
    }

    printf("Host: [%s]\n",http->host);
    printf("Method:[%s]\n",http->method);
    printf("URI:[%s]\n",http->uri);
    printf("Absolute URI:[%s]\n",http->absolute_uri);
    if(strlen(http->mail_upload_name) > 0)
       printf("Mail-Upload-name:[%s]\n",http->mail_upload_name);
    struct Entity_List *entity_list;
    struct Parameter_List *parameter_list;
    
    entity_list = http->entity_list;
    parameter_list = http->parameter_list;

    struct Entity *entity;
    struct Parameter *parameter;

    if(entity_list != NULL){
        printf("Entity:\n");
        entity = entity_list->head;
        while(entity != NULL){

            printf("entity->entity_length = %d\n",entity->entity_length);

            if(entity->entity_length <= 0 || entity->entity_length > 1024*1024*100){
                  entity = entity->next;
                  printf("too long\n");
                  continue;
            }

            char *entity_content_buffer = (char *)malloc(entity->entity_length + 1);
            memset(entity_content_buffer,0,entity->entity_length + 1);
            memcpy(entity_content_buffer,entity->entity_content,entity->entity_length);

            print_content_disposition_detail(&(entity->content_disposition_struct));
            printf("type is [%s]\ncontent is [%s]\n\n",entity->entity_type,entity_content_buffer);
            
            
            entity = entity->next;
        }
    }

    if(http->type == PATTERN_REQUEST_HEAD && parameter_list != NULL){
         printf("Parameter:\n");
         parameter = parameter_list->head;
         while(parameter != NULL){
             printf("name is [%s]\nvalue is [%s]\n\n",parameter->name,parameter->value);
             parameter = parameter->next;
         }
    }


    printf("print detail end\n");
}


extern void print_content_disposition_detail(struct Content_Disposition *content_disposition_struct){

   if(strlen(content_disposition_struct->type) > 0)
        printf("content disposition type : [%s]\n",content_disposition_struct->type);

   if(strlen(content_disposition_struct->name) > 0)
        printf("content disposition name : [%s]\n",content_disposition_struct->name);

   if(strlen(content_disposition_struct->filename) > 0)
        printf("content disposition filename : [%s]\n",content_disposition_struct->filename);

}

extern int get_parameter(struct Parameter_List *parameter_list,char *name,struct List *value_list){
     struct Parameter *point;
    
     if(parameter_list == NULL)
          return 0;

     int flag = 0;     

     point = parameter_list->head;
     while(point != NULL){

         if( point->name != NULL && point->value != NULL && compare_mem(point->name,point->name_length,name,strlen(name)) == 0){
            flag = 1;
            wireless_list_add(value_list,point->value,point->value_length);
         }
         point = point->next;
     }

     return flag;
}

extern int compare_mem(char *target,int target_length,char *source,int source_length){
   
   if(target_length != source_length){
      return -1;
   }

   int length = target_length;
   int i;
   for(i=0; i< length; i++){
       if(*(target+i) != *(source+i))
           return -1;
   }

   return 0;

}


extern int if_contain_value(struct List *value_list,char *value,int value_length){
    
   if(value_list == NULL)
      return 0;

   struct List_Node *point = value_list->head;
   while(point != NULL){
      if(compare_mem(point->data,point->length,value,value_length) == 0){
         return 1;
      }

      point = point->next;
   }

   return 0;
}



extern int get_first_value_from_name(struct Http *http,char *name,struct List_Node *value){

    int result = 0;
    struct List *value_list = (struct List *)malloc(sizeof(struct List));
    wireless_list_init(value_list);
    result = get_parameter(http->parameter_list,name,value_list);
    if(!result)
         return 0;
	
	struct List_Node *ptr;
	for( ptr = (struct List_Node*)value_list->head; ptr; ptr = ptr->next) {
        value->length = ptr->length;
        value->data = (char *)malloc(ptr->length+1);
        memset(value->data,0,ptr->length+1);
        memcpy(value->data,ptr->data,ptr->length);
        result = 1;
		break;
	}

    wireless_list_free(value_list);
    free(value_list);
    return result; 
}


extern void free_list_node(struct List_Node *value){
 
   if(value == NULL)
       return;

   if(value->length > 0 && value->data != NULL)
         free(value->data);
}

extern void email_info_init(struct Email_info *email_info){
	memset(email_info, 0, sizeof(struct Email_info));
	email_info->from 			= NULL;
	email_info->to				= NULL;
	email_info->subject			= NULL;
	email_info->content			= NULL;
	email_info->att_filename	= NULL;
	email_info->attachment		= NULL;
    email_info->att_length      = 0;
    email_info->next			= NULL;
}

extern void email_info_free(struct Email_info *email_info)
{
	if (email_info->from != NULL) free(email_info->from);
	if (email_info->to != NULL) free(email_info->to);
	if (email_info->subject != NULL) free(email_info->subject);
	if (email_info->content != NULL) free(email_info->content);
    if (email_info->att_filename != NULL) free(email_info->att_filename);
    if (email_info->attachment != NULL) free(email_info->attachment);

    if(email_info->next != NULL){
        email_info_free(email_info->next);
        free(email_info->next);
    }
}


extern void print_email_detai(struct Email_info *email_info){

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
   		 
         printf("attachement length: %d\n", email_info->att_length);

   		 if(email_info->att_filename != NULL) 
              printf("attachement name: [%s]\n",email_info->att_filename);
         else printf("attachement name: [NULL]\n");

         if(email_info->attachment != NULL)
   		      printf("attachement: [%s]\n",email_info->attachment);
         else printf("attachement: [NULL]\n");
                    
         printf("\n\n");

}

int pcre_matall(const char *pattern, const char *source, int src_len, int *ovector, int ov_size, int options)
{
      pcre *regex = NULL;
      const char *error = NULL;
      int erroffset, rc, mat_count = 0, i_temp[300] = {0}, endoffset = 0;
      
      if(strlen(pattern)==0)
      {
          return mat_count;
      }
      do
      {
       /* compile regex_pattern */
          regex = pcre_compile( pattern, options, &error, &erroffset, NULL);

       /* fail to compile, export error */
          if( regex == NULL )
          {    
              free( regex );
              return -28;
          }
                
       /* execute matching */ 
          rc = pcre_exec( regex, NULL, source + endoffset, src_len - endoffset, 0, 0, i_temp, sizeof(i_temp)/sizeof(int) );

       /* release storage of regex */
          free( regex );
          
          if(rc > 0)
          {
              if( ov_size < 2 * mat_count + 2 )
              {
                  return -29;
              }
              ovector[2 * mat_count] = i_temp[0] + endoffset;
              ovector[2 * mat_count + 1] = i_temp[1] + endoffset;
              endoffset += i_temp[1];
              mat_count++;
          }          
          
      }while(rc > 0);
      
      return mat_count;      
}

int pcre_match(char *pattern,const char *source, int length, int ovector[], 
	       int ov_size, int options) 
{
  pcre *regex = NULL;
  const char *error = NULL;
  int erroffset, rc;
  
  regex = pcre_compile(pattern, options, &error, &erroffset, NULL);
  if ( regex == NULL ) {
    free(regex);
    return -28;
  }
  rc = pcre_exec( regex, NULL, source, length, 0, 0, ovector, ov_size);
  free(regex);
  
  return rc;
}

extern int pcre_repl_all(const char *pattern, const char *replacement, 
			 char *source, int src_len, int options) 
{
  pcre *regex = NULL;
  const char *error = NULL;
  int ovector[60], erroffset, i = -1;
  int rc;
  
  do {
    regex = pcre_compile( pattern, options, &error, &erroffset, NULL);
    if( regex == NULL )
    {      
      free( regex );
      return -28;
    }
    rc = pcre_exec( regex, NULL, source, src_len, 0, 0, ovector, 60);
    free( regex );
    
    if( rc > 0 ) {
      int l1 = strlen(replacement);
      int l2 = ovector[1] - ovector[0];
      
      if ( l1 > l2 )
	source = (char*)realloc( source, src_len + l1 - l2 );
      memmove(source + ovector[1] + l1 - l2, source + ovector[1], 
	      src_len - ovector[1]);
      memcpy(source + ovector[0], replacement, l1);
      i = src_len + l1 - l2;
    } else {
      break;
    }  
  } while (1);
  
  return i;
}

extern int pcre_repl(const char *pattern, const char *replacement, const char *source, int src_len, char *buffer, int options)
{
      pcre *regex = NULL;
      const char *error = NULL;
      int ovector[30], erroffset, i = -1;
      int rc;
      
    /* compile regex_pattern */
      regex = pcre_compile( pattern, options, &error, &erroffset, NULL);
    /* fail to compile, export error */
      if( regex == NULL )
      {
           printf("PCER compilation failure at offset %d: %s\n", erroffset, error);       
           free( regex );
           return -28;
      }
     /* execute matching */ 
       rc = pcre_exec( regex, NULL, source, src_len, 0, 0, ovector, 30);
     /* release storage of regex */
       free( regex );
       
       if( rc > 0 )
       {
           char *dest = (char*)malloc( (src_len - ovector[1]) * sizeof(char) );
           memcpy(dest, source + ovector[1], src_len - ovector[1]);
           memcpy(buffer, source, ovector[0]);
           memcpy(buffer + ovector[0], replacement, strlen(replacement));
           memcpy(buffer + ovector[0] + strlen(replacement), dest, src_len - ovector[1]);
           i = src_len + strlen(replacement) - (ovector[1] - ovector[0]);
           free(dest);
       }
       return i;           
}


extern void print_json(cJSON *root){

   if(root == NULL){
      printf("json is null\n");
      return;
   }

   char *out;
   out = cJSON_Print(root);


   if(out != NULL){	
     printf("%s\n",out);

     free(out);
   }else printf("out is null\n");

}


extern int qp_decode(const char *in_str, int in_len, char *out_str)
{
    int out_len = 0, i = 0;
    char ch0, ch1, ch2;
    
    while( i < in_len )
    {
        if( in_str[i] == '\r' && in_str[i+1] == '\n')
        {
            i += 2;
            continue;
        }//skip \r\n
        ch0 = in_str[i];
        if( ch0 == '=' )
        {
            ch1 = in_str[i+1];
            if( ch1 == '\n' )
            {
                i += 2;
                continue;
            }
            ch2 = in_str[i+2];
            if( isxdigit(ch1) && isxdigit(ch2) )
            {
                out_str[out_len++] = (ch1>'9'?ch1-'A'+10:ch1-'0')*16+(ch2>'9'?ch2-'A'+10:ch2-'0');
                i += 3;
            }
            else 
            {
                out_str[out_len++] = ch0;
                i++;
            }
        }
        else 
        {
            out_str[out_len++] = ch0;
            i++;
        }
    }
    out_str[out_len] = '\0';
    return out_len;
}

extern int base64_decode(const char *in_str, int in_len, char *out_str)
{
    int i= 0, out_len = 0;
    
    char base64_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    while(i < in_len)
    {
        char a = strchr(base64_table, in_str[i]) - base64_table;
        char b = strchr(base64_table, in_str[i+1]) - base64_table;
        char c = strchr(base64_table, in_str[i+2]) - base64_table;
        char d = strchr(base64_table, in_str[i+3]) - base64_table;
        
        if( in_str[i] == '\r' && in_str[i+1] == '\n')
        {
            i += 2;
            continue;
        }// skip \r\n        
        else if( in_str[i+2] == '=' )
        {
           out_str[out_len++] = ((a<<2)&(0xfc)) + ((b>>4)&(0x3));
        }
        else if( in_str[i+3] == '=')
        {
           out_str[out_len++] = ((a<<2)&(0xfc)) + ((b>>4)&(0x3));
           out_str[out_len++] = ((b<<4)&(0xf0)) + ((c>>2)&(0x0f));
        }
        else
        {
           out_str[out_len++] = ((a<<2)&(0xfc)) + ((b>>4)&(0x3));           
           out_str[out_len++] = ((b<<4)&(0xf0)) + ((c>>2)&(0x0f));
           out_str[out_len++] = ((c<<6)&(0xc0)) + (d & (0x3f));
        }
        i += 4;
    }  
    out_str[out_len]='\0';
    
    return out_len;
}

extern int _7bit_decode(const unsigned char* pSrc, int nSrcLength, char* pDst) 
{     
	int nSrc;          
	int nDst;   
	int nByte; 
	unsigned char nLeft;   
 
	nSrc = 0;     
	nDst = 0;          
    nByte = 0;     
	nLeft = 0;          
	while(nSrc<nSrcLength) {         
		*pDst = ((*pSrc << nByte) | nLeft) & 0x7f;                  
		nLeft = *pSrc >> (7-nByte);              
		pDst++;         
		nDst++;              
		nByte++;       
     	if(nByte == 7) {             
	    	*pDst = nLeft;                              
			pDst++;             
			nDst++;                         
			nByte = 0;             
			nLeft = 0;        
		}                      
		pSrc++;         
		nSrc++;     
	}          
	*pDst = 0;             
	return nDst; 
}


int url_decode(const char *src, int src_len, char *dest, int *dest_len)
{
    int i;
    *dest_len = 0;

    for (i = 0; i < src_len; i++)
    {
        if (src[i] == '%')
        {
            if (isxdigit(src[i + 1]) && isxdigit(src[i + 2]))
            {
                char c1 = src[++i];
                char c2 = src[++i];
                c1 = c1 - 48 - ((c1 >= 'A') ? 7 : 0) - ((c1 >= 'a') ? 32 : 0);
                c2 = c2 - 48 - ((c2 >= 'A') ? 7 : 0) - ((c2 >= 'a') ? 32 : 0);
                dest[(*dest_len)++] = (unsigned char)(c1 * 16 + c2);
            }
        }
        else
            if (src[i] == '+')
            {
                dest[(*dest_len)++] = ' ';
            }
            else
            {
                dest[(*dest_len)++] = src[i];
            }
    }
    return 1;
}


void email_reference_init(struct Email_reference *er) {
	
	INIT_LIST_HEAD(&er->list_node);
	er->reference = NULL;
	memset(er->email_id, 0, sizeof(er->email_id));
}

void email_reference_free(struct Email_reference *er) {
	if (er->reference != NULL)
		free(er->reference);
	free(er);
}










