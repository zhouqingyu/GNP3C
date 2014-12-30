#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <memory.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <fcntl.h>
#include <ctype.h>
#include <pcre.h>
#include <zlib.h>
#include <math.h>
#include <syslog.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>

#include "project.h"
#include "information_monitor_main.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "http_analysis.h"
#include "list.h"

#define LMIN 0
#define LMAX 9000000
#define OVECCOUNT 100

static char data[LMAX];
static char zipout[LMAX];
static uLong data_length;
static uLong zipout_length;
static char *patterns[PATTER_MAX];

static int httpgzdecompress(Byte *zdata, uLong nzdata,                 
        Byte *data, uLong *ndata);
static int mypow(int a, int b);
static int readhs(char *content,int *hsstr_length);
static uLong read_length_from_head(char * head);
static void *process_function(void *);
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);
static int analysis_entity(struct Entity *entity,struct Entity_List *entity_list);
static int put_http_rr_data_into_job(struct Job *new_job,struct Http_RR *rr);
static void manage_one_http_rr_data(struct Http_RR *rr, struct tuple4 *addr);
static struct Http *find_one_http(char *head_for_match,int head_for_match_length,struct Http_List *list);
int cmp( const void *a , const void *b);

/* HTTP gzip decompress */
static int httpgzdecompress(Byte *zdata, uLong nzdata,                 
        Byte *data, uLong *ndata){
    int err = 0;
    z_stream d_stream = {0}; /* decompression stream */
    static char dummy_head[2] = 
    {
        0x8 + 0x7 * 0x10,
        (((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
    };
    d_stream.zalloc = (alloc_func)0;
    d_stream.zfree = (free_func)0;
    d_stream.opaque = (voidpf)0;
    d_stream.next_in  = zdata;
    d_stream.avail_in = 0;
    d_stream.next_out = data;
    if(inflateInit2(&d_stream, 47) != Z_OK) { printf("inflateInit2 !=Z_OK\n"); return -1; }
    while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
        d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
        if((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
        if(err != Z_OK )
        {
            if(err == Z_DATA_ERROR)
            {
                d_stream.next_in = (Bytef*) dummy_head;
                d_stream.avail_in = sizeof(dummy_head);
                if((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK) 
                {
                    return -1;
                }
            }
            else {
             return -1;
            }
        }
    }
    if(inflateEnd(&d_stream) != Z_OK) {
     return -1;
    }
    *ndata = d_stream.total_out;
    return 0;
}

static int mypow(int a, int b){

  int result = 1;
  while(b--) result *=a;
  return result;
  
}

static int readhs(char *content,int *hsstr_length){
  int i;
  char hsbuffer[1000];
  int count=0;
  int index[500];
  int result = 0;

  memset(hsbuffer,0,sizeof(char)*1000);  

  index['0'] = 0;
  index['1'] = 1;
  index['2'] = 2;
  index['3'] = 3;
  index['4'] = 4;
  index['5'] = 5;
  index['6'] = 6;
  index['7'] = 7;
  index['8'] = 8;
  index['9'] = 9;
  index['a'] = 10;
  index['A'] = 10;
  index['b'] = 11;
  index['B'] = 11;
  index['c'] = 12;
  index['C'] = 12;
  index['d'] = 13;
  index['D'] = 13;
  index['e'] = 14;
  index['E'] = 14;
  index['f'] = 15;
  index['F'] = 15;
  
  i = 0;
  while(content[i] && content[i+1] && content[i+2]){

      if(count>10){
         result = LMAX;
         *hsstr_length = 0;
         return result;
      }
  
     if(content[i]!='\r' && content[i]!='\n')
         hsbuffer[count++] = content[i];
     if(content[i+1]=='\r' && content[i+2] =='\n')
         break; 
      i++;
  }
  for(i=0;i<count;i++)
  {
    if( (hsbuffer[i]>='0'&&hsbuffer[i]<='9') || (hsbuffer[i]>='a' && hsbuffer[i]<='f') || (hsbuffer[i]>='A' && hsbuffer[i]<='F') ){
     result = result + index[ hsbuffer[i] ] * mypow(16, count -i -1);
    }
    else{
        result = LMAX;
        break;
    }
  }
  *hsstr_length = count;
  
  if(result<LMIN || result>LMAX){
     result = LMAX;
     *hsstr_length = 0;
  }
  return result;
}

static uLong read_length_from_head(char * head){

    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[OVECCOUNT];
    char lengthstr[10];
    
    char * pattern_respond = "[cC][Oo][Nn][Tt][eE][nN][Tt]-[lL][Ee][Nn][Gg][Tt][Hh]:\\s*(\\d*)";
    
    /* compile regex_pattern */
    regex = pcre_compile( pattern_respond , options, &error, &erroffset, NULL);

    /* fail to compile, export error */
    if( regex == NULL ){   
           free( regex );
           return 0;
    }

    /* execute matching */ 

    rc = pcre_exec( regex, NULL, head, strlen(head), 0, 0,ovector, OVECCOUNT);


    /* fail to match */  
    if ( rc < 0 )
    {
         return 0;
    }
            
    /* match successfully */
    int substrlength = ovector[3] - ovector[2];
    if( substrlength != 0 )
    {         
      memset(lengthstr,0,sizeof(char)*10);
      memcpy(lengthstr,head+ovector[2],substrlength);
    }
    /* release storage of regex */ 
    free( regex );
   return atoi(lengthstr);
}

static int analysis_content_disposition(struct Entity *entity){

    if(strlen(entity->content_disposition)<=0)
        return 0;

    match_one_substr(patterns[PATTERN_CONTENT_DISPOSITION_TYPE], \
                     entity->content_disposition,\
                     strlen(entity->content_disposition),\
                     entity->content_disposition_struct.type);

    match_one_substr(patterns[PATTERN_CONTENT_DISPOSITION_NAME], \
                     entity->content_disposition,\
                     strlen(entity->content_disposition),\
                     entity->content_disposition_struct.name);

    match_one_substr(patterns[PATTERN_CONTENT_DISPOSITION_FILENAME], \
                     entity->content_disposition,\
                     strlen(entity->content_disposition),\
                     entity->content_disposition_struct.filename);
}

static void judge_and_remove_quotes(char *data,int *data_length){
   if(data[0] == '"' && data[*data_length -1 ] == '"'){
       char *temp = (char *)malloc(5000);
       memset(temp,0,sizeof(5000));
       memcpy(temp,data+1,*data_length-2);
       memset(data,0,*data_length);
       memcpy(data,temp,*data_length - 2);
       *data_length  = *data_length -2;
   }
}

static int analysis_entity_head(struct Entity *entity,char *head,int head_length){
     match_one_substr(patterns[PATTERN_CONTENT_TYPE],head,head_length,entity->entity_type);
     match_one_substr(patterns[PATTERN_CONTENT_DISPOSITION],head,head_length,entity->content_disposition);
   
    if(strlen(entity->content_disposition)>0)
        analysis_content_disposition(entity);
    if(strlen(entity->entity_type) <= 0)
        strcpy(entity->entity_type,"text/plain");
}

static int analysis_entity_self(struct Entity *entity){

    char *head = (char *)malloc(entity->entity_all_data_length);
    memset(head,0,entity->entity_all_data_length);
    int head_length = match_one_substr(patterns[PATTERN_ENTITY_HEAD],entity->entity_all_data,entity->entity_all_data_length,head);
    char *entity_content_buffer = (char *)malloc(entity->entity_all_data_length);
    memset(entity_content_buffer,0,entity->entity_all_data_length);
    entity->entity_length =  match_one_substr(patterns[PATTERN_ENTITY_BODY],entity->entity_all_data,entity->entity_all_data_length,\
                                              entity_content_buffer);

    if(entity->entity_length <= 0 )
         return -1;

    entity->entity_content = (char *)malloc(entity->entity_length + 1);

    memcpy(entity->entity_content,entity_content_buffer,entity->entity_length);

    free(entity_content_buffer);
    analysis_entity_head(entity,head,head_length);  
    free(head);

    return 0;
}


static int analysis_content_type_multipart(struct Entity *entity,struct Entity_List *entity_list){

    char boundary[5000];
    int boundary_length;
    memset(boundary,0,sizeof(boundary));
    match_one_substr(patterns[PATTERN_BOUNDARY],entity->entity_type,strlen(entity->entity_type),boundary);
    boundary_length = strlen(boundary);
    judge_and_remove_quotes(boundary,&boundary_length);

    if(strlen(boundary) <= 0){
       printf("no boundary\n");
       return -1;
    }

    char *buffer_all = (char *)malloc(entity->entity_length);
    int buffer_all_length;
    char all_chips_pattern[5000];
    memset(all_chips_pattern,0,sizeof(all_chips_pattern));
    sprintf(all_chips_pattern,"--%s\\s*\r\n(.*?)--%s--",boundary,boundary);
    buffer_all_length = match_one_substr(all_chips_pattern,entity->entity_content,entity->entity_length,buffer_all);

    char *current_buffer;
    int current_buffer_length;
    char part_pattern[5000];
    int current_position;
    int analysis_entity_self_result;
    memset(part_pattern,0,sizeof(part_pattern));
    sprintf(part_pattern,"--%s\\s*\r\n",boundary);

    current_buffer = buffer_all;
    current_buffer_length = buffer_all_length;
    while(current_buffer_length > 0 && (current_position = match_strstr_position(part_pattern,current_buffer,current_buffer_length)) != -1){

       struct Entity *new_entity = (struct Entity *)malloc(sizeof(struct Entity));
       memset(new_entity,0,sizeof(struct Entity));
       new_entity->entity_all_data_length = current_position - 0;
       new_entity->entity_all_data = (char *)malloc(new_entity->entity_all_data_length + 1);
       memset(new_entity->entity_all_data,0,new_entity->entity_all_data_length + 1);
       memcpy(new_entity->entity_all_data,current_buffer,new_entity->entity_all_data_length);

       analysis_entity_self_result = analysis_entity_self(new_entity);
       free(new_entity->entity_all_data);
       new_entity->entity_all_data_length = 0;

       if(analysis_entity_self_result == 0)
          analysis_entity(new_entity,entity_list);


       current_buffer = current_buffer + current_position + strlen(boundary)+2+2;
       current_buffer_length = current_buffer_length - (current_position + strlen(boundary)+2+2);
    }

    if(current_buffer_length <= 0)
        return 0;

    struct Entity *new_entity = (struct Entity *)malloc(sizeof(struct Entity));
    memset(new_entity,0,sizeof(struct Entity));
    new_entity->entity_all_data_length = current_buffer_length;
    new_entity->entity_all_data = (char *)malloc(new_entity->entity_all_data_length + 1);
    memset(new_entity->entity_all_data,0,new_entity->entity_all_data_length + 1); 
    memcpy(new_entity->entity_all_data,current_buffer,new_entity->entity_all_data_length);
    analysis_entity_self_result = analysis_entity_self(new_entity);
    free(new_entity->entity_all_data);
    new_entity->entity_all_data_length = 0;
    if(analysis_entity_self_result == 0)
        analysis_entity(new_entity,entity_list);
}


static void free_entity(struct Entity *entity){
    if(entity !=NULL && entity->entity_content != NULL)
        free(entity->entity_content);
    if(entity != NULL)
        free(entity);
}

static int analysis_entity(struct Entity *entity,struct Entity_List *entity_list){
     if(match_or_not("multipart",entity->entity_type,strlen(entity->entity_type)) != 0 ){
          entity_list_add(entity_list,entity);
          return 0;
     }else{
          int result = analysis_content_type_multipart(entity,entity_list);
          free_entity(entity);
          return result;
     }
}

static int url_decode(const char *src, int src_len, char *dest, int *dest_len)
{
    int i;
    *dest_len = 0;

    for (i = 0; i < src_len; i++)
    {
        if(i+5<src_len && src[i] =='%' && src[i+1] == '0' && (src[i+2] == 'D' || src[i+2]== 'd')\
        && src[i+3] == '%' && src[i+4] == '0' && (src[i+5] == 'A' || src[i=5] == 'a')){
             i= i+5; printf("meet \\r\\n in urlencode\n");
        }
        else if (src[i] == '%' && i+1 < src_len && i+2<src_len)
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
        else if (src[i] == '+'){
           dest[(*dest_len)++] = ' ';
        }else{
                dest[(*dest_len)++] = src[i];
        }
    }
    return 1;
}


static int read_one_item(char *point,int length,struct Parameter_List *list){

   int i;
   char *item,*name,*value;
   int name_length,value_length;
   int ilen = 0;
   int item_index = 0;

   item = (char *)malloc(length+1);
   name = (char *)malloc(length+1);
   value = (char *)malloc(length+1);

   memset(name,0,length+1);
   memset(value,0,length+1);
   memset(item,0,length+1);
   ilen = 0;


   for(i=0;i<length+1;i++){
     if(*(point+i) != '='&& *(point+i) != 0){
        item[ilen++] = *(point+i);
        continue;
     }

    if(item_index==0){
       name_length = ilen;
       memcpy(name,item,ilen);
    }
    else if(item_index == 1){
       value_length = ilen;
       memcpy(value,item,ilen);
    }

    item_index++;

    memset(item,0,length+1);
    ilen = 0;
  }

  char *decode_value_buffer = (char *)malloc(value_length+1);
  char *decode_value;
  int decode_value_length;

  memset(decode_value_buffer,0,value_length+1);
  url_decode(value, value_length, decode_value_buffer,&decode_value_length);
  
  decode_value = (char *)malloc(decode_value_length + 1);
  memset(decode_value,0,decode_value_length + 1);
  memcpy(decode_value,decode_value_buffer,decode_value_length);
  free(decode_value_buffer);
  
  struct Parameter *parameter = (struct Parameter *)malloc(sizeof(struct Parameter));
  memset(parameter,0,sizeof(struct Parameter));

  parameter->name = name;
  parameter->name_length = name_length;
  parameter->value = decode_value;
  parameter->value_length = decode_value_length;
  parameter->next = NULL;

  parameter_list_add(list,parameter);

  free(item);
  free(value);
}

static int seperate_parameter_from_content(char *point,int length,struct Parameter_List *list){
   int i;
   char *item;
   int ilen=0;

   item = (char *)malloc(length+1);
   memset(item,0,length+1);
   ilen = 0;

   for(i=0;i<length+1;i++){
     if(*(point+i) != '&'&& *(point+i) != 0){
        item[ilen++] = *(point+i);
        continue;
     }

     if(strstr(item,"=") != NULL){
         read_one_item(item,ilen,list);
     }else{
     }
     
     memset(item,0,length+1);
     ilen = 0;
   }

   free(item);

}

static int generate_parameter_list(struct Http *http){

   if(http->type == PATTERN_RESPOND_HEAD)
         return 0;

   http->parameter_list = (struct Parameter_List *)malloc(sizeof(struct Parameter_List));
   parameter_list_init(http->parameter_list);

   if(strlen(http->uri) > 0 && strstr(http->uri,"?") != NULL){
      char *buffer = (char *)malloc(strlen(http->uri));
      int buffer_length;
      memset(buffer,0,strlen(http->uri));
      buffer_length = match_one_substr(patterns[PATTERN_URI_PARAMETER],http->uri,strlen(http->uri),buffer);
      seperate_parameter_from_content(buffer,buffer_length,http->parameter_list);
      free(buffer);
   }

   if(http->entity_list != NULL){
        struct Entity *point = http->entity_list->head;
        while(point != NULL){
          if(point->entity_content != NULL &&  \
             match_or_not("x-www-form-urlencoded",point->entity_type,strlen(point->entity_type)) == 0 )
                 seperate_parameter_from_content(point->entity_content,point->entity_length,http->parameter_list);
            point = point->next;
        }
   }
}

static int generate_entity_list(struct Http *http){

     if(http->http_packet_length <= 0 ||http->http_packet == NULL){
         http->entity_list = NULL;
         return 0;
     }

     if(strlen(http->content_type) == 0){
        strcpy(http->content_type,"application/octet-stream");
     }

     http->entity_list = (struct Entity_List *)malloc(sizeof(struct Entity_List));
     entity_list_init(http->entity_list);

     struct Entity *entity = (struct Entity *)malloc(sizeof(struct Entity));
     memset(entity,0,sizeof(struct Entity));
     strcpy(entity->entity_type,http->content_type);
     strcpy(entity->content_disposition,http->content_disposition);
     entity->entity_length = http->http_packet_length;
     entity->entity_content = (char *)malloc(entity->entity_length + 1);
     memset(entity->entity_content,0,entity->entity_length + 1);
     memcpy(entity->entity_content,http->http_packet,entity->entity_length);
     if(strlen(entity->content_disposition)>0)
         analysis_content_disposition(entity);
     analysis_entity(entity,http->entity_list);
}

static int analysis_content_encoding(struct Http *http){
     if(strlen(http->content_encoding) <=0)
         return -1;
     if(match_or_not("[Gg][Zz][Ii][Pp]",http->content_encoding,strlen(http->content_encoding)) == 0 ){
        //gzip
        //printf("gzip\n");
        zipout_length = LMAX;
        memset(zipout,0,sizeof(char)*LMAX);  
        if(httpgzdecompress(http->http_packet, http->http_packet_length, zipout, &zipout_length) == 0 ){
	    free(http->http_packet);
            http->http_packet = (char *)malloc(zipout_length+1);
            memset(http->http_packet,0,zipout_length+1);
            memcpy(http->http_packet,zipout,zipout_length);
            http->http_packet_length = zipout_length;
	}else{
            //printf("httpdzdecompress error\n"); 
            return -1;  
        }
        return 0;
     }

     if(match_or_not("[Cc][Oo][Mm][Pp][Rr][Ee][Ss][Ss]",http->content_encoding,strlen(http->content_encoding)) == 0 ){
        //gzip
        //printf("compress\n");
        return 0;
     }

     if(match_or_not("[Dd][Ee][Ff][Ll][Aa][Tt][Ee]",http->content_encoding,strlen(http->content_encoding)) == 0 ){
        //gzip
        //printf("deflate\n");
        return 0;
     }


     if(match_or_not("[Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy]",http->content_encoding,strlen(http->content_encoding)) == 0 ){
        //gzip
        //printf("identity\n");
        return 0;
     }

     return 0;
     
}

static int analysis_http_length_and_transfer_encoding(struct Http *http,char *source,int start_position,int head_length,int total_length){

  if(http->type == PATTERN_REQUEST_HEAD && strstr(http->method,"GET") != NULL){
      http->http_packet_length = 0;
      http->http_packet = NULL;
      return 0;
  }

  if(strlen(http->content_length)>0){
     
      http->http_packet_length = min( atoi(http->content_length), total_length - start_position - head_length);

      if(http->http_packet_length <=0 ){
         http->http_packet_length = 0;
         http->http_packet = NULL;
         return 0;
      }

      http->http_packet = (char *)malloc(http->http_packet_length+1);
      memset(http->http_packet,0,http->http_packet_length+1);
      memcpy(http->http_packet, source + start_position + head_length,http->http_packet_length);
      return 0;
  }


  if(match_or_not("[Cc][Hh][Uu][Nn][Kk][Ee][Dd]",http->transfer_encoding,strlen(http->transfer_encoding)) == 0){
      int this_position = start_position + head_length;
      int this_chunk_length;
      int hsstr_length=0;
      int p;
      int count_chunk = 0;
   
      memset(data,0,sizeof(char)*LMAX);
      data_length = 0;

      this_chunk_length = readhs(source + this_position,&hsstr_length);
      if(this_chunk_length == LMAX){
          http->http_packet_length = 0;
          http->http_packet = NULL;
          return 0;
      }
      this_position = this_position + hsstr_length + 2;

      while(this_chunk_length != 0){
          count_chunk++;
          if(total_length < this_position + this_chunk_length){
             break;
          }

          memcpy(data + data_length,source + this_position,this_chunk_length);
          data_length += this_chunk_length;

          this_position = this_position + this_chunk_length + 2;
          this_chunk_length = readhs(source + this_position,&hsstr_length);
          if(this_chunk_length == LMAX){
             break;
          }
          this_position = this_position + hsstr_length + 2;
     }//while     
 
     http->http_packet_length = data_length;
     http->http_packet = (char *)malloc(http->http_packet_length+1);
     memset(http->http_packet,0,http->http_packet_length+1);
     memcpy(http->http_packet, data,http->http_packet_length);
     return 0;
  }

  http->http_packet_length = 0;
  http->http_packet = NULL;
  return -1;
}

static void analysis_http_head(struct Http *http,char *head,int head_length){

   match_one_substr(patterns[PATTERN_TRANSFER_ENCODING],head,head_length,http->transfer_encoding);
   match_one_substr(patterns[PATTERN_CONTENT_TYPE],head,head_length,http->content_type);
   match_one_substr(patterns[PATTERN_CONTENT_LENGTH],head,head_length,http->content_length);
   match_one_substr(patterns[PATTERN_CONTENT_ENCODING],head,head_length,http->content_encoding);
   match_one_substr(patterns[PATTERN_CONTENT_DISPOSITION],head,head_length,http->content_disposition);
   match_one_substr(patterns[PATTERN_USER_AGENT],head,head_length,http->user_agent);
   match_one_substr(patterns[PATTERN_HOST],head,head_length,http->host);
   match_one_substr(patterns[PATTERN_REFERER],head,head_length,http->referer);
   match_one_substr(patterns[PATTERN_MAIL_UPLOAD_NAME],head,head_length,http->mail_upload_name);

   if(http->type == PATTERN_REQUEST_HEAD && strlen(http->uri) > 0){
       match_one_substr(patterns[PATTERN_ABSOLUTE_URI],http->uri,strlen(http->uri),http->absolute_uri);
   }
}


static void match_head_only_with_order(int pattern_type,char *source,int total_length,struct Http_List *list){

    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[OVECCOUNT];

    int result;

    regex = pcre_compile( patterns[pattern_type] , options, &error, &erroffset, NULL);
    if( regex == NULL ){
        free( regex );
        return;
    }
       
    now_position = 0;
    rc = 0;
    while(rc >=0){
          rc = pcre_exec( regex, NULL, source, total_length, now_position, 0,ovector, OVECCOUNT);
          now_position = ovector[1];

          if ( rc < 0 )
             continue;

          if(!( (rc == 3 && pattern_type == PATTERN_RESPOND_HEAD) || (rc ==4 && pattern_type == PATTERN_REQUEST_HEAD) ))
             continue;

          struct Http *http = (struct Http *)malloc(sizeof(struct Http));
          http_init(http);
          http->type = pattern_type;

          char *head = NULL;
          int head_length = 0;
          int start_position = 0;
          int total_head_length = 0;

          start_position = ovector[0];
          total_head_length = ovector[1] - ovector[0];

          http->head_for_match_length = min(total_head_length,total_length - start_position);
          http->head_for_match = (char *)malloc(http->head_for_match_length + 1);
          memset(http->head_for_match,0,http->head_for_match_length+1);
          memcpy(http->head_for_match,source + start_position,http->head_for_match_length);
          

          if(pattern_type == PATTERN_RESPOND_HEAD){
             strncpy(http->status,source + ovector[2],ovector[3] - ovector[2]);
             head_length = min(ovector[5] - ovector[4],total_length - 1 -ovector[4]);
             head = (char *)malloc(head_length+1);
             memset(head,0,head_length + 1);
             memcpy(head,source + ovector[4],head_length);

          }else if(pattern_type == PATTERN_REQUEST_HEAD){
             strncpy(http->method,source + ovector[2],ovector[3] - ovector[2]);
             strncpy(http->uri,source + ovector[4],ovector[5] - ovector[4]);
             head_length = min(ovector[7] - ovector[6],total_length -1 -ovector[6]);
             head = (char *)malloc(head_length+1);
             memset(head,0,head_length + 1);
             memcpy(head,source + ovector[6],head_length);
             
          }else{
                syslog(project_params.syslog_level,"Unknown pattern_type %d\n",pattern_type);
                free(http->head_for_match);
                free(http);
                continue;
          }

          if(head == NULL){
                free(http->head_for_match);
                free(http);
                continue;
          }

          http->start_position = start_position;
          analysis_http_head(http,head,head_length);
          free(head);

          http_list_add(list,http);
    }//while
    free( regex );
}

static void match_head(int pattern_type,char *source,int total_length,struct Http_List *list){

    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[OVECCOUNT];

    int result;

    regex = pcre_compile( patterns[pattern_type] , options, &error, &erroffset, NULL);
    if( regex == NULL ){
        free( regex );
        return;
    }
       
    now_position = 0;
    rc = 0;
    while(rc >=0){
          rc = pcre_exec( regex, NULL, source, total_length, now_position, 0,ovector, OVECCOUNT);
          now_position = ovector[1];

          if ( rc < 0 )
             continue;

          if(!( (rc == 3 && pattern_type == PATTERN_RESPOND_HEAD) || (rc ==4 && pattern_type == PATTERN_REQUEST_HEAD) ))
             continue;

          struct Http *http = (struct Http *)malloc(sizeof(struct Http));
          http_init(http);
          http->type = pattern_type;

          char *head = NULL;
          int head_length = 0;
          int start_position = 0;
          int total_head_length = 0;

          start_position = ovector[0];
          total_head_length = ovector[1] - ovector[0];
          
          http->head_for_match_length = min(total_head_length,total_length - start_position);
          http->head_for_match = (char *)malloc(http->head_for_match_length + 1);
          memset(http->head_for_match,0,http->head_for_match_length+1);
          memcpy(http->head_for_match,source + start_position,http->head_for_match_length);

          if(pattern_type == PATTERN_RESPOND_HEAD){
             strncpy(http->status,source + ovector[2],ovector[3] - ovector[2]);
             head_length = min(ovector[5] - ovector[4],total_length - 1 -ovector[4]);
             head = (char *)malloc(head_length+1);
             memset(head,0,head_length + 1);
             memcpy(head,source + ovector[4],head_length);

          }else if(pattern_type == PATTERN_REQUEST_HEAD){
             strncpy(http->method,source + ovector[2],ovector[3] - ovector[2]);
             strncpy(http->uri,source + ovector[4],ovector[5] - ovector[4]);
             head_length = min(ovector[7] - ovector[6],total_length -1 -ovector[6]);
             head = (char *)malloc(head_length+1);
             memset(head,0,head_length + 1);
             memcpy(head,source + ovector[6],head_length);
             
          }else{
                syslog(project_params.syslog_level,"Unknown pattern_type %d\n",pattern_type);
                free(http->head_for_match);
                free(http);
                continue;
          }

          if(head == NULL){
             free(http->head_for_match);
             free(http);
             continue;
          }

          http->start_position = start_position;
          analysis_http_head(http,head,head_length);
          free(head);

          result =  analysis_http_length_and_transfer_encoding(http,source,start_position,total_head_length,total_length);

          if(!(http->http_packet == NULL || http->http_packet_length <=0)){
               result =  analysis_content_encoding(http);
               result =  generate_entity_list(http);
               free(http->http_packet);
               http->http_packet_length = 0;
          }

          result = generate_parameter_list(http);
          
          http_list_add(list,http);

    }//while
    free( regex );
}

static void match_request_response(struct Http_RR *rr,char *source,int total_length){

      struct Http_List *list;
      list = (struct Http_List *)malloc(sizeof(struct Http_List));
      if(list == NULL)
            return;
      http_list_init(list);   

      struct Http *point;     

      match_head_only_with_order(PATTERN_RESPOND_HEAD,source,total_length,list);
      match_head_only_with_order(PATTERN_REQUEST_HEAD,source,total_length,list);
   
      struct Order_Http https[MAX_HTTP_ONE_PROMISC];
      struct Http *target_http;
      int order_number = 0;
      point = list->head;
      while(point != NULL){

          target_http = find_one_http(point->head_for_match,point->head_for_match_length,rr->request_list);
          if(target_http == NULL)
               target_http = find_one_http(point->head_for_match,point->head_for_match_length,rr->response_list);

          if(target_http == NULL){
              point = point->next;
              continue;
          }

          https[order_number].http = target_http;
          https[order_number].position = point->start_position;
          order_number++;          

          point = point->next;
      }

      struct Http_RR *rr_release = (struct Http_RR *)malloc(sizeof(struct Http_RR));
      rr_release->request_list = list;
      rr_release->response_list = NULL;
      free_http_rr(rr_release);
      free(rr_release);

      qsort(https,order_number,sizeof(struct Order_Http),cmp);

      int i;
      struct Http *another;
      for( i=0; i < order_number; i++){
         point = https[i].http;
         if( i != order_number - 1 && (point->type == PATTERN_REQUEST_HEAD )){
              another = https[i+1].http;
              if(another->type == PATTERN_RESPOND_HEAD){
                 point->matched_http = clone_http(another);
                 point->if_matched_http = HTTP_MATCH_YES;
              } 
         }
             
      }
}

int cmp( const void *a , const void *b){
    struct Order_Http *c = (struct Order_Http *)a;
    struct Order_Http *d = (struct Order_Http *)b;
    return c->position - d->position;
}

static struct Http *find_one_http(char *head_for_match,int head_for_match_length,struct Http_List *list){
  
    struct Http *point;    
    int compare_result; 
    point = list->head;
    while(point != NULL){

          compare_result = compare_mem(point->head_for_match,point->head_for_match_length,head_for_match,head_for_match_length);
          if(compare_result == 0)
             return point;        

          point = point->next;
    } 

    return NULL;
}

static void pattern_init(){
    patterns[PATTERN_RESPOND_HEAD] =  "HTTP/\\d\\.\\d[ ]+(\\d+)[ ]+.*?\r\n(.*?\r\n)\r\n";
    patterns[PATTERN_REQUEST_HEAD] = "(GET|POST)[ ]+([^ ]*?)[ ]+HTTP/\\d\\.\\d\r\n(.*?\r\n)\r\n";
    patterns[PATTERN_ACCEPT] = "Accept:\\s*(.*?)\r\n";
    patterns[PATTERN_ACCEPT_ENCODING] = "Accept-Encoding:\\s*(.*?)\r\n";
    patterns[PATTERN_ACCEPT_LANGUAGE] = "Accept-Language:\\s*(.*?)\r\n";
    patterns[PATTERN_CONTENT_ENCODING] = "Content-Encoding:\\s*(.*?)\r\n";
    patterns[PATTERN_CONTENT_LANGUAGE] = "Content-Language:\\s*(.*?)\r\n";
    patterns[PATTERN_CONTENT_LENGTH ] = "Content-Length:\\s*(\\d*)\r\n";
    patterns[PATTERN_CONTENT_TYPE] = "Content-Type:\\s*(.*?)\r\n";
    patterns[PATTERN_TRANSFER_ENCODING] = "Transfer-Encoding:\\s*(.*?)\r\n";
    patterns[PATTERN_CONTENT_DISPOSITION] = "Content-Disposition:\\s*(.*?)\r\n";
    patterns[PATTERN_BOUNDARY] = "boundary=([^?]*)";
    patterns[PATTERN_ENTITY_HEAD] = "(.*\r\n)\r\n";
    patterns[PATTERN_ENTITY_BODY] = "\r\n\r\n(.*)\r\n";
    patterns[PATTERN_URI_PARAMETER] = "\\?(.*)";
    patterns[PATTERN_USER_AGENT] = "User-Agent:\\s*(.*?)\r\n";
    patterns[PATTERN_HOST] = "Host:\\s*(.*?)\r\n";
    patterns[PATTERN_REFERER] = "Referer:\\s*(.*?)\r\n";
    patterns[PATTERN_ABSOLUTE_URI] = "(.*)\\?";
    patterns[PATTERN_MAIL_UPLOAD_NAME] = "Mail-Upload-name:\\s*(.*?)\r\n";
    patterns[PATTERN_CONTENT_DISPOSITION_TYPE] = "([^;\\s]*)";
    patterns[PATTERN_CONTENT_DISPOSITION_NAME] = "name=\"([^\"]*)\"";
    patterns[PATTERN_CONTENT_DISPOSITION_FILENAME] = "filename=\"([^\"]*)\"";


   

}

extern void http_analysis_init(){
    register_job(JOB_TYPE_HTTP_DECODING,process_function,process_judege,CALL_BY_TCP_DATA_MANAGE);
    pattern_init();
}

static void *process_function(void *arg){
   int job_type = JOB_TYPE_HTTP_DECODING;
   while(1){
       pthread_mutex_lock(&(job_mutex_for_cond[job_type]));
       pthread_cond_wait(&(job_cond[job_type]),&(job_mutex_for_cond[job_type]));
       pthread_mutex_unlock(&(job_mutex_for_cond[job_type]));
       
       process_function_actual(job_type);
    }
}

static void process_function_actual(int job_type){
   struct Job_Queue private_jobs;
   private_jobs.front = 0;
   private_jobs.rear = 0;
   get_jobs(job_type,&private_jobs);
   struct Job current_job;
   time_t nowtime;
   struct tcp_stream *a_tcp;

   while(!jobqueue_isEmpty(&private_jobs)){
          jobqueue_delete(&private_jobs,&current_job);

          struct Http_List *request_list,*response_list;
          request_list = (struct Http_List *)malloc(sizeof(struct Http_List));
          response_list = (struct Http_List *)malloc(sizeof(struct Http_List));

          if(request_list == NULL || response_list == NULL)
             continue;
        
          http_list_init(request_list);
          http_list_init(response_list);

          if(current_job.client_rev != NULL && current_job.client_rev->head != NULL && current_job.client_rev->head->data != NULL){
              match_head(PATTERN_RESPOND_HEAD,current_job.client_rev->head->data,current_job.client_rev->head->length,response_list);
          }

          if(current_job.server_rev != NULL && current_job.server_rev->head != NULL && current_job.server_rev->head->data != NULL){
              match_head(PATTERN_REQUEST_HEAD,current_job.server_rev->head->data,current_job.server_rev->head->length,request_list);
          }       

          if(response_list->head == NULL && request_list->head == NULL)
                continue;

          struct Http_RR *rr = (struct Http_RR *)malloc(sizeof(struct Http_RR));
          if(rr == NULL)
               continue;

          rr->request_list = request_list;
          rr->response_list = response_list;

          if(current_job.promisc != NULL && current_job.promisc->head != NULL && current_job.promisc->head->data != NULL){
             match_request_response(rr,current_job.promisc->head->data,current_job.promisc->head->length);
          }

          manage_one_http_rr_data(rr, &current_job.ip_and_port);
   }//while
}

static void manage_one_http_rr_data(struct Http_RR *rr, struct tuple4 *addr){

     if(rr == NULL)
         return;
    
     int job_type;
     for(job_type=0; job_type<JOB_NUMBER; job_type++){

        if(job_call_type[job_type] != CALL_BY_HTTP_ANALYSIS)
            continue;

        //if the job is unregister ingore the job
        if(!job_registed[job_type])
            continue;

        int judge_result = 0;//default is having no job
        struct Job new_job;
        new_job.judge_http_rr = rr;
        judge_result = job_judges[job_type](&new_job); 


        if(!judge_result)
           continue;

        if(!put_http_rr_data_into_job(&new_job,rr)){ // no need data 
           continue;
        }  
	memcpy(&new_job.ip_and_port, addr, sizeof(struct tuple4));
        pthread_mutex_lock(&(job_mutex_for_queue[job_type]));
        jobqueue_insert(&(job_queue[job_type]),&new_job);  // add job into job queue of job_type
        pthread_mutex_unlock(&(job_mutex_for_queue[job_type]));

        pthread_mutex_lock(&(job_mutex_for_cond[job_type]));
        pthread_cond_signal(&(job_cond[job_type])); // rouse job thread of job_type
        pthread_mutex_unlock(&(job_mutex_for_cond[job_type]));
   }

   free_http_rr(rr);
   free(rr);
}

static int put_http_rr_data_into_job(struct Job *new_job,struct Http_RR *rr){
    new_job->judge_http_rr =  NULL;
    new_job->http_rr = clone_http_rr(rr);
    
    if(new_job->http_rr == NULL)
      return 0;
    else return 1;
}

static int process_judege(struct Job *job){
   //have job return 1 or 0
   job->desport = 80;
   job->data_need = 4;
   return 1;
}
