#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<errno.h>
#include<memory.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/socket.h> //u_char
#include <dirent.h>
#include <pcre.h>

#include "project.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "list.h"
#include "tools.h"
#include "mime.h"

static void process_function_actual(int job_type);
static int process_judege(struct Job *job);
static void *process_function(void*);
static int hash_index;
#define OV_SIZE 300
static int get_user_pass(const int len, const char *source)
{
  const char *pointer = source;
  int ret, new_len = len;
  int ovector[OV_SIZE];

  ret = pcre_match("^(\\w+?)\\s+login\\s+(.+?@.+?)\\s+\"(.+)\"", 
		   pointer, new_len, ovector, OV_SIZE, 
		   PCRE_MULTILINE|PCRE_CASELESS|PCRE_NEWLINE_CRLF);
  if ( ret != 4 )
    return ret;

  printf("user : %.*s\n", ovector[5]-ovector[4], pointer+ovector[4]);
  printf("pass : %.*s\n", ovector[7]-ovector[6], pointer+ovector[6]);
  
  return ret;
}

static int is_response_err(const char *sign, int len) 
{
  int ovector[OV_SIZE];
  
  if ( pcre_match("ok", sign, len, ovector, OV_SIZE, 
		  PCRE_CASELESS) == 1 )
    return 0;
  else
    return 1;
}

static void tackle_command(const char *cmd, const char *ptr, 
			int len, int *ovector, int ov_size)
{
  char command[256], response[256], *tag;
  int ret, head, tail;
  
  sprintf(command, "^(\\w+?)\\s+%s\\s+\\d+\\s+\\"
    "(.+(?:body|all|fast|full|bodystructure|envelope).+\\)\r\n", cmd);
  
  do {
    struct Email_info email;
    
    email_info_init(&email);
    ret = pcre_match( command, ptr, len, ovector, ov_size, 
		      PCRE_MULTILINE|PCRE_CASELESS|
		      PCRE_NEWLINE_CRLF );
    if ( ret != 2 )
      break;
    head = ovector[1];
    tag = (char*)malloc( (ovector[3]-ovector[2]+1) * sizeof(char) );
    memset(tag, '\0', ovector[3]-ovector[2]+1);
    memcpy(tag, ptr + ovector[2], ovector[3]-ovector[2]);
    
    memset(response, '\0', sizeof(response));
    sprintf(response, "^%s\\s+(ok|no|bad).*?\r\n", tag);
    free(tag);
    ret = pcre_match( response, ptr, len, ovector, ov_size, 
		      PCRE_MULTILINE|PCRE_CASELESS|
		      PCRE_NEWLINE_CRLF ); 
    if ( is_response_err( ptr+ovector[2], ovector[3]-ovector[2]) ) {
      ptr += head;
      len -= head;
      continue;
    }
    tail = ovector[0];
    
    ret = pcre_match("\\((.*)\\)", 
		    ptr + head, tail - head, ovector, ov_size,
		    PCRE_CASELESS|PCRE_MULTILINE|PCRE_DOTALL|
		    PCRE_NEWLINE_CRLF);
    if ( ret != 2 ) {
      ptr += head;
      len -= head;
      continue;
    }
    strcpy(email.category,"Web Email");
    email.role = 0;    
    mime_entity(&email, ptr + head + ovector[2], ovector[3] - ovector[2]);
    sql_factory_add_email_record(&email, hash_index);
    email_info_free(&email);    
    ptr += tail;
    len -= tail;
  } while ( len != 0 );

}

static int analysis(const int len, const char *source)
{
  int ovector[OV_SIZE];
  
  tackle_command("uid fetch", source, len, ovector, OV_SIZE);
  tackle_command("fetch", source, len, ovector, OV_SIZE);
  
  return 0;
}


extern void imap_analysis_init(){
    register_job(JOB_TYPE_IMAP,process_function,process_judege,CALL_BY_TCP_DATA_MANAGE);
}

static void *process_function(void *arg){
   int job_type = JOB_TYPE_IMAP;
   while(1){
       pthread_mutex_lock(&(job_mutex_for_cond[job_type]));
       pthread_cond_wait(&(job_cond[job_type]),&(job_mutex_for_cond[job_type]));
       pthread_mutex_unlock(&(job_mutex_for_cond[job_type]));

       process_function_actual(job_type);
   }
   return NULL;
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
       
       hash_index = current_job.hash_index;
       get_user_pass(current_job.promisc->head->length,current_job.promisc->head->data);

       analysis(current_job.promisc->head->length,current_job.promisc->head->data);

       if(current_job.server_rev!=NULL){
          wireless_list_free(current_job.server_rev);
          free(current_job.server_rev);
       }

       if(current_job.client_rev !=NULL){
          wireless_list_free(current_job.client_rev);
          free(current_job.client_rev);
       }

       if(current_job.promisc != NULL){
          wireless_list_free(current_job.promisc);
          free(current_job.promisc);
       }
   }//while
}

static int process_judege(struct Job *job){
   job->desport = 143;
   job->data_need = 4;
   return 1;
}
