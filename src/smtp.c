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
static int pcre_cmp( char *pattern, const char *source, int len, 
		int options ) 
{
  int ret, ovector[OV_SIZE];
  
  options |= PCRE_CASELESS|PCRE_MULTILINE|PCRE_NEWLINE_CRLF;
  ret = pcre_match( pattern, source, len, ovector, OV_SIZE,
		    options );  
  if ( ret <= 0 ) return  1;
  else return 0;
}

static int get_user_pass(const int len, const char *source)
{
  const char *pointer = source;
  int new_len = len, ret;
  int ovector[OV_SIZE];
  char *username, *password, *u_temp, *p_temp;
  int u_len, utemp_len, p_len, ptemp_len;
  
  ret = pcre_match("^auth\\s+login\r\n"
		   "^334\\s+(.*?)\r\n"
		   "^(.*?)\r\n"
		   "^334\\s+(.*?)\r\n"
		   "^(.*?)\r\n"
		   "^235", 
		   pointer, new_len, ovector, OV_SIZE, 
		   PCRE_CASELESS|PCRE_MULTILINE|PCRE_NEWLINE_CRLF);
  if ( ret != 5 ) 
    return -1;
  
  u_temp = (char*)malloc( (ovector[3]-ovector[2] )*sizeof(char) );
  utemp_len = base64_decode(pointer + ovector[2], ovector[3] - 
			    ovector[2], u_temp);
  if ( pcre_cmp("username", u_temp, utemp_len, PCRE_CASELESS) != 0 ) {
    free(u_temp);
    return -1;
  }
  free(u_temp);
  username = (char*)malloc( (ovector[5]-ovector[4])*sizeof(char) );
  u_len = base64_decode(pointer + ovector[4], ovector[5] - ovector[4], 
			username);
  printf("username: %s\n", username);
  
  p_temp = (char*)malloc( (ovector[7]-ovector[6] )*sizeof(char) );
  ptemp_len = base64_decode(pointer + ovector[6], ovector[7] - 
			    ovector[6], p_temp);
  if ( pcre_cmp("password", p_temp, ptemp_len, PCRE_CASELESS) != 0 ) {
    free(p_temp);
    return -1;
  }
  free(p_temp);
  password = (char*)malloc( (ovector[9]-ovector[8])*sizeof(char) );
  p_len = base64_decode(pointer + ovector[8], ovector[9] - 
			    ovector[8], password);
  printf("password: %s\n", password);
  free(username);
  free(password);
  
  return 0;
}

static int analysis(const int len, const char *source)
{
  struct Email_info email;
  int ovector[OV_SIZE], ret;
  
  email_info_init(&email);
  ret = pcre_match("data\r\n"
		   "^354.*?\r\n" 
		   "^(.*?)\r\n\\.\r\n",
		   source, len, ovector, OV_SIZE,
		   PCRE_CASELESS|PCRE_MULTILINE|PCRE_NEWLINE_CRLF|
		   PCRE_DOTALL );
  if ( ret != 2 )
    return -1;
  strcpy(email.category,"Web Email");
  email.role = 0;
  mime_entity(&email, source + ovector[2], ovector[3] - ovector[2]);
  sql_factory_add_email_record(&email, hash_index);
  email_info_free(&email);
  
  return ret;
}

extern void smtp_analysis_init(){
    register_job(JOB_TYPE_SMTP,process_function,process_judege,CALL_BY_TCP_DATA_MANAGE);
}

static void *process_function(void *arg){
   int job_type = JOB_TYPE_SMTP;
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
       get_user_pass(current_job.promisc->head->length,
		     current_job.promisc->head->data);

       analysis(current_job.promisc->head->length,
		current_job.promisc->head->data);

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
   //have job return 1 or 0
   job->desport = 25;
   job->data_need = 4;
   return 1;
}
