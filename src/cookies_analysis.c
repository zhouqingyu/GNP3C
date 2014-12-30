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
#include<pcre.h>
#include <sys/socket.h> //u_char

#include "project.h"
#include "information_monitor_main.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "list.h"
#include "cookies_analysis.h"

#define MATCH_TRUE 1
#define MATCH_FALSE 2
#define OVECCOUNT 100
#define HAVE_COOKIES 1
#define HAVE_NO_COOKIES 2
#define HOST_COOKIES 1
#define COOKIES_HOST 2

struct Pattern{
   int ishavecookies; // 1 have  2 don't have
   int order;
   char *url;
   char *pattern;
}patterns[50];

static int pcount;

static void coinit();
static void  url_combine(char *host,char *sub_url,char *integer_url);
static void match_one_pattern(struct Pattern *the_pattern,char *data,int data_length,int hash_index);
static void match_up(char *data,int data_length,int hash_index);
static void *process_function(void *);
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);

static void coinit(){
   pcount = 0;
   
   patterns[pcount].url = "email.qq.com";
   patterns[pcount].pattern = "GET (/cgi-bin/(?:frame_html\\?sid=|today\\?sid=){1}[^\\s]+).*?(?:Host: ){1}([^\\s]+).*?(?:Cookie: ){1}(.*?)(?:\r\n){1}";
   patterns[pcount].ishavecookies = HAVE_COOKIES;
   patterns[pcount].order = HOST_COOKIES;
   pcount++;
}

static void  url_combine(char *host,char *sub_url,char *integer_url){
  strcat(integer_url,"http://");
  strcat(integer_url + strlen(integer_url),host);
  strcat(integer_url + strlen(integer_url),sub_url);
}

static void match_one_pattern(struct Pattern *the_pattern,char *data,int data_length,int hash_index){   
    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[OVECCOUNT];
    
    char host[1000];
    char sub_url[1000];
    char integer_url[2000];

    char *pattern_respond = the_pattern->pattern;

    regex = pcre_compile(pattern_respond , options, &error, &erroffset, NULL);

    if( regex == NULL ){
         printf("PCER compilation failure at offset %d: %s\n", erroffset, error); 
         free( regex );
         return;
    }

    now_position = 0;
    rc = 0;
       
    while(rc >=0){
         rc = pcre_exec( regex, NULL, data, data_length, now_position, 0,ovector, OVECCOUNT);
           now_position = ovector[0] + 1;

          /* fail to match */  
          if ( rc < 0 )
          {
             break;
          }
          
          if( !( ( the_pattern->ishavecookies == HAVE_COOKIES && rc == 4) || ( the_pattern->ishavecookies == HAVE_NO_COOKIES && rc == 2 ) ) ){
             break;
          }
         
          struct  CookiesInformation upinfo_instance,*upinfo;
          upinfo = &upinfo_instance;
          
          memset(upinfo->url,0,sizeof(char)*1000);
          memset(upinfo->cookies,0,sizeof(char)*1000);
          memset(upinfo->cookies_url,0,sizeof(char)*1000);
          
          upinfo->tcpid = hash_index;  
          upinfo->ishavecookies = the_pattern->ishavecookies;
          memcpy(upinfo->url,the_pattern->url,strlen(the_pattern->url));
          
          if(the_pattern->ishavecookies == HAVE_COOKIES){
          
             // order == HOST_COOKIES, the order is: sub_url(2-3),host(4-5),cookies(6-7)
             // order == COOKIES_HOST, the order is: sub_url(2-3),cookies(4-5),host(6-7)
          
             memset(sub_url,0,sizeof(char)*1000); 
             memset(host,0,sizeof(char)*1000); 
             memset(integer_url,0,sizeof(char)*2000);
                             
             if (the_pattern->order == COOKIES_HOST){
                  memcpy(sub_url,data + ovector[2],ovector[3] - ovector[2]);
                  memcpy(upinfo->cookies,data + ovector[4],ovector[5] - ovector[4]);
                  memcpy(host,data + ovector[6],ovector[7] - ovector[6]);
             }  else{
                  memcpy(sub_url,data + ovector[2],ovector[3] - ovector[2]);
                  memcpy(host,data + ovector[4],ovector[5] - ovector[4]);
                  memcpy(upinfo->cookies,data + ovector[6],ovector[7] - ovector[6]);
             }
             
             url_combine(host,sub_url,integer_url);
             memcpy(upinfo->cookies_url,integer_url,strlen(integer_url));
             
                  
          } else if(the_pattern->ishavecookies == HAVE_NO_COOKIES){
               memcpy(upinfo->cookies_url,data + ovector[2], ovector[3] - ovector[2]);
          }

          sql_factory_add_cookies_record(upinfo,hash_index);
        }//while
      free( regex );
}

static void match_up(char *data,int data_length,int hash_index){
    int i;
    for(i=0; i<pcount; i++){
      match_one_pattern(&(patterns[i]),data,data_length,hash_index);
    }
}

extern void cookie_analysis_init(){
    coinit();
    register_job(JOB_TYPE_COOKIES,process_function,process_judege,CALL_BY_TCP_DATA_MANAGE);
}

static void *process_function(void *arg){
   int job_type = JOB_TYPE_COOKIES;
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
       match_up(current_job.server_rev->head->data,  \
                   current_job.server_rev->head->length,current_job.hash_index);
       if(current_job.server_rev != NULL){
           wireless_list_free(current_job.server_rev);
           free(current_job.server_rev);
       }
       
   }//while
}

static int process_judege(struct Job *job){
   //have job return 1 or 0
   job->desport = 80;
   job->data_need = 2;
   return 1;
}
