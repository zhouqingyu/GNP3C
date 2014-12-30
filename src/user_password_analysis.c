#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <memory.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <pcre.h>
#include <syslog.h>
#include <sys/socket.h> //u_char

#include "project.h"
#include "information_monitor_main.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "list.h"
#include "user_password_analysis.h"

#define MAX 1024000 
#define MATCH_TRUE 1
#define MATCH_FALSE 2
#define OVECCOUNT 100

struct Pattern{
   char *url;
   char *user;
   char *password;
};

static struct Pattern patterns[100];
static int pcount;
static int hash_index;

static void process_function();
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);
static void analysis_userpassword_from_job(struct Job *current_job);
static void analysis_userpassword_from_http_list(struct Http_List *list);
static void analysis_userpassword_from_http(struct Http *http);

static void psinit(){
   
   pcount = 0;
   //configure for renren
   patterns[pcount].url = "www.renren.com";
   patterns[pcount].user = "email";
   patterns[pcount].password = "password";
   pcount++;

   //configure for 51
   patterns[pcount].url = "www.51.com";
   patterns[pcount].user = "passport_51_user";
   patterns[pcount].password = "passport_51_password";
   pcount++;

   //configure for tianya
   patterns[pcount].url = "www.tianya.cn";
   patterns[pcount].user =  "vwriter";
   patterns[pcount].password = "vpassword";
   pcount++;
  
   //configure for mop 2
   patterns[pcount].url = "www.mop.com";
   patterns[pcount].user = "user_name";
   patterns[pcount].password = "password";
   pcount++;

   //configure for sohu
   patterns[pcount].url = "mail.sohu.com";
   patterns[pcount].user = "username";
   patterns[pcount].password = "passwd";
   pcount++;
}

static void analysis_userpassword_from_job(struct Job *current_job){

    struct Http_RR *http_rr = current_job->http_rr;

    if(http_rr == NULL)
        return;

    analysis_userpassword_from_http_list(http_rr->request_list);
    analysis_userpassword_from_http_list(http_rr->response_list);
}

static void analysis_userpassword_from_http_list(struct Http_List *list){

    if(list == NULL)
        return;    

    struct Http * point = list->head;
    while(point != NULL){
         analysis_userpassword_from_http(point);
         point = point->next;
    }
}

static void analysis_userpassword_from_http(struct Http *http){
     
    struct  UPInformation upinfo;
    int i;
    int flag;
    for(i=0; i<pcount; i++){
      memset(&upinfo,0,sizeof(upinfo));
      int flag = 0;

      {
           char *name;
           struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node));
           value->length = 0;
           value->data = NULL;

           name = patterns[i].user;

           get_first_value_from_name(http,name,value);

           if(value->length > 0 && value->data != NULL){

                memset(upinfo.user,0,sizeof(upinfo.user));
                strcpy(upinfo.user,value->data);
                flag++;

                //printf("user value is [%s]\n",value->data);
           }
           free_list_node(value);
           free(value); 
      }

      {
           char *name;
           struct List_Node *value = (struct List_Node *)malloc(sizeof(struct List_Node));
           value->length = 0;
           value->data = NULL;
           name = patterns[i].password;
           get_first_value_from_name(http,name,value);
           if(value->length > 0 && value->data != NULL){
                memset(upinfo.password,0,sizeof(upinfo.password));
                strcpy(upinfo.password,value->data);
                flag++;
                 //printf("password value is [%s]\n",value->data);
           }
           free_list_node(value);
           free(value); 
       }

      if(flag == 2){

          //printf("find one\n");
          memset(upinfo.url,0,sizeof(upinfo.url));
          strcpy(upinfo.url,patterns[i].url);
          sql_factory_add_user_password_record(&upinfo,hash_index);
      }

    }

}


extern void user_password_analysis_init(){
    psinit();
    register_job(JOB_TYPE_USERANDPASSWORD,process_function,process_judege,CALL_BY_HTTP_ANALYSIS);
}

static void process_function(){
   int job_type = JOB_TYPE_USERANDPASSWORD;
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

   while(!jobqueue_isEmpty(&private_jobs)){

       jobqueue_delete(&private_jobs,&current_job);
       hash_index = current_job.hash_index;
       analysis_userpassword_from_job(&current_job);
       if(current_job.http_rr != NULL)
          free_http_rr(current_job.http_rr);      
   }//while
}

static int process_judege(struct Job *job){
   return 1;
}


