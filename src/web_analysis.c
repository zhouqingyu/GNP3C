#include <dirent.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

#include "project.h"
#include "database.h"
#include "information_monitor_main.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "http_analysis.h"
#include "list.h"

#define BUFFER_MAX 1024*1024*100

static void analysis_web_from_job(struct Job *current_job);
static void analysis_web_from_http_list(struct Http_List *list,time_t current_time, 
					struct tuple4 addr);
static void analysis_web_from_http(struct Http *http,time_t current_time, 
				   struct tuple4 addr);
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);
static void *process_function(void *);

static int hash_index;
static char buffer_postdata[BUFFER_MAX];

static void analysis_web_from_job(struct Job *current_job){

    struct Http_RR *http_rr = current_job->http_rr;

    if(http_rr == NULL)
        return;

    analysis_web_from_http_list(http_rr->request_list,current_job->time, 
				current_job->ip_and_port);
    analysis_web_from_http_list(http_rr->response_list,current_job->time, 
				current_job->ip_and_port);
}

static void analysis_web_from_http_list(struct Http_List *list,time_t current_time, 
					struct tuple4 addr){

    if(list == NULL)
        return;    

    struct Http * point = list->head;
    while(point != NULL){

         analysis_web_from_http(point,current_time, addr);
         point = point->next;
    }
}

static void analysis_web_from_http(struct Http *http,time_t current_time, 
				   struct tuple4 addr){

     if(http->type != PATTERN_REQUEST_HEAD)
         return;

     struct WebInformation webinfo;
     webinfo.request = http->method;
     webinfo.host = http->host;
     webinfo.url = http->uri;
     webinfo.referer = http->referer;
     webinfo.time = current_time;
     webinfo.data_length = 0;
     webinfo.data_type = NULL;
     webinfo.data = NULL;
     //printf("webinfo %s\n", int_ntoa(addr.saddr));
     strcpy(webinfo.srcip, int_ntoa(addr.saddr));
     strcpy(webinfo.dstip, int_ntoa(addr.daddr));

     char segment[] = "\n";

     if(strstr(webinfo.request,"POST")!= NULL){

         int length = 0;
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

               length += entity->entity_length;
               length += 1; 
               entity = entity->next;
             }
         }


         if(length > 1 && length < BUFFER_MAX){

              memset(buffer_postdata,0,length+1);

              entity_list = http->entity_list;


              if(entity_list != NULL){

                  entity = entity_list->head;
                  while(entity != NULL){
                       if(entity->entity_length <= 0 || entity->entity_length > 1024*1024*100){
                               entity = entity->next;
                               continue;
                        }
                        memcpy(buffer_postdata + length,entity->entity_content,entity->entity_length);
                        length += entity->entity_length;

                        memcpy(buffer_postdata + length,segment,1);
                        length += 1; 
                        entity = entity->next;
                  }
              }
              webinfo.data_length = length;
              webinfo.data_type = "";
              webinfo.data = buffer_postdata;
        }

     }
   
     sql_factory_add_web_record(&webinfo,hash_index);
}

static void *process_function(void *arg){
   int job_type = JOB_TYPE_WEB;
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

   while(!jobqueue_isEmpty(&private_jobs)){

       jobqueue_delete(&private_jobs,&current_job);
       hash_index = current_job.hash_index;
       analysis_web_from_job(&current_job);
       if(current_job.http_rr != NULL)
          free_http_rr(current_job.http_rr);      
   }//while
}

static int process_judege(struct Job *job){
   return 1;
}

extern void web_analysis_init(){
    register_job(JOB_TYPE_WEB,process_function,process_judege,CALL_BY_HTTP_ANALYSIS);
}
