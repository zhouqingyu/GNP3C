#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <malloc.h>

#include "project.h"
#include "list.h"
#include "job.h"
#include "save_environment.h"
#include "tools.h"

static void *process_function(void *);
static void process_function_actual(int job_type);
static int  process_judege(struct Job *job);

static char current_dictionary[100];

extern void save_environment_init(){
    time_t nowtime;
    memset(current_dictionary,0,sizeof(current_dictionary));
    time(&nowtime);
    sprintf(current_dictionary,"%s/%s/",configuration.save_environment_path,asctime(gmtime(&nowtime)));

    int i;
    i=0;
    while(current_dictionary[i]){
       if(current_dictionary[i]=='\r' || current_dictionary[i]=='\n')
          current_dictionary[i]=' ';
       i++;
    } 
    
    syslog(project_params.syslog_level,"current save path is %s\n",current_dictionary);

    create_dirctionary(current_dictionary);
    register_job(JOB_TYPE_SAVE_ENVIRONMENT,process_function,process_judege,CALL_BY_TCP_DATA_MANAGE);
}

static void *process_function(void *arg){
   int job_type = JOB_TYPE_SAVE_ENVIRONMENT;
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
   struct tcp_stream *a_tcp;
   char tcp_information_dir[100];
   char server[100],client[100],promisc[100];
  
   while(!jobqueue_isEmpty(&private_jobs)){
       
       jobqueue_delete(&private_jobs,&current_job);

       memset(tcp_information_dir,0,sizeof(tcp_information_dir));
       sprintf(tcp_information_dir,"%s/%hu_%hu_%u_%u_%d/",current_dictionary,current_job.ip_and_port.dest,\
                                                     current_job.ip_and_port.source,current_job.ip_and_port.daddr,\
                                                     current_job.ip_and_port.saddr,current_job.hash_index);       
       create_dirctionary(tcp_information_dir);

       if(current_job.server_rev != NULL && current_job.server_rev->head != NULL && current_job.server_rev->head->data != NULL){
          memset(server,0,100*sizeof(char));
          sprintf(server,"%s/log_server",tcp_information_dir);
          write_data_to_file(server,current_job.server_rev->head->data, current_job.server_rev->head->length);
       }
 
       if(current_job.client_rev != NULL && current_job.client_rev->head != NULL && current_job.client_rev->head->data != NULL){
          memset(client,0,100*sizeof(char));
          sprintf(client,"%s/log_client",tcp_information_dir);
          write_data_to_file(client,current_job.client_rev->head->data, current_job.client_rev->head->length);
       }

       if(current_job.promisc != NULL && current_job.promisc->head != NULL && current_job.promisc->head->data != NULL){
          memset(promisc,0,100*sizeof(char));
          sprintf(promisc,"%s/log_promisc",tcp_information_dir);
          write_data_to_file(promisc,current_job.promisc->head->data, current_job.promisc->head->length);
       }

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
   job->desport = 0;
   job->data_need = 4;
   return 1;
}
