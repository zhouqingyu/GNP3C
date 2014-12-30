#include <pthread.h>
#include <string.h>
#include <stdio.h>

#include "list.h"
#include "job.h"
#include "email_attachment_match.h"
#include "tools.h"

struct list_head content_list_head;
struct list_head attachment_list_head;
pthread_mutex_t content_list_mutex;
pthread_mutex_t attachment_list_mutex;

static void process_function_actual(int job_type){
   struct Job_Queue private_jobs;
   struct Job current_job;
   
   
   while(TRUE){
   
    jobqueue_init(&private_jobs);
    get_jobs(job_type,&private_jobs);
   
    if(jobqueue_isEmpty(&private_jobs))
       break;
   
    while(!jobqueue_isEmpty(&private_jobs)){
       jobqueue_delete(&private_jobs,&current_job);
       
       struct Email_reference *entry1, *entry2; 
       struct list_head *pos1, *pos2, *next1, *next2;
       //printf("into match progress\n");
       pthread_mutex_lock(&content_list_mutex);
       pthread_mutex_lock(&attachment_list_mutex);
       
       list_for_each_safe(pos1, next1, &content_list_head) {
       		int is_matched = 0;
       		
       		entry1 = list_entry(pos1, struct Email_reference, list_node);
       		list_for_each_safe(pos2, next2, &attachment_list_head) {
       			entry2 = list_entry(pos2, struct Email_reference, list_node);
       			
       			if (memcmp(entry1->reference, entry2->reference, entry1->ref_len) == 0) {
       				printf("\nIn match processing\nEmail id : %s\n", entry1->email_id);
       				printf("Reference : %.*s\n", entry1->ref_len, entry1->reference);
       				is_matched = 1;
       				list_del(pos2);
       				email_reference_free(entry2);
       			}
       		}
       		
       		if (is_matched) {
       			list_del(pos1);
       			email_reference_free(entry1);
       		}
       }
       pthread_mutex_unlock(&attachment_list_mutex);
       pthread_mutex_unlock(&content_list_mutex);
              
    }//while
   
   }//check remain jobs
}

static void process_function(){
   int job_type = JOB_TYPE_EMAIL_ATTACHMENT_MATCH;
   
   while(1){
       pthread_mutex_lock(&(job_mutex_for_cond[job_type]));
       pthread_cond_wait(&(job_cond[job_type]),&(job_mutex_for_cond[job_type]));
       pthread_mutex_unlock(&(job_mutex_for_cond[job_type]));
	//printf("match done\n");
       process_function_actual(job_type);
    }
}

static int process_judege(struct Job *job){
    return 1;
}

void email_attachment_match_init(){
	INIT_LIST_HEAD(&content_list_head);
	INIT_LIST_HEAD(&attachment_list_head);	
	
    register_job(JOB_TYPE_EMAIL_ATTACHMENT_MATCH,
		 (JOB_FUNCTION)process_function,
		 process_judege, CALL_BY_TIMER);
}





