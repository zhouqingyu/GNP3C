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
#include<errno.h>
#include<string.h>
#include<sys/socket.h>
#include<netpacket/packet.h> //reference  struct sockaddr_ll                                                                                   
#include<net/if.h> // reference struct ifreq
#include<linux/if_ether.h> // reference ETH_P_ALL
#include<sys/ioctl.h> // reference SIOCGIFINDEX	
#include <syslog.h>
#include <malloc.h>

#include "project.h"
#include "nids.h"
#include "pthread.h"
#include "job.h"
#include "list.h"
#include "tools.h"
#include "email_analysis.h"
#include "email_attachment_match.h"
#include "__126.h"
#include "__163.h"
#include "__qq.h"
#include "__hotmail.h"
#include "__yahoo.h"
#include "__sina.h"
#include "__sohu.h"
#include "__tom.h"
#include "__21cn.h"
#include "__139.h"

typedef int (*ANALYSIS_EMAIL)(struct Http*,struct Email_info*, struct Email_reference*);
typedef u_int32_t in_addr_t;
struct in_addr
{
    in_addr_t s_addr;
};

static int hash_index;

static ANALYSIS_EMAIL analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_NUMBER];

static void process_function();
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);
static void analysis_email_functions_init();
static void analysis_email_from_job(struct Job *current_job);
static void analysis_email_from_http(struct Http *http);
static void analysis_email_from_http_list(struct Http_List *list);

extern void email_init(){
    analysis_email_functions_init();  
    register_job(JOB_TYPE_EMAIL,process_function,
		 (JOB_FUNCTION) process_judege,
		 CALL_BY_HTTP_ANALYSIS);
}

static void process_function(){

   int job_type = JOB_TYPE_EMAIL;
   while(1){
       pthread_mutex_lock(&(job_mutex_for_cond[job_type]));
       pthread_cond_wait(&(job_cond[job_type]),&(job_mutex_for_cond[job_type]));
       pthread_mutex_unlock(&(job_mutex_for_cond[job_type]));
      
       process_function_actual(job_type);
    }
}

static void process_function_actual(int job_type){
   struct Job_Queue private_jobs;
   struct Job current_job;
   
   while(TRUE){
   
       jobqueue_init(&private_jobs);
       get_jobs(job_type,&private_jobs);
   
       if(jobqueue_isEmpty(&private_jobs))
         break;

       while(!jobqueue_isEmpty(&private_jobs)){

         int delete_result = jobqueue_delete(&private_jobs,&current_job);
         if(delete_result != 0)
              continue;
         
         hash_index = current_job.hash_index;
         analysis_email_from_job(&current_job);
         if(current_job.http_rr != NULL)
              free_http_rr(current_job.http_rr);      
       }//while
   }//check remain jobs
}

static int process_judege(struct Job *job){
   //add more filter condition code later...
   //....
   return 1;
}

static void analysis_email_functions_init(){

   int i;
   for(i=0; i< ANALYSIS_EMAIL_FUNCTION_NUMBER; i++){
     analysis_email_functions[i] = NULL;
   }
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_QQ_SEND_CONTENT] = __qq_send_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_QQ_SEND_ATTACHMENT] = __qq_send_attachment;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_QQ_RECEIVE_CONTENT] = __qq_receive_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_QQ_RECEIVE_ATTACHMENT] = __qq_receive_attachment;
#if 0	
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_126_SEND_CONTENT] = __126_send_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_126_SEND_ATTACHMENT] = __126_send_attachment;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_126_RECEIVE_CONTENT] = __126_receive_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_126_RECEIVE_ATTACHMENT] = __126_receive_attachment;
   
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_163_SEND_CONTENT] = __163_send_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_163_SEND_ATTACHMENT] = __163_send_attachment;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_163_RECEIVE_CONTENT] = __163_receive_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_163_RECEIVE_ATTACHMENT] = __163_receive_attachment;

   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_HOTMAIL_SEND_CONTENT] = __hotmail_send_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_HOTMAIL_SEND_ATTACHMENT] = __hotmail_send_attachment;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_HOTMAIL_RECEIVE_CONTENT] = __hotmail_receive_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_HOTMAIL_RECEIVE_ATTACHMENT] = __hotmail_receive_attachment;

   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_YAHOO_SEND_CONTENT] = __yahoo_send_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_YAHOO_SEND_ATTACHMENT] = __yahoo_send_attachment;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_YAHOO_RECEIVE_CONTENT] = __yahoo_receive_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_YAHOO_RECEIVE_ATTACHMENT] = __yahoo_receive_attachment;

   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_SINA_SEND_CONTENT] = __sina_send_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_SINA_SEND_ATTACHMENT] = __sina_send_attachment;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_SINA_RECEIVE_CONTENT] = __sina_receive_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_SINA_RECEIVE_ATTACHMENT] = __sina_receive_attachment;

   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_SOHU_SEND_CONTENT] = __sohu_send_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_SOHU_SEND_ATTACHMENT] = __sohu_send_attachment;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_SOHU_RECEIVE_CONTENT] = __sohu_receive_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_SOHU_RECEIVE_ATTACHMENT] = __sohu_receive_attachment;

   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_TOM_SEND_CONTENT] = __tom_send_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_TOM_SEND_ATTACHMENT] = __tom_send_attachment;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_TOM_RECEIVE_CONTENT] = __tom_receive_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_TOM_RECEIVE_ATTACHMENT] = __tom_receive_attachment;

   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_21CN_SEND_CONTENT] = __21cn_send_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_21CN_SEND_ATTACHMENT] = __21cn_send_attachment;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_21CN_RECEIVE_CONTENT] = __21cn_receive_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_21CN_RECEIVE_ATTACHMENT] = __21cn_receive_attachment;

   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_139_SEND_CONTENT] = __139_send_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_139_SEND_ATTACHMENT] = __139_send_attachment;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_139_RECEIVE_CONTENT] = __139_receive_content;
   analysis_email_functions[ANALYSIS_EMAIL_FUNCTION_139_RECEIVE_ATTACHMENT] = __139_receive_attachment;
#endif 

}

static void analysis_email_from_job(struct Job *current_job){

    struct Http_RR *http_rr = current_job->http_rr;

    if(http_rr == NULL)
        return;

    analysis_email_from_http_list(http_rr->request_list);
    analysis_email_from_http_list(http_rr->response_list);
}

static void analysis_email_from_http_list(struct Http_List *list){

    if(list == NULL)
        return;    

    struct Http * point = list->head;
    while(point != NULL){
         analysis_email_from_http(point);
         point = point->next;
    }
}

static void analysis_email_from_http(struct Http *http){

    int i;
    int result;
    for(i=0; i< ANALYSIS_EMAIL_FUNCTION_NUMBER; i++){
         if(analysis_email_functions[i] != NULL){
         	//printf("email analysis\n");
               struct Email_info *email_info = (struct Email_info *)malloc(sizeof(struct Email_info));
               struct Email_reference *email_reference = (struct Email_reference *)malloc(sizeof(struct Email_reference));
               
               email_info_init(email_info);
               email_reference_init(email_reference);
               
               memset(email_info->category,0,sizeof(email_info->category));
               strcpy(email_info->category,"Web Email");
               
               result = analysis_email_functions[i](http, email_info, email_reference);
               if(result == 1){
                    //analysis success then do another things
                    //....
        
                    //print_email_detai(email_info);
                  	sql_factory_add_email_record(email_info,hash_index, email_reference->email_id);
                  	
                  	printf("mail id %s\n", email_reference->email_id);
                  	
          	   		if( email_info->content != NULL && 
          	   		    strlen(email_info->content) > 0 &&
          	   		    email_reference->reference != NULL ) {
          	   			
          	   			pthread_mutex_lock(&content_list_mutex);
          	   			list_insert (&email_reference->list_node, &content_list_head);    
          	   			pthread_mutex_unlock(&content_list_mutex);     
          	   		}

          			if( email_info->attachment != NULL && 
          				email_info->att_length > 0 && 
          				email_reference->reference != NULL ) {
          				   
          				pthread_mutex_lock(&attachment_list_mutex);
          				list_insert (&email_reference->list_node, &attachment_list_head);
          				pthread_mutex_unlock(&attachment_list_mutex);
          			}
               } 
			   email_info_free(email_info);
               free(email_info);
         }
    }
}

















































