#include <malloc.h>

#include "ftp_file_manage.h"

static void process_function();
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);

extern void ftp_file_manage_init(){
    register_job(JOB_TYPE_FTP_FILE_MANAGE,process_function,process_judege,CALL_BY_TCP_DATA_MANAGE);
}

static void process_function(){
   int job_type = JOB_TYPE_FTP_FILE_MANAGE;
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

       if(current_job.client_rev == NULL|| \
          current_job.client_rev->head == NULL || \
          current_job.client_rev->head->data == NULL|| \
          current_job.client_rev->head->length == NULL)
            continue;


       pthread_mutex_lock(&ftp_file_mutex);
       struct FTP_FILE_NODE *one_ftp_file = ftp_file_list_find_remove(&ftp_file_list,current_job.current_desport);
       pthread_mutex_unlock(&ftp_file_mutex);

       if(one_ftp_file == NULL){
          continue;
       }

       struct Ftp_file_manage_information ftp_file_manange_information;
       if(one_ftp_file->user == NULL)
          ftp_file_manange_information.user = "";
       else
         ftp_file_manange_information.user = one_ftp_file->user;

       if(one_ftp_file->password == NULL)
          ftp_file_manange_information.password = "";
       else
         ftp_file_manange_information.password = one_ftp_file->password;


       if(one_ftp_file->file_name == NULL)
          ftp_file_manange_information.file_name = "";
       else
         ftp_file_manange_information.file_name = one_ftp_file->file_name;


       if(one_ftp_file->handle == NULL)
          ftp_file_manange_information.handle = "";
       else
         ftp_file_manange_information.handle = one_ftp_file->handle;


       char *type = safe_file_judge_type(current_job.client_rev->head->data,current_job.client_rev->head->length);

       if(type == NULL)
            ftp_file_manange_information.file_type = "";

       else
            ftp_file_manange_information.file_type = type;
      
       ftp_file_manange_information.data = current_job.client_rev->head->data;
       ftp_file_manange_information.data_length = current_job.client_rev->head->length;

       sql_factory_add_ftp_record(&ftp_file_manange_information,current_job.hash_index);

       if(current_job.client_rev != NULL){
          wireless_list_free(current_job.client_rev);
          free(current_job.client_rev);
       }
       free(one_ftp_file);
   }//while
}

static int process_judege(struct Job *job){
   //have job return 1 or 0

   struct FTP_FILE_NODE *point;
   job->data_need = 1;
   job->ismutildesport =1;

   int i;
   pthread_mutex_lock(&ftp_file_mutex);
   point = ftp_file_list.head;
   while(point != NULL){
      job->desports[job->number_desports++] = point->desport;
      point = point->next;
   }
   pthread_mutex_unlock(&ftp_file_mutex);

   if(job->number_desports == 0)
      return 0;
 
   return 1;
}
