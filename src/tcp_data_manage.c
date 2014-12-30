#include <syslog.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/socket.h> //u_char
#include <malloc.h>

#include "project.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "list.h"
#include "tcp_data_manage.h"

//for reorgarization and tcp_data mangement
struct Tcp_Data *tcp_data_table[TCP_STREAM_MAX];
pthread_mutex_t mutex_tcp_data_table;// mutex lock for tcp_data_table

static void * process_function(void *);
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);
static void check_tcp_delay_time();
static int put_tcp_data_into_job(struct Job *new_job,struct Tcp_Data *a_tcp);
static void manage_one_tcp(struct Tcp_Data *a_tcp);

extern void tcp_data_manage_init(){
    register_job(JOB_TYPE_TCP_DATA_MANAGE,process_function,process_judege,CALL_BY_TIMER);
}


static void *process_function(void *arg){
   int job_type = JOB_TYPE_TCP_DATA_MANAGE;
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
   int i;
  
   while(!jobqueue_isEmpty(&private_jobs)){
       jobqueue_delete(&private_jobs,&current_job);
       pthread_mutex_lock(&mutex_tcp_data_table);
       check_tcp_delay_time();
//        printf("**out of check_tcp_delay_time\n");
       pthread_mutex_unlock(&mutex_tcp_data_table);  

   }//while
}


static int process_judege(struct Job *job){
   //have job return 1 or 0
   return 1;
}


static void check_tcp_delay_time(){ 
// printf("**into check_tcp_delay_time\n");
     if(tcp_data_table == NULL)
         return;

     time_t nowtime = time((time_t *)0);
     int i;
     struct Tcp_Data *a_tcp,*head,*before,*temp;

     before = NULL;
     for(i=0; i<TCP_STREAM_MAX; i++){

        if(!tcp_data_table[i])
           continue;

        head = tcp_data_table[i];
        a_tcp = tcp_data_table[i];
        while(a_tcp) {

           int tcp_data_wait_max_time = configuration.tcp_data_wait_max;
           int desport = a_tcp->ip_and_port.dest;
           if(desport!=21 && desport!=23 && desport!=443 && \
              desport!=80 && desport!=1863 && desport!=110 && \
              desport!=995 && desport!=25 && desport !=465)
               tcp_data_wait_max_time = tcp_data_wait_max_time * 3;

           if(nowtime - a_tcp->last_update_time >= tcp_data_wait_max_time){

               if(a_tcp->ip_and_port.dest != 443){
                   manage_one_tcp(a_tcp);
               }

                //add filter ports must not be attachment....

                wireless_list_free(a_tcp->client_rev);
                free(a_tcp->client_rev);
                wireless_list_free(a_tcp->server_rev);
                free(a_tcp->server_rev);
                wireless_list_free(a_tcp->promisc);
                free(a_tcp->promisc);
               
                if(a_tcp == head){
                   //first node
                   tcp_data_table[i] = a_tcp->next;
                   head = a_tcp->next;
                   before = NULL;
                   temp = a_tcp;
                   a_tcp = a_tcp->next;
                   free(temp);
                   continue;
                }else{
                   before->next = a_tcp->next;
                   temp = a_tcp;
                   a_tcp = a_tcp->next;
                   free(temp);
                }
            }else{
                before = a_tcp;
                a_tcp = a_tcp->next;
            }
        }//while

    }//for
}

static void manage_one_tcp(struct Tcp_Data *a_tcp){
     int job_type;
     for(job_type=0; job_type<JOB_NUMBER; job_type++){
	
        if(job_call_type[job_type] != CALL_BY_TCP_DATA_MANAGE)
            continue;
// 	printf("****job_type : %d\n", job_type);
        //if the job is unregister ingore the job
        if(!job_registed[job_type])
            continue;

        int judge_result = 0;//default is having no job
        struct Job new_job;
        new_job.desport = 0; //defalut is all ports
        new_job.hash_index = a_tcp->hash_index;
        new_job.time = a_tcp->access_time;
        new_job.ip_and_port.dest =  a_tcp->ip_and_port.dest;
        new_job.ip_and_port.source = a_tcp->ip_and_port.source;
        new_job.ip_and_port.saddr =  a_tcp->ip_and_port.saddr;
        new_job.ip_and_port.daddr =  a_tcp->ip_and_port.daddr;
        new_job.server_rev = NULL;
        new_job.client_rev = NULL;
        new_job.promisc = NULL;
        new_job.dezip = NULL;
        new_job.ismutildesport = 0;
	new_job.number_desports = 0;
        
        judge_result = job_judges[job_type](&new_job); 

        if(!judge_result)
           continue;

        if(!put_tcp_data_into_job(&new_job,a_tcp)){ // no need data 
           continue;
        }
       
        pthread_mutex_lock(&(job_mutex_for_queue[job_type]));
        jobqueue_insert(&(job_queue[job_type]),&new_job);  // add job into job queue of job_type
        pthread_mutex_unlock(&(job_mutex_for_queue[job_type]));

        pthread_mutex_lock(&(job_mutex_for_cond[job_type]));
        pthread_cond_signal(&(job_cond[job_type])); // rouse job thread of job_type
        pthread_mutex_unlock(&(job_mutex_for_cond[job_type]));
   }
}

static int put_tcp_data_into_job(struct Job *new_job,struct Tcp_Data *a_tcp){

      int data_need = new_job->data_need;      
      int desport = new_job->desport;

      if(new_job->ismutildesport == 0){
         if(desport!=0 && desport!=a_tcp->ip_and_port.dest)
         return 0;
      }else{
         int i;
         for(i=0; i<new_job->number_desports; i++){
              if(a_tcp->ip_and_port.dest == new_job->desports[i]){
                   new_job->current_desport = a_tcp->ip_and_port.dest;
                   break;
              }
              
         }
         if(i == new_job->number_desports){
              return 0;
         }

      }

      if(data_need == 1){
          new_job->client_rev = get_one_block_data(a_tcp->client_rev);
      }else if(data_need == 2){
          new_job->server_rev = get_one_block_data(a_tcp->server_rev);
      }else if(data_need == 3){
          new_job->promisc = get_one_block_data(a_tcp->promisc);
      }else if(data_need == 4){
          new_job->client_rev = get_one_block_data(a_tcp->client_rev);
          new_job->server_rev = get_one_block_data(a_tcp->server_rev);
          new_job->promisc = get_one_block_data(a_tcp->promisc);
      }else {
          syslog(project_params.syslog_level,"unkonw data_need %d\n",data_need);
      }
      return 1;
}
