#include <syslog.h>
#include <sys/socket.h> //u_char

#include "packet.h"
#include "nids.h"
#include "job.h"
#include "list.h"
#include "configuration.h"
#include "change_channel.h"


//for minotor card operation
int card_channel[100];
char channelstr[CHANNEL_NUMBER][3]= {
  "1","2","3","4","5","6","7",
  "8","9","10","11","12","13"};

static int current_channel = 0;

static void *process_function(void *);
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);

void change_channel_init(){
    register_job(JOB_TYPE_CHANGE_CHANNEL,process_function,process_judege,CALL_BY_TIMER);
}

static void *process_function(void *arg){
   int job_type = JOB_TYPE_CHANGE_CHANNEL;
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
   }//while
}

static int process_judege(struct Job *job){
   job->current_channel = current_channel;
   current_channel = (current_channel+1) % CHANNEL_NUMBER;
   return 1;
}

