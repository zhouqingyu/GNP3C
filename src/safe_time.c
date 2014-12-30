#include<time.h>
#include<sys/time.h>
#include<syslog.h>
#include<pthread.h>
#include<signal.h>
#include <sys/socket.h> //u_char

#include "information_monitor_main.h"
#include "project.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "safe_time.h"

static void set_timer();
static void timer_handler(int sig);

static void set_timer(){

   struct itimerval itv,oldtv;
   //Interval time to run function
   itv.it_interval.tv_sec = configuration.time_wait_unit;
   itv.it_interval.tv_usec = 0;
   
   //Timeout to run function first time
   itv.it_value.tv_sec = configuration.time_wait_unit;
   itv.it_value.tv_usec = 0;
   
   int ret =  setitimer(ITIMER_REAL,&itv,&oldtv); 
   if(ret)
     syslog(project_params.syslog_level,"setitimer falure\n");  
}

static void timer_handler(int sig){
   int job_type;
   for(job_type=0; job_type<JOB_NUMBER; job_type++){

        //if the job is unregister ingore the job
        if(!job_registed[job_type])
          continue;

        if(job_call_type[job_type] != CALL_BY_TIMER)
          continue;

        int judge_result = 0;//default is having no job
        struct Job new_job;        
        judge_result = job_judges[job_type](&new_job); 
        if(!judge_result)
           continue;
       
        pthread_mutex_lock(&(job_mutex_for_queue[job_type]));
        jobqueue_insert(&(job_queue[job_type]),&new_job);  // add job into job queue of job_type
        pthread_mutex_unlock(&(job_mutex_for_queue[job_type]));

        pthread_mutex_lock(&(job_mutex_for_cond[job_type]));
        pthread_cond_signal(&(job_cond[job_type])); // rouse job thread of job_type
        pthread_mutex_unlock(&(job_mutex_for_cond[job_type]));
   }
}

extern void install_timer(){
    signal(SIGALRM,timer_handler);
    set_timer();
}
