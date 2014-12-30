#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <sys/socket.h> //u_char

#include "project.h"
#include "information_monitor_main.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "tcp_lost_manage.h"
#include "tcp.h"

pthread_mutex_t tcp_lost_mutex;

static void *process_function(void *);
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);
static void forcecontrol(struct tcp_stream *a_tcp,struct half_stream *snd, struct half_stream  *rcv);
static void forcemanage(struct tcp_stream * a_tcp);


extern void tcp_lost_manage_init(){
    register_job(JOB_TYPE_TCP_TIMER,process_function,process_judege,CALL_BY_TIMER);
}


static void *process_function(void *arg){
   int job_type = JOB_TYPE_TCP_TIMER;
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

   if(tcp_stream_table == NULL)
      return;

   pthread_mutex_lock(&tcp_lost_mutex);
   
   while(!jobqueue_isEmpty(&private_jobs)){
       jobqueue_delete(&private_jobs,&current_job);
       nowtime = time((time_t *)0);
       for(i=0; i<tcp_stream_table_size; i++){
         a_tcp = tcp_stream_table[i];
         while(a_tcp) {
            if(nowtime - a_tcp->lasttime >= configuration.tcp_delay_max_time){
                forcemanage(a_tcp);
            }
            a_tcp = a_tcp->next_node;
        }//while

      }//for

   }//while

  pthread_mutex_unlock(&tcp_lost_mutex);
}

static int process_judege(struct Job *job){
   //have job return 1 or 0
   return 1;
}

static void forcecontrol(struct tcp_stream *a_tcp,struct half_stream *snd, struct half_stream  *rcv){
 
           struct skbuff *pakiet;
           pakiet = rcv->list;
           while (pakiet) {
	      struct skbuff *tmp;
	      add_from_skb(a_tcp, rcv, snd, pakiet->data,
		       pakiet->len, pakiet->seq, pakiet->fin, pakiet->urg,
		       pakiet->urg_ptr + pakiet->seq - 1);
	      rcv->rmem_alloc -= pakiet->truesize;
	      if (pakiet->prev)
	         pakiet->prev->next = pakiet->next;
	      else
	         rcv->list = pakiet->next;

	      if (pakiet->next)
	         pakiet->next->prev = pakiet->prev;
	      else
	          rcv->listtail = pakiet->prev;
	      tmp = pakiet->next;
	      free(pakiet->data);
	      free(pakiet);
	      pakiet = tmp;   
         }  
}

static void forcemanage(struct tcp_stream * a_tcp){
    struct half_stream *snd, *rcv;

    snd = &a_tcp->client;
    rcv = &a_tcp->server;
    forcecontrol(a_tcp,snd,rcv);
    
    rcv = &a_tcp->client;
    snd = &a_tcp->server;
    forcecontrol(a_tcp,snd,rcv);
    //free_tcp(a_tcp);    
}



