#include<pthread.h>
#include<string.h>
#include <syslog.h>
#include <sys/socket.h> //u_char

#include "information_monitor_main.h"
#include "project.h"
#include "packet.h"
#include "nids.h"
#include "job.h"

struct Job_Queue job_queue[JOB_NUMBER];  //任务队列数组，每种任务一个单元。
pthread_cond_t job_cond[JOB_NUMBER]; //条件变量数组，用于唤醒任务线程
pthread_mutex_t job_mutex_for_cond[JOB_NUMBER]; //互斥量数组，用于同步条件变量
pthread_mutex_t job_mutex_for_queue[JOB_NUMBER]; //互斥量数组，用于任务队列
JOB_FUNCTION job_functions[JOB_NUMBER]; //执行任务的函数数组
JOB_JUDGE job_judges[JOB_NUMBER]; //判断是否需要唤醒线程进行工作 
int job_registed[JOB_NUMBER]; //标志某种任务是否注册
int job_call_type[JOB_NUMBER]; //CALL_BY_TCP_DATA_MANAGE,CALL_BY_TIMER,CALL_BY_HTTP_ANALYSIS

void jobqueue_init(struct Job_Queue *queue)
{
   queue->front=queue->rear=0;
   queue->insert_number = 0;
   queue->delete_number = 0;
   queue->length = 0;
}

int jobqueue_isFull(struct Job_Queue *queue)
{
   if( queue->front == (queue->rear+1)%JOB_MAX)
      return 1;
   else
       return 0;
}

int jobqueue_isEmpty(struct Job_Queue *queue)
{
    if(queue->front == queue->rear)
       return 1;
    else
       return 0;
}

int jobqueue_insert(struct Job_Queue *queue,struct Job *pnode)
{
    if(jobqueue_isFull(queue))
      return -1;
      
    queue->insert_number++;
    queue->length++;
    memcpy(&(queue->jobs[queue->rear]),pnode,sizeof(struct Job));

    queue->rear= ( queue->rear+1 )%JOB_MAX;
#if 0
    if(queue->job_type == JOB_TYPE_HTTP_DECODING)
         printf("after current insert  insert_number is %d delete_number is %d length is %d\n",queue->insert_number,queue->delete_number,queue->length);
#endif 
    
    return 0;
}

int jobqueue_delete(struct Job_Queue *queue,struct Job *pnode)
{
     if(jobqueue_isEmpty(queue))
         return -1;
         
     queue->delete_number++;
     queue->length--;
     memcpy(pnode,&(queue->jobs[queue->front]),sizeof(struct Job));
     queue->front = (queue->front+1)%JOB_MAX;
#if 0     
     if(queue->job_type == JOB_TYPE_HTTP_DECODING)
         printf("after current delete  insert_number is %d delete_number is %d length is %d\n",queue->insert_number,queue->delete_number,queue->length);
#endif     
     return 0;
}

void register_job(int job_type,JOB_FUNCTION function,JOB_JUDGE judge,int call_type){
   if(job_type<0 || job_type>=JOB_NUMBER){
      syslog(project_params.syslog_level,"job_type(%d) is error\n",job_type);
      return;
   }
   
   job_queue[job_type].job_type = job_type;
   jobqueue_init(&(job_queue[job_type]));//init work queue
   pthread_cond_init(&(job_cond[job_type]),NULL);// init job cond
   job_functions[job_type] = function; // init job_funtion
   job_call_type[job_type] = call_type; // init job_call_type
   job_judges[job_type] = judge; // init judge function
   pthread_mutex_init(&(job_mutex_for_cond[job_type]),NULL); // init mutex for cond
   pthread_mutex_init(&(job_mutex_for_queue[job_type]),NULL);// init mutex for work queue
   job_registed[job_type] = 1; //flag registered 1 represent true, 0 represent false
}

void unregister_job(int job_type){
   job_registed[job_type] = 0; //flag registered 1 represent true, 0 represent false
}

void get_jobs(int job_type,struct Job_Queue *private_jobs){
 //    if(job_type == JOB_TYPE_HTTP_DECODING)
//          printf("http job call get_jobs\n");

     pthread_mutex_lock(&(job_mutex_for_queue[job_type]));

     while(!jobqueue_isEmpty(&(job_queue[job_type]))){

       struct Job current_job;
       int delete_result = jobqueue_delete(&(job_queue[job_type]),&current_job);	
#if 0      
       if(job_type == JOB_TYPE_HTTP_DECODING)
           printf("delete_result is %d\n",delete_result);
      
      
       if(current_job.hash_index == 253854)
           printf("position-4\n");
#endif      
       jobqueue_insert(private_jobs,&current_job);
     }

     pthread_mutex_unlock(&(job_mutex_for_queue[job_type]));
}
