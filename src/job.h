#ifndef JOB_H
#define JOB_H

#include <pthread.h>

#define JOB_MAX 4000
#define JOB_NUMBER 22

#define JOB_TYPE_REORGANIZATION 	0 
#define JOB_TYPE_TCP_TIMER 		1
#define JOB_TYPE_IP_TIMER 		2
#define JOB_TYPE_EMAIL 			3
#define JOB_TYPE_MSN 			4
#define JOB_TYPE_COOKIES 		5
#define JOB_TYPE_HTTP_DECODING 		6
#define JOB_TYPE_WEB 			7
#define JOB_TYPE_USERANDPASSWORD 	8
#define JOB_TYPE_TELNET 		9
#define JOB_TYPE_FTP 			10
#define JOB_TYPE_TCP_DATA_MANAGE 	11
#define JOB_TYPE_ALL_DATA_LIST_MANAGE 	12
#define JOB_TYPE_CHANGE_CHANNEL 	13
#define JOB_TYPE_UPDATE_WINDOW_CONTENT 	14
#define JOB_TYPE_RECOVER_ENVIRONMENT 	15
#define JOB_TYPE_SAVE_ENVIRONMENT	16
#define JOB_TYPE_FTP_FILE_MANAGE 	17
#define JOB_TYPE_POP3  			18
#define JOB_TYPE_SMTP			19
#define JOB_TYPE_IMAP			20
#define JOB_TYPE_EMAIL_ATTACHMENT_MATCH 21

#define CALL_BY_TCP_DATA_MANAGE 	0
#define CALL_BY_TIMER 			1
#define CALL_BY_HTTP_ANALYSIS 		2

struct Start_End_Pair{
    int start;
    int end;
};

struct Job{
  struct Start_End_Pair sepair; //for JOB_TYPE_REORGANIZATION
  int hash_index; //for application analysis
  int desport; // for application analysis    0:all
  int data_need; // for application analysis  1:client_receive 2:server_receive 3:promisc 4:all 
  int ismutildesport;
  int number_desports;
  int desports[10];
  int current_desport;
  struct List *client_rev;
  struct List *server_rev;
  struct List *promisc;
  struct List *dezip;
  struct tuple4 ip_and_port;
  int current_channel;
  time_t time;
  struct Http_RR *judge_http_rr;
  struct Http_RR *http_rr;
};

struct Job_Queue{
   struct Job jobs[JOB_MAX];
   int front,rear;
   int job_type;
   int insert_number,delete_number,length;
};

typedef void * (*JOB_FUNCTION)(void*);
typedef int (*JOB_JUDGE)(struct Job *job);

extern struct Job_Queue job_queue[JOB_NUMBER];  //任务队列数组，每种任务一个单元。
extern pthread_cond_t job_cond[JOB_NUMBER]; //条件变量数组，用于唤醒任务线程
extern pthread_mutex_t job_mutex_for_cond[JOB_NUMBER]; //互斥量数组，用于同步条件变量
extern pthread_mutex_t job_mutex_for_queue[JOB_NUMBER]; //互斥量数组，用于任务队列
extern JOB_FUNCTION job_functions[JOB_NUMBER]; //执行任务的函数数组
extern JOB_JUDGE job_judges[JOB_NUMBER]; //判断是否需要唤醒线程进行工作 
extern int job_registed[JOB_NUMBER]; //标志某种任务是否注册
extern int job_call_type[JOB_NUMBER]; //CALL_BY_TCP_DATA_MANAGE,CALL_BY_TIMER,CALL_BY_HTTP_ANALYSIS

extern void jobqueue_init(struct Job_Queue *queue);
extern int jobqueue_isFull(struct Job_Queue *queue);
extern int jobqueue_isEmpty(struct Job_Queue *queue);
extern int jobqueue_insert(struct Job_Queue *queue,struct Job *pnode);
extern int jobqueue_delete(struct Job_Queue *queue,struct Job *pnode);
extern void register_job(int job_type, JOB_FUNCTION function,JOB_JUDGE judge,
			 int is_private_judge);
extern void get_jobs(int job_type,struct Job_Queue *private_jobs);

#endif
