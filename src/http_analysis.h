#ifndef HTTP_ANALYSIS_H

#define HTTP_ANALYSIS_H

extern struct project_prm project_params;
extern struct Job_Queue job_queue[JOB_NUMBER];  //任务队列数组，每种任务一个单元。
extern pthread_cond_t job_cond[JOB_NUMBER]; //条件变量数组，用于唤醒任务线程
extern pthread_mutex_t job_mutex_for_cond[JOB_NUMBER]; //互斥量数组，用于同步条件变量
extern pthread_mutex_t job_mutex_for_queue[JOB_NUMBER]; //互斥量数组，用于任务队列
extern JOB_FUNCTION job_functions[JOB_NUMBER]; //执行任务的函数数组
extern JOB_JUDGE job_judges[JOB_NUMBER]; //判断是否需要唤醒线程进行工作 
extern int job_registed[JOB_NUMBER]; //标志某种任务是否注册
extern int job_call_type[JOB_NUMBER]; //CALL_BY_TCP_DATA_MANAGE,CALL_BY_TIMER,CALL_BY_HTTP_ANALYSIS

extern void http_analysis_init();

#endif
