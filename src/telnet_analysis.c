#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<errno.h>
#include<memory.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include <errno.h>
#include <ctype.h>
#include<pcre.h>
#include <syslog.h>
#include <sys/socket.h> //u_char

#include "project.h"
#include "information_monitor_main.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "list.h"
#include "user_password_analysis.h"
#include "telnet_analysis.h"

#define SE  0
#define SB  1
#define IAC 2
#define WILL 3
#define DO   4
#define WONT 5
#define DONT 6

#define OVECCOUNT 100
#define MAX  9000000

static char result[MAX];
static char command[MAX];
static char password[100];

static int analysis(struct TelnetInformation *info,int length,char buffer[]);
static int getpassword(struct TelnetInformation *info,int length,char buffer[]);
static void process_function();
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);

static int getpassword(struct TelnetInformation *info,int length,char buffer[]){

    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int ovector[OVECCOUNT];

    char *pattern_respond = "Password: (.*?)(\r\n|\n)";

    regex = pcre_compile( pattern_respond , options, &error, &erroffset, NULL);

    if( regex == NULL ){      
           free( regex );
           return 0;
    }

    rc = pcre_exec( regex, NULL, buffer, length, 0, 0,ovector, OVECCOUNT);

    if ( rc != 3 ){
         return 0;
    }     
     
    memset(password,0,sizeof(password));
    memcpy(password,buffer + ovector[2], ovector[3] - ovector[2]);
    info->password = password;
   
    if(strlen(info->password)>0)
     return 1;
    else return 0;
}


static int analysis(struct TelnetInformation *info,int length,char buffer[]){

   char str_order[7][10]={"SE","SB","IAC","WILL","DO","WONT","DONT"};
   int  code_order[7]={0xfffffff0,0xfffffffa,0xffffffff,0xfffffffb,0xfffffffd,0xfffffffc,0xfffffffe};

   char *str_opion[1000];
   int opion_index;
   for(opion_index=0;opion_index<1000;opion_index++)
       str_opion[opion_index] = "";  

   str_opion[1] = "回显";
   str_opion[3] = "抑制继续进行";
   str_opion[24] = "终端类型";
   str_opion[31] = "窗口大小";
   str_opion[32] = "终端速率";
   str_opion[33] = "远程流量控制";
   str_opion[34] = "行方式";
   str_opion[36] = "环境变量";



 
  int ri = 0;
  int bi = 0;

  memset(result,0,sizeof(result));
  memset(command,0,sizeof(command));

  while(bi<length){
      if(buffer[bi] != code_order[IAC]){
         result[ri++] = buffer[bi];
         bi++;
         continue;
      }
      else {
         //前面一个是IAC
         bi++;

         if(buffer[bi] == code_order[SB]){
             //IAC后面是SB，即为子选项协商开始
             bi++;
             int opion;
             int param[1000];
             int pi=0;
             opion = buffer[bi++];
             while(buffer[bi]!=code_order[IAC] || buffer[bi+1]!=code_order[SE]){
                   
                   param[pi++] = buffer[bi++]; 
             }
             
             bi+=2;
            //一个 IAC SB 选项码 参数若干 IAC SE 解码结束
            sprintf(command+strlen(command),"IAC SB %s ",str_opion[opion],opion);
            int i;
            
            for(i=0;i<pi;i++)
              sprintf(command+strlen(command),"%d ",param[i]);
            
            sprintf(command+strlen(command),"IAC SE\n");
            continue;
         }//if
         else{
              if(buffer[bi] == code_order[WILL] || buffer[bi] == code_order[DO] || buffer[bi] == code_order[WONT] || buffer[bi] == code_order[DONT]){
                
                //IAC后面是命令： WILL、DO、WONT、DONT
                //解析出一条命令
                int k;
                int opion = buffer[bi+1];
                for(k=3;k<7;k++)
                  if(buffer[bi] == code_order[k])
                    break;
                
                sprintf(command+strlen(command),"IAC %s %d\n",str_order[k],opion);
                bi+=2;
                continue;
              }
              else{
               //前面是IAC，后面不是SB、也不是各个命令如WILL、DO、WONT、DONT，属于特殊情况，写入result缓存作为正常数据处理
                 
                 result[ri++] = buffer[bi];
                 bi++;
                 continue;
              }
         }//else
         
      }//else
 
  }//while

  info->content = result;
  info->command = command;

  if(strlen(info->content) > 0 || strlen(info->command) > 0)
     return 1;
  else return 0;
}//analysis


extern void telnet_analysis_init(){
    register_job(JOB_TYPE_TELNET,process_function,process_judege,CALL_BY_TCP_DATA_MANAGE);
}

static void process_function(){
   int job_type = JOB_TYPE_TELNET;
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
       
       struct TelnetInformation info;
       jobqueue_delete(&private_jobs,&current_job);

       int result_password = getpassword(&info,current_job.promisc->head->length,current_job.promisc->head->data);

       int result_content = analysis(&info,current_job.client_rev->head->length,current_job.client_rev->head->data);

       if(result_content || result_password)
         sql_factory_add_telnet_record(&info,current_job.hash_index);
 
       if(current_job.server_rev!=NULL){
          wireless_list_free(current_job.server_rev);
          free(current_job.server_rev);
       }

       if(current_job.client_rev !=NULL){
          wireless_list_free(current_job.client_rev);
          free(current_job.client_rev);
       }

       if(current_job.promisc != NULL){
          wireless_list_free(current_job.promisc);
          free(current_job.promisc);
       }      
   }//while
}

static int process_judege(struct Job *job){
   //have job return 1 or 0
   job->desport = 23;
   job->data_need = 4;
   return 1;
}
