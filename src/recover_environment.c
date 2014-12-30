#include <pthread.h>
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
#include <sys/socket.h> //u_char
#include <dirent.h>
#include<errno.h>

#include "project.h"
#include "configuration.h"
#include "job.h"
#include "recover_environment.h"
#include "list.h"

static void process_function();
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);
static void recover_one_tcp_stream_envoriment(char *current_dictionary_name,char *tcp_stream_name);
static void recover_envoriment();
static void recover_one_record_envoriment(char *current_dictionary_name);
static void recover_ip_and_port_using_name(struct tuple4 *ip_and_port,int *database_hash_index,char *tcp_stream_name);

extern void recover_environment(){
    register_job(JOB_TYPE_RECOVER_ENVIRONMENT,process_function,process_judege,CALL_BY_TIMER);
}

static void process_function(){
   int job_type = JOB_TYPE_RECOVER_ENVIRONMENT;

   //sleep(configuration.time_wait_unit*5);

   while(1){
       pthread_mutex_lock(&(job_mutex_for_cond[job_type]));
       pthread_cond_wait(&(job_cond[job_type]),&(job_mutex_for_cond[job_type]));
       pthread_mutex_unlock(&(job_mutex_for_cond[job_type]));
       
       process_function_actual(job_type);
       unregister_job(job_type);
       return;//kill myself
    }
}

static void process_function_actual(int job_type){
   struct Job_Queue private_jobs;
   private_jobs.front = 0;
   private_jobs.rear = 0;
   get_jobs(job_type,&private_jobs);
   struct Job current_job;
   int is_recoved = 0;
  
   while(!jobqueue_isEmpty(&private_jobs)){
       jobqueue_delete(&private_jobs,&current_job);
       if(!is_recoved){
          recover_envoriment();
          is_recoved = 1;
       }
   }//while
}

static int process_judege(struct Job *job){
   //have job return 1 or 0
   return 1;
}

static void recover_envoriment(){
   char current_dictionary_name[100];

   DIR *dp;
   struct dirent *entry;
   dp = opendir(configuration.recover_environment_path);
   if(dp == NULL) {
       syslog(project_params.syslog_level,"recover_environment_path(%s) does not exsit\n",configuration.recover_environment_path);
       return;
   }

   while((entry = readdir(dp) ) != NULL){
      if( entry->d_type == DT_DIR ) {
        if( strcmp(entry->d_name,".") == 0 || strcmp(entry->d_name,"..") == 0 )
            continue;
        
        memset(current_dictionary_name,0,sizeof(current_dictionary_name));
        strcpy(current_dictionary_name,configuration.recover_environment_path);
        if(current_dictionary_name[strlen(current_dictionary_name)-1] != '/')
           strcat(current_dictionary_name,"/");
        strcat(current_dictionary_name, entry->d_name);

        syslog(project_params.syslog_level,"deal with one record environment(%s)\n",current_dictionary_name);
        recover_one_record_envoriment(current_dictionary_name);
        
        break; // only recover one record environment once. 

      }else{
         syslog(project_params.syslog_level,\
         "first catagory(%s) contain file(%s) which is no directionary\n",configuration.recover_environment_path,entry->d_name);
      }
  }//while end
  closedir(dp);
}

static void recover_one_record_envoriment(char *current_dictionary_name){

   char one_tcp_stream_path[100];

   DIR *dp;
   struct dirent *entry;
   dp = opendir(current_dictionary_name);
   if(dp == NULL) {
       syslog(project_params.syslog_level,"recover_environment_path(%s) does not exsit\n",current_dictionary_name);
       return;
   }

   while((entry = readdir(dp) ) != NULL){
      if( entry->d_type == DT_DIR ) {
        if( strcmp(entry->d_name,".") == 0 || strcmp(entry->d_name,"..") == 0 )
            continue;
        
        memset(one_tcp_stream_path,0,sizeof(one_tcp_stream_path));
        strcpy(one_tcp_stream_path,current_dictionary_name);
        if(one_tcp_stream_path[strlen(one_tcp_stream_path)-1] != '/')
           strcat(one_tcp_stream_path,"/");
        strcat(one_tcp_stream_path, entry->d_name);

        syslog(project_params.syslog_level,"deal with one tcp record environment(%s)\n",one_tcp_stream_path);
        recover_one_tcp_stream_envoriment(one_tcp_stream_path,entry->d_name);

      }else{
         syslog(project_params.syslog_level,\
         "second catagory(%s) contain file(%s) which is no directionary\n",current_dictionary_name,entry->d_name);
      }
  }//while end
  
  closedir(dp);

}

   
static void recover_one_tcp_stream_envoriment(char *current_dictionary_name,char *tcp_stream_name){

   time_t waited_time;
   waited_time = time((time_t *)0);

   struct File_data file_data;
   DIR *dp;
   struct dirent *entry;

   dp = opendir(current_dictionary_name);
   if(dp == NULL) {
       syslog(project_params.syslog_level,"recover_environment_path(%s) does not exsit\n",current_dictionary_name);
       return;
   }

   struct tuple4 ip_and_port;
   int database_hash_index;
   recover_ip_and_port_using_name(&ip_and_port,&database_hash_index,tcp_stream_name);

   while( (entry = readdir(dp) )!=NULL){

     if( entry->d_type == DT_DIR ) {
        if( strcmp(entry->d_name,".") == 0 || strcmp(entry->d_name,"..") == 0 )
            continue;
        syslog(project_params.syslog_level,"third catagory(%s) contain catagory\n",current_dictionary_name,entry->d_name);
        continue;
     }

     if(entry->d_type == DT_REG){

        char file_path[100];
        memset(file_path,0,sizeof(file_path));
        strcpy(file_path,current_dictionary_name);
        if(file_path[strlen(file_path)-1] != '/')
           strcat(file_path,"/");
        strcat(file_path, entry->d_name);

        if(read_file(file_path,&file_data) != 0){
            continue;
        }
        
        int data_type;

        if(strstr(file_path,"server") != NULL){
             data_type = DATA_TYPE_SERVER;
        }
        else if(strstr(file_path,"client") != NULL){
             data_type = DATA_TYPE_CLIENT;
        }
        else if(strstr(file_path,"promisc") != NULL){
             data_type = DATA_TYPE_PROMISC;
        }
        else {
             syslog(project_params.syslog_level,"unknown data type(%s)\n",data_type);
             return;
        }
        syslog(project_params.syslog_level,"deal with one stream file environment(%s)\n",file_path);
        tcp_come_new_data_without_add_to_database(file_data.content,file_data.file_length,data_type,&ip_and_port,database_hash_index,waited_time);

     } 
 
   }//while

   closedir(dp);

}

static void recover_ip_and_port_using_name(struct tuple4 *ip_and_port,int *database_hash_index,char *tcp_stream_name){
    sscanf(tcp_stream_name,"%hu_%hu_%u_%u_%d",&(ip_and_port->dest),\
                                            &(ip_and_port->source),\
                                            &(ip_and_port->daddr),\
                                            &(ip_and_port->saddr),\
                                            database_hash_index);
}
