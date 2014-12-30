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
#include <syslog.h>
#include <sys/socket.h> //u_char
#include <dirent.h>
#include <pcre.h>

#include "project.h"
#include "information_monitor_main.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "list.h"

#define msnlen 1664

#define MAX 9000000
#define OVECCOUNT 100
#define MESSAGE_MAX 640000
#define MATCH_ONE_MAX 64000
#define SDG_MAX 64000000

static char bodytemp[MAX];
static char modetemp[MAX];

static void getnext(char mode[],int modelength,int next[]);
static char * zhstr(char mode[],char body[],int *length,int next[],int bodylength,int modelength);
static int get_msnmessenger(int hash_index,char *stream,int sumlen);
static void process_function();
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);
static void debug_write_data(char file[],char *data,int data_length);
static void debug_print_file(struct Job *current_job);

static int debug_job_number;


static void match_one_patch(char *data,int data_length,char *pattern,char *result){
    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[OVECCOUNT];

    char *pattern_respond = pattern;
    regex = pcre_compile( pattern_respond , options, &error, &erroffset, NULL);

    if(regex == NULL){
        printf("PCER compilation failure at offset %d: %s\n", erroffset, error); 
        free( regex );
        return;
    }

    rc = pcre_exec( regex, NULL, data, data_length, 0, 0,ovector, OVECCOUNT);  
    if(rc > 0){
        if(ovector[3] - ovector[2] < MATCH_ONE_MAX){
           memcpy(result,data + ovector[2],ovector[3] - ovector[2]);
        }
        else{
           memcpy(result,data + ovector[2],MATCH_ONE_MAX);
        }
    }
    free( regex );
}


static void deal_with_one_SDG(char *data,int data_length,int hash_index,time_t time){
    char *to = (char *)malloc(MATCH_ONE_MAX * sizeof(char));
    char *from = (char *)malloc(MATCH_ONE_MAX*sizeof(char));
    char *length_str = (char *)malloc(MATCH_ONE_MAX*sizeof(char));

    memset(to,0,MATCH_ONE_MAX*sizeof(char));
    memset(from,0,MATCH_ONE_MAX*sizeof(char));
    memset(length_str,0,MATCH_ONE_MAX*sizeof(char));

    match_one_patch(data,data_length,"To: \\d+?:(.*?)\r\n",to);

    match_one_patch(data,data_length,"From: \\d+?:(.*?);.*?\r\n",from);

    match_one_patch(data,data_length,"Content-Length: (\\d+?)\r\n",length_str);


    if(!(strlen(to)>0 && strlen(from)>0 && strlen(length_str)>0)){
       return;
    }
    printf("F-5\n");
    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[OVECCOUNT];
    char *message = (char *)malloc(MESSAGE_MAX*sizeof(char));

    memset(message,0,sizeof(message));
    char *pattern_respond = "Messaging.*?\r\n\r\n";
    regex = pcre_compile( pattern_respond , options, &error, &erroffset, NULL);

    if(regex == NULL){
        printf("PCER compilation failure at offset %d: %s\n", erroffset, error);
        free(to);
        free(from);
        free(length_str);
        free(message); 
        free( regex );
        return;
    }

    rc = pcre_exec( regex, NULL, data, data_length, now_position, 0,ovector, OVECCOUNT);  
    if(rc >0){

         if(atoi(length_str) < MESSAGE_MAX)
          memcpy(message,data + ovector[1],atoi(length_str));
         else memcpy(message,data + ovector[1],MESSAGE_MAX);
         printf("to is %s from is %s message is %s\n",to,from,message);
         if(atoi(length_str) > 0){
             sql_factory_add_msn_record(from,to,message,hash_index,time);
         }
   }
   free(to);
   free(from);
   free(length_str);
   free(message);
   free( regex );
}

static void getSDG(char *data,int data_length,int hash_index,time_t time){
    pcre *regex = NULL;
    const char *error = NULL;
    int erroffset;
    int rc;
    int options = PCRE_DOTALL;
    int now_position;
    int ovector[OVECCOUNT];
    char *conlenstr  =(char *)malloc(SDG_MAX*sizeof(char));

    char *pattern_respond = "SDG \\d+? \\d+?\r\n(.*?)SDG \\d+? \\d+?\r\n";
    regex = pcre_compile( pattern_respond , options, &error, &erroffset, NULL);
    if(regex == NULL){
        printf("PCER compilation failure at offset %d: %s\n", erroffset, error);
        free(conlenstr);
        return;
    }
    now_position = 0;
    rc = 0;
    do{
          rc = pcre_exec( regex, NULL, data, data_length, now_position, 0,ovector, OVECCOUNT);
          if ( rc < 0 ){
             break;
          }
          now_position = ovector[3];
        
          memset(conlenstr,0,sizeof(char)*SDG_MAX);
          if(SDG_MAX > ovector[3] - ovector[2]){
               memcpy(conlenstr,data + ovector[2],(ovector[3] - ovector[2])*sizeof(char));
               deal_with_one_SDG(conlenstr,ovector[3] - ovector[2],hash_index,time);
          }
          else {
              memcpy(conlenstr,data + ovector[2],SDG_MAX*sizeof(char));
              deal_with_one_SDG(conlenstr,SDG_MAX,hash_index,time);
          }
          
   }while(rc>0);

   int remain_data_length = data_length - now_position;
   if(now_position < data_length){
          memset(conlenstr,0,sizeof(char)*SDG_MAX);        
          memcpy(conlenstr,data + now_position,(data_length - now_position)*sizeof(char));
          deal_with_one_SDG(conlenstr,data_length - now_position,hash_index,time);
   }
   free(conlenstr);
   free( regex );
}


static void getnext(char mode[],int modelength,int next[]){    
    memcpy(modetemp+1,mode,modelength);
    int i,j;
     i=1;
     next[1]=0;
     j=0;
     while(i<modelength)
     {
        if(j==0 || modetemp[i] == modetemp[j]) 
           {
              i++;
              j++;
              next[i]=j;
           }
         else
              j=next[j];
     }
}


static char * zhstr(char mode[],char body[],int *length,int next[],int bodylength,int modelength){
   
    memcpy(bodytemp+1,body,bodylength);
    memcpy(modetemp+1,mode,modelength);
    
    int i=1;
    int j=1;
     
     while(j<=modelength && i<=bodylength){
      
           if(j==0 || bodytemp[i]==modetemp[j])
            {
               i++;
               j++;
            }
           else j=next[j];
     }

     if(j>modelength){
             *length = i-modelength-1; 
             return &(body[i-modelength-1]);
        }
     else return 0;
}


static int get_msnmessenger(int hash_index,char *stream,int sumlen){
        char id[4000],contact_account[4000],contact_name[4000],len[4000],my_account[4000],cmp[4000];
	int length,pstr_len=0,cpstr_len,be_len;
	char *begin,*p,*q,*pstream;
	int flag=0,i=0;
	char message[msnlen];
        int next1[30],next2[30],next3[30],next4[30],next5[30];
        int zhlen=0;
        pstream=stream;
	while(*pstream!='\0'){
             memset(next1,0,30);
             memset(next2,0,30);
             memset(next3,0,30);
             memset(next4,0,30);
             memset(next5,0,30);
             getnext("USR ",4,next1);
             getnext(" SSO ",5,next2);
             getnext("ANS ",4,next3);
             getnext(" OK ",4,next4);
             cpstr_len=pstr_len;
	     if(((begin=zhstr("USR ",pstream,&zhlen,next1,sumlen-pstr_len,4))&&(!zhstr(" SSO ",pstream,&zhlen,next2,sumlen-pstr_len,5))&&(!zhstr(" OK ",pstream,&zhlen,next4,sumlen-pstr_len,4)))||(begin=zhstr("ANS ",pstream,&zhlen,next3,sumlen-pstr_len,4)))
              {     
                    pstr_len+=zhlen;
                    begin+=4;     
                    pstr_len+=4;
                    p=begin;  
		    q=id;
                    while(*p!=' '&&*p) {*q++=*p++;pstr_len++;  printf("position 2 pstr_len = %d\n",pstr_len); }
                    *q=0;
                    p++;
                    pstr_len++;
                    q=my_account;
                    while(*p!=';'&&*p) {*q++=*p++;pstr_len++; printf("position 4 pstr_len = %d  %d\n",pstr_len,*p); }
                    *q='\0';
                    memset(next2,0,30);
                    getnext("JOI ",4,next2);
                    q=zhstr("JOI ",p,&zhlen,next2,sumlen-pstr_len,4);
                    while(q){   
                         pstr_len+=zhlen;
                         q+=4;
                         p=cmp; 
                         while(*q!=' '&&*q)  *p++=*q++;
                         *p='\0';
                         if(strcmp(my_account,cmp))  
                         {     
                               strcpy(contact_account,cmp);
                               if(p=strstr(contact_account,";")) *p='\0';
                               break;
                         }
                         else  {  p=q;
                                  memset(next2,0,30);
                                  getnext("JOI ",4,next2);
                                  q=zhstr("JOI ",p,&zhlen,next2,sumlen-pstr_len,4);
                               }
                     }
	       }

              
              memset(next1,0,4);
              getnext("MSG ",4,next1);
              if(begin=zhstr("MSG ",pstream,&zhlen,next1,sumlen-cpstr_len,4))
	      {     
                       pstr_len=cpstr_len+zhlen;
                       begin+=4;
                       pstr_len+=4;
		       p=begin;
		       if('0'<=*p&&*p<='9')                     
		       {
			       flag=0;
			       q=id;
			       while(*p!=' '&&*p)  {*q++=*p++;pstr_len++;}
			       *q=0;
			       p+=3;
			       pstr_len+=3;
			       memset(next3,0,30);
			       getnext("TypingUser:",11,next3);
			       q=zhstr("TypingUser:",p,&zhlen,next3,sumlen-pstr_len,11);
                               if((q)&&(zhlen<60))
			       {   
				     i=0;
				     q+=12;
				     while(*q!='\r'&&*q)  my_account[i++]=*q++;
				     my_account[i]=0;
				}
                         }
			 else 
			 {   
				flag=1;
				q=contact_account;
				while(*p!=' '&&*p)  {*q++=*p++;pstr_len++;}
				*q=0;
			        p++;
			        pstr_len++;
				q=contact_name;
                                while(*p!=' '&&*p)  {*q++=*p++;pstr_len++;}
				*q=0;
				p++;
				pstr_len++;
			 }
			 q=len;
                         while(*p!='\r'&&*p)  {*q++=*p++;pstr_len++;}
		         *q=0;
			 length=atoi(len);
		         p+=2;
		         pstr_len+=2;
		         be_len=pstr_len;
			 pstream=p;

                        //解析即时会话
                        memset(next2,0,30);
			getnext("Content-Type: text/plain;",25,next2);
			p=zhstr("Content-Type: text/plain;",pstream,&zhlen,next2,sumlen-pstr_len,25);
			if((p)&&(zhlen<length))       
			{   
			        pstr_len+=zhlen;
				memset(next1,0,30);
				getnext("\r\n\r\n",4,next1);

				q=zhstr("\r\n\r\n",p,&zhlen,next1,sumlen-pstr_len,4);

				pstr_len+=zhlen;
				
				q+=4;
				pstr_len+=4;
				begin=q;
				message[length-(pstr_len-be_len)]='\0';
                                i=0;
				while(i<(length-(pstr_len-be_len))&&*q) {   message[i++]=*q++; }

                               if(flag==0)
                                   sql_factory_add_msn_record(my_account,contact_account,message,hash_index);
                               else sql_factory_add_msn_record(contact_account,my_account,message,hash_index);

				pstream=q;
				pstr_len=be_len+length;

				
			}
                        else{  
                                pstream+=length;pstr_len=be_len+length;  
                        }
		}
	       else{
                 printf("to return 2\n");
                 return 2; 
               }
	}
       return 1;
}

extern void msn_analysis_init(){
    register_job(JOB_TYPE_MSN,process_function,process_judege,CALL_BY_TCP_DATA_MANAGE);
}

static void process_function(){
   int job_type = JOB_TYPE_MSN;
   while(1){
       pthread_mutex_lock(&(job_mutex_for_cond[job_type]));
       pthread_cond_wait(&(job_cond[job_type]),&(job_mutex_for_cond[job_type]));
       pthread_mutex_unlock(&(job_mutex_for_cond[job_type]));
       //printf("call msn\n");
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
       //debug_print_file(&current_job);
       //get_msnmessenger(current_job.hash_index,current_job.promisc->head->data,current_job.promisc->head->length);
       getSDG(current_job.promisc->head->data,current_job.promisc->head->length,current_job.hash_index,current_job.time);
       wireless_list_free(current_job.promisc);
       free(current_job.promisc);
   }//while
}

static int process_judege(struct Job *job){
   //have job return 1 or 0
   job->desport = 0;
   job->data_need = 3;
   return 1;
}


static void debug_print_file(struct Job *current_job){
/*
   int fp;
   char dirtemp[100];
   char identify_buffer[100];
   char server[100],client[100],dezip[100];
   char debug_job_number_str[100];


   memset(dirtemp,0,sizeof(dirtemp));
   strcat(dirtemp,"/var/log/msn/");

   int flag;
   DIR *d;
   if((d=opendir(dirtemp)) == NULL){
       if( (flag = mkdir(dirtemp,S_IRWXU )) == -1 )
           printf("mkdir %s error:%s",dirtemp,strerror(errno));
    }
    else{
        closedir(d);
    }

   memset(debug_job_number_str,0,100*sizeof(char));
   sprintf(debug_job_number_str,"%d",debug_job_number++);
   strcat(dirtemp,debug_job_number_str);

   if((d=opendir(dirtemp)) == NULL){
       if( (flag = mkdir(dirtemp,S_IRWXU )) == -1 )
           printf("mkdir %s error:%s",dirtemp,strerror(errno));
   }
   else{
        closedir(d);
   }
   if(current_job->promisc != NULL){
      memset(server,0,100*sizeof(char));
      sprintf(server,"%s/log_promisc",dirtemp);
      debug_write_data(server,current_job->promisc->head->data, current_job->promisc->head->length);
   }
*/
}


static void debug_write_data(char file[],char *data,int data_length){
   int fp = open(file,O_WRONLY|O_CREAT);
   if(fp == -1){
      printf("debug write data open file failure %s %s\n",file,strerror(errno));
      return;
   }
         
   unsigned int write_number;
   write_number = write(fp,data,data_length);
   printf("write_number is %s %d\n",file,write_number);
   close(fp);
}

