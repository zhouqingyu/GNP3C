#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include "project.h"
#include "ftp.h"
#include "mypcre.h"
#include "job.h"
#include "list.h"

static void process_function();
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);

static int min(int n1, int n2)
{
    return n1 > n2? n2: n1;  
}

static int itoa(char *num_a, int num_i)
{
    int i = 0, j, m;
    char index[10], ch;
    
    index[0] = '0';  index[5] = '5';
    index[1] = '1';  index[6] = '6';
    index[2] = '2';  index[7] = '7';
    index[3] = '3';  index[8] = '8';
    index[4] = '4';  index[9] = '9';
 
    do
    {
      num_a[i] = index[ num_i%10 ];
      num_i /= 10;
      i++;
    }while(num_i);


    m = i / 2;
    for(j = 0; j < m; j++)
    {
       ch         = num_a[j];
       num_a[j]   = num_a[i-1-j];
       num_a[i-1-j] = ch;
    }
    num_a[i] = '\0';
    
    return 0;
}


static int getuser(const char *src, int cnt, ftp_msg_t *p)
{
    int ovec[OVECCOUNT], rc;
    
    rc = pcre_match("^USER (.*?)\r\n", src, cnt, ovec, OVECCOUNT, PCRE_MULTILINE
                    |PCRE_DOTALL);
    if(rc != 2)                
       return -1;
    memcpy(p->user, src + ovec[1*2], ovec[1*2+1] - ovec[1*2]);
    p->user[ (ovec[1*2+1] - ovec[1*2]) ] = '\0';
    return 0;
}

static int getpasswd(const char *src, int cnt, ftp_msg_t *p)
{
    int ovec[OVECCOUNT], rc;
    
    rc = pcre_match("^PASS (.*?)\r\n", src, cnt, ovec, OVECCOUNT, PCRE_MULTILINE
                    |PCRE_DOTALL);
    if(rc != 2)                
       return -1;
    memcpy(p->passwd, src + ovec[1*2], ovec[1*2+1] - ovec[1*2]);
    p->passwd[ (ovec[1*2+1] - ovec[1*2]) ] = '\0';
    return 0;
}


static enum ftp_mode getmode(const char *src, int cnt, ftp_msg_t *p)
{
    int ovec[OVECCOUNT], rc;
    
    rc = pcre_match("^PASV\r\n", src, cnt, ovec, OVECCOUNT, PCRE_MULTILINE
                    |PCRE_DOTALL);
    if(rc > 0)
       return FM_PASV;
    
    rc = pcre_match("^PORT.*?\r\n", src, cnt, ovec, OVECCOUNT, PCRE_MULTILINE
                    |PCRE_DOTALL);
    if(rc > 0)
       return FM_PORT;
    
    return -1;
}

static int do_ftp_pasv(const char *sp, int scnt, const char *cp, int ccnt, 
                       ftp_msg_t *p)
{
    int ovec_s[OVECCOUNT], ovec_c[OVECCOUNT]; 
    int rc1, rc2, i;
    
    rc1 = pcre_matall("(^STOR.*?\r\n|^RETR.*?\r\n)", sp, scnt, ovec_s, OVECCOUNT, 
                      PCRE_MULTILINE|PCRE_DOTALL);
    rc2 = pcre_matall("227 Entering Passive Mode.*?\r\n", cp, ccnt, ovec_c, 
                      OVECCOUNT, PCRE_MULTILINE|PCRE_DOTALL);
    if( rc1 != rc2 || rc1 <= 0 || rc2 <= 0)
        printf("do_ftp_pasv some error\n");
    
    for(i = 0; i < min(rc1, rc2); i++)   /* we conside rc1 == rc2 */  
    {
       int rc3, rc4;
       int ov_s[OVECCOUNT], ov_c[OVECCOUNT]; 
       char desport[20], num_ch_1[10], num_ch_2[10], handle[10]; 
       int desport_i, num_i_1, num_i_2;
       
       rc3 = pcre_match("(STOR|RETR) (.*?)\r\n", sp + ovec_s[2*i], 
                        ovec_s[2*i+1] - ovec_s[2*i], ov_s, OVECCOUNT, 
                        PCRE_MULTILINE|PCRE_DOTALL);     
       memcpy(handle, sp + ovec_s[2*i] + ov_s[2*1], ov_s[2*1+1] - ov_s[2*1]);
       handle[ ov_s[2*1+1] - ov_s[2*1] ] = '\0';
       
       p->dn_list[i] = (char*)malloc( (ov_s[2*2+1]-ov_s[2*2]+1) * sizeof(char));
       memcpy(p->dn_list[i], sp + ovec_s[2*i] + ov_s[2*2], ov_s[2*2+1] - 
              ov_s[2*2]);
       p->dn_list[i][ ov_s[2*2+1] - ov_s[2*2] ] = '\0';
       
       if( strcmp(handle, "STOR") == 0 )
           p->dh_list[i] = FH_STOR;
       else
           p->dh_list[i] = FH_RETR;
       
       rc4 = pcre_match("\\(\\d+,\\d+,\\d+,\\d+,(\\d+),(\\d+)\\)", cp + 
                        ovec_c[2*i], ovec_c[2*i+1] - ovec_c[2*i], ov_c, 
                        OVECCOUNT, PCRE_MULTILINE|PCRE_DOTALL);
       memcpy(num_ch_1, cp + ovec_c[2*i] + ov_c[2*1], ov_c[2*1+1] - ov_c[2*1]);
       memcpy(num_ch_2, cp + ovec_c[2*i] + ov_c[2*2], ov_c[2*2+1] - ov_c[2*2]);
       num_ch_1[ ov_c[2*1+1] - ov_c[2*1] ] = '\0';
       num_ch_2[ ov_c[2*2+1] - ov_c[2*2] ] = '\0';
       num_i_1 = atoi(num_ch_1);
       num_i_2 = atoi(num_ch_2);
       
       desport_i = num_i_1 * 256 + num_i_2;
       p->dport_list[i] = desport_i;
       
    }
    p->dcount = i;
    p->dn_list[i] = NULL;
    
    return 0; 
}

static int do_ftp_port(const char *sp, int scnt, ftp_msg_t *p)
{
    int ovec[OVECCOUNT];
    int rc1, rc2, i;
       
    rc1 = pcre_matall("^PORT.*?\r\n", sp, scnt, ovec, OVECCOUNT, 
                      PCRE_MULTILINE|PCRE_DOTALL);
    if( rc1 <= 0 )
        return -1;
    
    for(i = 0; i < rc1; i++)
    {
       char desport[20], num_ch_1[10], num_ch_2[10], handle[10]; 
       int desport_i, num_i_1, num_i_2, len, ov[OVECCOUNT]; 
       
       if(i == rc1 - 1) len = scnt - ovec[2*i];
       else len = ovec[2*(i+1)] - ovec[2*i];
       
       rc2 = pcre_match("PORT \\d+,\\d+,\\d+,\\d+,(\\d+),(\\d+)\r\n(^STOR|^RETR) (.*?)\r\n", 
                        sp + ovec[2*i], len, ov, OVECCOUNT, PCRE_MULTILINE|
                        PCRE_DOTALL);
       if( rc2 != 5 )  continue;
              
       p->dn_list[ p->dcount ] = (char*)malloc( (ov[2*4+1]-ov[2*4]+1) 
                                                * sizeof(char) );
       memcpy(p->dn_list[ p->dcount ], sp + ovec[2*i] + ov[2*4], ov[2*4+1] - 
              ov[2*4]);
       p->dn_list[ p->dcount ][ ov[2*4+1]-ov[2*4] ] = '\0';
       
       memcpy(handle, sp + ovec[2*i] + ov[2*3], ov[2*3+1] - ov[2*3]);
       handle[ ov[2*3+1] - ov[2*3] ] = '\0';
       if( strcmp(handle, "STOR") == 0 )
           p->dh_list[ p->dcount ] = FH_STOR;
       else
           p->dh_list[ p->dcount ] = FH_RETR;
       
       memcpy(num_ch_1, sp + ovec[2*i] + ov[2*1], ov[2*1+1] - ov[2*1]);
       memcpy(num_ch_2, sp + ovec[2*i] + ov[2*2], ov[2*2+1] - ov[2*2]);
       num_ch_1[ ov[2*1+1] - ov[2*1] ] = '\0';
       num_ch_2[ ov[2*2+1] - ov[2*2] ] = '\0';
       num_i_1 = atoi(num_ch_1);
       num_i_2 = atoi(num_ch_2);
       desport_i = num_i_1 * 256 + num_i_2;
       p->dport_list[p->dcount] = desport_i;
       p->dcount++;
    }
    p->dn_list[ p->dcount ] = NULL;

    
    return 0; 
}

static int ftp_analysis(int scnt, char *sbuf, int ccnt, char *cbuf, ftp_msg_t *pfmsg)
{
    pfmsg->dcount = 0;
    getuser(sbuf, scnt, pfmsg);
    getpasswd(sbuf, scnt, pfmsg);
    enum ftp_mode mode = getmode(sbuf, ccnt, pfmsg);
    pfmsg->mode = mode;
    switch(mode)
    {
      case FM_PASV:
        return do_ftp_pasv(sbuf, scnt, cbuf, ccnt, pfmsg);

      case FM_PORT:
        return do_ftp_port(sbuf, scnt, pfmsg);
    
      default:
        return -1; 
    }
}

static void fmsg_free(ftp_msg_t *p)
{
   int i;
   
   for(i = 0; i < p->dcount; i++){  
     free(p->dn_list[i]);
   }
}

static void fmsg_print(ftp_msg_t *p)
{
   int i;
   for(i = 0; i < p->dcount; i++){
      pthread_mutex_lock(&ftp_file_mutex);
      ftp_file_list_add(&ftp_file_list,p->user,p->passwd,p->dn_list[i],p->dh_list[i] == FH_STOR? "STOR" : "RETR",p->dport_list[i]);
      pthread_mutex_unlock(&ftp_file_mutex);
   }
}

extern void ftp_analysis_init(){
    pthread_mutex_init(&ftp_file_mutex,NULL);
    ftp_file_list_init(&ftp_file_list);
    register_job(JOB_TYPE_FTP,process_function,process_judege,CALL_BY_TCP_DATA_MANAGE);
}

static void process_function(){
   int job_type = JOB_TYPE_FTP;
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
  
   while(!jobqueue_isEmpty(&private_jobs)){
       
       jobqueue_delete(&private_jobs,&current_job);
       
       ftp_msg_t fmsg;
       

       if(current_job.server_rev == NULL ||\
          current_job.server_rev->head == NULL ||\
          current_job.server_rev->head->data == NULL ||\
          current_job.client_rev == NULL ||\
          current_job.client_rev->head == NULL ||\
          current_job.client_rev->head->data == NULL)
          continue;

       ftp_analysis(current_job.server_rev->head->length,current_job.server_rev->head->data,\
                    current_job.client_rev->head->length,current_job.client_rev->head->data,\
                    &fmsg);
       fmsg_print(&fmsg);
       fmsg_free(&fmsg);

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
   job->desport = 21;
   job->data_need = 4;
   return 1;
}

