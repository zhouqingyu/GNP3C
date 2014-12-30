#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <mysql.h>
#include <syslog.h>
#include <malloc.h>
#include <gtk/gtk.h>

#include "database.h"
#include "packet.h"
#include "nids.h"
#include "job.h"
#include "safe_time.h"
#include "list.h"
#include "configuration.h"
#include "tcp_lost_manage.h"
#include "tcp_data_manage.h"
#include "http_analysis.h"
#include "user_password_analysis.h"
#include "change_channel.h"
#include "pop3.h"
#include "smtp.h"
#include "imap.h"

struct project_prm project_params={
   LOG_ALERT,			                 /* syslog_level */
};

struct Configuration configuration;

//for FTP analysis
struct FTP_FILE_LIST ftp_file_list;
pthread_mutex_t ftp_file_mutex;

//for packet catching
struct Packet packets[PACKET_QUEUE_MAX]; //for packet to save
int packet_queue_head;
pthread_mutex_t mutex_packet; //mutex lock for get head of packetes
static pthread_t get_packet_thread_handle;

//for database
pthread_mutex_t database_mutex;
MYSQL *database_sock;
MYSQL database_hadle;

//for jobs
static pthread_t job_threads[JOB_NUMBER];

//for email analysis
struct Content_Attachment_Match_List *content_list,*attachment_list;
pthread_mutex_t content_list_mutex,attachment_list_mutex;

//gtk
GtkWidget *PktInfoList;
GtkWidget *Window;

static void safe_init();
static void wait_for_system_shutdown();
static void init_job_threads();
extern void email_init();
extern void ftp_analysis_init();
extern void web_analysis_init();
static void create_window();

int main(int argc,char **argv){

   read_configuration();
   //init param
   openlog("wireless safe project",LOG_CONS|LOG_NDELAY
			      |LOG_PERROR|LOG_PID,LOG_LOCAL0);
   safe_init();
   
   g_thread_init(NULL);
   gdk_threads_init();
   gtk_init(NULL,NULL);
   
   create_window();
   gtk_widget_show(Window);
   gdk_threads_enter();
   gtk_main();
   gdk_threads_leave();   
   
   wait_for_system_shutdown();
   closelog();
   db_close(&database_hadle);
   
   return 0;
}

static void closeApp(GtkWidget *window, gpointer data)
{
	gtk_main_quit();
}

static gboolean delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	//g_print("In delete_event\n");
	return FALSE;
}

static GtkWidget *aclist(void)
{	
  gint i;
  gchar *titles[] = {
    "NO.",
    "Source",
    "Source Port",
    "Destination",
    "Destination Port",
    "State"
  };
	
  PktInfoList = gtk_clist_new_with_titles(6, titles);
  for (i = 0; i < 6; i++) {
    gtk_clist_set_column_auto_resize( GTK_CLIST(PktInfoList), i, FALSE);
  }
  gtk_widget_show(PktInfoList);
	
  return PktInfoList;
}

static void create_window() 
{ 
  GtkWidget *scrolled_win;
  
  Window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(Window), "GNP3C");
  gtk_window_set_position(GTK_WINDOW(Window), GTK_WIN_POS_CENTER);
  gtk_window_set_default_size(GTK_WINDOW(Window), 600, 400);
  gtk_container_set_border_width(GTK_CONTAINER(Window), 10);
	
  g_signal_connect(G_OBJECT(Window), "destroy", G_CALLBACK(closeApp), NULL);
  g_signal_connect(G_OBJECT(Window), "delete_event", G_CALLBACK(delete_event),
					NULL);	
  
  scrolled_win = gtk_scrolled_window_new(NULL, NULL);
  gtk_widget_set_usize(scrolled_win, 300, 100);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_ALWAYS, GTK_POLICY_ALWAYS);
  gtk_container_add(GTK_CONTAINER(Window), scrolled_win);
  gtk_widget_show(scrolled_win);

  gtk_container_add(GTK_CONTAINER(scrolled_win), aclist());
}

static void safe_init() {
  
   email_attachment_match_init();
  
   pthread_mutex_init(&content_list_mutex,NULL);
   pthread_mutex_init(&attachment_list_mutex,NULL);
   content_list = (struct Content_Attachment_Match_List *)malloc(sizeof(struct Content_Attachment_Match_List));
   content_attachment_match_list_init(content_list);
   attachment_list = (struct Content_Attachment_Match_List *)malloc(sizeof(struct Content_Attachment_Match_List));
   content_attachment_match_list_init(attachment_list);
   
   database_sock = db_init(&database_hadle);
   //init tcp data zone
   pthread_mutex_init(&mutex_tcp_data_table,NULL);
   memset(tcp_data_table,0,sizeof(tcp_data_table));
   pthread_mutex_init(&tcp_lost_mutex,NULL);
   
   packet_queue_head = 0;
   pthread_mutex_init(&mutex_packet,NULL);  
   pthread_create(&get_packet_thread_handle,NULL,(void *)recv_packet_function,NULL);
   
   install_timer();
   ip_tcp_udp_init();
   tcp_lost_manage_init();
   tcp_data_manage_init();
   http_analysis_init();
   //user_password_analysis_init();
   //msn_analysis_init();
   //cookie_analysis_init();
   //telnet_analysis_init();
   //change_channel_init();
   //ftp_analysis_init();
   //ftp_file_manage_init(); 
   web_analysis_init();
   pop3_analysis_init();
   smtp_analysis_init();
   imap_analysis_init();
   email_init();
   //save_environment_init();
   //recover_environment();
   init_job_threads();
   
}

static void wait_for_system_shutdown(){

   pthread_join(get_packet_thread_handle,NULL);

   int job_type;
   for(job_type=0; job_type<JOB_NUMBER; job_type++){
        if(!job_registed[job_type])
            continue;
        pthread_join(job_threads[job_type],NULL);
   }
}

static void init_job_threads(){
    int job_type;
    for(job_type=0; job_type<JOB_NUMBER; job_type++){
         if(!job_registed[job_type])
            continue;
         pthread_create(&(job_threads[job_type]),NULL,job_functions[job_type],NULL);
    }
}