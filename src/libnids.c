#include <config.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netpacket/packet.h>                                                                                        
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <gtk/gtk.h>

#include "project.h"
#include "packet.h"
#include "nids.h"
#include "checksum.h"
#include "ip_fragment.h"
#include "tcp.h"
#include "util.h"
#include "job.h"
#include "list.h"
#include "tcp_data_manage.h"
#include "tcp_lost_manage.h"
#include "database.h"

static void nids_syslog(int, int, struct ip *, void *);
static int nids_ip_filter(struct ip *, int);
static void tcp_protocol_callback(struct tcp_stream * tcp_connection , void **arg );
static void tcp_come_new_data(char *data,int length,int direction,struct tuple4 *ip_and_port,int hash_index);
static int add_new_tcp_to_database(struct tuple4 *ip_and_port);
static void *process_function(void*);
static void process_function_actual(int job_type);
static int process_judege(struct Job *job);
static inline struct Tcp_Data *find_tcpdata(struct Tcp_Data *point,struct tuple4 *ip_and_port);
static inline struct Tcp_Data *get_last_tcp(struct Tcp_Data *point);
static inline void write_identify(char *identify_buffer,struct tuple4 *ip_and_port);

static struct proc_node *ip_frag_procs;
static struct proc_node *ip_procs;
static struct proc_node *udp_procs;

struct proc_node *tcp_procs;
static u_int8_t linkoffset = 0;

char nids_errbuf[ERRBUF_SIZE];
struct pcap_pkthdr * nids_last_pcap_header = NULL;
struct Start_End_Pair sepair;
static struct Packet packets_temp_zone[PACKET_QUEUE_MAX];
static char target[100];

extern GtkWidget *PktInfoList;

char *nids_warnings[] = {
    "Murphy - you never should see this message !",
    "Oversized IP packet",
    "Invalid IP fragment list: fragment over size",
    "Overlapping IP fragments",
    "Invalid IP header",
    "Source routed IP frame",
    "Max number of TCP streams reached",
    "Invalid TCP header",
    "Too much data in TCP receive queue",
    "Invalid TCP flags"
};

struct nids_prm nids_params = {
    TCP_STREAM_MAX,		/* n_tcp_streams */
    256,			/* n_hosts */
    NULL,			/* device */
    NULL,			/* filename */
    168,			/* sk_buff_size */
    -1,				/* dev_addon */
    nids_syslog,		/* syslog() */
    LOG_ALERT,			/* syslog_level */
    256,			/* scan_num_hosts */
    3000,			/* scan_delay */
    10,				/* scan_num_ports */
    nids_no_mem,		/* no_mem() */
    nids_ip_filter,		/* ip_filter() */
    NULL,			/* pcap_filter */
    1,				/* promisc */
    0,				/* one_loop_less */
    1024,			/* pcap_timeout */
    0                           /* timecountinit */
};
static int nids_ip_filter(struct ip *x, int len)
{
    (void)x;
    (void)len;
    return 1;
}

static void nids_syslog(int type, int errnum, struct ip *iph, void *data)
{
    char saddr[20], daddr[20];
    switch (type) {

    case NIDS_WARN_IP:
	if (errnum != NIDS_WARN_IP_HDR) {
	    strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	    strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	    syslog(nids_params.syslog_level,
		   "%s, packet (apparently) from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	} else
	    syslog(nids_params.syslog_level, "%s\n",
		   nids_warnings[errnum]);
	break;

    case NIDS_WARN_TCP:
	strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	if (errnum != NIDS_WARN_TCP_HDR)
	    syslog(nids_params.syslog_level,
		   "%s,from %s:%hu to  %s:%hu\n", nids_warnings[errnum],
		   saddr, ntohs(((struct tcphdr *) data)->th_sport), daddr,
		   ntohs(((struct tcphdr *) data)->th_dport));
	else
	    syslog(nids_params.syslog_level, "%s,from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	break;
    default:
	syslog(nids_params.syslog_level, "Unknown warning number ?\n");
    }
}

inline void swap(u_int8_t *a,u_int8_t *b)
{
   int t;
   t=*a;
   *a=*b;
   *b=t;
}

static int process_number = 0;

static void process_one_packet(struct Packet node){
    struct proc_node *i;
    u_char *data_aligned, *data;
    
    data = node.content;
    struct ethhdr *et = (struct ethhdr*)data;
    switch ( ntohs(et->h_proto) ) {
      case ETH_P_IP : 
	linkoffset = ETH_HLEN;
	break;
      case ETH_P_PPP_SES :
	linkoffset = ETH_HLEN + 8;
	break;
      default:return;
    }   
    if (node.length < linkoffset)
	return;
    
    data_aligned = data + linkoffset;
    for (i = ip_frag_procs; i; i = i->next)
	(i->item) (data_aligned, node.length - linkoffset);
}

static void gen_ip_frag_proc(u_char * data, int len)
{
    struct proc_node *i;
    struct ip *iph = (struct ip *) data;
    int need_free = 0;
    int skblen;

    if (!nids_params.ip_filter(iph, len))
	{
            return;
        } 

    if (len < (int)sizeof(struct ip) || iph->ip_hl < 5 || iph->ip_v != 4 ||
	ip_fast_csum((unsigned char *) iph, iph->ip_hl) != 0 ||
	len < ntohs(iph->ip_len) || ntohs(iph->ip_len) < iph->ip_hl << 2) {
	nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_HDR, iph, 0);
	return;
    }
    if (iph->ip_hl > 5 && ip_options_compile((char*)data)) {
	nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_SRR, iph, 0);
	return;
    }
    switch (ip_defrag_stub((struct ip *) data, &iph)) {
    case IPF_ISF:
	return;
    case IPF_NOTF:
	need_free = 0;
	iph = (struct ip *) data;
	break;
    case IPF_NEW:
	need_free = 1;
	break;
    default:;
    }
    skblen = ntohs(iph->ip_len) + 16;
    if (!need_free)
	skblen += nids_params.dev_addon;
    skblen = (skblen + 15) & ~15;
    skblen += nids_params.sk_buff_size;
    for (i = ip_procs; i; i = i->next)
	(i->item) (iph, skblen);
    if (need_free)
	free(iph);
}

#if HAVE_BSD_UDPHDR
#define UH_ULEN uh_ulen
#define UH_SPORT uh_sport
#define UH_DPORT uh_dport
#else
#define UH_ULEN len
#define UH_SPORT source
#define UH_DPORT dest
#endif

static void process_udp(char *data)
{
    struct proc_node *ipp = udp_procs;
    struct ip *iph = (struct ip *) data;
    struct udphdr *udph;
    struct tuple4 addr;
    int hlen = iph->ip_hl << 2;
    int len = ntohs(iph->ip_len);
    int ulen;
    if (len - hlen < (int)sizeof(struct udphdr))
	return;
    udph = (struct udphdr *) (data + hlen);
    ulen = ntohs(udph->UH_ULEN);
    if (len - hlen < ulen || ulen < (int)sizeof(struct udphdr))
	return;
    if (my_udp_check
	((void *) udph, ulen, iph->ip_src.s_addr,
	 iph->ip_dst.s_addr)) return;
    addr.source = ntohs(udph->UH_SPORT);
    addr.dest = ntohs(udph->UH_DPORT);
    addr.saddr = iph->ip_src.s_addr;
    addr.daddr = iph->ip_dst.s_addr;
    while (ipp) {
	ipp->item(&addr, ((char *) udph) + sizeof(struct udphdr),
		  ulen - sizeof(struct udphdr), data);
	ipp = ipp->next;
    }
}

static void gen_ip_proc(u_char * data, int skblen)
{
    switch (((struct ip *) data)->ip_p) {
    case IPPROTO_TCP:
        pthread_mutex_lock(&tcp_lost_mutex);
	process_tcp(data, skblen);
        pthread_mutex_unlock(&tcp_lost_mutex);
	break;
    case IPPROTO_UDP:
	process_udp( (char*)data );
	break;
    case IPPROTO_ICMP:
	if (nids_params.n_tcp_streams)
	    process_icmp(data);
	break;
    default:
	break;
    }
}
static void init_procs()
{
    ip_frag_procs = mknew(struct proc_node);
    ip_frag_procs->item = gen_ip_frag_proc;
    ip_frag_procs->next = 0;
    ip_procs = mknew(struct proc_node);
    ip_procs->item = gen_ip_proc;
    ip_procs->next = 0;
    tcp_procs = 0;
    udp_procs = 0;
}

void nids_register_udp(void (*x))
{
    struct proc_node *ipp = mknew(struct proc_node);

    ipp->item = x;
    ipp->next = udp_procs;
    udp_procs = ipp;
}

void nids_register_ip(void (*x))
{
    struct proc_node *ipp = mknew(struct proc_node);

    ipp->item = x;
    ipp->next = ip_procs;
    ip_procs = ipp;
}

void nids_register_ip_frag(void (*x))
{
    struct proc_node *ipp = mknew(struct proc_node);

    ipp->item = x;
    ipp->next = ip_frag_procs;
    ip_frag_procs = ipp;
}

int nids_init()
{
    nids_params.dev_addon = 0;

    if (nids_params.syslog == nids_syslog)
	openlog("libnids", 0, LOG_LOCAL0);

    init_procs();
    tcp_init(nids_params.n_tcp_streams);
    ip_frag_init(nids_params.n_hosts);
    return 1;
}

extern void ip_tcp_udp_init(){
    if(!nids_init()){
	syslog(project_params.syslog_level,"error: %s\n",nids_errbuf);
        return;
    }
    nids_register_tcp(tcp_protocol_callback);
    register_job(JOB_TYPE_REORGANIZATION,process_function,process_judege,CALL_BY_TIMER);
    sepair.start = 0;
    sepair.end = 0;
}


static void *process_function(void *arg){
   int job_type = JOB_TYPE_REORGANIZATION;
   while(1){
       pthread_mutex_lock(&(job_mutex_for_cond[job_type]));
       pthread_cond_wait(&(job_cond[job_type]),&(job_mutex_for_cond[job_type]));
       pthread_mutex_unlock(&(job_mutex_for_cond[job_type]));

       process_function_actual(job_type);
    }
    
    return NULL;
}

static void process_function_actual(int job_type){
   struct Job_Queue private_jobs;
   private_jobs.front = 0;
   private_jobs.rear = 0;
   get_jobs(job_type,&private_jobs);
   struct Job current_job;
   while(!jobqueue_isEmpty(&private_jobs)){
       jobqueue_delete(&private_jobs,&current_job);
       int start = current_job.sepair.start;
       int end = current_job.sepair.end;
       int size;
       int i;

       if(start == end){
          continue;
       }
       else if(start < end){
          size = end -start;
          memcpy(packets_temp_zone,packets+start,(end - start)*sizeof(struct Packet));
// 	  printf("copy zone\n");
          for(i=0;i<size;i++){
            process_one_packet(packets_temp_zone[i]);
          }        
       }else{
          /* start >end */
          size = PACKET_QUEUE_MAX - start + end - 0;
          int position = PACKET_QUEUE_MAX - start;
          memcpy(packets_temp_zone,packets+start,(PACKET_QUEUE_MAX - start)*sizeof(struct Packet));
          memcpy(packets_temp_zone+position,packets,end*sizeof(struct Packet));
// 	  printf("swaf copy sone\n");
          for(i=0;i<size;i++){
             process_one_packet(packets_temp_zone[i]);
            
          }    
       }
// 	printf("out of JOB_TYPE_REORGANIZATION\n");
   }//while
   
}

static int process_judege(struct Job *job){
    int current_head;
    pthread_mutex_lock(&mutex_packet);
    current_head = packet_queue_head;
    pthread_mutex_unlock(&mutex_packet);

    sepair.start = sepair.end;
    sepair.end = current_head;

    if(sepair.start == sepair.end)
      return 0;

    job->sepair.start = sepair.start;
    job->sepair.end = sepair.end;
    //printf("start is %d end is %d\n", job->sepair.start,job->sepair.end);
    return 1;
}

static int add_new_tcp_to_database(struct tuple4 *ip_and_port){
        struct TcpInformation tcpinfo;
	
        strcpy(tcpinfo.src_ip, inet_ntoa( * ( (struct in_addr *) &(ip_and_port->saddr) ) ));
        strcpy(tcpinfo.des_ip, inet_ntoa( * ( (struct in_addr *) &(ip_and_port->daddr) ) ));
        tcpinfo.ip_and_port.dest =  ip_and_port->dest;
        tcpinfo.ip_and_port.source = ip_and_port->source;
        tcpinfo.ip_and_port.saddr =  ip_and_port->saddr;
        tcpinfo.ip_and_port.daddr =  ip_and_port->daddr;
        
        return sql_factory_add_new_tcp(&tcpinfo);
}

extern void tcp_come_new_data_without_add_to_database(char *data,int length,int data_type,struct tuple4 *ip_and_port,int database_hash_index,int waited_time){
     int hash_index = mk_hash_index(*ip_and_port);
     
     pthread_mutex_lock(&mutex_tcp_data_table);
     int tcp_id = hash_index;

     if(tcp_data_table[tcp_id] == 0){

         struct Tcp_Data *new_tcp = (struct Tcp_Data *)malloc(sizeof(struct Tcp_Data));

         new_tcp->client_rev = (struct List *)malloc(sizeof(struct List));
         wireless_list_init(new_tcp->client_rev);
         new_tcp->server_rev = (struct List *)malloc(sizeof(struct List));
         wireless_list_init(new_tcp->server_rev);
         new_tcp->promisc = (struct List *)malloc(sizeof(struct List));
         wireless_list_init(new_tcp->promisc);

         if(data_type == DATA_TYPE_SERVER)
             wireless_list_add(new_tcp->server_rev,data,length);
         else if(data_type == DATA_TYPE_CLIENT)
             wireless_list_add(new_tcp->client_rev,data,length);
         else if(data_type == DATA_TYPE_PROMISC)
             wireless_list_add(new_tcp->promisc,data,length);

         new_tcp->ip_and_port.dest =  ip_and_port->dest;
         new_tcp->ip_and_port.source = ip_and_port->source;
         new_tcp->ip_and_port.saddr =  ip_and_port->saddr;
         new_tcp->ip_and_port.daddr =  ip_and_port->daddr;
         write_identify( new_tcp->identify,ip_and_port);
         new_tcp->last_update_time = waited_time;
         new_tcp->access_time = waited_time;
         new_tcp->hash_index = database_hash_index;
         new_tcp->next = NULL;

         tcp_data_table[tcp_id] = new_tcp;
     }else {

         struct Tcp_Data *find_result = find_tcpdata(tcp_data_table[tcp_id],ip_and_port);

         if(find_result!=NULL){

              if(data_type == DATA_TYPE_SERVER)
                  wireless_list_add(find_result->server_rev,data,length);
              else if(data_type == DATA_TYPE_CLIENT)
                  wireless_list_add(find_result->client_rev,data,length);
              else if(data_type == DATA_TYPE_PROMISC)
                  wireless_list_add(find_result->promisc,data,length);

             find_result->last_update_time = waited_time;

         }else{
             struct Tcp_Data *last_tcp = get_last_tcp(tcp_data_table[tcp_id]);
             
             struct Tcp_Data *new_tcp = (struct Tcp_Data *)malloc(sizeof(struct Tcp_Data));

             new_tcp->client_rev = (struct List *)malloc(sizeof(struct List));
             wireless_list_init(new_tcp->client_rev);
             new_tcp->server_rev = (struct List *)malloc(sizeof(struct List));
             wireless_list_init(new_tcp->server_rev);
             new_tcp->promisc = (struct List *)malloc(sizeof(struct List));
             wireless_list_init(new_tcp->promisc);

             if(data_type == DATA_TYPE_SERVER)
                 wireless_list_add(new_tcp->server_rev,data,length);
             else if(data_type == DATA_TYPE_CLIENT)
                 wireless_list_add(new_tcp->client_rev,data,length);
             else if(data_type == DATA_TYPE_PROMISC)
                 wireless_list_add(new_tcp->promisc,data,length);

             new_tcp->ip_and_port.dest =  ip_and_port->dest;
             new_tcp->ip_and_port.source = ip_and_port->source;
             new_tcp->ip_and_port.saddr =  ip_and_port->saddr;
             new_tcp->ip_and_port.daddr =  ip_and_port->daddr;
             write_identify(new_tcp->identify,ip_and_port);
             new_tcp->last_update_time = waited_time;
             new_tcp->access_time = waited_time;
             new_tcp->hash_index = database_hash_index;
             new_tcp->next = NULL;

             last_tcp->next = new_tcp;
         }
     }
     pthread_mutex_unlock(&mutex_tcp_data_table);  
}




static void tcp_come_new_data(char *data,int length,int direction,struct tuple4 *ip_and_port,int hash_index){
//       printf("into tcp_come_new_data\n");
     pthread_mutex_lock(&mutex_tcp_data_table);
     int tcp_id = hash_index;

     if(tcp_data_table[tcp_id] == 0){
// 	 printf("table == 0\n");
         struct Tcp_Data *new_tcp = (struct Tcp_Data *)malloc(sizeof(struct Tcp_Data));

         new_tcp->client_rev = (struct List *)malloc(sizeof(struct List));
         wireless_list_init(new_tcp->client_rev);
         new_tcp->server_rev = (struct List *)malloc(sizeof(struct List));
         wireless_list_init(new_tcp->server_rev);
         new_tcp->promisc = (struct List *)malloc(sizeof(struct List));
         wireless_list_init(new_tcp->promisc);

         if(direction == DIRECTION_CLIENT_RECEIVE){
             wireless_list_add(new_tcp->client_rev,data,length);
             wireless_list_add(new_tcp->promisc,data,length);
         }else{
             wireless_list_add(new_tcp->server_rev,data,length);
             wireless_list_add(new_tcp->promisc,data,length);
         }
// 	printf("half of table == 0\n");
         new_tcp->ip_and_port.dest =  ip_and_port->dest;
         new_tcp->ip_and_port.source = ip_and_port->source;
         new_tcp->ip_and_port.saddr =  ip_and_port->saddr;
         new_tcp->ip_and_port.daddr =  ip_and_port->daddr;
         write_identify( new_tcp->identify,ip_and_port);
         new_tcp->last_update_time = time((time_t *)0);
         new_tcp->access_time = time((time_t *)0);
	 
         new_tcp->hash_index = add_new_tcp_to_database(ip_and_port);
	 
         new_tcp->next = NULL;

         tcp_data_table[tcp_id] = new_tcp;
         
// 	 printf("out of table == 0");
     }else {
// 	  printf("table != 0\n");
         struct Tcp_Data *find_result = find_tcpdata(tcp_data_table[tcp_id],ip_and_port);
// 	  printf("found tcpdata\n");
         if(find_result!=NULL){

             if(direction == DIRECTION_CLIENT_RECEIVE){
                wireless_list_add(find_result->client_rev,data,length);
                wireless_list_add(find_result->promisc,data,length);
             }else{
                wireless_list_add(find_result->server_rev,data,length);
                wireless_list_add(find_result->promisc,data,length);
             }
             find_result->last_update_time = time((time_t *)0);
         }else{
             struct Tcp_Data *last_tcp = get_last_tcp(tcp_data_table[tcp_id]);
             
             struct Tcp_Data *new_tcp = (struct Tcp_Data *)malloc(sizeof(struct Tcp_Data));

             new_tcp->client_rev = (struct List *)malloc(sizeof(struct List));
             wireless_list_init(new_tcp->client_rev);
             new_tcp->server_rev = (struct List *)malloc(sizeof(struct List));
             wireless_list_init(new_tcp->server_rev);
             new_tcp->promisc = (struct List *)malloc(sizeof(struct List));
             wireless_list_init(new_tcp->promisc);

             if(direction == DIRECTION_CLIENT_RECEIVE){
                 wireless_list_add(new_tcp->client_rev,data,length);
                 wireless_list_add(new_tcp->promisc,data,length);
             }else{
                 wireless_list_add(new_tcp->server_rev,data,length);
                 wireless_list_add(new_tcp->promisc,data,length);
             }

             new_tcp->ip_and_port.dest =  ip_and_port->dest;
             new_tcp->ip_and_port.source = ip_and_port->source;
             new_tcp->ip_and_port.saddr =  ip_and_port->saddr;
             new_tcp->ip_and_port.daddr =  ip_and_port->daddr;
             write_identify(new_tcp->identify,ip_and_port);
             new_tcp->last_update_time = time((time_t *)0);
             new_tcp->access_time = time((time_t *)0);
             new_tcp->hash_index = add_new_tcp_to_database(ip_and_port);
             new_tcp->next = NULL;

             last_tcp->next = new_tcp;
         }
     }
//      printf("out of tcp_come_new_data\n");
     pthread_mutex_unlock(&mutex_tcp_data_table);  
}

static inline struct Tcp_Data *find_tcpdata(struct Tcp_Data *point,struct tuple4 *ip_and_port){

      memset(target,0,sizeof(target));
      write_identify(target,ip_and_port);
      while(point!=NULL){
         if(strstr(point->identify,target)!=NULL)
              return point;
         point = point->next;
      }
      return NULL;
}

static inline struct Tcp_Data *get_last_tcp(struct Tcp_Data *point){
    while(point->next != NULL)
       point = point->next;
    return point;
}

static inline void write_identify(char *identify_buffer,struct tuple4 *ip_and_port){
   memset(identify_buffer,0,sizeof(identify_buffer));
   char saddr[100],daddr[100];
   memset(saddr,0,100*sizeof(char));
   memset(daddr,0,100*sizeof(char));
   strcpy(saddr,inet_ntoa( * ( (struct in_addr *) &(ip_and_port->saddr) ) ));
   strcpy(daddr,inet_ntoa( * ( (struct in_addr *) &(ip_and_port->daddr) ) ));
   
   sprintf(identify_buffer,"%s_%s_%d_%d", daddr,saddr,ip_and_port->dest,ip_and_port->source );
}

#if 0
static char *
adres (struct tuple4 addr)
{
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ",%i,", addr.source);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ",%i", addr.dest);
  return buf;
}
#endif

static char* ltoa(long long value, char *str)
{
    int i = 0, a;

    do
    {
        a = value % 10;
        switch(a)
        {
        case 0: str[i] = '0'; i++; break;
        case 1: str[i] = '1'; i++; break;
        case 2: str[i] = '2'; i++; break;
        case 3: str[i] = '3'; i++; break;
        case 4: str[i] = '4'; i++; break;
        case 5: str[i] = '5'; i++; break;
        case 6: str[i] = '6'; i++; break;
        case 7: str[i] = '7'; i++; break;
        case 8: str[i] = '8'; i++; break;
        case 9: str[i] = '9'; i++; break;
        }
        value /= 10;
    }while(value != 0);
    str[i] = '\0';
    
    int j, m;
    char temp;
    for(j = 0, m = i; j < m / 2; j++)
    {
        temp      =  str[j];
        str[j]     =  str[m-1-j];
        str[m-1-j] =  temp;
    }
    
    return str;
}  

static void add2clist(struct tuple4 addr, char *state)
{
  static long long record_num;
  gchar src_ip[32], dst_ip[32];
  gchar src_port[16], dst_port[16];
  gchar number[64];
  gchar *rowdata[7];
  
  record_num++;
  strcpy (src_ip, int_ntoa (addr.saddr));
  sprintf (src_port, "%i", addr.source);
  strcpy (dst_ip, int_ntoa (addr.daddr));
  sprintf (dst_port, "%i", addr.dest);
  rowdata[0] = ltoa(record_num, number);
  rowdata[1] = src_ip;
  rowdata[2] = src_port;
  rowdata[3] = dst_ip;
  rowdata[4] = dst_port;
  rowdata[5] = state; 
  gtk_clist_prepend( GTK_CLIST(PktInfoList), rowdata);
}

static char buf[1024] = {0};
static void tcp_protocol_callback(struct tcp_stream * tcp_connection , void **arg )
{
  struct tuple4 ip_and_port = tcp_connection->addr;
  int presult;
  
  switch( tcp_connection->nids_state ) {
    case  NIDS_JUST_EST:
      tcp_connection->client.collect++;
      tcp_connection->server.collect++;
      tcp_connection->client.collect_urg++;
      tcp_connection->server.collect_urg++;
      strcpy (buf, " established");
      break ;
      
    case NIDS_CLOSE:
      strcpy (buf, " closing");
      break;
	
    case NIDS_RESET :
      strcpy (buf, " reset");      
      break;
      
    case NIDS_DATA: {
      struct half_stream *half;
      
      if ( tcp_connection->client.count_new ) {
	half = &tcp_connection->client;
        tcp_come_new_data( half->data, half->count_new,
			  DIRECTION_CLIENT_RECEIVE,
			  &ip_and_port, 
			  tcp_connection->hash_index);
	strcpy (buf, "(<-)");
        break;
      }

      if( tcp_connection->server.count_new ) {
	half = & tcp_connection->server;
	tcp_come_new_data( half->data, half->count_new,
			  DIRECTION_SERVER_RECEIVE, 
			  &ip_and_port,
			  tcp_connection->hash_index);
	strcpy (buf, "(->)");
        break;
      }
                   
      if (tcp_connection->server.count_new_urg){
	half = & tcp_connection->server;
	tcp_come_new_data( half->urgdata, half->count_new_urg,
			  DIRECTION_SERVER_RECEIVE,
			  &ip_and_port,
			  tcp_connection->hash_index);
	strcpy (buf, "(->)");
	break;
      }

      if (tcp_connection->client.count_new_urg){
	half = & tcp_connection->client;
	tcp_come_new_data(half->urgdata, half->count_new_urg,
			  DIRECTION_CLIENT_RECEIVE,
			  &ip_and_port,tcp_connection->hash_index);
	strcpy (buf, "(<-)");
	break;
      }               
    }
    default:break;
  }
  //printf("%s\n", buf);
  gdk_threads_enter();
  add2clist(tcp_connection->addr, buf);
  gdk_threads_leave();
}