/*
 *
 * (C) 2005-12 - Luca Deri <deri@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * VLAN support courtesy of Vincent Magnin <vincent.magnin@ci.unil.ch>
 *
 */

#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"

#define ALARM_SLEEP             1
#define DEFAULT_SNAPLEN       128
#define MAX_NUM_THREADS        64

int verbose = 0, num_channels = 1;
pfring_stat pfringStats;

static struct timeval startTime;
pfring  *ring[MAX_NUM_THREADS] = { NULL };
unsigned long long numPkts[MAX_NUM_THREADS] = { 0 }, numBytes[MAX_NUM_THREADS] = { 0 };
u_int8_t use_extended_pkt_header = 0, wait_for_packet = 1, do_shutdown = 0;
pthread_t pd_thread[MAX_NUM_THREADS];
int thread_core_affinity[MAX_NUM_THREADS];
static u_int numCPU;

#define DEFAULT_DEVICE     "eth0"

/* *************************************** */
/*
 * The time difference in millisecond
 */
double delta_time (struct timeval * now,
		   struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* ******************************** */

void print_stats() {
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int64_t lastPkts[MAX_NUM_THREADS] = { 0 };
  u_int64_t diff;
  static struct timeval lastTime;
  int i;
  unsigned long long nBytes = 0, nPkts = 0, pkt_dropped = 0;
  unsigned long long nPktsLast = 0;
  double pkt_thpt = 0, tot_thpt = 0, delta;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  delta = delta_time(&endTime, &lastTime);

  for(i=0; i < num_channels; i++) {
    nBytes += numBytes[i], nPkts += numPkts[i];
  
    if(pfring_stats(ring[i], &pfringStat) >= 0) {
      double thpt = ((double)8*numBytes[i])/(deltaMillisec*1000);

      fprintf(stderr, "=========================\n"
	      "Absolute Stats: [channel=%d][%u pkts rcvd][%u pkts dropped]\n"
	      "Total Pkts=%u/Dropped=%.1f %%\n",
	      i, (unsigned int)numPkts[i], (unsigned int)pfringStat.drop,
	      (unsigned int)(numPkts[i]+pfringStat.drop),
	      numPkts[i] == 0 ? 0 : (double)(pfringStat.drop*100)/(double)(numPkts[i]+pfringStat.drop));
      fprintf(stderr, "%llu pkts - %llu bytes", numPkts[i], numBytes[i]);
      fprintf(stderr, " [%.1f pkt/sec - %.2f Mbit/sec]\n", (double)(numPkts[i]*1000)/deltaMillisec, thpt);
      pkt_dropped += pfringStat.drop;

      if(lastTime.tv_sec > 0) {
	double pps;
	
	diff = numPkts[i]-lastPkts[i];
	nPktsLast += diff;
	tot_thpt += thpt;
	pps = ((double)diff/(double)(delta/1000));
	fprintf(stderr, "=========================\n"
		"Actual Stats: [channel=%d][%llu pkts][%.1f ms][%.1f pkt/sec]\n",
		i, (long long unsigned int)diff, delta, pps);
	pkt_thpt += pps;
      }

      lastPkts[i] = numPkts[i];
    }
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n");
  fprintf(stderr, "Aggregate stats (all channels): [%.1f pkt/sec][%.2f Mbit/sec][%llu pkts dropped]\n", 
	  (double)(nPktsLast*1000)/(double)delta, tot_thpt, pkt_dropped);
  fprintf(stderr, "=========================\n\n");
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  int i;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();

  fprintf(stderr, "Shutting down sockets...\n");
  for(i=0; i<num_channels; i++) {
    pfring_shutdown(ring[i]);
    printf("\t%d...\n", i);
  }

  exit(0);
}

/* ******************************** */

void my_sigalarm(int sig) {
  if (do_shutdown)
    return;
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

void printHelp(void) {
  printf("pfcount_multichannel\n(C) 2005-12 Deri Luca <deri@ntop.org>\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (No device@channel), and dnaX for DNA\n");

  printf("-e <direction>  0=RX+TX, 1=RX only, 2=TX only\n");
  printf("-l <len>        Capture length\n");
  printf("-m              Long packet header (with PF_RING extensions)\n");
  printf("-w <watermark>  Watermark\n");
  printf("-p <poll wait>  Poll wait (msec)\n");
  printf("-b <cpu %%>      CPU pergentage priority (0-99)\n");
  printf("-a              Active packet wait\n");
  printf("-g <id:id...>   Specifies the thread affinity mask. Each <id> represents\n"
	 "                the codeId where the i-th will bind. Example: -g 7:6:5:4\n"
	 "                binds thread <device>@0 on coreId 7, <device>@1 on coreId 6\n"
	 "                and so on.\n");
  printf("-r              Rehash RSS packets\n");
  printf("-v              Verbose\n");
}

/* ****************************************************** */

static int32_t thiszone;

void dummyProcesssPacket(const struct pfring_pkthdr *h,
                         const u_char *p,
                         const u_char *user_bytes)
{
   const int BUFSIZE = 4096;
   char bigbuf[BUFSIZE]; // buf into which we spew prints
   int  buflen = 0;

   long threadId = (long)user_bytes;

   if(unlikely(do_shutdown)) return;

   if(verbose) {
      int s;
      uint nsec;

      if(h->ts.tv_sec == 0) {
        memset((void*)&h->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
	pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 5, 1, 1);
      }

      s = (h->ts.tv_sec + thiszone) % 86400;
      nsec = h->extended_hdr.timestamp_ns % 1000;
    
      buflen += snprintf(&bigbuf[buflen], BUFSIZE - buflen,
        "%02d:%02d:%02d.%06u%03u ",
        s / 3600, (s % 3600) / 60, s % 60,
        (unsigned)h->ts.tv_usec, nsec);

#if 0
      for(i=0; i<32; i++) buflen += snprintf(&bigbuf[buflen], BUFSIZE - buflen, "%02X ", p[i]);
      printf("\n");
#endif

      buflen += snprintf(&bigbuf[buflen], BUFSIZE - buflen, "[T%lu]", threadId);

      if(use_extended_pkt_header) {
        buflen += pfring_print_parsed_pkt(&bigbuf[buflen], BUFSIZE - buflen, p, h);
      } else {
        struct ether_header *ehdr = (struct ether_header *) p;
        u_short eth_type = ntohs(ehdr->ether_type);
        if(eth_type == 0x0806) buflen += snprintf(&bigbuf[buflen], BUFSIZE - buflen, "[ARP]");
        else buflen += snprintf(&bigbuf[buflen], BUFSIZE - buflen, "[eth_type=0x%04X]", eth_type);

        buflen += snprintf(&bigbuf[buflen], BUFSIZE - buflen, "[caplen=%d][len=%d][parsed_header_len=%d]"
                "[eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
                h->caplen, h->len, h->extended_hdr.parsed_header_len,
                h->extended_hdr.parsed_pkt.offset.eth_offset,
                h->extended_hdr.parsed_pkt.offset.l3_offset,
                h->extended_hdr.parsed_pkt.offset.l4_offset,
                h->extended_hdr.parsed_pkt.offset.payload_offset);
      }
      fputs(bigbuf, stdout);
   }

   numPkts[threadId]++, numBytes[threadId] += h->len+24 /* 8 Preamble + 4 CRC + 12 IFG */;
}

/* *************************************** */

int32_t gmt2local(time_t t) {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if (t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
    (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/* *************************************** */

void* packet_consumer_thread(void* _id)
{
   long thread_id = (long)_id;

#ifdef HAVE_PTHREAD_SETAFFINITY_NP
   if(numCPU > 1)
   {
      /* Bind this thread to a specific core */
      cpu_set_t cpuset;
      u_long core_id;
      int s;

      if (thread_core_affinity[thread_id] != -1)
         core_id = thread_core_affinity[thread_id] % numCPU;
      else
         core_id = (thread_id + 1) % numCPU;

      CPU_ZERO(&cpuset);
      CPU_SET(core_id, &cpuset);
      if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0)
         fprintf(stderr, "Error while binding thread %ld to core %ld: errno=%i\n", 
                 thread_id, core_id, s);
      else {
         printf("Set thread %lu on core %lu/%u\n", thread_id, core_id, numCPU);
      }
   }
#endif

   while(!do_shutdown) {
      u_char *buffer = NULL;
      struct pfring_pkthdr hdr;

      if(pfring_recv(ring[thread_id], &buffer, 0, &hdr, wait_for_packet) > 0) {
         dummyProcesssPacket(&hdr, buffer, (u_char*)thread_id);

      } else {
         if(wait_for_packet == 0) sched_yield();
         //usleep(1);
      }
   }

   return(NULL);
}

int
ethtool_set_flowdirector(int on)
{
   // @TODO: plop the ethtool ioctl code in here to set up flowdirector
   // perfect tuple filters.
   return 0;
}

int
setup_steering(pfring* thering, const char* addr, int queue)
{
   int rc;
   static int rule_id = 0; // @HACK!
   hw_filtering_rule rule;
   intel_82599_perfect_filter_hw_rule *perfect_rule;

   if (thering == 0 || addr == 0)
   {
      errno = EINVAL;
      return -1;
   }

   printf("### Perfect Rule Example ###\n");

   rc = pfring_set_filtering_mode(thering, hardware_only);
   printf("pfring_set_filtering_mode: hardware_only %s(%d)\n",
          (rc == 0) ? "SUCCEEDED" : "FAILED", rc );

   /*
     NOTE:
     - valid protocols: UDP or TCP
   */
   perfect_rule = &rule.rule_family.perfect_rule;

   memset(&rule, 0, sizeof(rule));
   rule.rule_family_type = intel_82599_perfect_filter_rule;

   rule.rule_id = rule_id++;
   perfect_rule->queue_id = queue;
   perfect_rule->proto = IPPROTO_UDP;
   perfect_rule->d_addr = ntohl(inet_addr(addr));

   rc = pfring_add_hw_rule(thering, &rule);
   
   if(rc != 0)
      printf("pfring_add_hw_rule(%d) failed [rc=%d]: "
             "did you enable the FlowDirector "
             "(ethtool -K ethX ntuple on)\n",
             rule.rule_id, rc);
   else
      printf("pfring_add_hw_rule(%d) succeeded: "
             "steering UDP traffic %s:* -> *\n",
             rule.rule_id,
             addr);

   return rc;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, *bind_mask = NULL;
  int snaplen = DEFAULT_SNAPLEN, rc, watermark = 0, rehash_rss = 0;
  packet_direction direction = rx_only_direction;
  long i;
  u_int16_t cpu_percentage = 0, poll_duration = 0;
  u_int32_t version;
  u_int32_t flags = 0;

  startTime.tv_sec = 0;
  thiszone = gmt2local(0);
  numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  memset(thread_core_affinity, -1, sizeof(thread_core_affinity));

  while((c = getopt(argc,argv,"hi:l:mvae:w:b:rp:g:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'e':
      switch(atoi(optarg)) {
      case rx_and_tx_direction:
      case rx_only_direction:
      case tx_only_direction:
	direction = atoi(optarg);
	break;
      }
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'm':
      use_extended_pkt_header = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'w':
      watermark = atoi(optarg);
      break;
    case 'b':
      cpu_percentage = atoi(optarg);
      break;
    case 'r':
      rehash_rss = 1;
      break;
    case 'p':
      poll_duration = atoi(optarg);
      break;
    case 'g':
      bind_mask = strdup(optarg);
      break;
    }
  }

  if(verbose) watermark = 1;
  if(device == NULL) device = DEFAULT_DEVICE;

  printf("Capturing from %s\n", device);

  flags |= PF_RING_PROMISC; /* hardcode: promisc=1 */
#if 0
  flags |=  PF_RING_DNA_FIXED_RSS_Q_0;
#else
  flags |= PF_RING_DNA_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-DNA drivers */
#endif
  if(use_extended_pkt_header) flags |= PF_RING_LONG_HEADER;

  num_channels = pfring_open_multichannel(device, snaplen, flags, ring);
  
  if(num_channels <= 0) {
    fprintf(stderr, "pfring_open_multichannel() returned %d [%s]\n", num_channels, strerror(errno));
    return(-1);
  }


  if (num_channels > MAX_NUM_THREADS)
  {
     printf("WARNING: Too many channels (%d), using %d channels\n", num_channels, MAX_NUM_THREADS);
     num_channels = MAX_NUM_THREADS;
  }
  else if (num_channels > numCPU)
  {
     printf("WARNING: More channels (%d) than available cores (%d), using %d channels\n", num_channels, numCPU, numCPU);
     num_channels = numCPU;
  }
  else 
  {
    printf("Found %d channels\n", num_channels);
  }

  if(bind_mask != NULL)
  {
     char *id = strtok(bind_mask, ":");
     int idx = 0;

     while(id != NULL) {
        thread_core_affinity[idx++] = atoi(id) % numCPU;
        if(idx >= num_channels) break;
        id = strtok(NULL, ":");
     }
  }

  pfring_version(ring[0], &version);  
  printf("Using PF_RING v.%d.%d.%d\n",
	 (version & 0xFFFF0000) >> 16,
	 (version & 0x0000FF00) >> 8,
	 version & 0x000000FF);
  
  for(i=0; i<num_channels; i++)
  {
     char buf[32];
    
     snprintf(buf, sizeof(buf), "pfcount_multichannel-thread %ld", i);
     pfring_set_application_name(ring[i], buf);

     if((rc = pfring_set_direction(ring[i], direction)) != 0)
	fprintf(stderr, "pfring_set_direction returned %d [direction=%d] (you can't capture TX with DNA)\n", rc, direction);
    
     if((rc = pfring_set_socket_mode(ring[i], recv_only_mode)) != 0)
	fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

     if(watermark > 0) {
        if((rc = pfring_set_poll_watermark(ring[i], watermark)) != 0)
           fprintf(stderr, "pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n", rc, watermark);
     }
#if 0    
  setup_steering(ring[0], "192.168.30.207", -1);

  /* UTDF */
  setup_steering(ring[0], "224.0.1.92", 1);
  setup_steering(ring[0], "224.0.1.94", 1);
  setup_steering(ring[0], "224.0.1.96", 1);

  /* BATS */
  setup_steering(ring[0], "224.0.62.2", 2);

  /* default: should go to channel 0 */
#endif
     if(rehash_rss)
        pfring_enable_rss_rehash(ring[i]);
    
     if(poll_duration > 0)
        pfring_set_poll_duration(ring[i], poll_duration);

     pfring_enable_ring(ring[i]);

     pthread_create(&pd_thread[i], NULL, packet_consumer_thread, (void*)i);
     usleep(500);
  }

  if(cpu_percentage > 0) {
    if(cpu_percentage > 99) cpu_percentage = 99;
    pfring_config(cpu_percentage);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  for(i=0; i<num_channels; i++) {
    pthread_join(pd_thread[i], NULL);
    pfring_close(ring[i]);
  }

  return(0);
}
