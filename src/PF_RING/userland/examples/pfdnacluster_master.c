/*
 *
 * (C) 2012 - Luca Deri <deri@ntop.org>
 *            Alfredo Cardigliano <cardigliano@ntop.org>
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
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "pfring.h"
#include "pfutils.c"

#define ALARM_SLEEP            1
#define MAX_NUM_APP            DNA_CLUSTER_MAX_NUM_SLAVES
#define MAX_NUM_DEV            DNA_CLUSTER_MAX_NUM_SOCKETS
#define DEFAULT_DEVICE         "dna0"

int num_dev = 0, num_apps = 0, tot_num_slaves = 0;
int instances_per_app[MAX_NUM_APP];
pfring *pd[MAX_NUM_DEV];
pfring_dna_cluster *dna_cluster_handle;

u_int8_t wait_for_packet = 1, print_interface_stats = 0, do_shutdown = 0, hashing_mode = 0, use_hugepages = 0;
socket_mode mode = recv_only_mode;

static struct timeval startTime;

/* ******************************** */

void print_stats() {
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static struct timeval lastTime;
  char buf0[64], buf1[64], buf2[64];
  u_int64_t RXdiff, TXdiff, RXProcdiff;
  static u_int64_t lastRXPkts = 0, lastTXPkts = 0, lastRXProcPkts = 0;
  unsigned long long nRXPkts = 0, nTXPkts = 0, nRXProcPkts = 0;
  pfring_dna_cluster_stat cluster_stats;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  if(dna_cluster_stats(dna_cluster_handle, &cluster_stats) == 0) {
    nRXPkts  = cluster_stats.tot_rx_packets;
    nTXPkts  = cluster_stats.tot_tx_packets;
    nRXProcPkts  = cluster_stats.tot_rx_processed;

    fprintf(stderr, "---\nAbsolute Stats:");
 
    if (mode != send_only_mode) {
      fprintf(stderr, " RX %s pkts", pfring_format_numbers((double)nRXPkts, buf1, sizeof(buf1), 0));
      if(print_all) fprintf(stderr, " [%s pkt/sec]", pfring_format_numbers((double)(nRXPkts*1000)/deltaMillisec, buf1, sizeof(buf1), 1));
      
      fprintf(stderr, " Processed %s pkts", pfring_format_numbers((double)nRXProcPkts, buf1, sizeof(buf1), 0));
      if(print_all) fprintf(stderr, " [%s pkt/sec]", pfring_format_numbers((double)(nRXProcPkts*1000)/deltaMillisec, buf1, sizeof(buf1), 1));
    }
	   
    if (mode != recv_only_mode) {
      fprintf(stderr, " TX %s pkts", pfring_format_numbers((double)nTXPkts, buf1, sizeof(buf1), 0));
      if(print_all) fprintf(stderr, " [%s pkt/sec]", pfring_format_numbers((double)(nTXPkts*1000)/deltaMillisec, buf1, sizeof(buf1), 1));
    }
	        
    fprintf(stderr, "\n");

    if (mode != send_only_mode && print_interface_stats) {
      int i;
      pfring_stat if_stats;
      for (i = 0; i < num_dev; i++) {
        if (pfring_stats(pd[i], &if_stats) >= 0)
          fprintf(stderr, "                %s RX %" PRIu64 " pkts Dropped %" PRIu64 " pkts (%.1f %%)\n", 
                  pd[i]->device_name, if_stats.recv, if_stats.drop, 
		  if_stats.recv == 0 ? 0 : ((double)(if_stats.drop*100)/(double)(if_stats.recv + if_stats.drop)));
      }
    }

    if(print_all && (lastTime.tv_sec > 0)) {
      deltaMillisec = delta_time(&endTime, &lastTime);
      RXdiff = nRXPkts - lastRXPkts;
      TXdiff = nTXPkts - lastTXPkts;
      RXProcdiff = nRXProcPkts - lastRXProcPkts;

      fprintf(stderr, "Actual Stats:  ");

      if (mode != send_only_mode) {
        fprintf(stderr, " RX %s pkts [%s ms][%s pps]",
	        pfring_format_numbers((double)RXdiff, buf0, sizeof(buf0), 0),
	        pfring_format_numbers(deltaMillisec, buf1, sizeof(buf1), 1),
	        pfring_format_numbers(((double)RXdiff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1));
			   
        fprintf(stderr, " Processed %s pkts [%s ms][%s pps]",
	        pfring_format_numbers((double)RXProcdiff, buf0, sizeof(buf0), 0),
                pfring_format_numbers(deltaMillisec, buf1, sizeof(buf1), 1),
                pfring_format_numbers(((double)RXProcdiff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1));
      }
						    
      if (mode != recv_only_mode) {
        fprintf(stderr, " TX %llu pkts [%s ms][%s pps]",
	        (long long unsigned int)TXdiff,
	        pfring_format_numbers(deltaMillisec, buf1, sizeof(buf1), 1),
                pfring_format_numbers(((double)TXdiff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1));
      }

      fprintf(stderr, "\n");
    }

    lastRXPkts = nRXPkts;
    lastTXPkts = nTXPkts;
    lastRXProcPkts = nRXProcPkts;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(do_shutdown)
    return;

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");

  if(called) return; else called = 1;
  
  dna_cluster_disable(dna_cluster_handle);
  
  do_shutdown = 1;
}

/* *************************************** */

void printHelp(void) {
  printf("pfdnacluster_master - (C) 2012 ntop.org\n\n");

  printf("pfdnacluster_master [-a] -i dev\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (comma-separated list)\n");
  printf("-c <cluster>    Cluster ID\n");
  printf("-n <num>        Number of app instances (comma-separated list for multiple apps)\n");
  printf("-r <core_id>    Bind the RX thread to a core\n");
  printf("-t <core_id>    Bind the TX thread to a core\n");
  printf("-m <hash mode>  Hashing modes:\n"
	 "                0 - IP hash (default)\n"
	 "                1 - MAC Address hash\n"
	 "                2 - IP protocol hash\n"
	 "                3 - Fan-Out\n");
  printf("-s              Enable TX\n");
  printf("-a              Active packet wait\n");
  printf("-u <mountpoint> Use hugepages for packet memory allocation\n");
  printf("-p              Print per-interface absolute stats\n");
  printf("-d              Daemon mode\n");
  printf("-P <pid file>   Write pid to the specified file (daemon mode only)\n");
  exit(0);
}

/* *************************************** */

inline u_int32_t master_custom_hash_function(const u_char *buffer, const u_int16_t buffer_len) {
  u_int32_t l3_offset = sizeof(struct compact_eth_hdr);
  u_int16_t eth_type;

  if(hashing_mode == 1 /* MAC hash */)
    return(buffer[3] + buffer[4] + buffer[5] + buffer[9] + buffer[10] + buffer[11]);

  eth_type = (buffer[12] << 8) + buffer[13];

  while (eth_type == 0x8100 /* VLAN */) {
    l3_offset += 4;
    eth_type = (buffer[l3_offset - 2] << 8) + buffer[l3_offset - 1];
  }

  switch (eth_type) {
  case 0x0800:
    {
      /* IPv4 */
      struct compact_ip_hdr *iph;

      if (unlikely(buffer_len < l3_offset + sizeof(struct compact_ip_hdr)))
	return 0;

      iph = (struct compact_ip_hdr *) &buffer[l3_offset];

      if(hashing_mode == 0 /* IP hash */)
	return ntohl(iph->saddr) + ntohl(iph->daddr); /* this can be optimized by avoiding calls to ntohl(), but it can lead to balancing issues */
      else /* IP protocol hash */
	return iph->protocol;
    }
    break;
  case 0x86DD:
    {
      /* IPv6 */
      struct compact_ipv6_hdr *ipv6h;
      u_int32_t *s, *d;

      if (unlikely(buffer_len < l3_offset + sizeof(struct compact_ipv6_hdr)))
	return 0;

      ipv6h = (struct compact_ipv6_hdr *) &buffer[l3_offset];

      if(hashing_mode == 0 /* IP hash */) {
	s = (u_int32_t *) &ipv6h->saddr, d = (u_int32_t *) &ipv6h->daddr;
	return(s[0] + s[1] + s[2] + s[3] + d[0] + d[1] + d[2] + d[3]);
      } else
	return(ipv6h->nexthdr);
    }
    break;
  default:
    return 0; /* Unknown protocol */
  }
}

/* ******************************* */

static int master_distribution_function(const u_char *buffer, const u_int16_t buffer_len, const pfring_dna_cluster_slaves_info *slaves_info, u_int32_t *id_mask, u_int32_t *hash) {
  u_int32_t slave_idx;
  
  /* computing a bidirectional software hash */
  *hash = master_custom_hash_function(buffer, buffer_len);
	   
  /* balancing on hash */
  slave_idx = (*hash) % slaves_info->num_slaves;
  *id_mask = (1 << slave_idx);

  return DNA_CLUSTER_PASS;
}

/* ******************************* */

static int multi_app_distribution_function(const u_char *buffer, const u_int16_t buffer_len, const pfring_dna_cluster_slaves_info *slaves_info, u_int32_t *id_mask, u_int32_t *hash) {
  u_int32_t i, offset = 0, app_instance, slaves_mask = 0;

  /* computing a bidirectional software hash */
  *hash = master_custom_hash_function(buffer, buffer_len);

  /* balancing on hash */
  for (i = 0; i < num_apps; i++) {
    app_instance = (*hash) % instances_per_app[i];
    slaves_mask |= (1 << (offset + app_instance));
    offset += instances_per_app[i];
  }

  *id_mask = slaves_mask;
  return DNA_CLUSTER_PASS;
}

/* ******************************** */

static int fanout_distribution_function(const u_char *buffer, const u_int16_t buffer_len, const pfring_dna_cluster_slaves_info *slaves_info, u_int32_t *id_mask, u_int32_t *hash) {
  u_int32_t n_zero_bits = 32 - slaves_info->num_slaves;

  /* returning slave id bitmap */
  *id_mask = ((0xFFFFFFFF << n_zero_bits) >> n_zero_bits);

  return DNA_CLUSTER_PASS;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  char buf[32];
  u_int32_t version;
  int rx_bind_core = 0, tx_bind_core = 1;
  int off, i, j, cluster_id = -1;
  char *device = NULL, *dev, *dev_pos = NULL;
  char *applications = NULL, *app, *app_pos = NULL;
  char *pidFileName = NULL;
  char *hugepages_mountpoint = NULL;
  int daemon_mode = 0;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:r:st:hi:n:m:du:pP:")) != -1) {
    switch(c) {
    case 'a':
      wait_for_packet = 0;
      break;
    case 'r':
      rx_bind_core = atoi(optarg);
      break;
    case 't':
      tx_bind_core = atoi(optarg);
      break;
    case 'h':
      printHelp();      
      break;
    case 's':
      mode = send_and_recv_mode;
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'n':
      applications = strdup(optarg);
      break;
    case 'm':
      hashing_mode = atoi(optarg);
      break;
    case 'd':
      daemon_mode = 1;
      break;
    case 'p':
      print_interface_stats = 1;
      break;
    case 'P':
      pidFileName = strdup(optarg);
      break;
    case 'u':
      use_hugepages = 1;
      hugepages_mountpoint = strdup(optarg);
      break;
    }
  }

  if (applications != NULL) {
    app = strtok_r(applications, ",", &app_pos);
    while(app != NULL) {
      instances_per_app[num_apps] = atoi(app);

      if (instances_per_app[num_apps] <= 0)
        printHelp();

      tot_num_slaves += instances_per_app[num_apps];
      num_apps++;

      app = strtok_r(NULL, ",", &app_pos);
    }
  }

  if (tot_num_slaves > MAX_NUM_APP) {
    printf("WARNING: You cannot instantiate more than %u slave applications\n", MAX_NUM_APP);
    printHelp();
  }

  if (num_apps == 0) {
    instances_per_app[num_apps] = 1;
    num_apps = 1;
  }

  if (cluster_id < 0 || hashing_mode < 0 || hashing_mode > 3)
    printHelp();

  if (device == NULL) device = strdup(DEFAULT_DEVICE);

  if (daemon_mode)
    daemonize(pidFileName);

  printf("Capturing from %s\n", device);
  
  /* Create the DNA cluster */
  if ((dna_cluster_handle = dna_cluster_create(cluster_id, 
                                               tot_num_slaves, 
					       0 
					       /* | DNA_CLUSTER_DIRECT_FORWARDING */
                                               /* | DNA_CLUSTER_NO_ADDITIONAL_BUFFERS */
					       /* | DNA_CLUSTER_DCA */
					       | (use_hugepages ? DNA_CLUSTER_HUGEPAGES : 0)
     )) == NULL) {
    fprintf(stderr, "Error creating DNA Cluster\n");
    return(-1);
  }

  /* Changing the default settings (experts only)
  dna_cluster_low_level_settings(dna_cluster_handle, 
                                 8192, // slave rx queue slots
                                 8192, // slave tx queue slots
				 4096  // slave additional buffers (available with  alloc/release)
				 );
  */

  if (use_hugepages) {
    if (dna_cluster_set_hugepages_mountpoint(dna_cluster_handle, hugepages_mountpoint) < 0) {
      fprintf(stderr, "Error setting the hugepages mountpoint: did you mount it?\n");
      return(-1);
    }
  }

  /* Setting the cluster mode */
  dna_cluster_set_mode(dna_cluster_handle, mode);

  dev = strtok_r(device, ",", &dev_pos);
  while(dev != NULL) {
    pd[num_dev] = pfring_open(dev, 1500 /* snaplen */, PF_RING_PROMISC);
    if(pd[num_dev] == NULL) {
      printf("pfring_open %s error [%s]\n", dev, strerror(errno));
      return(-1);
    }

    if (num_dev == 0) {
      pfring_version(pd[num_dev], &version);
      printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16, 
	     (version & 0x0000FF00) >> 8, version & 0x000000FF);
    }

    snprintf(buf, sizeof(buf), "pfdnacluster_master-cluster-%d-socket-%d", cluster_id, num_dev);
    pfring_set_application_name(pd[num_dev], buf);

    /* Add the ring we created to the cluster */
    if (dna_cluster_register_ring(dna_cluster_handle, pd[num_dev]) < 0) {
      fprintf(stderr, "Error registering rx socket\n");
      dna_cluster_destroy(dna_cluster_handle);
      return -1;
    }

    num_dev++;

    dev = strtok_r(NULL, ",", &dev_pos);

    if (num_dev == MAX_NUM_DEV && dev != NULL) {
      printf("Too many devices\n");
      break;
    }
  }

  if (num_dev == 0) {
    dna_cluster_destroy(dna_cluster_handle);
    printHelp();
  }

  /* Setting up important details... */
  dna_cluster_set_wait_mode(dna_cluster_handle, !wait_for_packet /* active_wait */);
  dna_cluster_set_cpu_affinity(dna_cluster_handle, rx_bind_core, tx_bind_core);

  switch(hashing_mode) {
  case 0:
    printf("Hashing packets per-IP Address\n");
    /* The default distribution function already balances per IP in a coherent mode */
    if (num_apps > 1) dna_cluster_set_distribution_function(dna_cluster_handle, multi_app_distribution_function);
    break;
  case 1:
    printf("Hashing packets per-MAC Address\n");
    if (num_apps > 1) dna_cluster_set_distribution_function(dna_cluster_handle, multi_app_distribution_function);
    else dna_cluster_set_distribution_function(dna_cluster_handle, master_distribution_function);
    break;
  case 2:
    printf("Hashing packets per-IP protocol (TCP, UDP, ICMP...)\n");
    if (num_apps > 1) dna_cluster_set_distribution_function(dna_cluster_handle, multi_app_distribution_function);
    else dna_cluster_set_distribution_function(dna_cluster_handle, master_distribution_function);
    break;
  case 3:
    printf("Replicating each packet on all applications (no copy)\n");
    dna_cluster_set_distribution_function(dna_cluster_handle, fanout_distribution_function);
    break;
  }

  /* Now enable the cluster */
  if (dna_cluster_enable(dna_cluster_handle) < 0) {
    fprintf(stderr, "Error enabling the engine; dna NICs already in use?\n");
    dna_cluster_destroy(dna_cluster_handle);
    return -1;
  }

  printf("The DNA cluster [id: %u][num slave apps: %u] is now running...\n", 
	 cluster_id, tot_num_slaves);
  printf("You can now attach to DNA cluster up to %d slaves as follows:\n", 
         tot_num_slaves);
  if (num_apps == 1) {
    printf("\tpfcount -i dnacluster:%d\n", cluster_id);
  } else {
    off = 0;
    for (i = 0; i < num_apps; i++) {
      printf("Application %u\n", i);
      for (j = 0; j < instances_per_app[i]; j++)
        printf("\tpfcount -i dnacluster:%d@%u\n", cluster_id, off++);
    }
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if (!daemon_mode) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  while (!do_shutdown) sleep(1); /* do something in the main */
 
  dna_cluster_destroy(dna_cluster_handle);

  sleep(2);
  return(0);
}

