/*
 *
 * (C) 2012 - ntop
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
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "pfring.h"
#include "pfutils.c"

struct packet {
  u_int16_t len;
  char      *data;
};

struct ip_header {
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int32_t	ihl:4,		/* header length */
    version:4;			/* version */
#else
  u_int32_t	version:4,	/* version */
    ihl:4;			/* header length */
#endif
  u_int8_t	tos;		/* type of service */
  u_int16_t	tot_len;	/* total length */
  u_int16_t	id;		/* identification */
  u_int16_t	frag_off;	/* fragment offset field */
  u_int8_t	ttl;		/* time to live */
  u_int8_t	protocol;	/* protocol */
  u_int16_t	check;		/* checksum */
  u_int32_t saddr, daddr;	/* source and dest address */
};

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udp_header {
  u_int16_t	source;		/* source port */
  u_int16_t	dest;		/* destination port */
  u_int16_t	len;		/* udp length */
  u_int16_t	check;		/* udp checksum */
};

pfring  *pd;
char *out_dev = NULL;
u_int8_t do_shutdown = 0;
int reforge_mac = 0;
char mac_address[6];
int send_len = 60;
int if_index = -1;

#define DEFAULT_DEVICE     "eth0"

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stdout, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  pfring_close(pd);

  exit(0);
}

/* *************************************** */

void printHelp(void) {
  printf("pflatency - Sends a packet and wait actively for the packet back, computing the rtt latency\n");
  printf("(C) 2012 ntop\n\n");
  printf("-i <device>     Device name\n");
  printf("-l <length>     Packet length to send. Ignored with -f\n");
  printf("-f <.pcap file> Send the first packet of a pcap file\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-m <dst MAC>    Reforge destination MAC (format AA:BB:CC:DD:EE:FF)\n");
  printf("-z              Disable zero-copy, if supported (DNA only)\n");
  printf("-x <if index>   Send to the selected interface, if supported\n");
  printf("-h              Print this help\n");
  printf("\nExample for testing the DNA bouncer latency:\n");
  printf("./pfdnabounce -i dna1 -m 0 -g 2 -f -a\n");
  printf("./pfsend -i dna0 -l 60 -g 1\n");
  exit(0);
}

/* ******************************************* */

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 * Borrowed from DHCPd
 */

static u_int32_t in_cksum(unsigned char *buf,
			  unsigned nbytes, u_int32_t sum) {
  uint i;

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  /* If there's a single byte left over, checksum it, too.   Network
     byte order is big-endian, so the remaining byte is the high byte. */
  if(i < nbytes) {
#ifdef DEBUG_CHECKSUM_VERBOSE
    debug ("sum = %x", sum);
#endif
    sum += buf [i] << 8;
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return sum;
}

/* ******************************************* */

static u_int32_t wrapsum (u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

/* ******************************************* */

static void forge_udp_packet(char *buffer, u_int idx) {
  int i;
  struct ip_header *ip_header;
  struct udp_header *udp_header;
  u_int32_t src_ip = (0x0A000000 + idx) % 0xFFFFFFFF /* from 10.0.0.0 */;
  u_int32_t dst_ip =  0xC0A80001 /* 192.168.0.1 */;
  u_int16_t src_port = 2012, dst_port = 3000;

  /* Reset packet */
  memset(buffer, 0, sizeof(buffer));

  for(i=0; i<12; i++) buffer[i] = i;
  buffer[12] = 0x08, buffer[13] = 0x00; /* IP */
  if(reforge_mac) memcpy(buffer, mac_address, 6);

  ip_header = (struct ip_header*) &buffer[sizeof(struct ether_header)];
  ip_header->ihl = 5;
  ip_header->version = 4;
  ip_header->tos = 0;
  ip_header->tot_len = htons(send_len-sizeof(struct ether_header));
  ip_header->id = htons(2012);
  ip_header->ttl = 64;
  ip_header->frag_off = htons(0);
  ip_header->protocol = IPPROTO_UDP;
  ip_header->daddr = htonl(dst_ip);
  ip_header->saddr = htonl(src_ip);
  ip_header->check = wrapsum(in_cksum((unsigned char *)ip_header,
			sizeof(struct ip_header), 0));

  udp_header = (struct udp_header*)(buffer + sizeof(struct ether_header) + sizeof(struct ip_header));
  udp_header->source = htons(src_port);
  udp_header->dest = htons(dst_port);
  udp_header->len = htons(send_len-sizeof(struct ether_header)-sizeof(struct ip_header));
  udp_header->check = 0; /* It must be 0 to compute the checksum */

  /*
    http://www.cs.nyu.edu/courses/fall01/G22.2262-001/class11.htm
    http://www.ietf.org/rfc/rfc0761.txt
    http://www.ietf.org/rfc/rfc0768.txt
  */

  i = sizeof(struct ether_header) + sizeof(struct ip_header) + sizeof(struct udp_header);
  udp_header->check = wrapsum(in_cksum((unsigned char *)udp_header, sizeof(struct udp_header),
                                       in_cksum((unsigned char *)&buffer[i], send_len-i,
                                       in_cksum((unsigned char *)&ip_header->saddr,
                                                2*sizeof(ip_header->saddr),
                                                IPPROTO_UDP + ntohs(udp_header->len)))));
}

/* *************************************** */

int main(int argc, char* argv[]) {
  struct packet packet_to_send = { 0 };
  char c, *pcap_in = NULL;
  int disable_zero_copy = 0;
  int use_zero_copy_tx = 0;
  u_int mac_a, mac_b, mac_c, mac_d, mac_e, mac_f;
  char buffer[9000];
  int bind_core = -1;
  ticks tick_start = 0, tick_delta = 0;
  ticks hz = 0;
  u_int num_tx_slots = 0;
  int rc;
  char buf1[64];
  u_char *pkt_buffer = NULL;
  struct pfring_pkthdr hdr;
  memset(&hdr, 0, sizeof(hdr));


  while((c = getopt(argc,argv,"hi:n:g:l:f:m:zx:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'i':
      out_dev = strdup(optarg);
      break;
    case 'f':
      pcap_in = strdup(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'l':
      send_len = atoi(optarg);
      break;
    case 'x':
      if_index = atoi(optarg);
      break;
    case 'm':
      if(sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &mac_a, &mac_b, &mac_c, &mac_d, &mac_e, &mac_f) != 6) {
	printf("Invalid MAC address format (XX:XX:XX:XX:XX:XX)\n");
	return(0);
      } else {
	reforge_mac = 1;
	mac_address[0] = mac_a, mac_address[1] = mac_b, mac_address[2] = mac_c;
	mac_address[3] = mac_d, mac_address[4] = mac_e, mac_address[5] = mac_f;
      }
      break;
    case 'z':
      disable_zero_copy = 1;
      break;
    }
  }

  if(out_dev == NULL)  printHelp();

  printf("Sending packets on %s\n", out_dev);

  pd = pfring_open(out_dev, 1500, PF_RING_PROMISC);
  if(pd == NULL) {
    printf("pfring_open %s error [%s]\n", out_dev, strerror(errno));
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfdnasend");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8, version & 0x000000FF);
  }

  if (!pd->send && pd->send_ifindex && if_index == -1) {
    printf("Please use -x <if index>\n");
    pfring_close(pd);
    return -1;
  } 

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if(send_len < 60)
    send_len = 60;

  /* cumputing usleep delay */
  tick_start = getticks();
  usleep(1);
  tick_delta = getticks() - tick_start;
    
  /* cumputing CPU freq */
  tick_start = getticks();
  usleep(1001);
  hz = (getticks() - tick_start - tick_delta) * 1000 /*kHz -> Hz*/;

  printf("Estimated CPU freq: %lu Hz\n", (long unsigned int)hz);

  if(pcap_in) {
    char ebuf[256];
    u_char *pkt;
    struct pcap_pkthdr *h;
    pcap_t *pt = pcap_open_offline(pcap_in, ebuf);

    if(!pt) {
      printf("Unable to open file %s\n", pcap_in);
      pfring_close(pd);
      return(-1);
    } else {
      int rc = pcap_next_ex(pt, &h, (const u_char**) &pkt);

      if(rc <= 0) {
        printf("Unable to read packet from pcap file %s\n", pcap_in);
	pfring_close(pd);
	return(-1);
      }

      packet_to_send.len = h->caplen;
      packet_to_send.data = (char*) malloc(packet_to_send.len);

      if(packet_to_send.data == NULL) {
        printf("Not enough memory\n");
	pfring_close(pd);
        return(-1);
      } else {
        memcpy(packet_to_send.data, pkt, packet_to_send.len);
        if(reforge_mac) memcpy(packet_to_send.data, mac_address, 6);
      }

      printf("Read %d bytes packet from pcap file %s\n", 
	     packet_to_send.len, pcap_in);

      pcap_close(pt);
    }
  } else {
    forge_udp_packet(buffer, 0);

    packet_to_send.len = send_len;
    packet_to_send.data = (char*)malloc(packet_to_send.len);

    if (packet_to_send.data == NULL) {
      printf("Not enough memory\n");
      pfring_close(pd);
      return(-1);
    }
      
    memcpy(packet_to_send.data, buffer, packet_to_send.len);
  }

  if(bind_core >= 0)
    bind2core(bind_core);

  pfring_set_socket_mode(pd, send_and_recv_mode);
  
  pfring_set_direction(pd, rx_and_tx_direction);

  pfring_set_poll_watermark(pd, 0);

  if(pfring_enable_ring(pd) != 0) {
    printf("Unable to enable ring :-(\n");
    pfring_close(pd);
    return(-1);
  }

  use_zero_copy_tx = 0;

  if((!disable_zero_copy) 
    && (pd->dna_copy_tx_packet_into_slot != NULL)) {

    num_tx_slots = pd->dna_get_num_tx_slots(pd);

    if(num_tx_slots > 0) {
      int ret;

      ret = pfring_copy_tx_packet_into_slot(pd, 0, packet_to_send.data, packet_to_send.len);
      
      if(ret >= 0)
        use_zero_copy_tx = 1;
    }
  }
  
  printf("%s zero-copy TX\n", use_zero_copy_tx ? "Using" : "NOT using");

redo:
  tick_start = getticks();

  if (if_index != -1)
    rc = pfring_send_ifindex(pd, packet_to_send.data, packet_to_send.len, 1, if_index);
  else if(use_zero_copy_tx)
    /* We pre-filled the TX slots */
    rc = pfring_send(pd, NULL, packet_to_send.len, 1);
  else
    rc = pfring_send(pd, packet_to_send.data, packet_to_send.len, 1);

  if(rc == PF_RING_ERROR_INVALID_ARGUMENT) {
    printf("Attempting to send invalid packet [len: %u][MTU: %u]%s\n",
	   packet_to_send.len, pd->mtu_len,
      	   if_index != -1 ? " or using a wrong interface id" : "");
  } else if (rc < 0) {
    goto redo;
  }
    
  while (pfring_recv(pd, &pkt_buffer, 0, &hdr, 0) <= 0);

  tick_delta = getticks() - tick_start;
  
  printf("\n%s usec\n", pfring_format_numbers((double) 1000000 /* us */ / ( hz / tick_delta ), buf1, sizeof(buf1), 1));

  pfring_close(pd);

  return(0);
}
