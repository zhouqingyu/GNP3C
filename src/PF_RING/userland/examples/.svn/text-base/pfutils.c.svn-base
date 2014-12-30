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

#include "../lib/config.h"

#ifndef __USE_GNU
#define __USE_GNU
#endif

//#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h> /* for CPU_XXXX */

typedef u_int64_t ticks;

/* ******************************** */

void daemonize(char *pidFile) {
  pid_t pid, sid;

  pid = fork();
  if (pid < 0) exit(EXIT_FAILURE);
  if (pid > 0) {
    if (pidFile != NULL) {
      FILE *fp = fopen(pidFile, "w");
      fprintf(fp, "%d", pid);
      fclose(fp);
    }
    exit(EXIT_SUCCESS);
  }

  sid = setsid();
  if (sid < 0) exit(EXIT_FAILURE);

  if ((chdir("/")) < 0) exit(EXIT_FAILURE);

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

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

/* *************************************** */

char* sec2dhms(u_int32_t sec, char *buf, u_int buf_len) {
  snprintf(buf, buf_len, "%u:%02u:%02u:%02u", 
    (sec / (60 * 60 * 24)), 
    (sec / (60 * 60)) % 24, 
    (sec /  60) % 60, 
    (sec % 60)
  );
  return(buf);
}

/* *************************************** */

/* Bind this thread to a specific core */

int bindthread2core(pthread_t thread_id, u_int core_id) {
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
  cpu_set_t cpuset;
  int s;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  if((s = pthread_setaffinity_np(thread_id, sizeof(cpu_set_t), &cpuset)) != 0) {
    fprintf(stderr, "Error while binding to core %u: errno=%i\n", core_id, s);
    return(-1);
  } else {
    return(0);
  }
#else
  fprintf(stderr, "WARNING: your system lacks of pthread_setaffinity_np() (not core binding)\n");
  return(0);
#endif
}

/* *************************************** */

/* Bind the current thread to a core */

int bind2core(u_int core_id) {
  return(bindthread2core(pthread_self(), core_id));
}

/* *************************************** */

static __inline__ ticks getticks(void)
{
  u_int32_t a, d;
  // asm("cpuid"); // serialization
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return (((ticks)a) | (((ticks)d) << 32));
}

/* *************************************** */

struct compact_eth_hdr {
  unsigned char   h_dest[ETH_ALEN];
  unsigned char   h_source[ETH_ALEN];
  u_int16_t       h_proto;
};

struct compact_ip_hdr {
  u_int8_t	ihl:4,
                version:4;
  u_int8_t	tos;
  u_int16_t	tot_len;
  u_int16_t	id;
  u_int16_t	frag_off;
  u_int8_t	ttl;
  u_int8_t	protocol;
  u_int16_t	check;
  u_int32_t	saddr;
  u_int32_t	daddr;
};

struct compact_ipv6_hdr {
  u_int8_t		priority:4,
		version:4;
  u_int8_t		flow_lbl[3];
  u_int16_t	payload_len;
  u_int8_t		nexthdr;
  u_int8_t		hop_limit;
  struct in6_addr saddr;
  struct in6_addr daddr;
};

/* *************************************** */

