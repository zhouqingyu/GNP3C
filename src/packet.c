#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include <sys/timeb.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include<errno.h>
#include<string.h>
#include<sys/socket.h>                                                                                
#include<net/if.h> // reference struct ifreq
#include<linux/if_ether.h> // reference ETH_P_ALL
#include<sys/ioctl.h> // reference SIOCGIFINDEX	
#include <syslog.h>


#include "configuration.h"
#include "packet.h"
#include "pfring.h"

static pfring *ring;

extern void recv_packet_function(){
    char *device = configuration.monitor_card_name[0];
    struct pfring_pkthdr hdr;
    int bktLen, received;
    u_char *pktpt;
       
    if( (ring = pfring_open(device, 1520, PF_RING_PROMISC)) == NULL ) 
    {
       syslog(project_params.syslog_level, "pfring_open error [%s]\n", 
	      strerror(errno));
       return;
    }
    pfring_enable_ring(ring);
    syslog(project_params.syslog_level, "Bind device %s\n", device);  
    
    packet_queue_head = 0;
    while(1){
        received = pfring_recv(ring, &pktpt, 0, &hdr, 1/* wait */);
	if( received <= 0 ) {
	    syslog(project_params.syslog_level,"EFAULT (errno is %d) count is %d\n",errno,packet_queue_head);
	    continue;
	}
	if(ring->slot_header_len != sizeof(struct pfring_pkthdr))
	    bktLen = hdr.caplen;
	else
	    bktLen = hdr.caplen+hdr.extended_hdr.parsed_header_len; 
	//printf("received : %d\n", bktLen);
	packets[packet_queue_head].length = bktLen;
	memcpy(packets[packet_queue_head].content, pktpt, bktLen);
        pthread_mutex_lock(&mutex_packet);
        packet_queue_head = (packet_queue_head+1) % PACKET_QUEUE_MAX;
        pthread_mutex_unlock(&mutex_packet);
    }//while 
}
