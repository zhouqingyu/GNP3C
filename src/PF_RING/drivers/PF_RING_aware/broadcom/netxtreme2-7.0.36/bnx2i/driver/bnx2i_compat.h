/* bnx2i_compat.h: Broadcom NetXtreme II iSCSI compatible header.
 *
 * Copyright (c) 2011 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Eddie Wai (eddie.wai@broadcom.com)
 */

#ifndef _BNX2I_COMPAT_H_
#define _BNX2I_COMPAT_H_

#if (defined(__RHELS_DISTRO_5__))
#include <scsi/iscsi_if2.h>
#include <scsi/iscsi_proto2.h>
#include <scsi/scsi_transport_iscsi2.h>
#include <scsi/libiscsi2.h>

#define iscsi_create_endpoint(a) iscsi2_create_endpoint(a)
#define iscsi_destroy_endpoint(a) iscsi2_destroy_endpoint(a)
#define iscsi_session_failure(a,b) iscsi2_session_failure(a,b)
#define iscsi_host_alloc(a,b,c) iscsi2_host_alloc(a,b,c)
#define iscsi_host_add(a,b) iscsi2_host_add(a,b)
#define iscsi_host_for_each_session(a,b) iscsi2_host_for_each_session(a,b)
#define iscsi_host_remove(a) iscsi2_host_remove(a)
#define iscsi_host_free(a) iscsi2_host_free(a)
#if (__RHELS_DISTRO_5__ > 0x0504)
#define iscsi_session_setup(a,b,c,d,e,f,g) iscsi2_session_setup(a,b,c,d,e,f,g)
#else
#define iscsi_session_setup(a,b,c,d,e,f,g) iscsi2_session_setup(a,b,c,e,f,g)
#endif
#define iscsi_session_teardown(a) iscsi2_session_teardown(a)
#define iscsi_session_recovery_timedout iscsi2_session_recovery_timedout
#define iscsi_session_get_param iscsi2_session_get_param
#define iscsi_conn_setup(a,b,c) iscsi2_conn_setup(a,b,c)
#define iscsi_conn_bind(a,b,c) iscsi2_conn_bind(a,b,c)
#define iscsi_conn_start(a) iscsi2_conn_start(a)
#define iscsi_conn_send_pdu iscsi2_conn_send_pdu
#define iscsi_conn_stop iscsi2_conn_stop
#define iscsi_conn_failure(a,b) iscsi2_conn_failure(a,b)
#define iscsi_conn_teardown(a) iscsi2_conn_teardown(a)
#define iscsi_lookup_endpoint(a) iscsi2_lookup_endpoint(a)
#define iscsi_conn_get_param(a,b,c) iscsi2_conn_get_param(a,b,c)
#define iscsi_host_get_param(a,b,c) iscsi2_host_get_param(a,b,c)
#define iscsi_host_for_each_session(a,b) iscsi2_host_for_each_session(a,b)
#define iscsi_register_transport(a) iscsi2_register_transport(a)
#define iscsi_unregister_transport(a) iscsi2_unregister_transport(a)

/* TODO: Setting the ISCSI_SUSPEND_BIT w/o bh lock! */
#define iscsi_suspend_queue(a) iscsi2_suspend_tx(a)

#define iscsi_queuecommand iscsi2_queuecommand
#define iscsi_eh_abort iscsi2_eh_abort
#define iscsi_eh_device_reset iscsi2_eh_device_reset
#define iscsi_change_queue_depth iscsi2_change_queue_depth

#define iscsi_set_param iscsi2_set_param

#define __iscsi_complete_pdu(a,b,c,d) __iscsi2_complete_pdu(a,b,c,d)
#define iscsi_put_task(a) iscsi2_put_task(a)

static inline ssize_t sysfs_format_mac(char *buf, const unsigned char *addr,
				       int len)
{
	int i;
	char *cp = buf;

	for (i = 0; i < len; i++)
		cp += sprintf(cp, "%02x%c", addr[i],
			      i == (len - 1) ? '\n' : ':');
	return cp - buf;
}

#define FORMAT_IP(buf, fstr, src, len)				\
	do {							\
		u8 *ip = (u8 *)&src[0];				\
		len = sprintf(buf, "%d.%d.%d.%d",		\
			      ip[0], ip[1], ip[2], ip[3]);	\
	} while (0)

#define FORMAT_IP6(buf, fstr, src, len)				\
	do {							\
		u16 *ip = (u16 *)&src[0];			\
		len = sprintf(buf, "%04x:%04x:%04x:%04x:"	\
				   "%04x:%04x:%04x:%04x\n",	\
				   htons(ip[0]), htons(ip[1]),	\
				   htons(ip[2]), htons(ip[3]),	\
				   htons(ip[4]), htons(ip[5]),	\
				   htons(ip[6]), htons(ip[7]));	\
	} while (0)

#define rounddown_pow_of_two(n)	(roundup_pow_of_two(n) << 1)

#define scsi_for_each_sg(cmd, sg, nseg, __i)                    \
        for (__i = 0, sg = scsi_sglist(cmd); __i < (nseg); __i++, (sg)++)

#else /* (defined(__RHELS_DISTRO_5__)) */

/* For RHEL6, SLES11 */

#include <scsi/iscsi_if.h>
#include <scsi/iscsi_proto.h>
#include <scsi/scsi_transport_iscsi.h>
#include <scsi/libiscsi.h>

#define FORMAT_IP(buf, fstr, src, len)		\
	do {					\
		len = sprintf(buf, fstr, src);	\
	} while (0)

#define FORMAT_IP6(buf, fstr, src, len) FORMAT_IP(buf, fstr, src, len)

#if (defined(__SLES_DISTRO__) && (__SLES_DISTRO__ > 0x1101))
#define iscsi_cmd	iscsi_scsi_req
#define iscsi_cmd_rsp	iscsi_scsi_rsp
#define iscsi_login	iscsi_login_req
#endif

#endif /* __RHELS_DISTRO_5__ */
#endif /* _BNX2I_COMPAT_H_ */
