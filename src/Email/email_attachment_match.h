#ifndef EMAIL_ATTACHMENT_H

#define EMAIL_ATTACHMENT_H

#include "../list.h"

struct Email_reference {
	struct list_head list_node;
	char *reference;
	int ref_len;
	char email_id[32];
};

extern struct list_head content_list_head;
extern struct list_head attachment_list_head;
extern pthread_mutex_t content_list_mutex;
extern pthread_mutex_t attachment_list_mutex;

extern void email_attachment_match_init();

#endif
