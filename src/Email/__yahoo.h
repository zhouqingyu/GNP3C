#ifndef __YAHOO_H

extern int __yahoo_send_content(struct Http *http,struct Email_info *email_info);
extern int __yahoo_send_attachment(struct Http *http,struct Email_info *email_info);
extern int __yahoo_receive_content(struct Http *http,struct Email_info *email_info);
extern int __yahoo_receive_attachment(struct Http *http,struct Email_info *email_info);

#define __YAHOO_H 

#endif
