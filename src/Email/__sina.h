#ifndef __SINA_H

extern int __sina_send_content(struct Http *http,struct Email_info *email_info);
extern int __sina_send_attachment(struct Http *http,struct Email_info *email_info);
extern int __sina_receive_content(struct Http *http,struct Email_info *email_info);
extern int __sina_receive_attachment(struct Http *http,struct Email_info *email_info);

#define __SINA_H

#endif
