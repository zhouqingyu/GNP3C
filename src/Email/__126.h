#ifndef __126_H

extern int __126_send_content(struct Http *http,struct Email_info *email_info);
extern int __126_send_attachment(struct Http *http,struct Email_info *email_info);
extern int __126_receive_content(struct Http *http,struct Email_info *email_info);
extern int __126_receive_attachment(struct Http *http,struct Email_info *email_info);

#define __126_H

#endif
