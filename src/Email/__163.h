#ifndef __163_H

extern int __163_send_content(struct Http *http,struct Email_info *email_info);
extern int __163_send_attachment(struct Http *http,struct Email_info *email_info);
extern int __163_receive_content(struct Http *http,struct Email_info *email_info);
extern int __163_receive_attachment(struct Http *http,struct Email_info *email_info);

#define __163_H

#endif
