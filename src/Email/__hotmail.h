#ifndef __HOTMAIL_H

extern int __hotmail_send_content(struct Http *http,struct Email_info *email_info);
extern int __hotmail_send_attachment(struct Http *http,struct Email_info *email_info);
extern int __hotmail_receive_content(struct Http *http,struct Email_info *email_info);
extern int __hotmail_receive_attachment(struct Http *http,struct Email_info *email_info);

#define __HOTMAIL_H

#endif
