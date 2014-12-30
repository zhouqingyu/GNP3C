#ifndef __139_H

extern int __139_send_content(struct Http *http,struct Email_info *email_info);
extern int __139_send_attachment(struct Http *http,struct Email_info *email_info);
extern int __139_receive_content(struct Http *http,struct Email_info *email_info);
extern int __139_receive_attachment(struct Http *http,struct Email_info *email_info);

#define __139_H

#endif
